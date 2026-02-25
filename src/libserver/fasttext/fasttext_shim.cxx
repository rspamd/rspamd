/*
 * Copyright 2026 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "fasttext_shim.h"
#include "libutil/cxx/file_util.hxx"
#include "fmt/base.h"
#include "contrib/ankerl/unordered_dense.h"

#include <unicode/utf8.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <numeric>
#include <queue>
#include <fcntl.h>
#include <sys/mman.h>

namespace rspamd::fasttext {

namespace {

/* Sanity limits for untrusted values read from model files */
constexpr std::int32_t MAX_SANE_DIM = 4096;
constexpr std::int32_t MAX_SANE_ENTRIES = 50'000'000;
constexpr std::int64_t MAX_SANE_MATRIX_ROWS = 500'000'000;
constexpr std::int32_t MAX_SANE_CODESIZE = 500'000'000;
constexpr std::int32_t MAX_SANE_BUCKET = 100'000'000;
constexpr std::size_t MAX_SANE_STRING = 1024;

/* --- Binary reader: a cursor over memory-mapped data --- */
/* Uses a fail-bit pattern instead of exceptions: once any read overflows,
 * the reader enters a failed state and all subsequent reads return zeroes.
 * Callers check fail() after a sequence of reads. */
class binary_reader {
public:
	binary_reader(const unsigned char *data, std::size_t size)
		: data_(data), size_(size), pos_(0), failed_(false)
	{
	}

	auto position() const -> std::size_t
	{
		return pos_;
	}
	auto remaining() const -> std::size_t
	{
		return failed_ ? 0 : size_ - pos_;
	}
	auto fail() const -> bool
	{
		return failed_;
	}

	void skip(std::size_t n)
	{
		if (!ensure(n)) return;
		pos_ += n;
	}

	auto read_i32() -> std::int32_t
	{
		if (!ensure(4)) return 0;
		std::int32_t v;
		std::memcpy(&v, data_ + pos_, 4);
		pos_ += 4;
		return v;
	}

	auto read_i64() -> std::int64_t
	{
		if (!ensure(8)) return 0;
		std::int64_t v;
		std::memcpy(&v, data_ + pos_, 8);
		pos_ += 8;
		return v;
	}

	auto read_f64() -> double
	{
		if (!ensure(8)) return 0.0;
		double v;
		std::memcpy(&v, data_ + pos_, 8);
		pos_ += 8;
		return v;
	}

	auto read_u8() -> std::uint8_t
	{
		if (!ensure(1)) return 0;
		auto v = data_[pos_];
		pos_ += 1;
		return v;
	}

	auto read_bool() -> bool
	{
		return read_u8() != 0;
	}

	auto read_cstring() -> std::string
	{
		std::string result;
		while (pos_ < size_) {
			auto ch = data_[pos_++];
			if (ch == 0) break;
			result.push_back(static_cast<char>(ch));
			if (result.size() > MAX_SANE_STRING) {
				failed_ = true;
				return {};
			}
		}
		return result;
	}

	auto read_floats(std::size_t count) -> const float *
	{
		if (count > SIZE_MAX / sizeof(float)) {
			failed_ = true;
			return nullptr;
		}
		auto bytes = count * sizeof(float);
		if (!ensure(bytes)) return nullptr;
		auto ptr = reinterpret_cast<const float *>(data_ + pos_);
		pos_ += bytes;
		return ptr;
	}

private:
	auto ensure(std::size_t n) -> bool
	{
		if (failed_ || pos_ + n > size_) {
			failed_ = true;
			return false;
		}
		return true;
	}

	const unsigned char *data_;
	std::size_t size_;
	std::size_t pos_;
	bool failed_;
};

/* --- FNV-1a hash matching FastText's implementation --- */
/* Critical: must use int8_t (signed) cast before XOR, not uint8_t */
auto fnv_hash(std::string_view str) -> std::uint32_t
{
	std::uint32_t h = 2166136261u;
	for (auto c: str) {
		h ^= static_cast<std::uint32_t>(static_cast<std::int8_t>(c));
		h *= 16777619u;
	}
	return h;
}

/* Find UTF-8 codepoint boundary positions in a string using ICU */
auto utf8_positions(std::string_view s) -> std::vector<std::size_t>
{
	std::vector<std::size_t> positions;
	positions.reserve(s.size());
	auto len = static_cast<std::int32_t>(s.size());
	std::int32_t i = 0;

	while (i < len) {
		positions.push_back(i);
		UChar32 c;
		U8_NEXT(s.data(), i, len, c);
	}
	positions.push_back(s.size()); /* sentinel */
	return positions;
}

} /* anonymous namespace */


/* --- Dictionary entry --- */
struct dict_entry {
	std::string word;
	std::int64_t count = 0;
	entry_type type = entry_type::word;
	std::vector<std::int32_t> subwords; /* precomputed subword IDs */
};

/* --- Product Quantizer --- */
class product_quantizer {
public:
	auto load(binary_reader &reader) -> bool
	{
		dim_ = reader.read_i32();
		nsubq_ = reader.read_i32();
		dsub_ = reader.read_i32();
		lastdsub_ = reader.read_i32();

		if (reader.fail() || dim_ <= 0 || dim_ > MAX_SANE_DIM ||
			nsubq_ <= 0 || dsub_ <= 0 || lastdsub_ <= 0) {
			return false;
		}

		/* Centroids are stored as dim * ksub floats (not nsubq * ksub * dsub) */
		auto total_floats = static_cast<std::size_t>(dim_) * ksub_;
		auto ptr = reader.read_floats(total_floats);
		if (!ptr) {
			return false;
		}
		centroids_.assign(ptr, ptr + total_floats);
		return true;
	}

	void add_code(const std::uint8_t *codes, float *vec, std::int32_t dim, float alpha) const
	{
		if (centroids_.empty()) return;
		std::int32_t offset = 0;

		for (std::int32_t sq = 0; sq < nsubq_; sq++) {
			auto centroid_idx = static_cast<std::size_t>(codes[sq]);
			auto sub_dim = (sq == nsubq_ - 1) ? lastdsub_ : dsub_;
			auto centroid_base = get_centroid_offset(sq, centroid_idx);

			for (std::int32_t d = 0; d < sub_dim; d++) {
				if (centroid_base + d < centroids_.size() && offset + d < dim) {
					vec[offset + d] += alpha * centroids_[centroid_base + d];
				}
			}
			offset += sub_dim;
		}
	}

	auto dot_code(const std::uint8_t *codes, const float *vec, std::int32_t dim, float alpha) const -> float
	{
		if (centroids_.empty()) return 0.0f;
		float result = 0.0f;
		std::int32_t offset = 0;

		for (std::int32_t sq = 0; sq < nsubq_; sq++) {
			auto centroid_idx = static_cast<std::size_t>(codes[sq]);
			auto sub_dim = (sq == nsubq_ - 1) ? lastdsub_ : dsub_;
			auto centroid_base = get_centroid_offset(sq, centroid_idx);

			for (std::int32_t d = 0; d < sub_dim; d++) {
				if (centroid_base + d < centroids_.size() && offset + d < dim) {
					result += centroids_[centroid_base + d] * vec[offset + d];
				}
			}
			offset += sub_dim;
		}
		return result * alpha;
	}

	auto get_nsubq() const -> std::int32_t
	{
		return nsubq_;
	}

	/* Look up a single centroid value (used for norm decoding via NPQ) */
	auto get_centroid_value(std::int32_t sq, std::uint8_t code) const -> float
	{
		auto offset = get_centroid_offset(sq, static_cast<std::size_t>(code));
		if (offset < centroids_.size()) {
			return centroids_[offset];
		}
		return 1.0f;
	}

private:
	/* Matches FastText's get_centroids: last sub-quantizer uses lastdsub stride */
	auto get_centroid_offset(std::int32_t sq, std::size_t centroid_idx) const -> std::size_t
	{
		if (sq == nsubq_ - 1) {
			return static_cast<std::size_t>(sq) * ksub_ * dsub_ + centroid_idx * lastdsub_;
		}
		return (static_cast<std::size_t>(sq) * ksub_ + centroid_idx) * dsub_;
	}

	static constexpr std::int32_t ksub_ = 256; /* number of centroids per sub-quantizer */
	std::int32_t dim_ = 0;
	std::int32_t nsubq_ = 0;
	std::int32_t dsub_ = 0;
	std::int32_t lastdsub_ = 0;
	std::vector<float> centroids_;
};

/* --- Matrix interface --- */
class matrix_base {
public:
	virtual ~matrix_base() = default;
	virtual void add_row_to_vec(float *vec, std::int32_t row, std::int32_t dim) const = 0;
	virtual auto dot_row(const float *vec, std::int32_t row, std::int32_t dim) const -> float = 0;
	virtual auto rows() const -> std::int64_t = 0;
	virtual auto cols() const -> std::int64_t = 0;
};

/* Dense matrix: pointer into mmap'd data or heap-owned */
class dense_matrix final : public matrix_base {
public:
	/* Construct from mmap pointer (zero-copy, for input matrix) */
	dense_matrix(const float *data, std::int64_t m, std::int64_t n)
		: data_(data), m_(m), n_(n)
	{
	}

	/* Construct from heap data (for output matrix) */
	dense_matrix(std::vector<float> &&storage, std::int64_t m, std::int64_t n)
		: storage_(std::move(storage)), m_(m), n_(n)
	{
		data_ = storage_.data();
	}

	void add_row_to_vec(float *vec, std::int32_t row, std::int32_t dim) const override
	{
		if (!data_ || row < 0 || row >= m_) return;
		auto base = static_cast<std::size_t>(row) * n_;
		auto count = std::min(static_cast<std::int32_t>(n_), dim);
		for (std::int32_t i = 0; i < count; i++) {
			vec[i] += data_[base + i];
		}
	}

	auto dot_row(const float *vec, std::int32_t row, std::int32_t dim) const -> float override
	{
		if (!data_ || row < 0 || row >= m_) return 0.0f;
		auto base = static_cast<std::size_t>(row) * n_;
		float result = 0.0f;
		auto count = std::min(static_cast<std::int32_t>(n_), dim);
		for (std::int32_t i = 0; i < count; i++) {
			result += data_[base + i] * vec[i];
		}
		return result;
	}

	auto rows() const -> std::int64_t override
	{
		return m_;
	}
	auto cols() const -> std::int64_t override
	{
		return n_;
	}

private:
	const float *data_ = nullptr;
	std::vector<float> storage_;
	std::int64_t m_;
	std::int64_t n_;
};

/* Quantized matrix: codes + product quantizer */
class quant_matrix final : public matrix_base {
public:
	quant_matrix(std::int64_t m, std::int64_t n, bool qnorm,
				 std::vector<std::uint8_t> &&codes,
				 std::vector<std::uint8_t> &&norm_codes,
				 product_quantizer &&pq,
				 product_quantizer &&npq)
		: m_(m), n_(n), qnorm_(qnorm),
		  codes_(std::move(codes)),
		  norm_codes_(std::move(norm_codes)),
		  pq_(std::move(pq)),
		  npq_(std::move(npq))
	{
	}

	void add_row_to_vec(float *vec, std::int32_t row, std::int32_t dim) const override
	{
		if (row < 0 || row >= m_) return;
		auto nsubq = pq_.get_nsubq();
		if (nsubq <= 0) return;
		auto offset = static_cast<std::size_t>(row) * nsubq;
		if (offset + nsubq > codes_.size()) return;
		auto norm = get_norm(row);
		pq_.add_code(codes_.data() + offset, vec, dim, norm);
	}

	auto dot_row(const float *vec, std::int32_t row, std::int32_t dim) const -> float override
	{
		if (row < 0 || row >= m_) return 0.0f;
		auto nsubq = pq_.get_nsubq();
		if (nsubq <= 0) return 0.0f;
		auto offset = static_cast<std::size_t>(row) * nsubq;
		if (offset + nsubq > codes_.size()) return 0.0f;
		auto norm = get_norm(row);
		return pq_.dot_code(codes_.data() + offset, vec, dim, norm);
	}

	auto rows() const -> std::int64_t override
	{
		return m_;
	}
	auto cols() const -> std::int64_t override
	{
		return n_;
	}

private:
	auto get_norm(std::int32_t row) const -> float
	{
		if (qnorm_ && row >= 0 && static_cast<std::size_t>(row) < norm_codes_.size()) {
			return npq_.get_centroid_value(0, norm_codes_[row]);
		}
		return 1.0f;
	}

	std::int64_t m_;
	std::int64_t n_;
	bool qnorm_;
	std::vector<std::uint8_t> codes_;
	std::vector<std::uint8_t> norm_codes_;
	product_quantizer pq_;
	product_quantizer npq_;
};

/* --- Dictionary --- */
class dictionary {
public:
	void load(binary_reader &reader, const model_args &args)
	{
		auto size = reader.read_i32(); /* total entries (words + labels) */
		nwords_ = reader.read_i32();
		nlabels_ = reader.read_i32();
		ntokens_ = reader.read_i64();

		auto pruneidx_size = reader.read_i64();

		if (reader.fail() || size <= 0 || size > MAX_SANE_ENTRIES ||
			nwords_ < 0 || nlabels_ < 0 || nwords_ + nlabels_ > size) {
			return;
		}

		entries_.resize(size);
		for (auto &entry: entries_) {
			entry.word = reader.read_cstring();
			entry.count = reader.read_i64();
			entry.type = static_cast<entry_type>(reader.read_u8());
		}

		/* Read prune index */
		pruneidx_.clear();
		for (std::int64_t i = 0; i < pruneidx_size; i++) {
			auto first = reader.read_i32();
			auto second = reader.read_i32();
			pruneidx_[first] = second;
		}
		pruneidx_size_ = pruneidx_size;

		/* Build word lookup map */
		word_map_.reserve(nwords_ + nlabels_);
		for (std::int32_t i = 0; i < static_cast<std::int32_t>(entries_.size()); i++) {
			word_map_[entries_[i].word] = i;
		}

		/* Precompute subwords for all known word entries */
		bucket_ = args.bucket;
		minn_ = args.minn;
		maxn_ = args.maxn;
		wordNgrams_ = args.wordNgrams;

		if (maxn_ > 0) {
			for (std::int32_t i = 0; i < nwords_; i++) {
				auto &entry = entries_[i];
				std::string wrapped = "<" + entry.word + ">";
				compute_subwords(wrapped, entry.subwords);
				/* The word's own ID is always the first element */
				entry.subwords.insert(entry.subwords.begin(), i);
			}
		}
	}

	auto find(std::string_view word) const -> std::int32_t
	{
		auto it = word_map_.find(word);
		if (it != word_map_.end()) {
			return it->second;
		}
		return -1;
	}

	auto get_entry(std::int32_t id) const -> const dict_entry *
	{
		if (id < 0 || id >= static_cast<std::int32_t>(entries_.size())) {
			return nullptr;
		}
		return &entries_[id];
	}

	auto get_label(std::int32_t id) const -> std::string_view
	{
		auto label_id = nwords_ + id;
		if (label_id >= 0 && label_id < static_cast<std::int32_t>(entries_.size())) {
			return entries_[label_id].word;
		}
		return {};
	}

	void compute_subwords(std::string_view word, std::vector<std::int32_t> &ngrams) const
	{
		auto positions = utf8_positions(word);
		auto ncp = static_cast<int>(positions.size() - 1); /* number of codepoints */

		for (int i = 0; i < ncp; i++) {
			for (int len = minn_; len <= maxn_ && i + len <= ncp; len++) {
				/* Skip single-char n-grams at BOW/EOW positions */
				if (len == 1 && (i == 0 || i + 1 == ncp)) continue;

				auto ngram = word.substr(positions[i], positions[i + len] - positions[i]);
				auto h = static_cast<std::int32_t>(fnv_hash(ngram) % bucket_);
				push_hash(ngrams, h);
			}
		}
	}

	auto hash_word(std::string_view word) const -> std::uint32_t
	{
		return fnv_hash(word);
	}

	auto get_nwords() const -> std::int32_t
	{
		return nwords_;
	}
	auto get_nlabels() const -> std::int32_t
	{
		return nlabels_;
	}
	auto get_ntokens() const -> std::int64_t
	{
		return ntokens_;
	}
	auto get_bucket() const -> std::int32_t
	{
		return bucket_;
	}

	auto get_label_counts() const -> std::vector<std::int64_t>
	{
		std::vector<std::int64_t> counts;
		counts.reserve(nlabels_);
		for (std::int32_t i = nwords_; i < nwords_ + nlabels_; i++) {
			if (i < static_cast<std::int32_t>(entries_.size())) {
				counts.push_back(entries_[i].count);
			}
		}
		return counts;
	}

private:
	/* Matches FastText's Dictionary::pushHash():
	 * - pruneidx_size_ < 0 (e.g. -1): no pruning, push directly
	 * - pruneidx_size_ == 0: all pruned, drop everything
	 * - pruneidx_size_ > 0: remap through pruneidx_ or drop if absent */
	void push_hash(std::vector<std::int32_t> &ngrams, std::int32_t id) const
	{
		if (pruneidx_size_ == 0 || id < 0) {
			return;
		}
		if (pruneidx_size_ > 0) {
			auto it = pruneidx_.find(id);
			if (it != pruneidx_.end()) {
				id = it->second;
			}
			else {
				return;
			}
		}
		ngrams.push_back(nwords_ + id);
	}

	std::int32_t nwords_ = 0;
	std::int32_t nlabels_ = 0;
	std::int64_t ntokens_ = 0;
	std::int64_t pruneidx_size_ = 0;
	std::int32_t bucket_ = 0;
	std::int32_t minn_ = 0;
	std::int32_t maxn_ = 0;
	std::int32_t wordNgrams_ = 1;

	std::vector<dict_entry> entries_;
	ankerl::unordered_dense::map<std::string_view, std::int32_t> word_map_;
	ankerl::unordered_dense::map<std::int32_t, std::int32_t> pruneidx_;
};


/* Loss function types (matches FastText's enum) */
constexpr std::int32_t LOSS_HS = 1;
constexpr std::int32_t LOSS_NS = 2;
constexpr std::int32_t LOSS_SOFTMAX = 3;

/* Huffman tree node for hierarchical softmax */
struct hs_node {
	std::int32_t parent = -1;
	std::int32_t left = -1;
	std::int32_t right = -1;
	std::int64_t count = 0;
	bool binary = false;
};

/* --- Model implementation (pimpl) --- */
class fasttext_model_impl {
public:
	model_args args;
	dictionary dict;
	std::unique_ptr<matrix_base> input_matrix;
	std::unique_ptr<matrix_base> output_matrix;
	/* Keep the mmap alive for the lifetime of the model */
	std::optional<rspamd::util::raii_mmaped_file> mmap_file;
	/* Huffman tree for hierarchical softmax */
	std::vector<hs_node> hs_tree;

	void word2vec(std::string_view word, std::vector<std::int32_t> &ngrams) const
	{
		auto wid = dict.find(word);

		if (wid >= 0) {
			auto *entry = dict.get_entry(wid);
			if (entry && entry->type == entry_type::word) {
				if (args.maxn <= 0) {
					ngrams.push_back(wid);
				}
				else {
					ngrams.insert(ngrams.end(),
								  entry->subwords.begin(), entry->subwords.end());
				}
			}
		}
		else {
			/* OOV: compute subwords on the fly */
			if (args.maxn > 0) {
				std::string wrapped = "<" + std::string(word) + ">";
				dict.compute_subwords(wrapped, ngrams);
			}
		}
	}

	/* Build Huffman tree for hierarchical softmax from label counts.
	 * Matches FastText's HierarchicalSoftmaxLoss::buildTree(). */
	void build_hs_tree()
	{
		auto counts = dict.get_label_counts();
		auto osz = static_cast<std::int32_t>(counts.size());
		if (osz <= 0) return;

		hs_tree.resize(2 * osz - 1);
		for (auto &node: hs_tree) {
			node.parent = -1;
			node.left = -1;
			node.right = -1;
			node.count = 1e15;
			node.binary = false;
		}

		/* Leaves get their actual counts */
		for (std::int32_t i = 0; i < osz; i++) {
			hs_tree[i].count = counts[i];
		}

		/* Build tree bottom-up */
		std::int32_t leaf = osz - 1;
		std::int32_t node = osz;
		for (std::int32_t i = osz; i < 2 * osz - 1; i++) {
			std::int32_t mini[2] = {0, 0};
			for (int j = 0; j < 2; j++) {
				if (leaf >= 0 && hs_tree[leaf].count < hs_tree[node].count) {
					mini[j] = leaf--;
				}
				else {
					mini[j] = node++;
				}
			}
			hs_tree[i].left = mini[0];
			hs_tree[i].right = mini[1];
			hs_tree[i].count = hs_tree[mini[0]].count + hs_tree[mini[1]].count;
			hs_tree[mini[0]].parent = i;
			hs_tree[mini[1]].parent = i;
			hs_tree[mini[0]].binary = true;
			hs_tree[mini[1]].binary = false;
		}
	}

	void predict(int k, const std::vector<std::int32_t> &word_ids,
				 std::vector<prediction> &results, float threshold) const
	{
		results.clear();

		if (word_ids.empty() || !input_matrix || !output_matrix) return;

		auto dim = args.dim;
		auto nlabels = dict.get_nlabels();

		if (dim <= 0 || dim > MAX_SANE_DIM || nlabels <= 0) return;

		/* Compute hidden layer: average of input rows */
		std::vector<float> hidden(dim, 0.0f);
		for (auto id: word_ids) {
			input_matrix->add_row_to_vec(hidden.data(), id, dim);
		}

		float inv_count = 1.0f / static_cast<float>(word_ids.size());
		for (auto &v: hidden) {
			v *= inv_count;
		}

		if (args.loss == LOSS_HS && !hs_tree.empty()) {
			predict_hs(k, hidden.data(), dim, nlabels, threshold, results);
		}
		else {
			predict_softmax(k, hidden.data(), dim, nlabels, threshold, results);
		}
	}

private:
	/* Flat softmax prediction */
	void predict_softmax(int k, const float *hidden, std::int32_t dim,
						 std::int32_t nlabels, float threshold,
						 std::vector<prediction> &results) const
	{
		std::vector<float> scores(nlabels);
		for (std::int32_t i = 0; i < nlabels; i++) {
			scores[i] = output_matrix->dot_row(hidden, i, dim);
		}

		/* Softmax (numerically stable) */
		float max_score = *std::max_element(scores.begin(), scores.end());
		float sum = 0.0f;
		for (auto &s: scores) {
			s = std::exp(s - max_score);
			sum += s;
		}
		if (sum > 0.0f) {
			for (auto &s: scores) {
				s /= sum;
			}
		}

		collect_topk(k, scores, threshold, results);
	}

	/* Hierarchical softmax prediction via DFS on Huffman tree.
	 * Matches FastText's HierarchicalSoftmaxLoss::predict(). */
	void predict_hs(int k, const float *hidden, std::int32_t dim,
					std::int32_t osz, float threshold,
					std::vector<prediction> &results) const
	{
		using pair_t = std::pair<float, std::int32_t>;
		auto cmp = [](const pair_t &a, const pair_t &b) { return a.first > b.first; };
		std::vector<pair_t> heap;

		float log_threshold = std::log(threshold + 1e-5f);
		dfs_predict(k, log_threshold, 2 * osz - 2, 0.0f, hidden, dim, osz, heap, cmp);

		/* Convert log-probs to probabilities and build results */
		results.reserve(heap.size());
		for (auto &[score, idx]: heap) {
			auto label = dict.get_label(idx);
			results.push_back({std::exp(score), std::string(label)});
		}

		/* Sort descending by probability */
		std::sort(results.begin(), results.end(),
				  [](const prediction &a, const prediction &b) { return a.prob > b.prob; });
	}

	/* DFS on the Huffman tree. At each internal node, compute sigmoid
	 * and recurse left (1-f) and right (f). Leaves are labels. */
	template<typename Cmp>
	void dfs_predict(int k, float log_threshold, std::int32_t node, float score,
					 const float *hidden, std::int32_t dim, std::int32_t osz,
					 std::vector<std::pair<float, std::int32_t>> &heap,
					 Cmp &cmp) const
	{
		if (score < log_threshold) return;
		if (node < 0 || node >= static_cast<std::int32_t>(hs_tree.size())) return;

		if (node < osz) {
			/* Leaf node = label */
			if (static_cast<int>(heap.size()) == k && score < heap.front().first) {
				return;
			}
			heap.push_back({score, node});
			std::push_heap(heap.begin(), heap.end(), cmp);
			if (static_cast<int>(heap.size()) > k) {
				std::pop_heap(heap.begin(), heap.end(), cmp);
				heap.pop_back();
			}
			return;
		}

		/* Internal node: sigmoid of dot product */
		float f = output_matrix->dot_row(hidden, node - osz, dim);
		f = 1.0f / (1.0f + std::exp(-f));

		dfs_predict(k, log_threshold, hs_tree[node].left,
					score + std::log(1.0f - f + 1e-5f), hidden, dim, osz, heap, cmp);
		dfs_predict(k, log_threshold, hs_tree[node].right,
					score + std::log(f + 1e-5f), hidden, dim, osz, heap, cmp);
	}

	/* Top-k selection from a scores vector, collecting results */
	void collect_topk(int k, const std::vector<float> &scores,
					  float threshold, std::vector<prediction> &results) const
	{
		using pair_t = std::pair<float, std::int32_t>;
		auto cmp = [](const pair_t &a, const pair_t &b) { return a.first > b.first; };
		std::priority_queue<pair_t, std::vector<pair_t>, decltype(cmp)> heap(cmp);

		auto nlabels = static_cast<std::int32_t>(scores.size());
		for (std::int32_t i = 0; i < nlabels; i++) {
			if (scores[i] < threshold) continue;

			if (static_cast<int>(heap.size()) < k) {
				heap.push({scores[i], i});
			}
			else if (scores[i] > heap.top().first) {
				heap.pop();
				heap.push({scores[i], i});
			}
		}

		results.reserve(heap.size());
		while (!heap.empty()) {
			auto [prob, idx] = heap.top();
			heap.pop();
			auto label = dict.get_label(idx);
			results.push_back({prob, std::string(label)});
		}

		/* Min-heap pops in ascending order; reverse for descending */
		std::reverse(results.begin(), results.end());
	}

public:
	void get_word_vector(std::vector<float> &vec, std::string_view word) const
	{
		auto dim = args.dim;
		if (dim <= 0 || dim > MAX_SANE_DIM || !input_matrix) {
			vec.clear();
			return;
		}
		vec.assign(dim, 0.0f);

		std::vector<std::int32_t> ngrams;
		word2vec(word, ngrams);

		if (ngrams.empty()) return;

		for (auto id: ngrams) {
			input_matrix->add_row_to_vec(vec.data(), id, dim);
		}

		float inv = 1.0f / static_cast<float>(ngrams.size());
		for (auto &v: vec) {
			v *= inv;
		}
	}
};

/* --- Load a dense matrix from binary data --- */
static auto load_dense_matrix(binary_reader &reader, const unsigned char *mmap_base)
	-> std::unique_ptr<dense_matrix>
{
	auto m = reader.read_i64();
	auto n = reader.read_i64();

	if (reader.fail() || m <= 0 || m > MAX_SANE_MATRIX_ROWS ||
		n <= 0 || n > MAX_SANE_DIM) {
		return nullptr;
	}

	/* Check for overflow: m * n must fit in size_t */
	auto um = static_cast<std::size_t>(m);
	auto un = static_cast<std::size_t>(n);
	if (um > SIZE_MAX / un) {
		return nullptr;
	}

	auto float_count = um * un;
	auto data_ptr = reader.read_floats(float_count);

	if (!data_ptr) {
		return nullptr;
	}

	/* Check if this pointer is inside the mmap region (zero-copy) or need to copy */
	if (mmap_base != nullptr) {
		return std::make_unique<dense_matrix>(data_ptr, m, n);
	}
	else {
		std::vector<float> storage(data_ptr, data_ptr + float_count);
		return std::make_unique<dense_matrix>(std::move(storage), m, n);
	}
}

/* --- Load a quantized matrix from binary data --- */
/* FastText QMatrix binary format:
 *   qnorm (bool), m (int64), n (int64), codesize (int32),
 *   codes[codesize] (uint8), PQ::load(),
 *   [if qnorm: norm_codes[m] (uint8), NPQ::load()]
 */
static auto load_quant_matrix(binary_reader &reader)
	-> std::unique_ptr<quant_matrix>
{
	auto qnorm = reader.read_bool();
	auto m = reader.read_i64();
	auto n = reader.read_i64();
	auto codesize = reader.read_i32();

	if (reader.fail() || m <= 0 || m > MAX_SANE_MATRIX_ROWS ||
		n <= 0 || n > MAX_SANE_DIM ||
		codesize <= 0 || codesize > MAX_SANE_CODESIZE) {
		return nullptr;
	}

	/* Read codes BEFORE PQ */
	std::vector<std::uint8_t> codes(codesize);
	for (std::int32_t i = 0; i < codesize; i++) {
		codes[i] = reader.read_u8();
	}

	/* Read PQ */
	product_quantizer pq;
	if (!pq.load(reader)) {
		return nullptr;
	}

	std::vector<std::uint8_t> norm_codes;
	product_quantizer npq;

	if (qnorm) {
		/* Read norm codes (one per row) then norm PQ */
		norm_codes.resize(m);
		for (std::int64_t i = 0; i < m; i++) {
			norm_codes[i] = reader.read_u8();
		}
		if (!npq.load(reader)) {
			return nullptr;
		}
	}

	if (reader.fail()) {
		return nullptr;
	}

	return std::make_unique<quant_matrix>(m, n, qnorm,
										  std::move(codes),
										  std::move(norm_codes),
										  std::move(pq), std::move(npq));
}


/* --- fasttext_model public API --- */

fasttext_model::fasttext_model(std::unique_ptr<fasttext_model_impl> impl)
	: impl_(std::move(impl))
{
}

fasttext_model::~fasttext_model() = default;

fasttext_model::fasttext_model(fasttext_model &&other) noexcept = default;

fasttext_model &fasttext_model::operator=(fasttext_model &&other) noexcept = default;

auto fasttext_model::load(const char *path, std::int64_t offset) -> tl::expected<fasttext_model, rspamd::util::error>
{
	/* mmap the file (possibly at an offset for map cache files) */
	auto mmap_result = rspamd::util::raii_mmaped_file::mmap_shared(
		path, O_RDONLY, PROT_READ, offset);

	if (!mmap_result) {
		return tl::make_unexpected(mmap_result.error());
	}

	/* Use the mapped region size, not full file size (they differ when offset > 0) */
	auto file_size = mmap_result->get_size() - (std::size_t) offset;
	auto *base = static_cast<const unsigned char *>(mmap_result->get_map());

	binary_reader reader(base, file_size);

	/* Read and validate magic */
	auto magic = reader.read_i32();
	if (reader.fail() || magic != FASTTEXT_FILEFORMAT_MAGIC) {
		return tl::make_unexpected(
			rspamd::util::error(
				fmt::format("invalid fasttext magic: {} (expected {})", magic, FASTTEXT_FILEFORMAT_MAGIC),
				EINVAL));
	}

	/* Read and validate version */
	auto version = reader.read_i32();
	if (reader.fail() || version > FASTTEXT_VERSION) {
		return tl::make_unexpected(
			rspamd::util::error(
				fmt::format("unsupported fasttext version: {} (max {})", version, FASTTEXT_VERSION),
				EINVAL));
	}

	auto impl = std::make_unique<fasttext_model_impl>();

	/* Read model args (52 bytes of packed data) */
	auto &args = impl->args;
	args.dim = reader.read_i32();
	args.ws = reader.read_i32();
	args.epoch = reader.read_i32();
	args.minCount = reader.read_i32();
	args.neg = reader.read_i32();
	args.wordNgrams = reader.read_i32();
	args.loss = reader.read_i32();
	args.model = static_cast<model_name>(reader.read_i32());
	args.bucket = reader.read_i32();
	args.minn = reader.read_i32();
	args.maxn = reader.read_i32();
	args.lrUpdateRate = reader.read_i32();
	args.t = reader.read_f64();

	if (reader.fail()) {
		return tl::make_unexpected(
			rspamd::util::error(
				fmt::format("truncated fasttext model header in '{}'", path),
				EINVAL));
	}

	/* Validate model args sanity */
	if (args.dim <= 0 || args.dim > MAX_SANE_DIM ||
		args.bucket < 0 || args.bucket > MAX_SANE_BUCKET ||
		args.minn < 0 || args.maxn < 0 || args.maxn > 100) {
		return tl::make_unexpected(
			rspamd::util::error(
				fmt::format("invalid fasttext model parameters in '{}': dim={} bucket={} minn={} maxn={}",
							path, args.dim, args.bucket, args.minn, args.maxn),
				EINVAL));
	}

	/* Read dictionary */
	impl->dict.load(reader, args);

	if (reader.fail()) {
		return tl::make_unexpected(
			rspamd::util::error(
				fmt::format("truncated fasttext dictionary in '{}'", path),
				EINVAL));
	}

	/* Determine if input matrix is quantized */
	auto quant_input = reader.read_bool();

	if (quant_input) {
		impl->input_matrix = load_quant_matrix(reader);
	}
	else {
		/* Dense input matrix - pointer into mmap region (zero-copy) */
		impl->input_matrix = load_dense_matrix(reader, base);
	}

	if (!impl->input_matrix || reader.fail()) {
		return tl::make_unexpected(
			rspamd::util::error(
				fmt::format("failed to load fasttext input matrix in '{}'", path),
				EINVAL));
	}

	/* Read output matrix — FastText always writes a qout bool here */
	auto quant_output = reader.read_bool();

	if (quant_input && quant_output) {
		impl->output_matrix = load_quant_matrix(reader);
	}
	else {
		impl->output_matrix = load_dense_matrix(reader, nullptr);
	}

	if (!impl->output_matrix || reader.fail()) {
		return tl::make_unexpected(
			rspamd::util::error(
				fmt::format("failed to load fasttext output matrix in '{}'", path),
				EINVAL));
	}

	/* Build Huffman tree for hierarchical softmax models */
	if (args.loss == LOSS_HS) {
		impl->build_hs_tree();
	}

	/* Store the mmap to keep it alive */
	impl->mmap_file.emplace(std::move(*mmap_result));

	return fasttext_model(std::move(impl));
}

void fasttext_model::word2vec(std::string_view word, std::vector<std::int32_t> &ngrams) const
{
	impl_->word2vec(word, ngrams);
}

void fasttext_model::predict(int k, const std::vector<std::int32_t> &word_ids,
							 std::vector<prediction> &results, float threshold) const
{
	impl_->predict(k, word_ids, results, threshold);
}

void fasttext_model::get_word_vector(std::vector<float> &vec, std::string_view word) const
{
	impl_->get_word_vector(vec, word);
}

auto fasttext_model::get_dimension() const -> std::int32_t
{
	return impl_->args.dim;
}

auto fasttext_model::get_nlabels() const -> std::int32_t
{
	return impl_->dict.get_nlabels();
}

auto fasttext_model::get_ntokens() const -> std::int64_t
{
	return impl_->dict.get_ntokens();
}

auto fasttext_model::get_word_frequency(std::string_view word) const -> double
{
	auto id = impl_->dict.find(word);
	if (id < 0) {
		return 0.0;
	}
	auto *entry = impl_->dict.get_entry(id);
	if (!entry) {
		return 0.0;
	}
	auto ntokens = impl_->dict.get_ntokens();
	if (ntokens <= 0) {
		return 0.0;
	}
	return static_cast<double>(entry->count) / static_cast<double>(ntokens);
}

} /* namespace rspamd::fasttext */
