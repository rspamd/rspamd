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

#ifndef RSPAMD_FASTTEXT_SHIM_H
#define RSPAMD_FASTTEXT_SHIM_H
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>

#include "contrib/expected/expected.hpp"
#include "libutil/cxx/error.hxx"

namespace rspamd::fasttext {

/* FastText binary format constants */
static constexpr std::int32_t FASTTEXT_FILEFORMAT_MAGIC = 793712314;
static constexpr std::int32_t FASTTEXT_VERSION = 12;

/* Entry types in the dictionary */
enum class entry_type : std::int8_t {
	word = 0,
	label = 1
};

/* Model type */
enum class model_name : std::int32_t {
	cbow = 1,
	sg = 2,
	sup = 3
};

/* Parsed binary header args */
struct model_args {
	std::int32_t dim = 0;
	std::int32_t ws = 5;
	std::int32_t epoch = 5;
	std::int32_t minCount = 5;
	std::int32_t neg = 5;
	std::int32_t wordNgrams = 1;
	std::int32_t loss = 0;
	model_name model = model_name::sup;
	std::int32_t bucket = 2000000;
	std::int32_t minn = 3;
	std::int32_t maxn = 6;
	std::int32_t lrUpdateRate = 100;
	double t = 1e-4;
};

/* A prediction result: probability + label string */
struct prediction {
	float prob;
	std::string label;
};

/* Forward declarations for implementation types */
class fasttext_model_impl;

/**
 * Top-level FastText model facade.
 * Loads .bin/.ftz models using mmap for the large input matrix.
 * Thread-safe for concurrent read operations after construction.
 */
class fasttext_model {
public:
	~fasttext_model();
	fasttext_model(fasttext_model &&other) noexcept;
	fasttext_model &operator=(fasttext_model &&other) noexcept;

	/* No copy */
	fasttext_model(const fasttext_model &) = delete;
	fasttext_model &operator=(const fasttext_model &) = delete;

	/**
	 * Load a FastText model from a .bin or .ftz file.
	 * The large input matrix is mmap'd with MAP_SHARED for cross-process sharing.
	 * @param path path to the model file
	 * @return loaded model or error
	 */
	static auto load(const char *path) -> tl::expected<fasttext_model, rspamd::util::error>;
	static auto load(const std::string &path) -> tl::expected<fasttext_model, rspamd::util::error>
	{
		return load(path.c_str());
	}

	/**
	 * Convert a word into input matrix row IDs (word ID + subword n-gram IDs).
	 * For known words: returns the word's own row plus its precomputed subword IDs.
	 * For OOV words: returns only subword n-gram IDs computed from the word.
	 * @param word the input word
	 * @param ngrams output vector to append row IDs to
	 */
	void word2vec(std::string_view word, std::vector<std::int32_t> &ngrams) const;

	/**
	 * Run supervised classification.
	 * @param k number of top predictions to return
	 * @param word_ids accumulated word IDs from word2vec() calls
	 * @param results output predictions (cleared first)
	 * @param threshold minimum probability threshold (default 0)
	 */
	void predict(int k, const std::vector<std::int32_t> &word_ids,
				 std::vector<prediction> &results, float threshold = 0.0f) const;

	/**
	 * Get the embedding vector for a word (subword-averaged).
	 * @param vec output vector, resized to dimension
	 * @param word the input word
	 */
	void get_word_vector(std::vector<float> &vec, std::string_view word) const;

	/**
	 * Get model dimension.
	 */
	auto get_dimension() const -> std::int32_t;

	/**
	 * Get number of labels in supervised model.
	 */
	auto get_nlabels() const -> std::int32_t;

	/**
	 * Get number of tokens in dictionary.
	 */
	auto get_ntokens() const -> std::int64_t;

private:
	explicit fasttext_model(std::unique_ptr<fasttext_model_impl> impl);
	std::unique_ptr<fasttext_model_impl> impl_;
};

}// namespace rspamd::fasttext

#endif// RSPAMD_FASTTEXT_SHIM_H
