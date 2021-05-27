/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <sys/types.h>
#include "printf_check.h"
#include "clang/AST/AST.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <sstream>
#include <ctype.h>
#include <signal.h>
#include <assert.h>
#include <cstdint>

using namespace clang;

namespace rspamd {
	struct PrintfArgChecker;

	static bool cstring_arg_handler (const Expr *arg,
			struct PrintfArgChecker *ctx);

	static bool int_arg_handler (const Expr *arg,
			struct PrintfArgChecker *ctx);

	static bool long_arg_handler (const Expr *arg,
			struct PrintfArgChecker *ctx);

	static bool size_arg_handler (const Expr *arg,
			struct PrintfArgChecker *ctx);

	static bool char_arg_handler (const Expr *arg,
			struct PrintfArgChecker *ctx);

	static bool double_arg_handler (const Expr *arg,
			struct PrintfArgChecker *ctx);

	static bool long_double_arg_handler (const Expr *arg,
			struct PrintfArgChecker *ctx);

	static bool pointer_arg_handler (const Expr *arg,
			struct PrintfArgChecker *ctx);

	static bool pid_arg_handler (const Expr *arg,
			struct PrintfArgChecker *ctx);

	static bool time_arg_handler (const Expr *arg,
			struct PrintfArgChecker *ctx);

	static bool int64_arg_handler (const Expr *arg,
			struct PrintfArgChecker *ctx);

	static bool int32_arg_handler (const Expr *arg,
			struct PrintfArgChecker *ctx);

	static bool tok_arg_handler (const Expr *arg,
			struct PrintfArgChecker *ctx);

	static bool fstring_arg_handler (const Expr *arg,
			struct PrintfArgChecker *ctx);

	static bool gstring_arg_handler (const Expr *arg,
			struct PrintfArgChecker *ctx);

	static bool gerr_arg_handler (const Expr *arg,
			struct PrintfArgChecker *ctx);

	using arg_parser_t = bool (*) (const Expr *, struct PrintfArgChecker *);

	static void
	print_error (const char *err, const Expr *e, const ASTContext *ast,
			CompilerInstance *ci)
	{
		auto loc = e->getExprLoc ();
		auto &diag = ci->getDiagnostics ();
		auto id = diag.getCustomDiagID (DiagnosticsEngine::Error,
				"format query error: %0");
		diag.Report (loc, id) << err;
	}

	static void
	print_warning (const char *err, const Expr *e, const ASTContext *ast,
			CompilerInstance *ci)
	{
		auto loc = e->getExprLoc ();
		auto &diag = ci->getDiagnostics ();
		auto id = diag.getCustomDiagID (DiagnosticsEngine::Warning,
				"format query warning: %0");
		diag.Report (loc, id) << err;
	}

	static void
	print_remark (const char *err, const Expr *e, const ASTContext *ast,
				   CompilerInstance *ci)
	{
		auto loc = e->getExprLoc ();
		auto &diag = ci->getDiagnostics ();
		auto id = diag.getCustomDiagID (DiagnosticsEngine::Remark,
				"format query warning: %0");
		diag.Report (loc, id) << err;
	}

	struct PrintfArgChecker {
	private:
		arg_parser_t parser;
	public:
		int width;
		int precision;
		bool is_unsigned;
		ASTContext *past;
		CompilerInstance *pci;

		PrintfArgChecker (arg_parser_t _p, ASTContext *_ast, CompilerInstance *_ci) :
				parser (_p), past (_ast), pci(_ci)
		{
			width = 0;
			precision = 0;
			is_unsigned = false;
		}

		virtual ~PrintfArgChecker ()
		{
		}

		bool operator() (const Expr *e)
		{
			return parser (e, this);
		}
	};

	class PrintfCheckVisitor::impl {
		std::unordered_map<std::string, unsigned int> printf_functions;
		std::unordered_set<char> format_specs;
		ASTContext *pcontext;
		CompilerInstance *ci;

		std::unique_ptr <PrintfArgChecker> parseFlags (const std::string &flags,
				const Expr *e)
		{
			auto type = flags.back ();

			switch (type) {
			case 's':
				return std::make_unique<PrintfArgChecker> (cstring_arg_handler,
						this->pcontext, this->ci);
			case 'd':
				return std::make_unique<PrintfArgChecker> (int_arg_handler,
						this->pcontext, this->ci);
			case 'z':
				return std::make_unique<PrintfArgChecker> (size_arg_handler,
						this->pcontext, this->ci);
			case 'l':
				return std::make_unique<PrintfArgChecker> (long_arg_handler,
						this->pcontext, this->ci);
			case 'f':
			case 'g':
				return std::make_unique<PrintfArgChecker> (double_arg_handler,
						this->pcontext, this->ci);
			case 'F':
			case 'G':
				return std::make_unique<PrintfArgChecker> (
						long_double_arg_handler,
						this->pcontext, this->ci);
			case 'c':
				return std::make_unique<PrintfArgChecker> (char_arg_handler,
						this->pcontext, this->ci);
			case 'p':
				return std::make_unique<PrintfArgChecker> (pointer_arg_handler,
						this->pcontext, this->ci);
			case 'P':
				return std::make_unique<PrintfArgChecker> (pid_arg_handler,
						this->pcontext, this->ci);
			case 't':
				return std::make_unique<PrintfArgChecker> (time_arg_handler,
						this->pcontext, this->ci);
			case 'L':
				return std::make_unique<PrintfArgChecker> (int64_arg_handler,
						this->pcontext, this->ci);
			case 'D':
				return std::make_unique<PrintfArgChecker> (int32_arg_handler,
						this->pcontext, this->ci);
			case 'T':
				return std::make_unique<PrintfArgChecker> (tok_arg_handler,
						this->pcontext, this->ci);
			case 'V':
				return std::make_unique<PrintfArgChecker> (fstring_arg_handler,
						this->pcontext, this->ci);
			case 'v':
				return std::make_unique<PrintfArgChecker> (gstring_arg_handler,
						this->pcontext, this->ci);
			case 'e':
				return std::make_unique<PrintfArgChecker> (gerr_arg_handler,
						this->pcontext, this->ci);
			default: {
				auto err_msg = std::string ("unknown parser flag: ") + type;
				print_warning (err_msg.c_str(),
						e, this->pcontext, this->ci);
				break;
				}
			}

			return nullptr;
		}

		std::shared_ptr <std::vector<PrintfArgChecker>>
		genParsers (const StringRef query, const Expr *e)
		{
			enum {
				ignore_chars = 0,
				read_percent,
				read_width,
				read_precision,
				read_arg
			} state = ignore_chars;
			int width, precision;
			std::string flags;

			auto res = std::make_shared<std::vector<PrintfArgChecker> > ();

			for (auto citer = query.begin(); citer != query.end(); ++citer) {
				auto c = *citer;

				switch (state) {
				case ignore_chars:
					if (c == '%') {
						state = read_percent;
						flags.clear ();
						width = precision = 0;
					}
					break;
				case read_percent:
					if (isdigit (c)) {
						state = read_width;
						width = c - '0';
					}
					else if (c == '.') {
						state = read_precision;
						precision = c - '0';
					}
					else if (c == '*') {
						/* %*s - need integer argument */
						res->emplace_back (int_arg_handler, this->pcontext,
								this->ci);

						if (*std::next (citer) == '.') {
							++citer;
							state = read_precision;
						}
						else {
							state = read_arg;
						}
					}
					else if (c == '%') {
						/* Percent character, ignore */
						state = ignore_chars;
					}
					else {
						// Rewind iter
						--citer;
						state = read_arg;
					}
					break;
				case read_width:
					if (isdigit (c)) {
						width *= 10;
						width += c - '0';
					}
					else if (c == '.') {
						state = read_precision;
						precision = c - '0';
					}
					else {
						// Rewind iter
						--citer;
						state = read_arg;
					}
					break;
				case read_precision:
					if (isdigit (c)) {
						precision *= 10;
						precision += c - '0';
					}
					else if (c == '*') {
						res->emplace_back (int_arg_handler, this->pcontext,
								this->ci);
						state = read_arg;
					}
					else {
						// Rewind iter
						--citer;
						state = read_arg;
					}
					break;
				case read_arg:
					auto found = format_specs.find (c);
					if (found != format_specs.end () || !isalpha (c)) {

						if (isalpha (c)) {
							flags.push_back (c);
						}

						auto handler = parseFlags (flags, e);

						if (handler) {
							auto handler_copy = *handler;
							handler_copy.precision = precision;
							handler_copy.width = width;
							res->emplace_back (std::move (handler_copy));
						}
						else {
							return nullptr;
						}

						if (c == '%') {
							state = read_percent;
						}
						else {
							state = ignore_chars;
						}
						flags.clear ();
						width = precision = 0;
					}
					else {
						flags.push_back (c);
					}
					break;
				}
			}

			if (state == read_arg) {
				auto handler = parseFlags (flags, e);

				if (handler) {
					auto handler_copy = *handler;
					handler_copy.precision = precision;
					handler_copy.width = width;
					res->emplace_back (std::move (handler_copy));
				}
				else {
					return nullptr;
				}
			}

			return res;
		}

	public:
		impl (ASTContext *_ctx, clang::CompilerInstance &_ci)
				: pcontext (_ctx), ci(&_ci)
		{
			/* name -> format string position */
			printf_functions = {
					{"rspamd_printf",                 0},
					{"rspamd_default_log_function",   4},
					{"rspamd_snprintf",               2},
					{"rspamd_fprintf",                1},
					{"rspamd_printf_gstring",         1},
					{"rspamd_printf_fstring",         1},
					{"rspamd_conditional_debug_fast", 6},
			};

			format_specs = {
					's', 'd', 'l', 'L', 'v', 'V', 'f', 'F', 'g', 'G',
					'T', 'z', 'D', 'c', 'p', 'P', 'e'
			};
		};

		bool VisitCallExpr (CallExpr *E)
		{
			if (E->getCalleeDecl () == nullptr) {
				print_remark ("cannot get callee decl",
						E, this->pcontext, this->ci);
				return true;
			}
			auto callee = dyn_cast<NamedDecl> (E->getCalleeDecl ());
			if (callee == NULL) {
				print_remark ("cannot get named callee decl",
						E, this->pcontext, this->ci);
				return true;
			}

			auto fname = callee->getNameAsString ();

			auto pos_it = printf_functions.find (fname);

			if (pos_it != printf_functions.end ()) {
				const auto args = E->getArgs ();
				auto pos = pos_it->second;
				auto query = args[pos];

				if (!query->isEvaluatable (*pcontext)) {
					print_remark ("cannot evaluate query",
							E, this->pcontext, this->ci);
					/* It is not assumed to be an error */
					return true;
				}

				clang::Expr::EvalResult r;

				if (!query->EvaluateAsRValue (r, *pcontext)) {
					print_warning ("cannot evaluate rvalue of query",
							E, this->pcontext, this->ci);
					return false;
				}

				auto qval = dyn_cast<StringLiteral> (
						r.Val.getLValueBase ().get<const Expr *> ());
				if (!qval) {
					print_warning ("bad or absent query string",
							E, this->pcontext, this->ci);
					return false;
				}

				auto parsers = genParsers (qval->getString (), E);

				if (parsers) {
					if (parsers->size () != E->getNumArgs () - (pos + 1)) {
						std::ostringstream err_buf;
						err_buf << "number of arguments for " << fname
								<< " mismatches query string '" <<
								qval->getString ().str ()
										<< "', expected " << parsers->size () <<
								" args"
										<< ", got " <<
								(E->getNumArgs () - (pos + 1))
										<< " args";
						print_error (err_buf.str().c_str(), E, this->pcontext, this->ci);

						return false;
					}
					else {
						for (auto i = pos + 1; i < E->getNumArgs (); i++) {
							auto arg = args[i];

							if (arg) {
								if (!parsers->at (i - (pos + 1)) (arg)) {
									return false;
								}
							}
						}
					}
				}
			}

			return true;
		}
	};

	PrintfCheckVisitor::PrintfCheckVisitor (ASTContext *ctx,
			clang::CompilerInstance &ci) :
			pimpl{new impl (ctx, ci)}
	{
	}

	PrintfCheckVisitor::~PrintfCheckVisitor ()
	{
	}

	bool PrintfCheckVisitor::VisitCallExpr (clang::CallExpr *E)
	{
		return pimpl->VisitCallExpr (E);
	}

	/* Type handlers */
	static bool
	cstring_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		auto type = arg->getType ().split ().Ty;

		if (!type->isPointerType ()) {
			auto err_msg = std::string ("bad string argument for %s: ") +
						   arg->getType ().getAsString ();
			print_error (err_msg.c_str(),
					arg, ctx->past, ctx->pci);
			return false;
		}

		auto ptr_type = type->getPointeeType ().split ().Ty;

		if (!ptr_type->isCharType ()) {
			/* We might have gchar * here */
			auto desugared_type = ptr_type->getUnqualifiedDesugaredType ();
			auto desugared_ptr_type = type->getUnqualifiedDesugaredType ();

			if (!desugared_type || (!desugared_type->isCharType () &&
						!desugared_ptr_type->isVoidPointerType ())) {
				if (desugared_type) {
					desugared_type->dump ();
				}
				auto err_msg = std::string ("bad string argument for %s: ") +
							   arg->getType ().getAsString ();
				print_error (err_msg.c_str(),
						arg, ctx->past, ctx->pci);
				return false;
			}
		}

		return true;
	}

	static bool
	check_builtin_type (const Expr *arg, struct PrintfArgChecker *ctx,
			const std::vector <BuiltinType::Kind> &k, const std::string &fmt)
	{
		auto type = arg->getType ().split ().Ty;

		auto desugared_type = type->getUnqualifiedDesugaredType ();

		if (!desugared_type->isBuiltinType ()) {
			auto err_msg = std::string ("not a builtin type for ") + fmt + " arg: " +
						   arg->getType ().getAsString ();
			print_error (err_msg.c_str(),
					arg, ctx->past, ctx->pci);
			return false;
		}

		auto builtin_type = dyn_cast<BuiltinType> (desugared_type);
		auto kind = builtin_type->getKind ();
		auto found = false;

		for (auto kk : k) {
			if (kind == kk) {
				found = true;
				break;
			}
		}

		if (!found) {
			auto err_msg = std::string ("bad argument for ") +
						   fmt + " arg: " +
						   arg->getType ().getAsString () +
						   ", resolved as: " +
						   builtin_type->getNameAsCString (ctx->past->getPrintingPolicy ());
			print_error (err_msg.c_str(),
					arg, ctx->past, ctx->pci);
			return false;
		}

		return true;
	}

	static bool
	int_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		return check_builtin_type (arg,
				ctx,
				{BuiltinType::Kind::UInt,
				 BuiltinType::Kind::Int},
				"%d or *");
	}

	static bool
	long_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		return check_builtin_type (arg,
				ctx,
				{BuiltinType::Kind::ULong,
				 BuiltinType::Kind::Long},
				"%l");
	}

	static bool
	char_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		return check_builtin_type (arg,
				ctx,
				{BuiltinType::Kind::UChar,
				 BuiltinType::Kind::SChar,
				 BuiltinType::Kind::Int}, // Because of char -> int propagation
				"%c");
	}

	static bool
	size_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		if (sizeof (size_t) == sizeof (long)) {
			if (sizeof (long long) == sizeof (long)) {
				return check_builtin_type (arg,
						ctx,
						{BuiltinType::Kind::ULong,
						 BuiltinType::Kind::Long,
						 BuiltinType::Kind::LongLong,
						 BuiltinType::Kind::ULongLong},
						"%z");
			}
			else {
				return check_builtin_type (arg,
						ctx,
						{BuiltinType::Kind::ULong,
						 BuiltinType::Kind::Long},
						"%z");
			}
		}
		else if (sizeof (size_t) == sizeof (int)) {
			return check_builtin_type (arg,
					ctx,
					{BuiltinType::Kind::UInt,
					 BuiltinType::Kind::Int},
					"%z");
		}
		else {
			assert (0);
		}

		return true;
	}

	static bool
	double_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		return check_builtin_type (arg,
				ctx,
				{BuiltinType::Kind::Double},
				"%f or %g");
	}

	static bool
	long_double_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		return check_builtin_type (arg,
				ctx,
				{BuiltinType::Kind::LongDouble},
				"%F or %G");
	}

	static bool
	pid_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		if (sizeof (pid_t) == sizeof (long)) {
			return check_builtin_type (arg,
					ctx,
					{BuiltinType::Kind::ULong,
					 BuiltinType::Kind::Long},
					"%P");
		}
		else if (sizeof (pid_t) == sizeof (int)) {
			return check_builtin_type (arg,
					ctx,
					{BuiltinType::Kind::UInt,
					 BuiltinType::Kind::Int},
					"%P");
		}
		else {
			assert (0);
		}
	}

	static bool
	time_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		if (sizeof (time_t) == sizeof (long)) {
			return check_builtin_type (arg,
					ctx,
					{BuiltinType::Kind::ULong,
							BuiltinType::Kind::Long},
					"%t");
		}
		else if (sizeof (time_t) == sizeof (int)) {
			return check_builtin_type (arg,
					ctx,
					{BuiltinType::Kind::UInt,
							BuiltinType::Kind::Int},
					"%t");
		}
		else {
			assert (0);
		}
	}

	static bool
	pointer_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		auto type = arg->getType ().split ().Ty;

		if (!type->isPointerType ()) {
			auto err_msg = std::string ("bad pointer argument for %p: ") +
						   arg->getType ().getAsString ();
			print_error (err_msg.c_str(),
					arg, ctx->past, ctx->pci);
			return false;
		}

		return true;
	}

	static bool
	int64_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		std::vector <BuiltinType::Kind> check;

		if (sizeof (int64_t) == sizeof (long long)) {
			check.push_back (BuiltinType::Kind::ULongLong);
			check.push_back (BuiltinType::Kind::LongLong);
		}
		if (sizeof (int64_t) == sizeof (long)) {
			check.push_back (BuiltinType::Kind::ULong);
			check.push_back (BuiltinType::Kind::Long);
		}

		return check_builtin_type (arg,
				ctx,
				check,
				"%L");

		return true;
	}

	static bool
	int32_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		std::vector < BuiltinType::Kind> check;

		if (sizeof (int32_t) == sizeof (long)) {
			check.push_back (BuiltinType::Kind::ULong);
			check.push_back (BuiltinType::Kind::Long);
		}
		if (sizeof (int32_t) == sizeof (int)) {
			check.push_back (BuiltinType::Kind::UInt);
			check.push_back (BuiltinType::Kind::Int);
		}

		return check_builtin_type (arg,
				ctx,
				check,
				"%D");

		return true;
	}

	static bool
	check_struct_type (const Expr *arg, struct PrintfArgChecker *ctx,
			const std::string &sname, const std::string &fmt)
	{
		auto type = arg->getType ().split ().Ty;

		if (!type->isPointerType ()) {
			auto err_msg = std::string ("non pointer argument for %s: ") +
						   arg->getType ().getAsString ();
			print_error (err_msg.c_str(),
					arg, ctx->past, ctx->pci);
			return false;
		}

		auto ptr_type = type->getPointeeType ().split ().Ty;
		auto desugared_type = ptr_type->getUnqualifiedDesugaredType ();

		if (!desugared_type->isRecordType ()) {
			auto err_msg = std::string ("not a record type for ") + fmt + " arg: " +
						   arg->getType ().getAsString ();
			print_error (err_msg.c_str(),
					arg, ctx->past, ctx->pci);
			return false;
		}

		auto struct_type = desugared_type->getAsStructureType ();
		auto struct_decl = struct_type->getDecl ();
		auto struct_def = struct_decl->getNameAsString ();

		if (struct_def != sname) {
			auto err_msg = std::string ("bad argument '") + struct_def + "' for "
						   + fmt + " arg: " +
						   arg->getType ().getAsString ();
			print_error (err_msg.c_str(),
					arg, ctx->past, ctx->pci);
			return false;
		}

		return true;
	}

	static bool
	tok_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		return check_struct_type (arg,
				ctx,
				"f_str_tok",
				"%T");
	}

	static bool
	fstring_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		return check_struct_type (arg,
				ctx,
				"f_str_s",
				"%V");
	}

	static bool
	gstring_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		return check_struct_type (arg,
				ctx,
				"_GString",
				"%v");
	}

	static bool
	gerr_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		return check_struct_type (arg,
				ctx,
				"_GError",
				"%e");
	}
}
