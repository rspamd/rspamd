/*
 * Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include "printf_check.h"
#include "clang/AST/AST.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include <unordered_map>
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

	static bool int64_arg_handler (const Expr *arg,
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
	print_error (const std::string &err, const Expr *e, const ASTContext *ast,
			CompilerInstance *ci)
	{
		auto loc = e->getExprLoc ();
		auto &diag = ci->getDiagnostics ();
		auto id = diag.getCustomDiagID (DiagnosticsEngine::Error,
				"format query error: %0");
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
		ASTContext *pcontext;
		CompilerInstance *ci;

		std::unique_ptr <PrintfArgChecker> parseFlags (const std::string &flags)
		{
			auto type = flags.back ();

			switch (type) {
			case 's':
				return llvm::make_unique<PrintfArgChecker> (cstring_arg_handler,
						this->pcontext, this->ci);
			case 'd':
				return llvm::make_unique<PrintfArgChecker> (int_arg_handler,
						this->pcontext, this->ci);
			case 'z':
				return llvm::make_unique<PrintfArgChecker> (size_arg_handler,
						this->pcontext, this->ci);
			case 'l':
				return llvm::make_unique<PrintfArgChecker> (long_arg_handler,
						this->pcontext, this->ci);
			case 'f':
			case 'g':
				return llvm::make_unique<PrintfArgChecker> (double_arg_handler,
						this->pcontext, this->ci);
			case 'F':
			case 'G':
				return llvm::make_unique<PrintfArgChecker> (
						long_double_arg_handler,
						this->pcontext, this->ci);
			case 'c':
				return llvm::make_unique<PrintfArgChecker> (char_arg_handler,
						this->pcontext, this->ci);
			case 'p':
				return llvm::make_unique<PrintfArgChecker> (pointer_arg_handler,
						this->pcontext, this->ci);
			case 'P':
				return llvm::make_unique<PrintfArgChecker> (pid_arg_handler,
						this->pcontext, this->ci);
			case 'L':
				return llvm::make_unique<PrintfArgChecker> (int64_arg_handler,
						this->pcontext, this->ci);
			case 'T':
				return llvm::make_unique<PrintfArgChecker> (tok_arg_handler,
						this->pcontext, this->ci);
			case 'V':
				return llvm::make_unique<PrintfArgChecker> (fstring_arg_handler,
						this->pcontext, this->ci);
			case 'v':
				return llvm::make_unique<PrintfArgChecker> (gstring_arg_handler,
						this->pcontext, this->ci);
			case 'e':
				return llvm::make_unique<PrintfArgChecker> (gerr_arg_handler,
						this->pcontext, this->ci);
			default:
				llvm::errs () << "unknown parser flag: " << type << "\n";
				break;
			}

			return nullptr;
		}

		std::shared_ptr <std::vector<PrintfArgChecker>>
		genParsers (const StringRef query)
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

			for (const auto c : query) {
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
						state = read_arg;
					}
					else if (c == '%') {
						/* Percent character, ignore */
						state = ignore_chars;
					}
					else {
						flags.push_back (c);
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
						flags.push_back (c);
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
						flags.push_back (c);
						state = read_arg;
					}
					break;
				case read_arg:
					if (!isalpha (c)) {
						auto handler = parseFlags (flags);

						if (handler) {
							auto handler_copy = *handler;
							handler_copy.precision = precision;
							handler_copy.width = width;
							res->emplace_back (std::move (handler_copy));
						}
						else {
							llvm::errs () << "invalid modifier\n";
							return nullptr;
						}

						if (c == '%') {
							state = read_percent;
						}
						else {
							state = ignore_chars;
						}
					}
					else {
						flags.push_back (c);
					}
					break;
				}
			}

			if (state == read_arg) {
				auto handler = parseFlags (flags);

				if (handler) {
					auto handler_copy = *handler;
					handler_copy.precision = precision;
					handler_copy.width = width;
					res->emplace_back (std::move (handler_copy));
				}
				else {
					llvm::errs () << "invalid modifier\n";
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
					{"rspamd_printf",               0},
					{"rspamd_default_log_function", 4},
					{"rspamd_snprintf",             2},
					{"rspamd_fprintf",              1}
			};
		};

		bool VisitCallExpr (CallExpr *E)
		{
			auto callee = dyn_cast<NamedDecl> (E->getCalleeDecl ());
			if (callee == NULL) {
				llvm::errs () << "Bad callee\n";
				return false;
			}

			auto fname = callee->getNameAsString ();

			auto pos_it = printf_functions.find (fname);

			if (pos_it != printf_functions.end ()) {
				const auto args = E->getArgs ();
				auto pos = pos_it->second;
				auto query = args[pos];

				if (!query->isEvaluatable (*pcontext)) {
					llvm::errs () << "Cannot evaluate query\n";
					return false;
				}

				clang::Expr::EvalResult r;

				if (!query->EvaluateAsRValue (r, *pcontext)) {
					llvm::errs () << "Cannot evaluate query\n";
					return false;
				}

				auto qval = dyn_cast<StringLiteral> (
						r.Val.getLValueBase ().get<const Expr *> ());
				if (!qval) {
					llvm::errs () << "Bad or absent query string\n";
					return false;
				}

				auto parsers = genParsers (qval->getString ());

				if (parsers) {
					if (parsers->size () != E->getNumArgs () - (pos + 1)) {
						std::ostringstream err_buf;
						err_buf << "number of arguments for " << fname
								<< " missmatches query string '" <<
								qval->getString ().str ()
										<< "', expected " << parsers->size () <<
								" args"
										<< ", got " <<
								(E->getNumArgs () - (pos + 1))
										<< " args";
						print_error (err_buf.str (), E, this->pcontext, this->ci);

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
			print_error (
					std::string ("bad string argument for %s: ") +
					arg->getType ().getAsString (),
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
				print_error (
						std::string ("bad string argument for %s: ") +
								arg->getType ().getAsString (),
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
			print_error (
					std::string ("not a builtin type for ") + fmt + " arg: " +
							arg->getType ().getAsString (),
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
			print_error (
					std::string ("bad argument for ") + fmt + " arg: " +
							arg->getType ().getAsString (),
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
				 BuiltinType::Kind::SChar},
				"%c");
	}

	static bool
	size_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		if (sizeof (size_t) == sizeof (long)) {
			return check_builtin_type (arg,
					ctx,
					{BuiltinType::Kind::ULong,
					 BuiltinType::Kind::Long},
					"%z");
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
	pointer_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		auto type = arg->getType ().split ().Ty;

		if (!type->isPointerType ()) {
			print_error (
					std::string ("bad pointer argument for %p: ") +
							arg->getType ().getAsString (),
					arg, ctx->past, ctx->pci);
			return false;
		}

		return true;
	}

	static bool
	int64_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		if (sizeof (int64_t) == sizeof (long long)) {
			return check_builtin_type (arg,
					ctx,
					{BuiltinType::Kind::ULongLong,
					 BuiltinType::Kind::LongLong},
					"%L");
		}
		else if (sizeof (int64_t) == sizeof (long)) {
			return check_builtin_type (arg,
					ctx,
					{BuiltinType::Kind::ULong,
					 BuiltinType::Kind::Long},
					"%z");
		}
		else {
			assert (0);
		}

		return true;
	}

	static bool
	check_struct_type (const Expr *arg, struct PrintfArgChecker *ctx,
			const std::string &sname, const std::string &fmt)
	{
		auto type = arg->getType ().split ().Ty;

		if (!type->isPointerType ()) {
			print_error (
					std::string ("bad string argument for %s: ") +
							arg->getType ().getAsString (),
					arg, ctx->past, ctx->pci);
			return false;
		}

		auto ptr_type = type->getPointeeType ().split ().Ty;
		auto desugared_type = ptr_type->getUnqualifiedDesugaredType ();

		if (!desugared_type->isRecordType ()) {
			print_error (
					std::string ("not a record type for ") + fmt + " arg: " +
							arg->getType ().getAsString (),
					arg, ctx->past, ctx->pci);
			return false;
		}

		auto struct_type = desugared_type->getAsStructureType ();
		auto struct_decl = struct_type->getDecl ();
		auto struct_def = struct_decl->getNameAsString ();

		if (struct_def != sname) {
			print_error (std::string ("bad argument '") + struct_def + "' for "
					+ fmt + " arg: " +
					arg->getType ().getAsString (),
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
};
