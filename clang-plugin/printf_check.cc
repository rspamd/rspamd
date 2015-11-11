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

#include "printf_check.h"
#include "clang/AST/AST.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include <unordered_map>
#include <vector>
#include <sstream>
#include <ctype.h>

using namespace clang;

namespace rspamd {
	struct PrintfArgChecker;

	static bool cstring_arg_handler (const Expr *arg,
			struct PrintfArgChecker *ctx);
	static bool int_arg_handler (const Expr *arg,
			struct PrintfArgChecker *ctx);

	using arg_parser_t = bool (*) (const Expr *, struct PrintfArgChecker *);

	static void
	print_error (const std::string &err, const Expr *e, const ASTContext *ast)
	{
		auto const &sm = ast->getSourceManager ();
		auto loc = e->getExprLoc ();
		llvm::errs() << err << " at " << loc.printToString (sm) << "\n";
	}

	struct PrintfArgChecker {
	private:
		arg_parser_t parser;
	public:
		int width;
		int precision;
		ASTContext *past;

		PrintfArgChecker (arg_parser_t _p, ASTContext *_ast) :
				parser(_p), past(_ast) {}
		virtual ~PrintfArgChecker () {}

		bool operator () (const Expr *e)
		{
			return parser (e, this);
		}
	};

	class PrintfCheckVisitor::impl {
		std::unordered_map<std::string, int> printf_functions;
		ASTContext *pcontext;

		std::unique_ptr<PrintfArgChecker> parseFlags (const std::string &flags)
		{
			auto type = flags.back();

			switch (type) {
			case 's':
				return llvm::make_unique<PrintfArgChecker>(cstring_arg_handler,
						this->pcontext);
			case 'd':
				return llvm::make_unique<PrintfArgChecker>(int_arg_handler,
						this->pcontext);
			default:
				llvm::errs () << "unknown parser flag: " << type << "\n";
				break;
			}

			return nullptr;
		}

		std::shared_ptr<std::vector<PrintfArgChecker> >
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

			auto res = std::make_shared<std::vector<PrintfArgChecker> >();

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
						res->emplace_back (int_arg_handler, this->pcontext);
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
						res->emplace_back (int_arg_handler, this->pcontext);
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
						state = ignore_chars;
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
		impl (ASTContext *_ctx) : pcontext(_ctx)
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
								qval->getString().str()
								<< "', expected " << parsers->size () << " args"
								<< ", got " << (E->getNumArgs () - (pos + 1))
								<< " args";
						print_error (err_buf.str (), E, this->pcontext);

						return false;
					}
					else {
						for (auto i = pos + 1; i < E->getNumArgs (); i++) {
							auto arg = args[i];

							if (arg) {
								if (!parsers->at(i - (pos + 1))(arg)) {
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

	PrintfCheckVisitor::PrintfCheckVisitor (ASTContext *ctx) :
		pimpl { new impl(ctx) }
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
							arg->getType ().getAsString (), arg, ctx->past);
			return false;
		}

		auto ptr_type = type->getPointeeType().split().Ty;

		if (!ptr_type->isCharType ()) {
			/* We might have gchar * here */
			auto desugared_type = ptr_type->getUnqualifiedDesugaredType ();

			if (!desugared_type || !desugared_type->isCharType ()) {
				if (desugared_type) {
					desugared_type->dump ();
				}
				print_error (
						std::string ("bad string argument for %s: ") +
								arg->getType ().getAsString (), arg, ctx->past);
				return false;
			}
		}

		return true;
	}

	static bool
	int_arg_handler (const Expr *arg, struct PrintfArgChecker *ctx)
	{
		auto type = arg->getType ().split ().Ty;

		auto desugared_type = type->getUnqualifiedDesugaredType ();

		if (!desugared_type->isIntegerType ()) {
			print_error (std::string ("bad integer argument for %d or * arg: ") +
					arg->getType ().getAsString (), arg, ctx->past);
			return false;
		}
		else if (!desugared_type->isBuiltinType ()) {
			print_error (std::string ("bad integer argument for %d or * arg: ") +
							arg->getType ().getAsString(), arg, ctx->past);
			return false;
		}

		auto builtin_type = dyn_cast<BuiltinType>(desugared_type);
		auto kind = builtin_type->getKind ();

		if (kind != BuiltinType::Kind::UInt &&
				kind != BuiltinType::Kind::Int) {
			print_error (std::string ("bad integer argument for %d or * arg: ") +
					arg->getType ().getAsString (), arg, ctx->past);
			return false;
		}

		return true;
	}
};
