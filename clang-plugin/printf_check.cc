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

using namespace clang;

namespace rspamd {
	class PrintfCheckVisitor::impl {
		std::unordered_map<std::string, int> printf_functions;
		ASTContext *pcontext;

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
				if (qval) {
					llvm::errs () << "query string: "
							<< qval->getString () << "\n";
				}

				for (auto i = pos + 1; i < E->getNumArgs (); i++) {
					auto arg = args[i];

					if (arg) {
						auto type = arg->getType ().split ().Ty;
						type->dump ();
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
};
