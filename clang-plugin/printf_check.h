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
#ifndef RSPAMD_PRINTF_CHECK_H
#define RSPAMD_PRINTF_CHECK_H

#include <memory>
#include "clang/AST/AST.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/AST/Expr.h"

namespace rspamd {

	class PrintfCheckVisitor : public clang::RecursiveASTVisitor<PrintfCheckVisitor> {
		class impl;
		std::unique_ptr<impl> pimpl;

	public:
		PrintfCheckVisitor (clang::ASTContext *ctx, clang::CompilerInstance &ci);
		virtual ~PrintfCheckVisitor (void);
		bool VisitCallExpr (clang::CallExpr *E);
	};

}

#endif
