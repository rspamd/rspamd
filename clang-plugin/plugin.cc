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
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Sema/Sema.h"
#include "llvm/Support/raw_ostream.h"
#include "printf_check.h"


using namespace clang;

namespace rspamd {

	class RspamdASTConsumer : public ASTConsumer {
		CompilerInstance &Instance;

	public:
		RspamdASTConsumer (CompilerInstance &Instance)
				: Instance (Instance)
		{
		}

		void HandleTranslationUnit (ASTContext &context) override
		{
			rspamd::PrintfCheckVisitor v(&context, Instance);
			v.TraverseDecl (context.getTranslationUnitDecl ());
		}
	};

	class RspamdASTAction : public PluginASTAction {
	protected:
		std::unique_ptr <ASTConsumer> CreateASTConsumer (CompilerInstance &CI,
				llvm::StringRef) override
		{
			return std::make_unique<RspamdASTConsumer> (CI);
		}

		bool ParseArgs (const CompilerInstance &CI,
				const std::vector <std::string> &args) override
		{
			return true;
		}

		void PrintHelp (llvm::raw_ostream &ros)
		{
			ros << "Nothing here\n";
		}

	};

}

static FrontendPluginRegistry::Add <rspamd::RspamdASTAction>
		X ("rspamd-ast", "rspamd ast checker");
