/*
 * Copyright (c) 2007-2015 University of Illinois at Urbana-Champaign.
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


#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Sema/Sema.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;

namespace {

	class RspamdASTConsumer : public ASTConsumer {
		CompilerInstance &Instance;

	public:
		RspamdASTConsumer (CompilerInstance &Instance)
				: Instance (Instance)
		{
		}

		bool HandleTopLevelDecl (DeclGroupRef DG) override
		{
			for (DeclGroupRef::iterator i = DG.begin (), e = DG.end (); i != e;
				 ++i) {
				const Decl *D = *i;
				if (const NamedDecl *ND = dyn_cast<NamedDecl> (D))
					llvm::errs () << "top-level-decl: \"" <<
							ND->getNameAsString () << "\"\n";
			}

			return true;
		}

		void HandleTranslationUnit (ASTContext &context) override
		{
			struct Visitor : public RecursiveASTVisitor<Visitor> {

				Visitor (void)
				{
				}

				bool VisitFunctionDecl (FunctionDecl *FD)
				{
					if (FD->isLateTemplateParsed ())
						LateParsedDecls.insert (FD);
					return true;
				}

				std::set<FunctionDecl *> LateParsedDecls;
			} v;
			v.TraverseDecl (context.getTranslationUnitDecl ());
			clang::Sema &sema = Instance.getSema ();
			for (const FunctionDecl *FD : v.LateParsedDecls) {
				clang::LateParsedTemplate *LPT = sema.LateParsedTemplateMap.lookup (
						FD);
				sema.LateTemplateParser (sema.OpaqueParser, *LPT);
				llvm::errs () << "late-parsed-decl: \"" <<
						FD->getNameAsString () << "\"\n";
			}
		}
	};

	class RspamdASTAction : public PluginASTAction {
	protected:
		std::unique_ptr <ASTConsumer> CreateASTConsumer (CompilerInstance &CI,
				llvm::StringRef) override
		{
			return llvm::make_unique<RspamdASTConsumer> (CI);
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

static FrontendPluginRegistry::Add <RspamdASTAction>
		X ("rspamd-ast", "rspamd ast checker");
