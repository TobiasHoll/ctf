#include "clang/AST/Attr.h"
#include "clang/Sema/ParsedAttr.h"
#include "clang/Sema/Sema.h"

using namespace clang;

namespace {

struct LemonadeAttrInfo : public ParsedAttrInfo {
  LemonadeAttrInfo() {
    static constexpr Spelling S[] = {{ParsedAttr::AS_GNU, "lemonade"},
                                     {ParsedAttr::AS_C23, "lemonade"},
                                     {ParsedAttr::AS_CXX11, "lemonade"}};
    Spellings = S;
    OptArgs = 0;
    NumArgs = 0;
  }

  bool diagAppertainsToDecl(Sema &S, const ParsedAttr &Attr,
                            const Decl *D) const override {
    if (!isa<FunctionDecl>(D)) {
      S.Diag(Attr.getLoc(), diag::warn_attribute_wrong_decl_type)
          << Attr << Attr.isRegularKeywordAttribute() << ExpectedFunction;
      return false;
    }
    return true;
  }

  AttrHandling handleDeclAttribute(Sema &S, Decl *D,
                                   const ParsedAttr &Attr) const override {
    D->addAttr(AnnotateAttr::Create(S.Context, "lemonade", nullptr, 0,
                                    Attr.getRange()));
    return AttributeApplied;
  }
};

}

static ParsedAttrInfoRegistry::Add<LemonadeAttrInfo> X("make-lemonade", "Makes lemonade");
