#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <llvm/ADT/STLExtras.h>
#include <llvm/IR/Analysis.h>
#include <llvm/IR/Argument.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>

#define CHECK(condition, message) \
  do { if (!(condition)) report_fatal_error(message, false); } while (0)

#define MAX_DYNAMIC_ALLOCA_SIZE 345

using namespace llvm;

// NB: This is mostly for testing (and finding bugs) - it should not be true in the final version
constexpr bool Volatile = false;

namespace {
  SmallVector<Value *> GEPIndex(LLVMContext &C, unsigned I) {
    return {
      ConstantInt::get(Type::getInt32Ty(C), 0),
      ConstantInt::get(Type::getInt32Ty(C), I),
    };
  }

  unsigned ArgumentIndex(CallInst *Insn, Value *Value) {
    for (unsigned Index = 0; Index < Insn->arg_size(); ++Index)
      if (Value == Insn->getArgOperand(Index))
        return Index;
    return -1;
  };

  auto Users(Value *V) {
    SmallVector<User *, 4> Collected;
    for (auto User : V->users())
      Collected.push_back(User);
    return Collected;
  };
}

struct Segment {
  uint16_t Selector;
  unsigned Offset;
  Constant *DynamicOffset;

  Value *toFarPointer(LLVMContext &C) const {
    auto FarPtrTy = Type::getIntNTy(C, 48);
    if (!DynamicOffset) // This is the default case.
      return ConstantInt::get(FarPtrTy, (uint64_t) Selector << 32 | (uint64_t) Offset);

    return ConstantExpr::getAdd(
      ConstantInt::get(FarPtrTy, (uint64_t) Selector << 32),
      ConstantExpr::getPtrToInt(DynamicOffset, FarPtrTy)
    );
  }
};

class LemonadePass : public PassInfoMixin<LemonadePass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
  bool Obfuscate(Function &F);

private:
  GlobalVariable *AddGlobal(Module &M, Type *Ty, Twine Name);
  Segment AllocateSegment(Module &M, Constant *Target, bool IsData);
  CallInst *FindCall(BasicBlock &BB);
  void InjectTerminator(Function *Into, BranchInst *Branch, const SmallDenseMap<ReturnInst *, GlobalVariable *> &RetMap, const SmallDenseMap<BasicBlock *, BasicBlock *> &Forwarding, Constant *ReturnThunk);
  void InjectDataRandomization(Function *Into);
  void ReplaceGEPs(Function &F);
  void ReplaceAllocas(Function &F);
  void ReplaceArgs(Function &F);
  void WipeLifetimes(Function &F);

  SmallVector<Function *, 64> SplitFunctions = {};
  Type *ThunkStorageTy;
  GlobalVariable *ReturnThunkStorage;
  unsigned SelectorIndex = 1;
  std::unique_ptr<RandomNumberGenerator> RNG;
};

extern "C" PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION,
    "lemonade",
    "v0.1",
    [](PassBuilder &PB) {
      PB.registerPipelineEarlySimplificationEPCallback(
        [](ModulePassManager &MPM, OptimizationLevel) {
          static std::once_flag once;
          std::call_once(once, [&] { MPM.addPass(LemonadePass()); });
        }
      );
    }
  };
}


PreservedAnalyses LemonadePass::run(Module &M, ModuleAnalysisManager &MAM) {
  RNG = M.createRNG("lemonade");
  auto *Annotations = M.getGlobalVariable("llvm.global.annotations");
  auto PA = PreservedAnalyses::all();
  if (Annotations && Annotations->hasInitializer())
    if (auto *Initializer = dyn_cast<ConstantArray>(Annotations->getInitializer()))
      for (unsigned Index = 0; Index < Initializer->getNumOperands(); ++Index)
        if (auto *Annotation = dyn_cast<ConstantStruct>(Initializer->getOperand(Index)))
            if (auto *AnnotLabel = dyn_cast<GlobalVariable>(Annotation->getOperand(1)->stripPointerCasts()))
              if (auto *AnnotName = dyn_cast<ConstantDataSequential>(AnnotLabel->getInitializer()))
                if (AnnotName->isCString() && AnnotName->getAsCString() == "lemonade")
                  if (auto *F = dyn_cast<Function>(Annotation->getOperand(0)->stripPointerCasts()))
                    PA.intersect(Obfuscate(*F) ? PreservedAnalyses::none() : PreservedAnalyses::all());
  return PreservedAnalyses::none();
}

GlobalVariable *LemonadePass::AddGlobal(Module &M, Type *Ty, Twine Name) {
  auto *Variable = new GlobalVariable {
    M,
    Ty,
    /* isConstant */ false,
    GlobalVariable::InternalLinkage,
    Constant::getNullValue(Ty),
    Name,
  };
  Variable->setSection(".data.lemonade"); // These will be lowered to segment-relative accesses later.
  return Variable;
}

Segment LemonadePass::AllocateSegment(Module &M, Constant *Target, bool IsData) {
  LLVMContext &C = M.getContext();

  CHECK(Target, "Allocating selector for NULL target");
  auto Index = SelectorIndex++;
  auto Uint32Ty = Type::getInt32Ty(C);
  auto DescriptorType = StructType::create({
      Uint32Ty,
      Uint32Ty,
      Uint32Ty,
      Uint32Ty,
  });
#if defined(NO_RANDOMIZE)
  unsigned Offset = 0;
  unsigned Limit = 0xfffff;
  unsigned ExtraFlags = 0x10; // Limit is in pages, not bytes
  Constant *Base = ConstantInt::get(Uint32Ty, 0);
  Constant *DynamicOffset = Target;
#else
#if defined(HALF_RANDOMIZE)
  unsigned Offset = 0x10000;
  if (auto *F = dyn_cast<Function>(Target)) {
    unsigned FnIndex = 0;
    F->getName().rsplit(".").second.consumeInteger(10, FnIndex);
    Offset = FnIndex ? (FnIndex << 16) : 0x10000;
  }
#else
  unsigned Offset = 0x10000 + ((*RNG)() & 0x0007fff0);
#endif
  // This was something fancy but that kept faulting so alas.
  unsigned Limit = Offset + 0x10000 + ((*RNG)() & 0x7fff);
  CHECK(Limit > Offset, "Limit computation overflowed");
  unsigned ExtraFlags = 0;
  Constant *Base = ConstantExpr::getSub(
    ConstantExpr::getPtrToInt(Target, Uint32Ty),
    ConstantInt::get(Uint32Ty, Offset)
  );
  Constant *DynamicOffset = nullptr;
#endif

  auto *Descriptor = new GlobalVariable {
    M,
    DescriptorType,
    /* isConstant */ true,
    GlobalVariable::InternalLinkage,
    ConstantStruct::get(DescriptorType, {
        ConstantInt::get(Uint32Ty, Index),
        Base,
        ConstantInt::get(Uint32Ty, Limit),
        ConstantInt::get(Uint32Ty, ExtraFlags | (IsData ? 0xc1 : 0xcd)),
    }),
    "lemonade.descriptor." + std::to_string(Index),
  };
  Descriptor->setSection(".lemonade.descriptors");
  appendToUsed(M, { Descriptor });

  return { static_cast<uint16_t>((Index << 3) | 7), Offset, DynamicOffset };
}

// Do not keep pointers flying around
void LemonadePass::ReplaceGEPs(Function &F) {
  SmallVector<GetElementPtrInst *, 8> GEPs;
  for (auto &BB : F)
    for (auto &Insn : BB)
      if (auto GEP = dyn_cast<GetElementPtrInst>(&Insn))
        GEPs.push_back(GEP);

  for (auto *GEP : GEPs) {
    auto *Ptr = GEP->getPointerOperand();
    if (!isa<Instruction>(Ptr))
      continue;

    // GEP on an instruction... instead of loading that, save the offsets - if it is used across BBs.
    SmallVector<Instruction *, 8> CrossBBUsers;
    for (auto *User : GEP->users()) {
      auto *Insn = dyn_cast<Instruction>(User);
      if (!Insn)
        continue;
      if (Insn->getParent() != GEP->getParent())
        CrossBBUsers.push_back(Insn);
    }

    if (CrossBBUsers.empty())
      continue;

    SmallVector<Value *, 8> Indices;
    IRBuilder<> IRB(GEP);
    for (auto &Index : GEP->indices()) {
      auto Value = Index.get();
      if (isa<Constant>(Value)) {
        Indices.push_back(Value);
      } else {
        auto Replacement = AddGlobal(*F.getParent(), Value->getType(), "lemonade.gep." + GEP->getName());
        IRB.CreateStore(Value, Replacement, Volatile);
        Indices.push_back(Replacement);
      }
    }

    for (auto *Insn : CrossBBUsers) {
      IRBuilder<> IRB(Insn);
      SmallVector<Value *, 8> Is;
      for (auto *Index : Indices) {
        if (auto *Var = dyn_cast<GlobalVariable>(Index))
          Is.push_back(IRB.CreateLoad(Var->getValueType(), Index, Volatile));
        else
          Is.push_back(Index);
      }
      Value *NewGEP = nullptr;
      if (GEP->isInBounds())
        NewGEP = IRB.CreateInBoundsGEP(GEP->getSourceElementType(), GEP->getPointerOperand(), Is);
      else
        NewGEP = IRB.CreateGEP(GEP->getSourceElementType(), GEP->getPointerOperand(), Is);
      bool Any = Insn->replaceUsesOfWith(GEP, NewGEP);
      CHECK(Any, "No replacements made");
    }
  }
}

// Move alloca instructions into globals.
void LemonadePass::ReplaceAllocas(Function &F) {
  for (auto &BB : F) {
    SmallVector<AllocaInst *, 8> Allocas;

    for (auto &Insn : BB)
      if (auto Alloca = dyn_cast<AllocaInst>(&Insn))
          Allocas.push_back(Alloca);

    for (auto *Alloca : Allocas) {
      if (Alloca->getAllocatedType()->isPtrOrPtrVectorTy()) {
        CHECK(false, "Pointer allocas are not supported");
      } else {
        Value *Storage = nullptr;
        if (auto *Size = dyn_cast<ConstantInt>(Alloca->getArraySize())) {
          auto FixedSize = Size->getZExtValue();
          auto StorageTy = ArrayType::get(Alloca->getAllocatedType(), FixedSize);
          Storage = AddGlobal(*F.getParent(), StorageTy, "lemonade.alloca" + Alloca->getName());
        } else {
          auto StorageTy = ArrayType::get(Alloca->getAllocatedType(), MAX_DYNAMIC_ALLOCA_SIZE);
          Storage = AddGlobal(*F.getParent(), StorageTy, "lemonade.alloca.dyn" + Alloca->getName());

          IRBuilder<> IRB(Alloca);
          auto ReplacementSize = ConstantInt::get(Type::getInt32Ty(F.getContext()), MAX_DYNAMIC_ALLOCA_SIZE);
          Storage = IRB.CreateSelect(
            IRB.CreateICmpULE(Alloca->getOperand(0), ReplacementSize),
            Storage,
            Constant::getNullValue(StorageTy->getPointerTo())
          );
        }
        Alloca->replaceAllUsesWith(Storage);
        Alloca->eraseFromParent();
      }
    }
  }
}

void LemonadePass::ReplaceArgs(Function &F) {
  CHECK(!F.isVarArg(), "Can't handle variadic functions");
  SmallVector<GlobalVariable *, 8> Args;
  unsigned Index = 0;
  for (auto &Arg : F.args()) {
    CallInst *CallSite = nullptr;
    bool Unique = true;
    for (auto *U : F.users()) {
      if (auto Call = dyn_cast<CallInst>(U); Call && Call->getCalledFunction() == &F) {
        if (CallSite)
          Unique = false;
        else
          CallSite = Call;
      }
    }

    if (Arg.getType()->isPtrOrPtrVectorTy()) {
      // Expect that the parent already is a GlobalVariable.
      // We can use that if we're the only place where this is called.
      CHECK(CallSite, "Function is never called");
      CHECK(Unique, "Function takes a pointer argument and is called multiple times");

      Value *Val = CallSite->getArgOperand(Index)->stripPointerCasts();
      auto *Var = dyn_cast<GlobalVariable>(Val);
      CHECK(Var, "Caller did not pass global variable as pointer argument");
      // OK, where does that leave us?
      // We need to replace any load/store with direct loads/stores into this variable.
      CHECK(!Var->getValueType()->isPtrOrPtrVectorTy(), "Uh oh, global is still a pointer");
      Arg.replaceAllUsesWith(Var);
      Args.push_back(nullptr);
    } else {
      GlobalVariable *Replacement = nullptr;
      if (CallSite && Unique) {
        Value *Val = CallSite->getArgOperand(Index)->stripPointerCasts();
        if (auto Var = dyn_cast<GlobalVariable>(Val)) {
          CHECK(!Var->getValueType()->isPtrOrPtrVectorTy(), "Global variable is pointer-typed");
          Replacement = Var;
          Args.push_back(nullptr);
          goto replace;
        }
      }

      Replacement = AddGlobal(*F.getParent(), Arg.getType(), "lemonade.arg." + F.getName() + "." + Arg.getName());
      Args.push_back(Replacement);

replace:
      for (auto User : Users(&Arg)) {
        auto *Insn = dyn_cast<Instruction>(User);
        CHECK(Insn, "Non-instruction use of argument value");
        IRBuilder<> Loader(Insn);
        auto Value = Loader.CreateLoad(Arg.getType(), Replacement, Volatile);
        bool Any = User->replaceUsesOfWith(&Arg, Value);
        CHECK(Any, "No replacements made");
      }
    }
    ++Index;
  }
  for (auto *User : Users(&F)) {
    auto *Insn = dyn_cast<CallInst>(User);
    if (!Insn && isa<Instruction>(User))
      CHECK(Insn, "Non-call use of function");
    else if (!Insn)
      continue;
    IRBuilder<> Storer(Insn);
    for (unsigned I = 0; I < Args.size(); ++I) {
      auto Op = Insn->getArgOperand(I);
      if (Args[I])
        Storer.CreateStore(Op, Args[I], Volatile);
      // Null out the argument anyways.
      Insn->setArgOperand(I, Constant::getNullValue(Op->getType()));
    }
  }
}

void LemonadePass::WipeLifetimes(Function &F) {
  SmallVector<CallInst *, 8> Calls;
  for (auto &BB : F)
    for (auto &Insn : BB)
      if (auto *Call = dyn_cast<CallInst>(&Insn))
        if (auto *Target = Call->getCalledFunction())
          if (Target->isIntrinsic() && Target->getName().starts_with("llvm.lifetime"))
            Calls.push_back(Call);

  for (auto *Call : Calls)
    Call->eraseFromParent();
}


CallInst *LemonadePass::FindCall(BasicBlock &BB) {
  auto It = find_if(BB, [](Instruction &Insn) {
    auto *Call = dyn_cast<CallInst>(&Insn);
    return Call && Call->getCalledFunction() && !Call->getCalledFunction()->isIntrinsic();
  });
  return It == BB.end() ? nullptr : dyn_cast<CallInst>(It);
}

void LemonadePass::InjectDataRandomization(Function *Into) {
  auto &C = Into->getContext();
  auto Seg = AllocateSegment(*Into->getParent(), Into, true);
  auto Selector = Seg.Selector;
  IRBuilder<> IRB(&Into->getEntryBlock(), Into->getEntryBlock().getFirstInsertionPt());
  auto SelTy = Type::getInt16Ty(C);
  InlineAsm *IA = InlineAsm::get(
    FunctionType::get(Type::getVoidTy(C), { SelTy }, false),
    R"asm(
      nopl -${0:c}(%esp)
      .skip 16, 0xf4
    )asm",
    "i,~{dirflag},~{fpsr},~{flags}",
    /* hasSideEffects */ true,
    /* isAlignStack */ false,
    InlineAsm::AD_ATT
  );
  IRB.CreateCall(IA, { ConstantInt::get(SelTy, Selector) });
}

void LemonadePass::InjectTerminator(Function *Into, BranchInst *Branch, const SmallDenseMap<ReturnInst *, GlobalVariable *> &RetMap, const SmallDenseMap<BasicBlock *, BasicBlock *> &Forwarding, Constant *ReturnThunk) {
  auto &C = Into->getContext();
  // There are really two cases here.
  // First, the function returns a value leading into a conditional branch.
  // Second, the function does not return a value, leading into an unconditional branch.
  // We checked that the condition depends on the returned value above.

  // Find the successor functions.
  Function *TrueTarget = nullptr;
  Function *FalseTarget = nullptr;
  ReturnInst *TrueReturn = nullptr;
  ReturnInst *FalseReturn = nullptr;

  for (unsigned Index = 0; Index < Branch->getNumSuccessors(); ++Index) {
    auto *Succ = Branch->getSuccessor(Index);
    for (;;) {
      auto It = Forwarding.find(Succ);
      if (It == Forwarding.end())
        break;
      Succ = It->second;
    }
    ReturnInst *Return = dyn_cast<ReturnInst>(Succ->getTerminator());

    Function *Target = nullptr;
    if (!Return)
      if (auto Call = FindCall(*Succ))
        Target = Call->getCalledFunction();

    switch (Index) {
      case 0: TrueTarget = Target; TrueReturn = Return; break;
      case 1: FalseTarget = Target; FalseReturn = Return; break;
      default: CHECK(false, "More than two successors in a branch instruction");
    }
  }
  CHECK(TrueTarget || TrueReturn, "Failed to find true target");
  CHECK(!(TrueTarget && TrueReturn), "Can't have target and return");
  // Sanity check.
  bool IsVoid = Into->getReturnType()->isVoidTy();
  if (Branch->isConditional()) {
    CHECK(!IsVoid, "Conditional branch on void return");
    CHECK(FalseTarget || FalseReturn, "Failed to find false target for conditional branch");
  } else {
    CHECK(IsVoid, "Non-void return despite unconditional branch");
    CHECK(!FalseTarget && !FalseReturn, "Somehow found false target for unconditional branch");
  }
  CHECK(!(FalseTarget && FalseReturn), "Can't have target and return");

  // Find every return in the function.
  for (auto &BB : *Into) {
    if (auto *Ret = dyn_cast<ReturnInst>(BB.getTerminator())) {
      CHECK(ReturnThunk, "Return thunk not found");
      auto RandomTarget = [Into]() -> Constant * { return Into; }; // This is fine, it all ends up the same way anyways. TODO: Not on DSOs I think

      Constant *TrueFn = TrueReturn ? ReturnThunk : TrueTarget ? TrueTarget : RandomTarget();
      Constant *FalseFn = FalseReturn ? ReturnThunk : FalseTarget ? FalseTarget : RandomTarget();
      if (TrueFn == FalseFn) {
        FalseFn = RandomTarget();
        FalseReturn = nullptr;
        FalseTarget = nullptr;
        IsVoid = true;
      }

      IRBuilder<> IRB(Ret);
      Value *Predicate = nullptr;
      if (IsVoid) {
        // Opaque predicates via storage.
        auto OpaqueType = Type::getInt32Ty(C);
        auto Opaque = AddGlobal(*Into->getParent(), OpaqueType, "lemonade.opaque");
        Predicate = IRB.CreateCmp(CmpInst::Predicate::ICMP_EQ, IRB.CreateLoad(OpaqueType, Opaque, true), ConstantInt::get(OpaqueType, 0));
      } else {
        Predicate = Ret->getReturnValue();
        CHECK(Predicate, "No return value from conditional");
      }

      auto TrueSeg = AllocateSegment(*Into->getParent(), TrueFn, false);
      auto FalseSeg = AllocateSegment(*Into->getParent(), FalseFn, false);

      auto *TrueValue = TrueSeg.toFarPointer(C);
      auto *FalseValue = FalseSeg.toFarPointer(C);
      auto JumpTarget = IRB.CreateSelect(Predicate, TrueValue, FalseValue);

      if (TrueReturn || FalseReturn) {
        auto TrueGlobal = TrueReturn ? RetMap.at(TrueReturn) : nullptr;
        auto FalseGlobal = FalseReturn ? RetMap.at(FalseReturn) : nullptr;
        auto TrueRV = TrueGlobal ? IRB.CreateLoad(TrueGlobal->getValueType(), TrueGlobal) : nullptr;
        auto FalseRV = FalseGlobal ? IRB.CreateLoad(FalseGlobal->getValueType(), FalseGlobal) : nullptr;
        auto IsOuterVoid = (TrueRV ? TrueRV->getType()->isVoidTy() : false) ||
                           (FalseRV ? FalseRV->getType()->isVoidTy() : false);
        if (!IsOuterVoid) {
          Value *ReturnValue = nullptr;
          if (TrueReturn && FalseReturn) {
            CHECK(TrueRV->getType() == FalseRV->getType(), "Mismatched return types");
            ReturnValue = IRB.CreateSelect(Predicate, TrueRV, FalseRV);
          } else {
            ReturnValue = TrueRV ?: FalseRV;
          }
          CHECK(ReturnValue, "No return value");

          auto RetTy = ReturnValue->getType();
          IRB.CreateStore(ReturnValue, IRB.CreateGEP(ThunkStorageTy, ReturnThunkStorage, GEPIndex(C, 2)));
        }
      }

#if defined(NO_FAR_JUMPS)
      // This also removes the opaque predicates
      TrueValue = ConstantExpr::getPtrToInt(TrueFn, Type::getInt32Ty(C));
      FalseValue = ConstantExpr::getPtrToInt(FalseFn, Type::getInt32Ty(C));
      JumpTarget = IsVoid ? TrueValue : IRB.CreateSelect(Predicate, TrueValue, FalseValue);
      InlineAsm *IA = InlineAsm::get(
        FunctionType::get(Type::getVoidTy(C), ArrayRef<Type *> { JumpTarget->getType() }, false),
        R"asm(
          jmp *$0
        )asm",
        "rm,~{dirflag},~{fpsr},~{flags}",
        /* hasSideEffects */ true,
        /* isAlignStack */ false,
        InlineAsm::AD_ATT
      );
      IRB.CreateCall(IA, ArrayRef { JumpTarget });
#else
      InlineAsm *IA = InlineAsm::get(
        FunctionType::get(Type::getVoidTy(C), ArrayRef<Type *> { JumpTarget->getType() }, false),
        R"asm(
          ljmp *$0
        )asm",
        "m,~{dirflag},~{fpsr},~{flags}",
        /* hasSideEffects */ true,
        /* isAlignStack */ false,
        InlineAsm::AD_ATT
      );
      IRB.CreateCall(IA, ArrayRef { JumpTarget });
#endif
      IRB.CreateUnreachable();
      Ret->eraseFromParent();
    }
  }
}

bool LemonadePass::Obfuscate(Function &F) {
  // This is control flow flattening, but there is a nuance.
  if (F.size() < 2) {
    errs() << "\x1b[1;31m" << F.getName() << " is too small to obfuscate.\x1b[0m\n";
    return false;
  }
  if (any_of(F.args(), [](Argument &A) { return A.getType()->isPtrOrPtrVectorTy(); })) {
    errs() << "\x1b[1;31m" << F.getName() << " takes a pointer argument, which is incompatible with data randomization.\x1b[0m\n";
    return false;
  }
  errs() << "\x1b[32mObfuscating " << F.getName() << "\x1b[0m\n";

  ReplaceGEPs(F);
  ReplaceAllocas(F);
  ReplaceArgs(F);
  WipeLifetimes(F);

  // Flatten Phi nodes first. They'll cause us trouble later, and if we do this early,
  // this makes code extraction simpler. To do this cleanly, split critical edges first.
  // It will break some analyses though, so build a DT first.
  SplitAllCriticalEdges(F);
  DominatorTree DT { F };
  auto *EntryBlock = &F.getEntryBlock();
  for (auto &BB : F) {
    SmallVector<PHINode *, 8> Phis;
    for (auto &Insn : BB) {
      // Phi nodes must be at the start of the BB.
      auto *Phi = dyn_cast<PHINode>(&Insn);
      if (!Phi)
        break;
      Phis.push_back(Phi);

      auto *Replacement = AddGlobal(*F.getParent(), Phi->getType(), "lemonade.phi" + Phi->getName());
      for (unsigned Index = 0; Index < Phi->getNumIncomingValues(); ++Index) {
        auto *Predecessor = Phi->getIncomingBlock(Index);
        auto *Value = Phi->getIncomingValue(Index);

        IRBuilder<> PredIRB(Predecessor->getTerminator());
        PredIRB.CreateStore(Value, Replacement, Volatile);
      }

      IRBuilder<> PhiIRB(Phi);
      auto Value = PhiIRB.CreateLoad(Phi->getType(), Replacement, Volatile);
      Phi->replaceAllUsesWith(Value);
    }
    for (auto *Phi : Phis) {
      CHECK(Phi->getNumUses() == 0, "Phi node is still in use");
      Phi->eraseFromParent();
    }
  }

  // Create a new pre-entry block
  auto PreEntryBlock = BasicBlock::Create(F.getContext(), "pre-entry", &F, &F.getEntryBlock());

  // Insert our return thunk function, and insert the "save" code at the start of the pre-entry block.
  // We do this here because it means we don't have to mess with the IRB placement - the basic block
  // is currently empty.
  Function *ReturnThunk = nullptr;
  {
    IRBuilder<> IRB(PreEntryBlock);
    PointerType *AllocaPtrTy = F.getParent()->getDataLayout().getAllocaPtrType(F.getContext());
    auto StackSaved = IRB.CreateCall(Intrinsic::getDeclaration(F.getParent(), Intrinsic::stacksave, { AllocaPtrTy }));

    auto SelectorSavedTy = Type::getInt32Ty(F.getContext());
    InlineAsm *IA = InlineAsm::get(
      FunctionType::get(SelectorSavedTy, false),
      R"asm(
        pushw %cs
        pushw %ds
        popl  $0
        nopl  (%eax)
        hlt
      )asm",
      "=r,~{dirflag},~{fpsr},~{flags}",
      /* hasSideEffects */ true,
      /* isAlignStack */ false,
      InlineAsm::AD_ATT
    );
    auto SelectorSaved = IRB.CreateCall(IA);

    {
      ReturnThunk = Function::Create(
        FunctionType::get(F.getReturnType(), false),
        GlobalValue::LinkageTypes::InternalLinkage,
        "lemonade.return_thunk." + F.getName(),
        F.getParent()
      );

      ThunkStorageTy = StructType::get(
        StackSaved->getType(),
        SelectorSavedTy,
        F.getReturnType(),
        ReturnThunk->getType()
      );

      ReturnThunkStorage = AddGlobal(*F.getParent(), ThunkStorageTy, "lemonade.thunk");
      auto ThunkBlock = BasicBlock::Create(F.getContext(), "entry", ReturnThunk);
      IRBuilder<> ThunkBuilder(ThunkBlock);

      // Make this volatile so it doesn't reorder against the IA
      auto Stack = ThunkBuilder.CreateLoad(StackSaved->getType(), ThunkBuilder.CreateGEP(ThunkStorageTy, ReturnThunkStorage, GEPIndex(F.getContext(), 0)), true);
      ThunkBuilder.CreateCall(Intrinsic::getDeclaration(F.getParent(), Intrinsic::stackrestore, { AllocaPtrTy }),
                              { Stack });

      auto Selectors = ThunkBuilder.CreateLoad(SelectorSavedTy, ThunkBuilder.CreateGEP(ThunkStorageTy, ReturnThunkStorage, GEPIndex(F.getContext(), 1)), true);
      auto ReturnValue = ThunkBuilder.CreateLoad(F.getReturnType(), ThunkBuilder.CreateGEP(ThunkStorageTy, ReturnThunkStorage, GEPIndex(F.getContext(), 2)), true);
      auto Self = ThunkBuilder.CreateLoad(ReturnThunk->getType(), ThunkBuilder.CreateGEP(ThunkStorageTy, ReturnThunkStorage, GEPIndex(F.getContext(), 3)), true);

      InlineAsm *IA = InlineAsm::get(
        FunctionType::get(Type::getVoidTy(F.getContext()), { SelectorSavedTy, ReturnThunk->getType() }, false),
        R"asm(
           pushw $$0 # lret pops 8 bytes, not 6. Because of course.
           pushl $0
           popw  %ds
           pushl $1
           addl  $$0x2a, (%esp) # fixed in post-processing, since we can't get the right value here anyways.
           lret
        1:
        )asm",
        "r,r,~{dirflag},~{fpsr},~{flags}",
        /* hasSideEffects */ true,
        /* isAlignStack */ false,
        InlineAsm::AD_ATT
      );
      ThunkBuilder.CreateCall(IA, { Selectors, Self });
      ThunkBuilder.CreateRet(F.getReturnType()->isVoidTy() ? nullptr : ReturnValue);

      InjectDataRandomization(ReturnThunk);
    }
    CHECK(ReturnThunkStorage, "No return thunk storage");

    IRB.CreateStore(StackSaved, IRB.CreateGEP(ThunkStorageTy, ReturnThunkStorage, GEPIndex(F.getContext(), 0)));
    IRB.CreateStore(SelectorSaved, IRB.CreateGEP(ThunkStorageTy, ReturnThunkStorage, GEPIndex(F.getContext(), 1)));
    IRB.CreateStore(ReturnThunk, IRB.CreateGEP(ThunkStorageTy, ReturnThunkStorage, GEPIndex(F.getContext(), 3)));
  }

  // Now, split every BB out into a separate function.
  // The control flow stays in this function for now.
  // We'll split that up soon enough.
  SmallVector<BasicBlock *, 32> BBs;
  for (auto &BB : F) {
    if (&BB == EntryBlock || &BB == PreEntryBlock)
      continue; // Don't do the entry block.
    if (auto *Term = dyn_cast<BranchInst>(BB.getTerminator()); Term && !Term->isConditional() && BB.size() == 1)
      continue; // Skip empty blocks from edge splitting.
    BBs.push_back(&BB);
  }

  SmallVector<GlobalValue *, 64> OutlinedFunctions;
  CodeExtractorAnalysisCache CEAC { F };
  for (auto *BB : BBs) {
    SmallVector<BasicBlock *, 1> Targets = { BB };
    if (const InvokeInst *II = dyn_cast<InvokeInst>(BB->getTerminator()))
      CHECK(!II->getUnwindDest(), "Unexpected invoke instruction has unwind destination");

    CodeExtractor CE {
      /* BBs */                    Targets,
      /* DT */                     &DT,
      /* AggregateArgs */          false,
      /* BFI */                    nullptr,
      /* BPI */                    nullptr,
      /* AC */                     nullptr,
      /* AllowVarArgs */           false,
      /* AllowAlloca */            true,
      /* AllocationBlock */        PreEntryBlock,
      /* Suffix */                 "lemonade",
      /* ArgsInZeroAddressSpace */ false
    };

    auto Replacement = CE.extractCodeRegion(CEAC);
    CHECK(Replacement, "Failed to outline basic block");
    Replacement->addFnAttr(Attribute::NoInline);

    // Replace arguments with globals - but replace pointer arguments with their actual values.
    CHECK(Replacement->getNumUses() == 1, "Outlined function is used more than once.");
    OutlinedFunctions.push_back(Replacement);
  }

  // Replace new allocas.
  WipeLifetimes(F);
  ReplaceAllocas(F);
  for (auto ReplacementPtr : OutlinedFunctions) {
    auto &Replacement = *dyn_cast<Function>(ReplacementPtr);
    ReplaceArgs(Replacement);
    InjectDataRandomization(&Replacement);
    WipeLifetimes(Replacement);
  }

  // Close the PreEntryBlock
  IRBuilder<> IRB(PreEntryBlock, PreEntryBlock->end());
  IRB.CreateBr(EntryBlock);

  SmallDenseMap<BasicBlock *, BasicBlock *> Forwarding;
  SmallDenseMap<ReturnInst *, GlobalVariable *> RetMap;
  SmallDenseMap<Value *, GlobalVariable *> ValueMap;
  SmallVector<Instruction *, 32> ToDelete;
  SmallVector<std::pair<Function *, BranchInst *>> Worklist;

  auto GetReplacement = [&](Value *For) {
    if (auto It = ValueMap.find(For); It != ValueMap.end())
      return It->second;
    auto Replacement = AddGlobal(*F.getParent(), For->getType(), "lemonade.defuse" + For->getName());
    ValueMap[For] = Replacement;
    return Replacement;
  };

  // IDA is already unhappy :D
  // Now make it more sad: Lift the terminator too.
  // This means we need to move any loads and stores around the call into the function itself.
  for (auto &BB : F) {
    if (&BB == EntryBlock || &BB == PreEntryBlock)
      continue;

    auto Terminator = BB.getTerminator();

    // Find the outlined call, if any.
    auto *Call = FindCall(BB);

    auto AssertIsOnlyCall = [](CallInst *Insn) {
      auto Target = Insn->getCalledFunction();
      CHECK(Target, "Undetermined target function");
      unsigned Calls = 0;
      for (auto *User : Target->users())
        if (isa<CallInst>(User))
          ++Calls;
      CHECK(Calls == 1, "Target function is not called exactly once");
    };

    if (auto *Ret = dyn_cast<ReturnInst>(Terminator)) {
      // This is generally a BB that _only_ does ret now, the call in here is optional.
      // We want to outline a separate function that does the returning.
      // So, lret instead - but when this is a branch target.
      // No need to touch this BB.
      CHECK(!Call, "Outlined call in return (this needs additional handling)");
    } else if (auto *Branch = dyn_cast<BranchInst>(Terminator)) {
      // Before the call, we can only have stores.
      // After the call, we can only have loads.
      if (!Call) {
        CHECK(Branch->getNumSuccessors() == 1, "Branch without call has multiple successors");
        Forwarding[&BB] = Branch->getSuccessor(0);
        continue;
      }

      if (Branch->isConditional())
        CHECK(Branch->getCondition() == Call, "Conditional branch in obfuscation does not depend on outlined block");
      auto Outlined = Call->getCalledFunction();

      bool BeforeCall = true;
      for (auto &Insn : BB) {
        if (&Insn == Call) {
          BeforeCall = false;
        } else if (&Insn == Terminator) {
          break;
        } else if (auto *Store = dyn_cast<StoreInst>(&Insn)) {
          CHECK(BeforeCall, "Unexpected store after call in inline block");

          // This store must be done at the start of the function.
          // This should be fine since this is the only call site.
          CHECK(isa<GlobalVariable>(Store->getPointerOperand()), "Cannot handle dynamic stores");
          AssertIsOnlyCall(Call);

          auto DefUse = GetReplacement(Store->getValueOperand()->stripPointerCasts());
          IRBuilder<> IRB(&Outlined->getEntryBlock(), Outlined->getEntryBlock().getFirstInsertionPt());

          IRB.CreateStore(
            IRB.CreateLoad(DefUse->getValueType(), DefUse, Volatile),
            Store->getPointerOperand(),
            Volatile
          );

          ToDelete.push_back(Store);
        } else if (auto *Load = dyn_cast<LoadInst>(&Insn)) {
          CHECK(!BeforeCall, "Unexpected load before call in inline block");

          // Similarly, put the store at the end of the function.
          // But since the function may have multiple returns, put it into each one of them.
          CHECK(isa<GlobalVariable>(Load->getPointerOperand()), "Cannot handle dynamic loads");
          AssertIsOnlyCall(Call);

          auto DefUse = GetReplacement(Load);
          for (auto &BB : *Outlined) {
            if (auto *Ret = dyn_cast<ReturnInst>(BB.getTerminator())) {
              IRBuilder<> IRB(Ret);
              IRB.CreateStore(
                IRB.CreateLoad(DefUse->getValueType(), Load->getPointerOperand(), Volatile),
                DefUse,
                Volatile
              );
            }
          }

          // If the load is used in a return, track it.
          for (auto *User : Load->users())
            if (auto UserRet = dyn_cast<ReturnInst>(User))
              RetMap[UserRet] = DefUse;

          ToDelete.push_back(Load);
        } else {
          errs() << "\x1b[1;31mInline basic block contains unexpected instruction:\x1b[0m " << Insn << "\n";
          CHECK(false, "Cannot handle this instruction");
        }
      }

      // Finally, remember to move over the terminators.
      Worklist.push_back({ Outlined, Branch });
    } else {
      errs() << "\x1b[1;31mBasic block ends with an unknown instruction:\x1b[0m " << *(BB.getTerminator()) << "\n";
    }
  }
  for (auto &[Outlined, Branch] : Worklist)
    InjectTerminator(Outlined, Branch, RetMap, Forwarding, ReturnThunk);

  /// This crashes for some unclear reason. Trust in DCE to clean it up anyways.
  // for (auto *Insn : ToDelete)
  //   Insn->eraseFromParent();

  // Since LLVM no longer realizes that this function does indeed return, hide the call away.
  // I blame isGuaranteedToTransferExecutionToSuccessor for this.
  auto *Stub = Function::Create(
    F.getFunctionType(),
    GlobalValue::LinkageTypes::InternalLinkage,
    "lemonade.stub." + F.getName(),
    F.getParent()
  );
  Stub->addFnAttr(Attribute::Naked);
  Stub->addFnAttr(Attribute::NoInline);
  Stub->addFnAttr(Attribute::NoUnwind);
  Stub->addFnAttr(Attribute::OptimizeNone);
  Stub->addFnAttr("no_callee_saved_registers");
  auto StubBlock = BasicBlock::Create(F.getContext(), "entry", Stub);
  IRBuilder<> StubIRB(StubBlock);

  InlineAsm *IA = InlineAsm::get(
    FunctionType::get(F.getReturnType(), { F.getType() }, false),
    R"asm(
      jmp ${0:c}
    )asm",
    "is,~{dirflag},~{fpsr},~{flags},~{memory}",
    /* hasSideEffects */ true,
    /* isAlignStack */ false,
    InlineAsm::AD_ATT
  );
  StubIRB.CreateCall(IA, { &F });
  StubIRB.CreateUnreachable();

  SmallVector<CallInst *, 4> CallSites;
  for (auto *User : F.users())
    if (auto *CallSite = dyn_cast<CallInst>(User))
      if (CallSite->getParent()->getParent() != Stub)
        CallSites.push_back(CallSite);
  for (auto *CallSite : CallSites)
    CallSite->setCalledFunction(Stub);

  appendToUsed(*F.getParent(), { Stub, ReturnThunk });
  appendToUsed(*F.getParent(), OutlinedFunctions);
  return true;
}
