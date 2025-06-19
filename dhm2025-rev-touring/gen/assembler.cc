#include <byteswap.h>
#include <liburing.h>
#include <linux/time_types.h>
#include <netinet/in.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <concepts>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <ostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "mapping.h"

using namespace std::literals::string_literals;

namespace std {
    template <> struct less<__kernel_timespec> {
        constexpr bool operator()(const __kernel_timespec& lhs, const __kernel_timespec& rhs) const {
            return lhs.tv_sec < rhs.tv_sec || (lhs.tv_sec == rhs.tv_sec && lhs.tv_nsec < rhs.tv_nsec);
        }
    };
}

enum class FixedFile : int {
    Stdin = 0,
    Stdout = 1,
    Memfd = 2,
    Eventfd = 3,
    PipeRead = 4,
    PipeWrite = 5,
    Socket = 6, // Not occupied initially
};

// XXX: Combine scratch buffer space (8 bytes) into start of constant buffer
enum class FixedBuffer : int {
    Scratch = 0,
    Constants = 1,
};

//! Represents offsets into the constant buffer
//! The constant buffer is canonically mapped at CONSTANTS_BASE, so we can use that as the pointer base
struct Constant {
    off_t Offset;
    size_t Size;
    operator off_t() const { return Offset; }
};

enum class Register : off_t {
    // These are offsets in the register bank.
    RZ = 0x00, // Always 0 by convention. Don't write this.
    R1 = 0x04,
    R2 = 0x08,
    R3 = 0x0c,
    R4 = 0x10,
    R5 = 0x14,
    R6 = 0x18,
    R7 = 0x1c,
    R8 = 0x20,
    R9 = 0x24,
    RA = 0x28,
    RB = 0x2c,
    RC = 0x30,
    RD = 0x34,
    RE = 0x38,
    RT = 0x3c, // Temporary register. Don't use this.
    RMAX = RT,
};

constexpr size_t RegisterSize = 4;

// Utilities that wrap liburing
namespace Util {
    template <typename T> concept Off = requires { static_cast<off_t>(std::declval<T>()); };

    char *BufferPointer(FixedBuffer Buffer, Off auto Offset) {
        switch (Buffer) {
            case FixedBuffer::Scratch: return reinterpret_cast<char *>(SCRATCH_BASE) + static_cast<off_t>(Offset);
            case FixedBuffer::Constants: return reinterpret_cast<char *>(CONSTANTS_BASE) + static_cast<off_t>(Offset);
            default: throw std::runtime_error { "Bad buffer selector" };
        }
    }

    void ReadFixed(io_uring_sqe *Sqe, FixedFile Fd, Off auto FileOffset, FixedBuffer ToBuffer, Off auto BufferOffset, size_t Size) {
        io_uring_prep_read_fixed(Sqe, static_cast<int>(Fd), BufferPointer(ToBuffer, BufferOffset), Size, static_cast<off_t>(FileOffset), static_cast<int>(ToBuffer));
        Sqe->flags |= IOSQE_FIXED_FILE;
    }

    void WriteFixed(io_uring_sqe *Sqe, FixedFile Fd, Off auto FileOffset, FixedBuffer FromBuffer, Off auto BufferOffset, size_t Size) {
        io_uring_prep_write_fixed(Sqe, static_cast<int>(Fd), BufferPointer(FromBuffer, BufferOffset), Size, static_cast<off_t>(FileOffset), static_cast<int>(FromBuffer));
        Sqe->flags |= IOSQE_FIXED_FILE;
    }

    void SpliceFixed(io_uring_sqe *Sqe, FixedFile From, Off auto FromOffset, FixedFile To, Off auto ToOffset, size_t Size) {
        io_uring_prep_splice(Sqe, static_cast<int>(From), static_cast<off_t>(FromOffset), static_cast<int>(To), static_cast<off_t>(ToOffset), Size, SPLICE_F_FD_IN_FIXED);
        Sqe->flags |= IOSQE_FIXED_FILE;
    }

    void CreateSocket(io_uring_sqe *Sqe, FixedFile Into) {
        io_uring_prep_socket_direct(Sqe, AF_INET, SOCK_DGRAM, IPPROTO_UDP, static_cast<unsigned>(Into), 0);
    }
}

//! Code generation for a VM
class CodeGen {
protected:
    enum FixedLabel : uint64_t {
        TailLabel = 0,
        HeadLabel = 2,
        LastFixedLabel = HeadLabel,
    };

    constexpr static uint64_t AllowCqe = 1;

public:
    CodeGen(std::ostream &Code, std::ostream &Constants) : Code(Code), Constants(Constants) {}

    void Emit(auto Fn, std::optional<FixedLabel> Lbl = std::nullopt) {
        auto BaseSqe = Sqe(Lbl);
        Fn(&BaseSqe);
        Code.write(reinterpret_cast<const char *>(&BaseSqe), sizeof(BaseSqe));
    }

#define EMIT_LBL(lbl, ...) Emit([&](io_uring_sqe *sqe) { __VA_ARGS__; }, lbl)
#define EMIT(...) Emit([&](io_uring_sqe *sqe) { __VA_ARGS__; })

    // Unfortunately, we cannot directly move data between file descriptors here, so we need the scratch buffer, or a scratch pipe.
    void RegToPipe(Register Reg, size_t Size = RegisterSize, off_t RegOffset = 0) {
        EMIT(Util::SpliceFixed(sqe, FixedFile::Memfd, static_cast<off_t>(Reg) + RegOffset, FixedFile::PipeWrite, -1, Size));
    }
    void RegFromPipe(Register Reg, size_t Size = RegisterSize, off_t RegOffset = 0) {
        EMIT(Util::SpliceFixed(sqe, FixedFile::PipeRead, -1, FixedFile::Memfd, static_cast<off_t>(Reg) + RegOffset, Size));
    }
    void RegToScratch(Register Reg, size_t Size = RegisterSize, off_t ScratchOffset = 0, off_t RegOffset = 0) {
        EMIT(Util::ReadFixed(sqe, FixedFile::Memfd, static_cast<off_t>(Reg) + RegOffset, FixedBuffer::Scratch, ScratchOffset, Size));
    }
    void RegFromScratch(Register Reg, size_t Size = RegisterSize) {
        EMIT(Util::WriteFixed(sqe, FixedFile::Memfd, Reg, FixedBuffer::Scratch, 0, Size));
    }
    void RegToPipeViaScratch(Register Reg, size_t Size = RegisterSize, off_t RegOffset = 0) {
        RegToScratch(Reg, Size, 0, RegOffset);
        EMIT(Util::WriteFixed(sqe, FixedFile::PipeWrite, -1, FixedBuffer::Scratch, 0, Size));
    }

    // Sadly, splicing into eventfd does not work (no f_op->splice_write, and default_splice_file_write
    // died with Linux 5.10). Similarly, reading _also_ broke around that time.
    // So, we use scratch memory instead for this operation only
    void RegToEventfd(Register Reg) {
        RegToScratch(Reg);
        EMIT(Util::WriteFixed(sqe, FixedFile::Eventfd, 0, FixedBuffer::Scratch, 0, 8));
    }
    void RegFromEventfd(Register Reg) {
        EMIT(Util::ReadFixed(sqe, FixedFile::Eventfd, 0, FixedBuffer::Scratch, 0, 8));
        RegFromScratch(Reg);
        RegToScratch(Register::RZ, 8 - RegisterSize, RegisterSize);
        static_assert(8 - RegisterSize <= RegisterSize, "Cannot clear scratch buffer properly");
    }
    void FixEventfd() {
        // NB: Reading from the eventfd will break if both inputs are zero.
        // So, always add (1 << 32), which we will truncate off later.
        auto Adjust = EmitConst(static_cast<uint64_t>(1ul << 32));
        EMIT(Util::WriteFixed(sqe, FixedFile::Eventfd, 0, FixedBuffer::Constants, Adjust, 8));
    }

    // Set a register to a constant
    void Set(Register Reg, uint32_t Value) {
        static_assert(RegisterSize == sizeof(Value));
        auto Val = EmitConst(Value);
        EMIT(Util::WriteFixed(sqe, FixedFile::Memfd, Reg, FixedBuffer::Constants, Val, RegisterSize));
    }

    // Reads a character from stdin
    void Getc(Register Reg) {
        EMIT(Util::SpliceFixed(sqe, FixedFile::Stdin, -1, FixedFile::Memfd, Reg, 1));
    }

    // Writes (a) character(s) to stdout
    void Putc(Register Reg, size_t Count = 1, bool UseSplice = false) {
        if (UseSplice) {
            // NB: Splicing from shmem is a risky thing, it will keep a reference to the page only.
            // This means that if the register we putc'd here changes "too quickly" (= before the character
            // is read from the pipe), it actually changes the character that is output.
            EMIT(Util::SpliceFixed(sqe, FixedFile::Memfd, Reg, FixedFile::Stdout, -1, Count));
        } else {
            // Replacing splice with a read/write pair works nicely to ensure sanity.
            RegToScratch(Reg);
            EMIT(Util::WriteFixed(sqe, FixedFile::Stdout, -1, FixedBuffer::Scratch, 0, Count));
        }
    }

    // Moves data between registers
    void Mov(Register Dst, Register Src, size_t Size = RegisterSize, off_t RegOffset = 0) {
        RegToPipe(Src, Size, RegOffset);
        RegFromPipe(Dst, Size, RegOffset);
    }

    // Adds two register values
    void Add(Register Dst, Register Src1, Register Src2) {
        RegToEventfd(Src1);
        RegToEventfd(Src2);
        FixEventfd();
        RegFromEventfd(Dst);
    }

    // Adds a constant to a register
    void Add(Register Dst, Register Src, uint32_t Value) {
        if (Value) {
            // No FixEventfd here since the sum cannot be zero.
            RegToEventfd(Src);
            EMIT(Util::WriteFixed(sqe, FixedFile::Eventfd, 0, FixedBuffer::Constants, EmitConst(static_cast<uint64_t>(Value)), 8));
            RegFromEventfd(Dst);
        } else if (Dst != Src) {
            Mov(Dst, Src);
        }
    }

    // Subtracts a constant from a register
    void Sub(Register Dst, Register Src, uint32_t Value) {
        if (Value) {
            // No FixEventfd here since the sum cannot be zero.
            RegToEventfd(Src);
            uint64_t Inverse = (1ul << 32) - Value;
            EMIT(Util::WriteFixed(sqe, FixedFile::Eventfd, 0, FixedBuffer::Constants, EmitConst(Inverse), 8));
            RegFromEventfd(Dst);
        } else if (Dst != Src) {
            Mov(Dst, Src);
        }
    }

    // Masks bytes
    void Mask(Register Dst, Register Src, uint32_t Mask, uint32_t Background, bool PackOut = false, bool PackIn = false) {
        struct AcceptPair { size_t Offset, Count; };
        std::vector<AcceptPair> Pairs;

        if (Mask == ~0u)
            return Mov(Dst, Src);
        if (Mask == 0)
            return Set(Dst, Background);

        for (size_t I = 0; I < RegisterSize; ++I) {
            switch (Mask & 0xff) {
                case 0xff:
                    if (!Pairs.empty() && Pairs.back().Offset + Pairs.back().Count == I)
                        Pairs.back().Count += 1;
                    else
                        Pairs.push_back({ I, 1 });
                    break;
                case 0x00:
                    break;
                default:
                    throw std::runtime_error { "bad byte mask for Mask (bytes must be 0x00 or 0xff)" };
            }
            Mask >>= 8;
        }

        auto SaneSrcToPipe = [&](size_t Count, off_t Offset) {
            if (Src == Dst) // Can't change Dst while Src is still in the pipe in this case.
                RegToPipeViaScratch(Src, Count, Offset);
            else
                RegToPipe(Src, Count, Offset);
        };

        if (PackIn) {
            size_t Offset = 0;
            for (const auto &[_, Count] : Pairs) {
                SaneSrcToPipe(Count, Offset);
                Offset += Count;
            }
        } else {
            for (const auto &[Offset, Count] : Pairs)
                SaneSrcToPipe(Count, Offset);
        }

        Set(Dst, Background);

        if (PackOut) {
            size_t Offset = 0;
            for (const auto &[_, Count] : Pairs) {
                RegFromPipe(Dst, Count, Offset);
                Offset += Count;
            }
        } else {
            for (const auto &[Offset, Count] : Pairs)
                RegFromPipe(Dst, Count, Offset);
        }
    }

    // Select bit into a full register.
    void Select(Register Dst, Register Src, unsigned Bit) {
        if (Bit >= 32)
            throw std::runtime_error { "bad bit index" };

        // Select the correct byte into the low byte of RT first.
        uint32_t ByteMask = (Bit < 8) ? 0x000000ffu : (Bit < 16) ? 0x0000ff00u : (Bit < 24) ? 0x00ff0000u : 0xff000000u;
        Mask(Register::RT, Src, ByteMask, 0, /* Pack */ true);

        // Now, shift left enough so that our target bit is the top bit, then truncate off anything above that.
        unsigned Shift = 7 - (Bit % 8);
        Shl(Register::RT, Register::RT, Shift);
        if (Shift)
            Mask(Register::RT, Register::RT, 0xff, 0);

        // Shift left one further bit, then only keep the low bit
        Add(Register::RT, Register::RT, Register::RT);
        Mask(Dst, Register::RT, 0xff00, 0, /* Pack */ true);
    }

    // Shift a value left
    void Shl(Register Dst, Register Src, unsigned Shift) {
        Mov(Dst, Src);
        for (unsigned I = 0; I < Shift; ++I)
            Add(Dst, Dst, Dst);
    }

    // Compresses a register value to the sum of its bytes (<= 0x3fc)
    void CompressOnce(Register Dst, Register Src, size_t UpTo = RegisterSize) {
        for (size_t Index = 0; Index < UpTo; ++Index) {
            RegToScratch(Src, 1, 0, Index);
            EMIT(Util::WriteFixed(sqe, FixedFile::Eventfd, 0, FixedBuffer::Scratch, 0, 8));
        }
        FixEventfd();
        RegFromEventfd(Dst);
    }

    // Compresses a register value to the (recursive) sum of its bytes, until it is guaranteed to be a single byte.
    // Clobbers RT (but RT is OK to use as Dst or Src)
    void Compress(Register Dst, Register Src) {
        CompressOnce(Register::RT, Src);             // <= 0x3fc (from 0xffffffff)
        CompressOnce(Register::RT, Register::RT, 2); // <= 0x101 (from 0x2ff)
        CompressOnce(Dst, Register::RT, 2);          // <= 0xff  (from 0xff)
    }

    // Exits with the specified exit code
    void Exit(Register Code) {
        RegToEventfd(Code);
        FixEventfd();
        Exit();
    }

    // Stops processing (by emitting a CQE).
    void Exit() {
        // NB: This may continue execution behind it, so emit an actual blocking operation (a read on the empty pipe)
        // NB: We need to ensure the first operation in this chain is cancelable (with the correct current label)
        EMIT(io_uring_prep_close_direct(sqe, static_cast<unsigned>(FixedFile::Socket)), sqe->flags &= ~IOSQE_CQE_SKIP_SUCCESS);
        EMIT(Util::ReadFixed(sqe, FixedFile::PipeRead, -1, FixedBuffer::Scratch, 0, RegisterSize), sqe->flags &= ~IOSQE_CQE_SKIP_SUCCESS);
    }

    constexpr static __kernel_timespec Infinity { .tv_sec = std::numeric_limits<int64_t>::max(), .tv_nsec = 0 };
    constexpr static __kernel_timespec ElseTimeout { .tv_sec = 0, .tv_nsec = 50ul * 1000ul * 1000ul }; // 250ms
    constexpr static __kernel_timespec TinyTimeout { .tv_sec = 0, .tv_nsec = 10ul * 1000ul * 1000ul }; // 10ms
    constexpr static __kernel_timespec BeginTimeout { .tv_sec = 0, .tv_nsec = 250ul * 1000ul * 1000ul }; // 250ms

    // Emits a timeout
    void Timeout(__kernel_timespec Timeout) {
        auto TimeoutConst = EmitConst(Timeout);
        EMIT(io_uring_prep_timeout(sqe, reinterpret_cast<struct __kernel_timespec *>(Util::BufferPointer(FixedBuffer::Constants, TimeoutConst)), 0, IORING_TIMEOUT_ETIME_SUCCESS),
             sqe->flags &= ~IOSQE_ASYNC);
    }

    // Updates a timeout
    void UpdateTimeout(auto InLabel, __kernel_timespec NewTimeout, bool Unlink = false) {
        auto TimeoutConst = EmitConst(NewTimeout);
        EMIT(io_uring_prep_timeout_update(sqe, reinterpret_cast<struct __kernel_timespec *>(Util::BufferPointer(FixedBuffer::Constants, TimeoutConst)), InLabel, 0),
             sqe->flags &= Unlink ? ~IOSQE_IO_LINK : ~0u);
    }

    // Run the Then block if Src == Value, otherwise run the Else block
    void IfEq(Register Src, uint32_t Value, auto Then, auto Else) {
        auto Previous = CurrentLabel;
        auto JumpTarget = "__impl_else_"s + std::to_string(Code.tellp());
        auto PostTarget = "__impl_post_"s + std::to_string(Code.tellp());

        auto ElseLabel = ReserveLabel(JumpTarget);
        auto PostLabel = ReserveLabel(PostTarget);

        // Checks whether a value is equal to a constant.
        // This abuses an operation that can fail depending on memory state _at issue time_ (rather than at prep time).
        // Note that most operations (especially on file paths) don't have this behavior.
        // Candidates are
        //   CONNECT (but prep_async will move the address to the kernel, so this is not _really_ an option)
        //   FUTEX (since 6.7)
        //   FUTEXV (since 6.7)
        //   IO_URING_CMD(setsockopt) (since 6.7, 6.6 has SIOCINQ/SIOCOUTQ only)
        // Unfortunately, futex operations don't really use the actual value, so that leaves us with exactly setsockopt.
        // We can do this ourselves, at least.
        // The "cleanest" socket option to fail on is SO_DEBUG (it errors if the value is nonzero and we are not CAP_NET_ADMIN).
        // So, assert that we are not CAP_NET_ADMIN (innocently) in the runner.
        auto Jne = [this](Register Src, uint32_t Value, uint64_t ElseLabel) mutable {
            // If we need a new socket, we can create one here. But we already have one around.
            //   EMIT(io_uring_prep_close_direct(sqe, static_cast<unsigned>(FixedFile::Socket)));
            //   EMIT(Util::CreateSocket(sqe, FixedFile::Socket));
            // RT = (Src == Value) ? 0 : <non-zero>
            Sub(Register::RT, Src, Value);
            // Update the timeout so that the Else branch will start running if we don't cancel it
            UpdateTimeout(ElseLabel, ElseTimeout);
            // This "forgets" to actually use fixed buffers; this is by design.
            RegToScratch(Register::RT);
            EMIT_LBL(static_cast<FixedLabel>(CurrentLabel | AllowCqe),
                     io_uring_prep_cmd_sock(sqe, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(FixedFile::Socket), SOL_SOCKET, SO_DEBUG, Util::BufferPointer(FixedBuffer::Scratch, 0), sizeof(int)),
                     sqe->flags |= IOSQE_FIXED_FILE);
            // Cancel all instructions of the false label (since we hit the true label).
            EMIT(io_uring_prep_cancel64(sqe, ElseLabel, IORING_ASYNC_CANCEL_ALL));
            // NB: There is no clean way to not trigger a full cascade on failure (io_disarm_next / io_fail_links). So:
            //  - If the condition is true, we executed the IORING_OP_ASYNC_CANCEL. This means that
            //    we can just continue with the true case immediately and should be fine
            //  - If the condition is false, the full chain up to the next non-linked task is gone.
            //    We need to make sure that the next chain does not start early.
        };

        // If Src == Value,
        //   (1) explicitly cancel JumpTarget,
        //   (2) then proceed with the Then instructions.
        // Otherwise,
        //   (1) the Then instructions are implicitly canceled (IOSQE_IO_LINK), and
        //   (2) the Else instructions will be executed - but we need to ensure that they do not
        //       start executing before the cancellation has had a chance to go through.
        // Finally, at the end of either branch, we signal to the post-if code.

        // The most difficult part is delaying execution for the Else part.
        // We can cheat by listening for the CQE of the Jne's jump and feeding a write into the delay pipe,
        // but that requires either a second io_uring or main process involvement (which I would like to avoid).
        // Unfortunately, we can't put an IOSQE_IO_DRAIN in here, since that requires us to get rid of
        // IOSQE_CQE_SKIP_SUCCESS in the entire ring, not just in the link as some sources claim.
        // So how can we ensure that the Else chain (below) does not start early (either before it is
        // canceled by the Jne, or before the Jne finishes)?
        // The only working way I can think of that is at least somewhat sound involves setting an infinite
        // timeout on the initial instruction, then reducing that timeout as the Jne fires so that there
        // is enough time to cancel the Else branch, but no infinite stall. This isn't supposed to be high-
        // performance after all.

        Jne(Src, Value, ElseLabel);

        {
            Then();
            UpdateTimeout(PostLabel, TinyTimeout, /* Unlink */ true);
        }

        {
            Label(JumpTarget);
            // This needs to be pulled from the constant _buffer_ at submission time.
            // We also need to ensure that it gets issued immediately, so the update can actually find it.
            Timeout(Infinity);
            Else();
            UpdateTimeout(PostLabel, TinyTimeout, /* Unlink */ true);
        }

        // After the Else branch, we return to the original labelling.
        // Again, we can't link this to the Else branch with IOSQE_IO_LINK (since then the Jne
        // will cancel too much), and need to delay its start explicitly. Since we will always run code
        // before this point (either the Then branch or the Else branch), this is easy enough to handle.
        Label(PostTarget);
        Timeout(Infinity);
        CurrentLabel = Previous;
    }

    // Emits a chain of if-else blocks (this makes things nicer for coding only).
    template <typename F, typename... Rs> void Switch(Register Src, uint32_t Value, F &&Then, Rs &&...Rest) {
        static_assert(sizeof...(Rest) % 2 == 1, "Bad arguments to Switch (must be sequence of Value and Then, then an Else branch)");
        if constexpr (sizeof...(Rest) != 1) {
            IfEq(Src, Value, std::forward<F>(Then), [&] {
                Switch(Src, std::forward<Rs>(Rest)...);
            });
        } else {
            IfEq(Src, Value, std::forward<F>(Then), std::forward<Rs>(Rest)...);
        }
    }

    // Emits initialization code
    void Begin() {
        auto Guard = WithLabel(HeadLabel);
        // Create the socket for conditionals
        EMIT(Util::CreateSocket(sqe, FixedFile::Socket));
        // Wait a little bit for the timeouts to be enqueued first
        // We don't want to hit a timeout update before the timeout is actually ready.
        Timeout(BeginTimeout);
    }

    // Emits finalization code
    void End() {
        // Enqueue an operation that will emit a CQE to give us time to resubmit the entire set of SQEs
        auto Guard = WithLabel(TailLabel);
        EMIT(io_uring_prep_close_direct(sqe, static_cast<unsigned>(FixedFile::Socket)), sqe->flags &= ~IOSQE_CQE_SKIP_SUCCESS);

        // Make sure the constants file exists and is nonempty
        if (ConstantOffset == 0)
            Constants.write("\0", 1);
    }

    // Emits debug code
    void Debug(Register Reg, Register Tmp1, Register Tmp2, Register Tmp3) {
        std::cerr << "\x1b[33;1mWARNING: Found a call to CodeGen::Debug()\x1b[0m" << std::endl;
        uint32_t RegLabel = 0x203a0052;
        if (Reg < Register::RA)
            RegLabel |= (static_cast<uint32_t>('0') + static_cast<uint32_t>(Reg) / 4) << 8;
        else
            RegLabel |= (static_cast<uint32_t>('A') + static_cast<uint32_t>(Reg) / 4 - static_cast<uint32_t>(Register::RA) / 4) << 8;
        Set(Register::RT, RegLabel);
        Putc(Register::RT, 4);

        auto PrintHex = [&](Register V) {
            Sub(Tmp3, V, 0xa);
            Select(Tmp3, Tmp3, 31);
            IfEq(Tmp3, 0, [&] {
                Add(Tmp3, V, 'a' - 0xa);
            }, [&] {
                Add(Tmp3, V, '0');
            });
            Putc(Tmp3);
        };

        for (int Byte = 3; Byte >= 0; --Byte) {
            // Grab the byte
            Mask(Register::RT, Reg, 0xff << (8 * Byte), 0, true);
            // Grab the nibbles
            Shl(Tmp1, Register::RT, 4);
            Mask(Tmp2 /* top */, Tmp1, 0xff00, 0, true);
            Mask(Tmp1, Tmp1, 0xff, 0);
            Shl(Tmp1, Tmp1, 4);
            Mask(Tmp1 /* bottom */, Tmp1, 0xff00, 0, true);
            // Turn each into hex
            PrintHex(Tmp2);
            PrintHex(Tmp1);
        }

        Set(Register::RT, '\n');
        Putc(Register::RT);
    }

protected:
    uint64_t ReserveLabel(const std::string &Name) {
        uint64_t Value;
        if (auto It = ReservedLabels.find(Name); It != ReservedLabels.end()) {
            Value = It->second;
        } else {
            Value = NextLabel;
            NextLabel += 2;
            auto [_, Success] = ReservedLabels.insert({ Name, Value });
            if (!Success)
                throw std::logic_error { "reservation should not fail" };
        }
        return Value;
    }

    void Label(const std::string &Name) {
        uint64_t Value;
        if (auto It = ReservedLabels.find(Name); It != ReservedLabels.end()) {
            Value = It->second;
        } else {
            Value = NextLabel;
            NextLabel += 2;
        }
        auto [_, Success] = Labels.insert({ Name, Value });
        if (!Success)
            throw std::runtime_error { "label '"s + Name + "' already exists" };
        CurrentLabel = Value;
    }

    friend struct LabelGuard;
    struct LabelGuard {
        CodeGen &CG;
        uint64_t Saved;

        LabelGuard(CodeGen &CG, uint64_t NewLabel) : CG(CG) {
            Saved = CG.CurrentLabel;
            CG.CurrentLabel = NewLabel;
        }

        ~LabelGuard() {
            CG.CurrentLabel = Saved;
        }
    };

    LabelGuard WithLabel(uint64_t Label) {
        return LabelGuard { *this, Label };
    }

    // Emits a constant integer into the constant pool
    Constant EmitConst(std::integral auto Value) {
        switch (sizeof(Value)) {
            case 1: return EmitCachedConst(CachedU8, static_cast<uint8_t>(Value));
            case 2: return EmitCachedConst(CachedU16, static_cast<uint16_t>(Value));
            case 4: return EmitCachedConst(CachedU32, static_cast<uint32_t>(Value));
            case 8: return EmitCachedConst(CachedU64, static_cast<uint64_t>(Value));
            default: return EmitConst(std::span { &Value, 1 });
        }
    }
    Constant EmitConst(struct __kernel_timespec Value) { return EmitCachedConst(CachedTimespec, Value); }
    template <typename T> Constant EmitCachedConst(std::map<T, Constant> &Cache, T Value) {
        if (auto It = Cache.find(Value); It != Cache.end())
            return It->second;
        return Cache[Value] = EmitConst(std::span { &Value, 1 });
    }
    // Emits a constant string into the constant pool
    Constant EmitConst(const std::string &Value) {
        if (auto It = CachedStr.find(Value); It != CachedStr.end())
            return It->second;
        return CachedStr[Value] = EmitConst(std::span { Value.c_str(), Value.size() + 1 });
    }
    // Emits constant bytes into the constant pool
    template <typename T> Constant EmitConst(std::span<T> Bytes) {
        auto Offset = ConstantOffset;
        Constants.write(reinterpret_cast<const char *>(Bytes.data()), Bytes.size_bytes());
        ConstantOffset += Bytes.size_bytes();
        return Constant { Offset, Bytes.size_bytes() };
    }

    std::ostream &Code;
    std::ostream &Constants;
    off_t ConstantOffset = 0;

    std::map<uint8_t, Constant> CachedU8 {};
    std::map<uint16_t, Constant> CachedU16 {};
    std::map<uint32_t, Constant> CachedU32 {};
    std::map<uint64_t, Constant> CachedU64 {};
    std::map<std::string, Constant> CachedStr {};
    std::map<struct __kernel_timespec, Constant> CachedTimespec {};

    uint64_t CurrentLabel = LastFixedLabel + 2;
    uint64_t NextLabel = LastFixedLabel + 4;
    std::map<std::string, uint64_t> Labels {};
    std::map<std::string, uint64_t> ReservedLabels {};

    io_uring_sqe Sqe(std::optional<FixedLabel> Lbl = std::nullopt) {
        io_uring_sqe Sqe;
        io_uring_initialize_sqe(&Sqe);
        Sqe.user_data = Lbl.value_or(static_cast<FixedLabel>(CurrentLabel));
        Sqe.flags |= IOSQE_CQE_SKIP_SUCCESS | IOSQE_IO_LINK | IOSQE_ASYNC;
        return Sqe;
    }
};

//! Build the VM
int main(int argc, char *argv[])
{
    if (argc != 3)
        throw std::runtime_error { "usage: assembler <vm.iou> <constants.iou>" };

    std::ofstream Code { argv[1], std::ios::binary };
    std::ofstream Constants { argv[2], std::ios::binary };
    CodeGen CG { Code, Constants };

    // At the top level, this basically needs CFF to dispatch (we can do this based on a loop counter, or with actual constants)
    const auto LocalState = Register::R8;
    const auto MangledFlagChar = Register::R9;
    const auto AccDword = Register::RA;
    const auto CffReg = Register::RB;
    const auto BytesRead = Register::RC;
    const auto CombinedState = Register::RD;
    const auto FlagChar = Register::RE;

    enum StateMachine : uint32_t {
        ReadInput = 0,
        MangleByte = 1,
        HashIntoState = 2,
        CheckFlag = 3,
        FailEarly = 4,
    };

    const std::string FLAG = "DHM{touring_with_a_uring_5bf6265c6d7}";

    auto GenerateFlagFormatCheck = [&] {
        auto FormatCount = FLAG.find('{');
        if (FormatCount++ == std::string::npos)
            throw std::runtime_error { "No { in flag prefix" };
        if (FormatCount < 4)
            throw std::runtime_error { "Flag prefix is too short" };

        std::vector<std::pair<uint32_t, uint32_t>> FormatChecks;
        for (size_t Start = 0; Start < FormatCount; Start += 4) {
            size_t Count = FormatCount - Start;
            if (Count < 4)
                Start = FormatCount - 4;
            uint32_t Accumulated = bswap_32(* reinterpret_cast<const uint32_t *>(&FLAG[Start]));
            FormatChecks.push_back({ Start + 4, Accumulated });
        }

        auto Impl = [&](auto Begin, auto End, auto IImpl) {
            if (Begin == End)
                return;
            CG.IfEq(BytesRead, Begin->first, [&] {
                // AccDword must be correct here.
                CG.IfEq(AccDword, Begin->second, [&] {}, [&] {
                    // Short-circuit: Bad flag prefix.
                    CG.Set(CffReg, FailEarly);
                });
            }, [&] {
                IImpl(Begin + 1, End, IImpl);
            });
        };
        Impl(FormatChecks.begin(), FormatChecks.end(), Impl);
    };

    auto GenerateMangledFlagSwitch = [&](Register Dst, Register Mangled) {
        std::string_view NoSuffix = FLAG;
        if (!NoSuffix.ends_with('}'))
            throw std::runtime_error { "Flag does not end with '}'" };
        NoSuffix.remove_suffix(1);

        std::map<uint32_t, std::pair<std::string, uint32_t>> Values;
        for (size_t Chunk = 0; Chunk < FLAG.size() / 4; ++Chunk) {
            std::string_view Trailing = NoSuffix.substr(4 * Chunk);
            if (Trailing.length() < 4)
                throw std::runtime_error { "Bad flag length (excluding the trailing '}', the length must be divisible by 4), we were left with '"s + std::string { Trailing } + "'" };

            std::string Slice { Trailing.substr(0, 4) };
            uint32_t Value = 0;
            for (size_t I = 0; I < 4; ++I) {
                Value <<= 8;
                uint32_t FlagChar = Slice[I];
                if (FlagChar & 0x80)
                    throw std::runtime_error { "Bad character in reference flag" };

                FlagChar += 4 * Chunk + I + 1;
                FlagChar ^= 0x2a;

                uint32_t BitReversed = 0;
                for (size_t Bit = 0; Bit < 7; ++Bit)
                    BitReversed |= ((FlagChar >> Bit) & 1) << (6 - Bit);
                Value |= (BitReversed & 0xff);
            }
            if (auto It = Values.find(Value); It != Values.end())
                throw std::runtime_error { "Identical value generated from '"s + It->second.first + "' and '" + Slice + "'" };

            Values[Value] = { Slice, static_cast<uint32_t>(-Chunk - 1) };
        }

        std::vector<std::pair<uint32_t, uint32_t>> Ordered;
        for (const auto &[Value, Pair] : Values)
            Ordered.push_back({Value, Pair.second});
        std::sort(Ordered.begin(), Ordered.end());

        uint32_t Garbage = 1;
        auto Impl = [&](auto Begin, auto End, auto IImpl) -> void {
            auto Count = std::distance(Begin, End);
            auto Midpoint = Begin + (Count / 2);
            if (Midpoint == End) {
                CG.Set(Dst, Garbage++);
            } else {
                CG.Sub(Register::R6, Mangled, Midpoint->first);
                CG.IfEq(Register::R6, 0, [&] {
                    CG.Set(Dst, Midpoint->second);
                }, [&] {
                    CG.Select(Register::R6, Register::R6, 31);
                    CG.IfEq(Register::R6, 0, [&] {
                        // Mangled - Value > 0, check second half
                        IImpl(Midpoint + 1, End, IImpl);
                    }, [&] {
                        // Mangled - Value < 0, check first half
                        IImpl(Begin, Midpoint, IImpl);
                    });
                });
            }
        };

        Impl(Ordered.begin(), Ordered.end(), Impl);
    };

    CG.Begin();
    CG.Switch(CffReg,
        ReadInput, [&] {
            CG.IfEq(BytesRead, 0, [&] {
                CG.Set(Register::R1, 0x65746e45 /* 'Ente' */);
                CG.Putc(Register::R1, 4);
                CG.Set(Register::R1, 0x6c662072 /* 'r fl' */);
                CG.Putc(Register::R1, 4);
                CG.Set(Register::R1, 0x203a6761 /* 'ag: ' */);
                CG.Putc(Register::R1, 4);
            }, [&] {});
            CG.Add(BytesRead, BytesRead, 1);
            CG.Getc(FlagChar);
            CG.Mask(AccDword, AccDword, 0xffffff00, 0, false, true); // Faster shift-left by 8
            CG.Mask(LocalState, LocalState, 0xffffff00, 0, false, true);
            CG.Mov(AccDword, FlagChar, 1);
            CG.Set(Register::R1, '.');
            CG.Putc(Register::R1);

            static_assert(MangleByte - ReadInput == 1);
            CG.Add(CffReg, CffReg, 1);

            // Check if we're done
            CG.IfEq(BytesRead, FLAG.size(), [&] {
                CG.Set(CffReg, CheckFlag);
            }, [&] {
                CG.Set(CffReg, MangleByte);
            });

            // Check flag format immediately
            GenerateFlagFormatCheck();

            // Check for early newlines
            CG.IfEq(FlagChar, '\n', [&] {
                CG.IfEq(BytesRead, FLAG.size(), [&] {}, [&] {
                    // Short-circuit: Got EOL but not enough bytes read yet.
                    CG.Set(CffReg, FailEarly);
                });
            }, [&] {});

            // Check for non-ASCII characters
            CG.Select(Register::R1, FlagChar, 7);
            CG.IfEq(Register::R1, 0, [&] {}, [&] {
                // Short-circuit: Bit 7 is set (not ASCII)
                CG.Set(CffReg, FailEarly);
            });
        },
        MangleByte, [&] {
            // Add the round count
            CG.Add(MangledFlagChar, FlagChar, BytesRead);
            // Split into bits
            CG.Select(Register::R1, MangledFlagChar, 0);
            CG.Select(Register::R2, MangledFlagChar, 1);
            CG.Select(Register::R3, MangledFlagChar, 2);
            CG.Select(Register::R4, MangledFlagChar, 3);
            CG.Select(Register::R5, MangledFlagChar, 4);
            CG.Select(Register::R6, MangledFlagChar, 5);
            CG.Select(Register::R7, MangledFlagChar, 6);
            // XOR with 0x2a
            CG.Add(Register::R2, Register::R2, 1);
            CG.Select(Register::R2, Register::R2, 0);
            CG.Add(Register::R4, Register::R4, 1);
            CG.Select(Register::R4, Register::R4, 0);
            CG.Add(Register::R6, Register::R6, 1);
            CG.Select(Register::R6, Register::R6, 0);
            // Recombine, bit-reversed
            // We have  Rx: 0000000x
            // and want R?: 01234567
            CG.Shl(Register::R1, Register::R1, 1);            // R1: 00000010
            CG.Add(Register::R1, Register::R1, Register::R2); // R1: 00000012
            CG.Shl(Register::R1, Register::R1, 1);            // R1: 00000120
            CG.Add(Register::R1, Register::R1, Register::R3); // R1: 00000123
            CG.Shl(Register::R1, Register::R1, 1);            // R1: 00001230
            CG.Add(Register::R1, Register::R1, Register::R4); // R1: 00001234
            CG.Shl(Register::R1, Register::R1, 1);            // R1: 00012340
            CG.Add(Register::R1, Register::R1, Register::R5); // R1: 00012345
            CG.Shl(Register::R1, Register::R1, 1);            // R1: 00123450
            CG.Add(Register::R1, Register::R1, Register::R6); // R1: 00123456
            CG.Shl(Register::R1, Register::R1, 1);            // R1: 01234560
            CG.Add(MangledFlagChar, Register::R1, Register::R7); //  01234567
            CG.Set(CffReg, HashIntoState);
        },
        HashIntoState, [&] {
            CG.Add(LocalState, LocalState, MangledFlagChar);
            CG.Shl(Register::R1, BytesRead, 6);
            CG.Mask(Register::R2, Register::R1, 0xff00, 0, true);
            CG.Mask(Register::R1, Register::R1, 0xff, 0);
            CG.IfEq(Register::R1, 0, [&] {
                // Read 4 bytes, and this is the R2'th chunk
                // This should statically return -ExpectedR2 for each value
                GenerateMangledFlagSwitch(Register::R1, LocalState);
                CG.Add(Register::R3, Register::R2, Register::R1);
                CG.Add(CombinedState, CombinedState, Register::R3);
                CG.Compress(CombinedState, CombinedState);
                CG.Mask(CombinedState, CombinedState, 0xff000000, 0, false, true);
            }, [&] {});
            CG.Set(CffReg, ReadInput);
        },
        CheckFlag, [&] {
            CG.Set(Register::R6, 0x335b1b0a /* '\n\x1b[3' */);
            CG.Set(Register::R7, 0x6d313b31 /* '1;1m' */);
            CG.Set(Register::R8, 0x5b1b283a /* ':(\x1b[' */);
            CG.Set(Register::R9, 0x0a6d30   /* '0m\n' */);
            // Clobber if last char is not }.
            CG.Sub(FlagChar, FlagChar, FLAG[FLAG.size() - 1]);
            CG.Add(CombinedState, CombinedState, FlagChar);
            CG.IfEq(CombinedState, 0, [&] {
                CG.Add(Register::R7, Register::R7, 0x01 /* Turn red (31) into green (32) */);
                CG.Add(Register::R8, Register::R8, 0x01 << 8 /* Turn ':(' into ':)' */);
            }, [&] {
                CG.Set(CombinedState, 0);
            });
            CG.Putc(Register::R6, 4);
            CG.Putc(Register::R7, 4);
            CG.Putc(Register::R8, 4);
            CG.Putc(Register::R9, 3);
            CG.Exit(CombinedState);
        },
        FailEarly, [&] {
            CG.Set(CombinedState, 0x80000000); // this + (char - '}') is never 0
            CG.Set(BytesRead, FLAG.size());
            CG.Set(CffReg, CheckFlag);
        },
        /* else */ [&] {
            CG.Exit(CffReg);
        }
    );
    CG.End();
}
