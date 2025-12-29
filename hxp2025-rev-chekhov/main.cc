#define MAIN

#include "aes.h"
#include "checks.h"
#include "hash.h"
#include "utils.h"
#include "strings.h"
#if defined(_HXP_DEBUG)
#include "testing.h"
#endif

#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <linux/prctl.h>
#include <linux/taskstats.h>
#include <linux/userfaultfd.h>
#include <sched.h>
#include <sys/auxv.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/rseq.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <source_location>
#include <type_traits>

using namespace strings::literals;

// Marking antidebug failures
namespace antidebug {
    namespace action {
        enum class operation {
            step_prng,
            page_in_pages,
            count,
        };

        enum class trigger {
            failure,
            success,
            count,
        };

        [[gnu::always_inline]] inline void step_prng();
        [[gnu::always_inline]] inline void page_in_pages();
    }

    struct handler {
        action::operation op;
        action::trigger trigger;

        constexpr static auto op_count = static_cast<uint64_t>(action::operation::count);
        constexpr static auto pairs = op_count * static_cast<uint64_t>(action::trigger::count);

        [[gnu::always_inline]]
        consteval static handler derive(std::source_location location)
        {
            auto hashed = hash::hash_location(location) % pairs;
            auto op = static_cast<action::operation>(hashed % op_count);
            auto trigger = static_cast<action::trigger>(hashed / op_count);
            return { op, trigger };
        }
    };

    [[gnu::always_inline, gnu::flatten]] void log_failure([[maybe_unused]] strings::debug_only reason)
    {
#if defined(_HXP_DEBUG)
        testing::log("\x1b[31mtainting execution\x1b[0m: ");
        testing::logln(reason);
#endif
    }

    [[gnu::always_inline]] void assert(bool success, strings::debug_only reason,
                                       handler here = handler::derive(std::source_location::current()))
    {
        if (!success)
            log_failure(reason);

        if (success != (here.trigger == action::trigger::success)) {
            switch (here.op) {
                case action::operation::step_prng:
                    action::step_prng();
                    break;
                case action::operation::page_in_pages:
                    action::page_in_pages();
                    break;
                case action::operation::count:
                    __builtin_unreachable();
            }
        }
    }
}

// ELF handling
namespace antidebug::elf {
    template <typename LookupType>
    [[gnu::noinline, gnu::no_instrument_function]] static void *find_symbol(const Elf64_Ehdr *elf,
                                                                            LookupType identifier,
                                                                            bool is_relocated)
    {
        // We need to walk the DT_SYMTAB.
        // Also, we can just assume the symbol exists, so we don't need to guess
        // at the length of the symtab (doing that correctly is _painful_)

        const char *base = reinterpret_cast<const char *>(elf);
        const char *reloc_base = is_relocated ? nullptr : base;
        const Elf64_Phdr *phdrs = reinterpret_cast<const Elf64_Phdr *>(base + elf->e_phoff);

        const Elf64_Dyn *dynamic = nullptr;
        for (size_t index = 0; index < elf->e_phnum; ++index) {
            if (phdrs[index].p_type == PT_DYNAMIC) {
                dynamic = reinterpret_cast<const Elf64_Dyn *>(base + phdrs[index].p_vaddr);
                break;
            }
        }
        if (!dynamic)
            return nullptr;

        const Elf64_Sym *symtab = nullptr;
        const char *strtab = nullptr;
        for (; dynamic->d_tag; ++dynamic) {
            switch (dynamic->d_tag) {
                case DT_SYMTAB:
                    symtab = reinterpret_cast<const Elf64_Sym *>(reloc_base + dynamic->d_un.d_ptr);
                    break;
                case DT_STRTAB:
                    strtab = reloc_base + dynamic->d_un.d_ptr;
                    break;
                default: break;
            }
        }

        if (!symtab || !strtab)
            return nullptr;

        for (;; ++symtab) {
            bool matches = false;
            if constexpr (std::is_convertible_v<LookupType, const char *>)
                matches = !__builtin_strcmp(&strtab[symtab->st_name],
                                            static_cast<const char *>(identifier));
            else
                matches = identifier == hash::hash_string(&strtab[symtab->st_name]);
            if (matches)
                return const_cast<void *>(reinterpret_cast<const void *>(base + symtab->st_value));
        }
    }

    // This works on mapped but not loaded ELF files - that's different from find_symbol above!
    [[gnu::noinline]] static void for_each_probe(const Elf64_Ehdr *elf, Elf64_Addr load_addr, void (*handler)(Elf64_Addr))
    {
        // Find the .note.stapsdt section
        const char *base = reinterpret_cast<const char *>(elf);
        const Elf64_Shdr *shdrs = reinterpret_cast<const Elf64_Shdr *>(base + elf->e_shoff);

        if (elf->e_shstrndx == SHN_UNDEF || elf->e_shstrndx == SHN_XINDEX)
            return;
        if (elf->e_shstrndx >= elf->e_shnum)
            return;
        const char *shstrtab = base + shdrs[elf->e_shstrndx].sh_offset;

        Elf64_Addr actual_base_addr = 0;
        for (size_t index = 0; index < elf->e_shnum; ++index) {
            const char *name = &shstrtab[shdrs[index].sh_name];
            if (hash::hash_string(name) != ".stapsdt.base"_hash)
                continue;
            actual_base_addr = shdrs[index].sh_addr;
            break;
        }
        if (!actual_base_addr)
            return;

        for (size_t index = 0; index < elf->e_shnum; ++index) {
            const char *name = &shstrtab[shdrs[index].sh_name];
            if (hash::hash_string(name) != ".note.stapsdt"_hash)
                continue;

            // Found it. Now, walk the probe data.
            for (size_t offset = 0; offset < shdrs[index].sh_size;) {
                const char *note = base + shdrs[index].sh_offset + offset;
                const uint32_t *header = reinterpret_cast<const uint32_t *>(note);

                uint32_t name_len = utils::align_up(header[0], sizeof(uint32_t));
                uint32_t desc_len = utils::align_up(header[1], sizeof(uint32_t));
                uint32_t note_type = header[2];

                auto name_hash = hash::hash_string(&note[12], name_len);

                if (note_type == 3 && name_len == 8 && name_hash == "stapsdt\0"_hash) {
                    // Descriptor starts with three Elf64_Addr entries.
                    // We don't actually care about provider name, probe name, and argument format.
                    const Elf64_Addr *addrs = reinterpret_cast<const Elf64_Addr *>(&note[12 + name_len]);
                    Elf64_Addr probe_pc = addrs[0];
                    Elf64_Addr base_addr = addrs[1];
                    // addrs[2] is the address of the semaphore. We don't need that.
                    // If the base address mismatches the actual base address, prelinking adjusted
                    // things, and we need to do so too.
                    Elf64_Addr probe_offset = probe_pc - base_addr + actual_base_addr;
                    handler(load_addr + probe_offset);
                }

                offset += 12 + name_len + desc_len;
            }
            return;
        }
    }
}

// Internals
namespace {
    struct license_checker_state {
        int uffd;
        int auxv_fd;
        int status_fd;
        int fd_dirfd;

        void *shellcode;
        void *current_shellcode;
        std::atomic_uint64_t prng_state;
        constexpr static size_t shellcode_size = 0x1000 * payload::valid_checks;

        unsigned long start_time;
        unsigned long last_function_entry;
        unsigned long clk_tck;

        struct r_debug *ldso_r_debug;
        decltype(&clock_gettime) vdso_clock_gettime;

        struct rseq_cs rseq_cs alignas(32);
        int32_t rseq_offset;

        pid_t initial_pid;

        std::array<void *, 32> stapsdt_probes; // This ought to be enough for anybody...
        unsigned stapsdt_probe_count;

        std::array<uint8_t, 32> license_key alignas(32);
        unsigned rseq_failures;
        unsigned check_failures;

        alignas(0x1000) char stack[0x1000];
        alignas(0x1000) char thread_stack[0x1000];

        char padding_entry; // Make sure the stacks are not the end of the secretmem
        constexpr static size_t redzone = 0x80;

        [[gnu::always_inline]] void with_stack(void (*target)(void))
        {
            char *sp = &this->stack[sizeof(this->stack) - redzone];
            __asm__ volatile ( "xchg %[sp], %%rsp" : [sp]"+r"(sp) );
            target();
            __asm__ volatile ( "xchg %[sp], %%rsp" : [sp]"+r"(sp) );
        }

        void remember_probe(void *probe)
        {
            stapsdt_probes[stapsdt_probe_count++ % stapsdt_probes.size()] = probe;
        }

        [[gnu::no_instrument_function]] void load_auxv()
        {
            uint64_t buffer[128];
            ssize_t bytes = utils::check(sys::read(auxv_fd, buffer, sizeof(buffer)));
            utils::check(sys::close(auxv_fd));

            for (size_t index = 0; index + 1 < static_cast<size_t>(bytes) / 8; index += 2) {
                size_t tag = buffer[index];
                if (!tag)
                    break;

                size_t value = buffer[index + 1];
                switch (tag) {
                    case AT_BASE:
                        // _r_debug is a fallback solution.
                        // We like having it anyways to detect LD_PRELOAD.
                        ldso_r_debug = reinterpret_cast<decltype(ldso_r_debug)>(
                            antidebug::elf::find_symbol(
                                reinterpret_cast<const Elf64_Ehdr *>(value),
                                "_r_debug"_hash,
                                true /* ld-linux.so is already relocated here */
                            )
                        );
                        // Instead, GDB uses the systemtap probes from .note.stapsdt
                        // That requires different parsing, since those are not
                        // in the loaded memory after all (we only have .stapsdt.base
                        // as a relocation aid).
                        // We'll process those later on.
                        break;
                    case AT_SYSINFO_EHDR:
                        vdso_clock_gettime = reinterpret_cast<decltype(vdso_clock_gettime)>(
                            antidebug::elf::find_symbol(
                                reinterpret_cast<const Elf64_Ehdr *>(value),
                                "__vdso_clock_gettime"_hash,
                                false /* vdso is not. */
                            )
                        );
                        break;
                    case AT_CLKTCK:
                        // Save the clock ticks.
                        clk_tck = value;
                        break;
                    default:
                        break;
                }
            }
        }

        uint8_t touch_shellcode_byte(size_t offset)
        {
            auto target = reinterpret_cast<const volatile uint8_t *>(shellcode);
            target += offset;
            utils::check(sys::mprotect(shellcode, license_checker_state::shellcode_size,
                                       PROT_READ | PROT_WRITE | PROT_EXEC));
            uint8_t byte = *target;
            utils::check(sys::mprotect(shellcode, license_checker_state::shellcode_size, PROT_EXEC));

            // Page-in order should be different, which cycles the PRNG.
            // Also, make sure the value is "used" for the compiler
            __asm__ volatile ( "" : "+&r"(byte) :: "memory" );
            return byte;
        }
    };

    license_checker_state *g_state = nullptr;
}

// Actions that change the internal state.
namespace antidebug::action {
    [[gnu::always_inline]] inline void step_prng(void) {
        g_state->prng_state = hash::xorshift64(g_state->prng_state);
    }

    [[gnu::always_inline]] inline void page_in_pages(void) {
        g_state->touch_shellcode_byte(g_state->prng_state % license_checker_state::shellcode_size);
    }
}

// Time-based checks
namespace antidebug::time {
    // This is the total maximum runtime of this program in nanoseconds.
    // The SIGALRM timer should hit before this is possible to achieve without debugging.
    // If you patch that out, that's your problem :D
    // TODO: Actually determine a sane threshold
    constexpr static unsigned long runtime_limit = 1'000'000'000;

    // This is the actual maximum runtime from the point where the SIGALRM timer is armed.
    // We have that to make sure we don't silently become unsolvable on slow machines.
    // TODO: Actually determine a sane threshold
    constexpr static unsigned long strict_runtime_limit = 500'000'000;

    // This is the maximum runtime of this program between two instrumented function calls in ns
    // TODO: Actually determine a sane threshold
    constexpr static unsigned long step_runtime_limit = 25'000'000;

    // When the overall SIGALRM timer expires, exit and warn the user.
    [[gnu::no_instrument_function]]
    static void timer_expired(int)
    {
        utils::exit_with_message("license validation timed out (your computer may be too slow)");
    }

    // Get the current time
    [[gnu::always_inline]]
    static inline unsigned long now()
    {
        // This is in nanoseconds.
        // The vdso call cannot fail, as far as I can tell.
        struct timespec ts;
        g_state->vdso_clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
        return ts.tv_sec * 1'000'000'000ul + ts.tv_nsec;
    }

    // Get the process's start time
    [[gnu::noinline, gnu::no_instrument_function]] /* Checks not ready yet */ static unsigned long process_start()
    {
        // Read the start time (task_struct->start_boottime, adjusted for the local namespace) from
        // /proc/self/stat. This format isn't exactly well-behaved, with it containing the task name
        // at the start. But it's a userspace task, so we know comm is at most 16 bytes, and the
        // field we want has a higher index, so you'd need more spaces to fake this.
        // NB: Because this is boot time, it might break if we suspend in the middle of the function
        // I'm willing to take that risk, since we can't query CLOCK_BOOTTIME efficiently via vDSO.
        char buffer[1024];
        const char *path = "/proc/self/stat"_hide();
        int fd = utils::check(sys::open(path, O_RDONLY));
        ssize_t bytes = utils::check(sys::read(fd, buffer, sizeof(buffer)));
        utils::check(sys::close(fd));

        char *pos = &buffer[0];
        char *end = &buffer[bytes];
        while (pos < end && *pos != '(')
            ++pos;

        char *comm = ++pos;
        utils::assert(comm + 16 + 1 < end);
        for (size_t offset = 0; offset < 16 + 1; ++offset)
            if (comm[offset] == ')')
                pos = &comm[offset];
        utils::assert(pos + 1 < end && pos != comm);

        size_t field = 0;
        for (++pos; field < 20 && pos < end; ++pos)
            if (*pos == ' ' && pos[-1] != ' ' /* Just in case */)
                ++field;
        utils::assert(pos < end);

        char *next = pos;
        while (next < end && *next != ' ')
            ++next;
        utils::assert(pos < next && next < end);

        unsigned long start_time = 0;
        while (pos < next) {
            char digit = *pos++;
            start_time = 10 * start_time + (digit - '0');
        }

        // Now we need to convert from clock ticks (_SC_CLK_TCK / AT_CLKTCK) since boot
        // to a CLOCK_MONOTONIC_COARSE timestamp.
        // We have the resolution, but need the actual uptime.

        // Start time in nanoseconds
        // Usually, clk_tck is 100, so this works out.
        start_time *= 1'000'000'000ul / g_state->clk_tck;

        // Read the total uptime.
        // We check the current clock time _slightly after_ the read, so the imputed boot time
        // is slightly after the actual boot time. This gives a little bit more grace period.
        // Also, _this_ value is in seconds, not in AT_CLKTCK instances.
        fd = utils::check(sys::open("/proc/uptime"_hide(), O_RDONLY));
        bytes = utils::check(sys::read(fd, buffer, sizeof(buffer)));
        unsigned long current = antidebug::time::now();
        utils::check(sys::close(fd));

        pos = &buffer[0];
        end = &buffer[bytes];

        unsigned long uptime = 0;
        char *decimal_sep = NULL;
        while (pos < end && *pos != ' ') {
            char digit = *pos++;
            if (digit == '.') {
                decimal_sep = pos;
                continue;
            }
            uptime = 10 * uptime + (digit - '0');
        }
        utils::assert(pos < end);

        unsigned long uptime_factor = 1'000'000'000;
        if (decimal_sep)
            for (ssize_t i = 0; i < pos - decimal_sep; ++i)
                uptime_factor /= 10;
        uptime *= uptime_factor;

        unsigned long boot_time = current - uptime;
        unsigned long process_start_time = boot_time + start_time;

        return process_start_time;
    }
}

// simple checks
namespace antidebug::simple {
    struct status_entry {
        uint64_t key_hash;
        size_t size;
    };

    // Read /proc/self/status
    // This is lines in (\w+):\s*(.*) format.
    static inline status_entry read_status_line(char *buffer, size_t size)
    {
        enum class progress { key, value } reading = progress::key;

        uint64_t key_hash = 0;
        size_t position = 0;
        for (;;) {
            if (position >= size) {
                char skip;
                do {
                    utils::check_exact(sys::read(g_state->status_fd, &skip, 1), 1);
                } while (skip != '\n');
                return status_entry { 0, size };
            }

            ssize_t bytes = utils::check(sys::read(g_state->status_fd, &buffer[position++], 1));
            if (!bytes)
                return status_entry { 0, 0 };

            char *last = &buffer[position - 1];
            switch (reading) {
                case progress::key:
                    if (*last == ':') {
                        key_hash = hash::hash_string(buffer, position - 1);
                        position = 0;
                        reading = progress::value;
                    }
                    utils::assert(*last != '\n');
                    break;
                case progress::value:
                    if (position == 1 && (*last == ' ' || *last == '\t')) {
                        *last = 0;
                        position = 0;
                    } else if (*last == '\n') {
                        *last = 0;
                        return status_entry { key_hash, position - 1 };
                    }
                    break;
            }
        }
    }

    // Simple anti-ptrace check
    static inline void check_tracer(void)
    {
        auto fd_nr = strings::itoa(g_state->status_fd);

        std::array<char, 128> buffer;
        for (;;) {
            status_entry next = read_status_line(buffer.data(), buffer.size());
            if (next.key_hash == 0 && next.size == 0)
                break;
            if (next.key_hash != "TracerPid"_hash)
                continue;
            // TracerPid must be the parent PID from the ifunc
            auto tracer_pid = strings::atoi<pid_t>(buffer.data(), next.size);
            antidebug::assert(tracer_pid == g_state->initial_pid,
                              "Process is being traced by the wrong tracer"_debug);
        }

        // Re-open /proc/self/status
        int size = utils::check(sys::readlinkat(g_state->fd_dirfd, fd_nr.data(),
                                                buffer.data(), buffer.size()));
        utils::assert(static_cast<size_t>(size) < buffer.size());
        buffer[size] = 0;

        int new_fd = utils::check(sys::open(buffer.data(), O_RDONLY | O_CLOEXEC));
        utils::check(sys::close(g_state->status_fd));
        g_state->status_fd = new_fd;
    }
}

// rseq checks
namespace antidebug::rseq {
    // Raw rseq check: Install a new rseq and check the prior flags
    static inline void check_rseq_install(uint64_t from_ip, uint64_t to_ip, uint64_t abort_ip)
    {
        g_state->rseq_cs.version = 0;
        g_state->rseq_cs.flags = 0;
        g_state->rseq_cs.start_ip = from_ip;
        g_state->rseq_cs.post_commit_offset = to_ip - from_ip;
        g_state->rseq_cs.abort_ip = abort_ip;
        unsigned flags = 0; // These could be used to disable rseq for single-stepping
        __asm__ volatile (
            "xchgl %[flags], %%fs:(%[flags_offset])\n"
            "movq %[rseq_cs], %%fs:(%[rseq_cs_offset])\n"
            : [flags]"+r"(flags)
            : [rseq_cs_offset]"r"(g_state->rseq_offset + offsetof(struct rseq, rseq_cs)),
              [flags_offset]"r"(g_state->rseq_offset + offsetof(struct rseq, flags)),
              [rseq_cs]"r"(&g_state->rseq_cs)
        );
        // NB: This has syscalls and can't be part of the rseq itself
        antidebug::assert(flags == 0 && g_state->rseq_cs.flags == 0,
                          "rseq flags indicate single-stepping"_debug);
    }

    // Check that the rseq installed in check_rseq_installed was not removed or had its flags changed
    // NB: On abort, the rseq_cs is cleared. Make sure not to get surprised by that.
    static inline void check_rseq_valid(void)
    {
        uint32_t flags = 0;
        struct rseq_cs *rseq_cs = nullptr;
        __asm__ volatile (
            "movl %%fs:(%[flags_offset]), %[flags]\n"
            "movq %%fs:(%[rseq_cs_offset]), %[rseq_cs]\n"
            : [flags]"=r"(flags),
              [rseq_cs]"=r"(rseq_cs)
            : [rseq_cs_offset]"r"(g_state->rseq_offset + offsetof(struct rseq, rseq_cs)),
              [flags_offset]"r"(g_state->rseq_offset + offsetof(struct rseq, flags))
        );
        antidebug::assert(flags == 0 /* && rseq_cs == &g_state->rseq_cs */, "rseq settings changed"_debug);
    }

    static inline uint64_t abort(void)
    {
        g_state->rseq_failures++;
        return static_cast<uint64_t>(-1);
    }

    extern "C" uint64_t rseq_abort(void);

    [[gnu::naked, gnu::used]] static inline void __dummy_rseq_abort(void)
    {
        __asm__ volatile (
            ".local rseq_abort\n"
            ".type rseq_abort, STT_FUNC\n"
            "   .4byte %c[signature]\n"
            "rseq_abort:\n"
            "    jmp %p[impl]\n"
            "    ud2\n"
            :: [signature]"i"(RSEQ_SIG), [impl]"Ws"(abort)
        );
    }
}

// Memory checks (secretmem, breakpoints, etc.)
namespace antidebug::memory {
    // This works even if you do `set stop-on-solib-events 0`.
    [[gnu::always_inline]]
    static void check_solib_breakpoints(void)
    {
        // None of the proble locations are allowed to have breakpoints on them
        no_unrolling for (void *probe : g_state->stapsdt_probes)
            antidebug::assert(!probe || * reinterpret_cast<const uint8_t *>(probe) != 0xcc,
                              "stapsdt or r_brk probe detected"_debug);
    }

    // Stack check: The distance between g_state and the stack pointer can't be too large
    [[gnu::always_inline]]
    static void check_stack_in_state(void)
    {
        unsigned long sp;
        __asm__ volatile ("movq %%rsp, %[out]\n" : [out]"=r"(sp));
        antidebug::assert(((sp - reinterpret_cast<unsigned long>(g_state)) & ~0xffff) == 0,
                          "stack is outside of global state"_debug);
    }

    // State check: memory should be secretmem.
    // We ensure that by passing it into a syscall that uses GUP instead of copy_*_user.
    [[gnu::always_inline]]
    static void check_state_is_secretmem(void)
    {
        // You'd think this is a modification check.
        // But actually it's not >:D
        int pid = utils::check(sys::getpid());
        uintptr_t next_state = hash::xorshift64(g_state->prng_state ^ 1);
        struct iovec remote = {
            .iov_base = &g_state->prng_state,
            .iov_len = sizeof(g_state->prng_state)
        };
        struct iovec local = {
            .iov_base = &next_state,
            .iov_len = sizeof(next_state)
        };
        ssize_t result = sys::process_vm_writev(pid, &local, 1, &remote, 1, 0);
        if (utils::is_ok(result)) [[likely]] // Not actually likely
            antidebug::log_failure("process_vm_writev succeeded on state memory"_debug);
    }
}

namespace {
    // Hook for -finstrument-function-entry-bare
    // Here, we check the elapsed time since the program start.
    // I would really like to use the taskstats netlink API for this,
    // but it needs CAP_SYS_ADMIN. Instead, do a more lightweight
    // approach with vDSO calls (clock_gettime) and reading /proc/self/stat.
    // See antidebug::time::* above.
    extern "C" [[gnu::no_instrument_function]]
    void __cyg_profile_func_enter_bare(void)
    {
        auto previous = g_state->last_function_entry;
        auto current = g_state->last_function_entry = antidebug::time::now();

        antidebug::assert(current - g_state->start_time < antidebug::time::runtime_limit,
                          "total runtime limit exceeded"_debug);
        antidebug::assert(current - previous < antidebug::time::step_runtime_limit,
                          "step runtime limit exceeded"_debug);

        antidebug::action::step_prng();
    }
}

namespace ifunc {
    [[gnu::no_instrument_function]] auto setup_ifunc(void)
    {
        // Open this early, prctl will break it.
        // PR_GET_AUXV is only available starting with Linux 6.4.
        // That's a little too recent for my taste.
        // I'll read /proc/self/auxv instead.
        int auxv_fd = utils::check(sys::open("/proc/self/auxv"_hide(), O_RDONLY | O_CLOEXEC));
        pid_t initial_pid = utils::check(sys::getpid());

        // Timer setup
        timer_t timer;
        struct kernel_sigaction action = {};
        action.sa_handler = antidebug::time::timer_expired;
        action.sa_flags = SA_RESTORER | SA_RESTART;
        action.sa_restorer = __sigreturn_trampoline;
        action.sa_mask = 1ul << (SIGALRM - 1);
        utils::check(sys::rt_sigaction(SIGALRM, &action, nullptr, sizeof(action.sa_mask)));
        struct itimerspec timeout = {
            .it_interval = {
                .tv_sec  = 0,
                .tv_nsec = 0
            },
            .it_value = {
                .tv_sec  = antidebug::time::strict_runtime_limit / 1'000'000'000,
                .tv_nsec = antidebug::time::strict_runtime_limit % 1'000'000'000,
            },
        };
        struct sigevent event = {};
        event.sigev_signo = SIGALRM,
        event.sigev_notify = SIGEV_SIGNAL,
        utils::check(sys::timer_create(CLOCK_MONOTONIC, &event /* Can't be NULL here */, &timer));
        utils::check(sys::timer_settime(timer, 0, &timeout, nullptr));

        // Initial ptrace anti-debug (this should be obvious to fix)
        // Comment these out if you want to debug this.
        // If we are "privileged" (via capabilities) and try to do this we
        // fail unless we are also more privileged. But if it succeeds,
        // this makes our parent process the ptracer (which is suboptimal,
        // since we cannot distinguish from being spawned by GDB).
        // Instead, clone out another task and just stall this parent.
        struct clone_args args = {};
        args.flags = CLONE_FILES | CLONE_FS | CLONE_SYSVSEM;
        args.exit_signal = SIGCHLD;
        pid_t pid = utils::check(sys::clone3(&args, sizeof(args)));

        utils::check(sys::prctl(PR_SET_DUMPABLE, 0 /* SUID_DUMP_DISABLE */)); // No coredumps, please
        utils::check(sys::prctl(PR_SET_PTRACER, 1)); // With Yama, only init (PID 1) may ptrace this now.

        if (pid) {
            utils::check_exact(sys::wait4(-1, nullptr, __WALL, nullptr), pid);
            sys::exit_group(0);
        }

        utils::check(sys::ptrace(PTRACE_TRACEME));
        utils::check_exact(sys::ptrace(PTRACE_TRACEME), -EPERM);

        utils::check(sys::prctl(PR_SET_PDEATHSIG, SIGKILL));

        // Create secretmem mapping for the actual state.
        int secretmem_fd = utils::check(sys::memfd_secret(O_CLOEXEC));
        utils::check(sys::ftruncate(secretmem_fd, utils::page_align_up(sizeof(license_checker_state))));
        g_state = reinterpret_cast<license_checker_state *>(utils::check(sys::mmap(
            nullptr,
            utils::page_align_up(sizeof(license_checker_state)),
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            secretmem_fd,
            0
        )));
        utils::check(sys::close(secretmem_fd));
        utils::check(sys::madvise(g_state, utils::page_align_up(sizeof(license_checker_state)),
                                  MADV_DONTFORK));
        utils::check(sys::madvise(g_state, utils::page_align_up(sizeof(license_checker_state)),
                                  MADV_DONTDUMP));

        g_state->auxv_fd = auxv_fd;
        g_state->prng_state = 0x707868;
        g_state->initial_pid = initial_pid;

        g_state->with_stack([] [[gnu::no_instrument_function, gnu::always_inline]] {
            g_state->load_auxv();
            g_state->start_time = antidebug::time::process_start();
            g_state->last_function_entry = antidebug::time::now();
            // Tracking of function entry times is now ready.
            // After here, we can call any functions, not just those with the always_inline or
            // no_instrument_function attributes.

            // Usually, r_brk isn't used for probing. But register it anyways, just in case.
            g_state->remember_probe(reinterpret_cast<void *>(g_state->ldso_r_debug->r_brk));

            // Grab the loader for the probe points. We need the full path, and there are two
            // sane ways to do this. Either we get it from ld.so itself, or via /proc/self/map_files.
            // We'll try ld.so for now.
            // Unfortunately, we can't sanely check for LD_PRELOAD this way, since we might have libc
            // dependencies (e.g., libm). But since we don't _call_ into libc, it doesn't matter either.
            // Other checks will catch this still.
            // The loader should be the last entry in the map.
            struct link_map *map = g_state->ldso_r_debug->r_map;
            while (map->l_next)
                map = map->l_next;

            struct stat ldso_stat;
            int ldso_fd = utils::check(sys::open(map->l_name, O_RDONLY | O_CLOEXEC));
            utils::check(sys::fstat(ldso_fd, &ldso_stat));
            void *ldso_map = utils::check(sys::mmap(
                nullptr,
                ldso_stat.st_size,
                PROT_READ,
                MAP_SHARED,
                ldso_fd,
                0
            ));
            utils::check(sys::close(ldso_fd));
            antidebug::elf::for_each_probe(
                reinterpret_cast<const Elf64_Ehdr *>(ldso_map),
                map->l_addr,
                [](Elf64_Addr probe_addr) {
                    g_state->remember_probe(reinterpret_cast<void *>(probe_addr));
                }
            );
            utils::check(sys::munmap(ldso_map, ldso_stat.st_size));

            // TODO: Verify this is actually in the loader
            //  - Debian bookworm: yes
            //  - Debian bullseye: no
            //  - Ubuntu 24.04: yes
            //  - Ubuntu 22.04: yes
            //  - Ubuntu 20.04: no
            g_state->rseq_offset = * reinterpret_cast<int32_t *>(
                antidebug::elf::find_symbol(
                    reinterpret_cast<Elf64_Ehdr *>(map->l_addr),
                    "__rseq_offset"_hash,
                    true
                )
            );

            // Open /proc/self/status for later.
            g_state->status_fd = utils::check(sys::open("/proc/self/status"_hide(), O_RDONLY | O_CLOEXEC));
            g_state->fd_dirfd = utils::check(sys::open("/proc/self/fd/"_hide(), O_DIRECTORY | O_PATH | O_CLOEXEC));

            // Create userfaultfd.
            if ((g_state->uffd = sys::userfaultfd(O_CLOEXEC)) == -EPERM) {
                // Try the fallback method via /dev/userfaultfd
                int uffd_dev = sys::open("/dev/userfaultfd"_hide(), O_RDWR | O_CLOEXEC);
                if (utils::is_ok(uffd_dev)) {
                    g_state->uffd = sys::ioctl(uffd_dev, USERFAULTFD_IOC_NEW,
                                               reinterpret_cast<void *>(O_CLOEXEC));
                    utils::check(sys::close(uffd_dev));
                }
                if (g_state->uffd == -EPERM)
                    utils::exit_with_message("please setcap 'cap_dac_read_search=ep cap_sys_ptrace=ep' chekhov");
            }
            utils::check(g_state->uffd);
            struct uffdio_api uffd_api = {
                .api = UFFD_API,
                // UFFD_FEATURE_EVENT_FORK unfortunately requires privileges.
                // This is also probably the highest we can go compatibility-wise
                // (UFFD_FEATURE_EXACT_ADDRESS needs Linux 5.18)
                // WP only works on private anonymous ranges. MINOR only works with shared ranges.
                .features = UFFD_FEATURE_EVENT_REMAP | UFFD_FEATURE_MISSING_SHMEM |
                            UFFD_FEATURE_THREAD_ID | UFFD_FEATURE_PAGEFAULT_FLAG_WP |
                            UFFD_FEATURE_MINOR_SHMEM | UFFD_FEATURE_EXACT_ADDRESS,
                .ioctls = 0,
            };
            utils::check(sys::ioctl(g_state->uffd, UFFDIO_API, &uffd_api));

            // Map shellcode area, and register it with the userfaultfd
            // This can't be secretmem, because that's banned from being executable.
            g_state->shellcode = utils::check(sys::mmap(
                nullptr,
                license_checker_state::shellcode_size,
                PROT_EXEC,
                MAP_ANONYMOUS | MAP_NORESERVE | MAP_PRIVATE,
                -1,
                0
            ));
            g_state->current_shellcode = g_state->shellcode;
            utils::check(sys::madvise(g_state->shellcode, license_checker_state::shellcode_size,
                                      MADV_DONTDUMP));
            utils::check(sys::madvise(g_state->shellcode, license_checker_state::shellcode_size,
                                      MADV_DONTNEED));

            struct uffdio_register uffd_register = {
                .range = {
                    .start = reinterpret_cast<__u64>(g_state->shellcode),
                    .len = license_checker_state::shellcode_size,
                },
                .mode = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP,
                .ioctls = 0,
            };
            utils::check(sys::ioctl(g_state->uffd, UFFDIO_REGISTER, &uffd_register));

            constexpr static const decltype(uffd_register.ioctls) required_flags =
                (1ul << _UFFDIO_COPY) | (1ul << _UFFDIO_WAKE) | (1ul << _UFFDIO_WRITEPROTECT);
            utils::check_exact(uffd_register.ioctls & required_flags, required_flags);

            // Start a handler thread for the userfaultfd
            struct clone_args args = {};
            args.flags = CLONE_FILES | CLONE_FS | CLONE_SIGHAND | CLONE_SYSVSEM
                                     | CLONE_THREAD | CLONE_VM | CLONE_UNTRACED;
            args.stack = reinterpret_cast<uint64_t>(g_state->thread_stack);
            args.stack_size = sizeof(g_state->thread_stack);
            int pid = utils::check(sys::clone3(&args, sizeof(args)));
            if (pid == 0) {
                antidebug::memory::check_stack_in_state();
                antidebug::memory::check_state_is_secretmem();
                struct uffd_msg msg;
                for (;;) {
                    utils::check(sys::read(g_state->uffd, &msg, sizeof(msg)));
                    antidebug::assert(msg.event == UFFD_EVENT_PAGEFAULT ||
                                      msg.event == UFFD_EVENT_REMOVE,
                                      "unexpected userfaultfd event"_debug);
                    if (msg.event != UFFD_EVENT_PAGEFAULT)
                        continue;

                    uint64_t page = msg.arg.pagefault.address & ~0xfff;
                    uint64_t current = reinterpret_cast<uint64_t>(g_state->current_shellcode);

                    // This is not antidebug::assert since that assert can trigger additional
                    // page faults, and we'd never get out of this.
                    // We also don't log this violation since one page fault violation per check is OK
                    // (it is used to clear the entry).
                    if (page != current)
                        g_state->prng_state += page - reinterpret_cast<uint64_t>(g_state->shellcode);
                    else
                        g_state->current_shellcode = reinterpret_cast<void *>(current + 0x1000);

                    size_t check_id = g_state->prng_state % payload::checks.size();

#if defined(_HXP_DEBUG_IDS)
#pragma GCC warning "_HXP_DEBUG_IDS is enabled!"
                    if (page == current) {
                        testing::log("            case ");
                        testing::log(testing::dec_number(check_id));
                        testing::log(": ");
                    }
#endif

                    auto check = payload::checks[check_id];
                    struct uffdio_copy copy_call = {
                        .dst = page,
                        .src = reinterpret_cast<uint64_t>(check),
                        .len = 0x1000,
                        .mode = 0,
                        .copy = 0,
                    };
                    utils::check(sys::ioctl(g_state->uffd, UFFDIO_COPY, &copy_call));
                    utils::check_exact(copy_call.copy, 0x1000);
                }
                sys::exit(EXIT_SUCCESS);
            }

            // In the future, we'd want to mseal() the shellcode area. But mseal is too new to reliably
            // use for anything.
        });

        return static_cast<void (*)()>(nullptr);
    }
    // Don't worry, the name will disappear again.
    [[gnu::ifunc("_ZN5ifunc11setup_ifuncEv")]] static void setup_target(void);
    [[gnu::used]] auto setup = &setup_target;
}

extern "C" [[noreturn, gnu::noinline, gnu::no_instrument_function, gnu::flatten]]
void __sigreturn_trampoline()
{
    sys::rt_sigreturn();
}

// TODO: References to __syscall_failed will be dead giveaways as to where the interesting
//       parts of the code are. However, the shellcode doesn't use them so maybe this is fine?
extern "C" [[noreturn, gnu::noinline, gnu::no_instrument_function, gnu::flatten]]
void __syscall_failed()
{
    utils::exit_with_message("failed to validate license");
}

namespace {
    [[gnu::constructor(0)]] void perform_initial_checks(void)
    {
        antidebug::memory::check_solib_breakpoints();
    }

    [[gnu::noinline]] void check_license(size_t index)
    {
        auto base = reinterpret_cast<uint64_t>(g_state->shellcode);
        auto check = reinterpret_cast<payload::check_t>(g_state->current_shellcode);
        uint64_t result;
        do {
            antidebug::memory::check_state_is_secretmem();
            antidebug::rseq::check_rseq_install(base, base + license_checker_state::shellcode_size - 1,
                                                reinterpret_cast<uint64_t>(antidebug::rseq::rseq_abort));
            result = check(g_state->license_key.data(), index);

#if defined(_HXP_DEBUG_IDS)
            uint64_t actual = 0;
            __asm__ volatile ( "" : "=d"(actual) );

            if (static_cast<uint32_t>(result) != static_cast<uint32_t>(-1)) {
                testing::log("return ");
                testing::log(testing::dec_number(actual));
                testing::logln("ul;");
            }
#endif

            antidebug::assert(g_state->rseq_failures < 0x100 + payload::valid_checks,
                              "too many rseq failures"_debug);
            antidebug::memory::check_stack_in_state();
        } while (static_cast<uint32_t>(result) == static_cast<uint32_t>(-1));
        g_state->check_failures |= (result >> 32);
        antidebug::rseq::check_rseq_valid();

        utils::check(sys::madvise(g_state->shellcode, license_checker_state::shellcode_size,
                                  MADV_DONTNEED));

        for (unsigned i = 0; i < static_cast<uint32_t>(result); ++i)
            antidebug::action::step_prng();

        // Page in the current shellcode page again. This should be in a different place now.
        g_state->touch_shellcode_byte(
            reinterpret_cast<uint64_t>(check) - reinterpret_cast<uint64_t>(g_state->shellcode)
        );
        antidebug::action::step_prng();
        antidebug::simple::check_tracer();
        antidebug::memory::check_solib_breakpoints();
    }

    [[gnu::noinline]] void check_format_and_initialize_checker(char *input)
    {
        no_unrolling for (size_t index = 0; index < g_state->license_key.size() / 4; ++index) {
            if (index && *input++ != '-')
                utils::exit_with_message("invalid format (expected dash)");

            uint32_t group = 0;
            no_unrolling for (size_t in_group = 0; in_group < 6; ++in_group, ++input) {
                group *= 36;
                switch (*input) {
                    case '0' ... '9':
                        group += *input - '0';
                        break;
                    case 'A' ... 'Z':
                        group += *input - 'A' + 10;
                        break;
                    default:
                        utils::exit_with_message("invalid format (bad character)");
                }
            }

            g_state->license_key[index * 4] = group & 0xff;
            g_state->license_key[index * 4 + 1] = (group >> 8) & 0xff;
            g_state->license_key[index * 4 + 2] = (group >> 16) & 0xff;
            g_state->license_key[index * 4 + 3] = (group >> 24) & 0xff;
        }
        if (*input)
            utils::exit_with_message("invalid format (too long)");
    }

    static constinit std::array<uint8_t, 7 * 16> flag_ciphertext = {
        0xc1, 0x3c, 0x3d, 0x6b, 0x5f, 0x7f, 0x70, 0x72, 0x40, 0x76, 0xdf, 0x4f, 0x5d, 0x62, 0x55, 0x83,
        0x6e, 0x7e, 0xa9, 0xc5, 0x03, 0x81, 0x2c, 0xa0, 0xc4, 0xa8, 0xdc, 0x1d, 0xfd, 0x94, 0x03, 0xca,
        0xdb, 0xe5, 0xb2, 0x54, 0xcf, 0xdc, 0x0a, 0x9a, 0x53, 0x52, 0x0d, 0xa4, 0x68, 0xca, 0x3b, 0xde,
        0x44, 0xc4, 0x21, 0xfa, 0x01, 0x9f, 0x55, 0xde, 0x27, 0xce, 0xa2, 0xa7, 0xd9, 0x71, 0xad, 0xed,
        0x23, 0x6b, 0xf8, 0x3c, 0x85, 0x57, 0x87, 0xeb, 0x24, 0x4d, 0x2d, 0xfc, 0xa0, 0x41, 0x66, 0xc4,
        0x58, 0x3a, 0x13, 0x1a, 0xd6, 0xdf, 0x46, 0x6d, 0xef, 0xfb, 0x35, 0x40, 0xa2, 0x56, 0x87, 0x96,
        0xe1, 0xb9, 0xc1, 0x28, 0x44, 0x17, 0x60, 0xba, 0x5a, 0x27, 0xea, 0x76, 0xda, 0xf2, 0xa5, 0xd0
    };

    [[gnu::noinline, noreturn]] void decrypt_flag_and_check(const aesni::aes_key &key)
    {
        decltype(flag_ciphertext) decrypted = {};

        auto cipher = key.for_decryption();
        no_unrolling for (size_t block_start = 0; block_start < flag_ciphertext.size(); block_start += 16) {
            aesni::aes_block block = {};
            __builtin_memcpy_inline(block.data(), &flag_ciphertext[block_start], 16);
            block = cipher.decrypt_ecb(block);
            __builtin_memcpy_inline(&decrypted[block_start], block.data(), 16);
        }

        if (decrypted[0] == 'h' && decrypted[1] == 'x' && decrypted[2] == 'p' && decrypted[3] == '{')
            utils::exit_with_success(reinterpret_cast<char *>(decrypted.data()));
        else
            utils::exit_with_message("you are close"_hide());
        __builtin_unreachable();
    }
}

int main(int argc, char *argv[])
{
    // Check the basic format and decode blocks into uint32_t
    // (XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX)
    if (argc != 2)
        utils::exit_with_message("no license key specified");
    check_format_and_initialize_checker(argv[1]);

#if defined(_HXP_AES_SELFTEST)
#pragma GCC warning "_HXP_AES_SELFTEST is enabled! This will change PRNG state!"
    aesni::selftest();
#endif

    // Pivot stack into the secretmem again.
    g_state->with_stack([] {
        // TODO: Intersperse checks, also in timer interrupts
        antidebug::memory::check_solib_breakpoints();
        antidebug::memory::check_stack_in_state();
        antidebug::memory::check_state_is_secretmem();

        no_unrolling for (size_t index = 0; index < payload::valid_checks; ++index)
            check_license(index);

        // We should get at least one rseq failure per check, since we need to handle the
        // page fault.
        antidebug::assert(g_state->rseq_failures >= payload::valid_checks,
                          "unexpectedly few rseq failures"_debug);

        if (g_state->check_failures)
            utils::exit_with_message("license is invalid"_hide());
        else
            decrypt_flag_and_check(static_cast<aesni::aes_key>(g_state->license_key));
    });
}
