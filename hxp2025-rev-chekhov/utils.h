#pragma once

#include <linux/sched.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <tuple>
#include <type_traits>

extern "C" [[noreturn, gnu::noinline, gnu::no_instrument_function, gnu::flatten]]
void __sigreturn_trampoline();

extern "C" [[noreturn, gnu::noinline, gnu::no_instrument_function, gnu::flatten]]
void __syscall_failed();

#define no_unrolling _Pragma("GCC unroll 1")

struct itimerspec;
struct utsname;
struct sigevent;

// Userspace sigaction is different from kernel sigaction. So, bring in the correct one here.
// We can do magic to include <asm/signal.h>, but that in turn breaks macros like sa_handler.
// Unfortunately, forward-declaring siginfo_t for the sa_sigaction argument is impossible.
// But that doesn't really matter here.
#define sigaction __kernel_sigaction
#define sigset_t kernel_sigset_t
#define stack_t kernel_stack_t
#include <asm/signal.h>
#undef sigaction
#undef sigset_t
#undef stack_t
struct kernel_sigaction {
    union {
        __sighandler_t sa_handler;
        void (*sa_sigaction) (int, void /* siginfo_t */ *, void *);
    } __sigaction_handler;
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    kernel_sigset_t sa_mask;
};
static_assert(offsetof(kernel_sigaction, sa_mask) == offsetof(__kernel_sigaction, sa_mask));
static_assert(offsetof(kernel_sigaction, sa_flags) == offsetof(__kernel_sigaction, sa_flags));
static_assert(offsetof(kernel_sigaction, sa_restorer) == offsetof(__kernel_sigaction, sa_restorer));


namespace cpp {
    template <size_t Index, typename T, typename... Rest>
    [[gnu::always_inline, gnu::flatten]]
    static inline auto arg_impl(T head, Rest ...tail)
    {
        if constexpr (Index == 0) {
            return head;
        } else {
            return arg_impl<Index - 1>(tail...);
        }
    }

    template <size_t Index, typename... Args>
    [[nodiscard, gnu::always_inline, gnu::flatten]]
    static inline auto arg(Args ...args)
    {
        static_assert(sizeof...(args) > Index, "sys::gen::arg: Index out of range");
        // C++26 has proper pack indexing:
        //    return args...[Index];
        // But we can't do that yet.
        // The optimizer should save us:
        //    return std::get<Index>(std::make_tuple(args...));
        // But it most certainly did not.
        // So we do it by hand.
        return arg_impl<Index>(args...);
    }

    template <typename To, typename From>
    [[gnu::always_inline]]
    static inline To force_cast(From from)
    {
        if constexpr (sizeof(To) == sizeof(From) &&
                      std::is_trivially_copyable_v<From> &&
                      std::is_trivially_copyable_v<To>)
            return std::bit_cast<To>(from);
        else if constexpr (std::is_pointer_v<From> || std::is_pointer_v<To>)
            return reinterpret_cast<To>(from);
        else
            return static_cast<To>(from);
    }
}

namespace sys {
    namespace gen {
        template <long Nr, typename R, typename... Args>
        [[gnu::always_inline, gnu::flatten]]
        static inline R syscall(Args ...args)
        {
            static_assert(sizeof...(args) <= 6, "sys::gen::syscall: Too many arguments");

#define sys_gen_syscall(...) \
        __asm__ volatile ( "syscall" : "+r"(_nr) : __VA_ARGS__ : "rcx", "r11", "memory" )

            register auto _nr __asm__ ("rax") = Nr;
            if constexpr (sizeof...(args) == 0) {
                sys_gen_syscall();
            } else {
                register auto _a __asm__ ("rdi") = cpp::arg<0>(args...);
                if constexpr (sizeof...(args) == 1) {
                    sys_gen_syscall("r"(_a));
                } else {
                    register auto _b __asm__ ("rsi") = cpp::arg<1>(args...);
                    if constexpr (sizeof...(args) == 2) {
                        sys_gen_syscall("r"(_a), "r"(_b));
                    } else {
                        register auto _c __asm__ ("rdx") = cpp::arg<2>(args...);
                        if constexpr (sizeof...(args) == 3) {
                            sys_gen_syscall("r"(_a), "r"(_b), "r"(_c));
                        } else {
                            register auto _d __asm__ ("r10") = cpp::arg<3>(args...);
                            if constexpr (sizeof...(args) == 4) {
                                sys_gen_syscall("r"(_a), "r"(_b), "r"(_c), "r"(_d));
                            } else {
                                register auto _e __asm__ ("r8") = cpp::arg<4>(args...);
                                if constexpr (sizeof...(args) == 5) {
                                    sys_gen_syscall("r"(_a), "r"(_b), "r"(_c), "r"(_d), "r"(_e));
                                } else {
                                    register auto _f __asm__ ("r9") = cpp::arg<5>(args...);
                                    sys_gen_syscall("r"(_a), "r"(_b), "r"(_c), "r"(_d), "r"(_e), "r"(_f));
                                }
                            }
                        }
                    }
                }
            }

#undef sys_gen_syscall

            return cpp::force_cast<R>(_nr);
        }
    }

    // Actual syscall wrappers

    // SYS_read: 0
    [[nodiscard, gnu::always_inline]]
    static inline ssize_t read(int fd, void *buf, size_t size)
    {
        return sys::gen::syscall<SYS_read, ssize_t>(fd, buf, size);
    }

    // SYS_read: 1
    [[nodiscard, gnu::always_inline]]
    static inline ssize_t write(int fd, const void *buf, size_t size)
    {
        return sys::gen::syscall<SYS_write, ssize_t>(fd, buf, size);
    }

    // SYS_open: 2
    [[nodiscard, gnu::always_inline]]
    static inline int open(const char *path, int flags, mode_t mode = 0)
    {
        return sys::gen::syscall<SYS_open, int>(path, flags, mode);
    }

    // SYS_close: 3
    [[nodiscard, gnu::always_inline]]
    static inline int close(int fd)
    {
        return sys::gen::syscall<SYS_close, int>(fd);
    }

    // SYS_fstat: 5
    [[nodiscard, gnu::always_inline]]
    static inline int fstat(int fd, struct stat *statbuf)
    {
        return sys::gen::syscall<SYS_fstat, int>(fd, statbuf);
    }

    // SYS_mmap: 9
    [[nodiscard, gnu::always_inline]]
    static inline void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
    {
        return sys::gen::syscall<SYS_mmap, void *>(addr, length, prot, flags, fd, offset);
    }

    // SYS_mprotect: 10
    [[nodiscard, gnu::always_inline]]
    static inline int mprotect(void *addr, size_t length, int prot)
    {
        return sys::gen::syscall<SYS_mprotect, int>(addr, length, prot);
    }

    // SYS_munmap: 11
    [[nodiscard, gnu::always_inline]]
    static inline int munmap(void *addr, size_t length)
    {
        return sys::gen::syscall<SYS_munmap, int>(addr, length);
    }

    // SYS_rt_sigaction: 13
    [[nodiscard, gnu::always_inline]]
    static inline int rt_sigaction(int signum, const struct kernel_sigaction *act,
                                   struct kernel_sigaction *oldact, size_t sigsetsize)
    {
        return sys::gen::syscall<SYS_rt_sigaction, int>(signum, act, oldact, sigsetsize);
    }

    // SYS_rt_sigreturn: 15
    [[noreturn, gnu::always_inline]]
    static inline int rt_sigreturn()
    {
        sys::gen::syscall<SYS_rt_sigreturn, long>();
        __builtin_unreachable();
    }

    // SYS_ioctl: 16
    [[nodiscard, gnu::always_inline]]
    static inline long ioctl(int fd, unsigned long op, void *arg)
    {
        return sys::gen::syscall<SYS_ioctl, long>(fd, op, arg);
    }

    // SYS_pread64: 17
    [[nodiscard, gnu::always_inline]]
    static inline long pread64(int fd, void *buf, size_t count, loff_t pos)
    {
        return sys::gen::syscall<SYS_pread64, long>(fd, buf, count, pos);
    }

    // SYS_access: 21
    [[nodiscard, gnu::always_inline]]
    static inline int access(const char *pathname, int mode)
    {
        return sys::gen::syscall<SYS_access, int>(pathname, mode);
    }

    // SYS_madvise: 28
    [[nodiscard, gnu::always_inline]]
    static inline int madvise(void *addr, size_t length, int advice)
    {
        return sys::gen::syscall<SYS_madvise, int>(addr, length, advice);
    }

    // SYS_getpid: 39
    [[nodiscard, gnu::always_inline]]
    static inline int getpid()
    {
        return sys::gen::syscall<SYS_getpid, int>();
    }

    // SYS_socket: 41
    [[nodiscard, gnu::always_inline]]
    static inline int socket(int domain, int type, int protocol)
    {
        return sys::gen::syscall<SYS_socket, int>(domain, type, protocol);
    }

    // SYS_bind: 49
    [[nodiscard, gnu::always_inline]]
    static inline int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
    {
        return sys::gen::syscall<SYS_bind, int>(sockfd, addr, addrlen);
    }

    // SYS_exit: 60
    [[noreturn, gnu::always_inline]]
    static inline void exit(int status)
    {
        for (;;)
            sys::gen::syscall<SYS_exit, long>(status);
        __builtin_unreachable();
    }

    // SYS_wait4: 61
    [[nodiscard, gnu::always_inline]]
    static inline pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage)
    {
        return sys::gen::syscall<SYS_wait4, pid_t>(pid, status, options, rusage);
    }

    // SYS_uname: 63 (this is actually newuname)
    [[nodiscard, gnu::always_inline]]
    static inline int uname(struct utsname *name)
    {
        return sys::gen::syscall<SYS_uname, int>(name);
    }

    // SYS_ftruncate: 77
    [[nodiscard, gnu::always_inline]]
    static inline int ftruncate(int fd, off_t length)
    {
        return sys::gen::syscall<SYS_ftruncate, int>(fd, length);
    }

    // SYS_ptrace: 101
    [[nodiscard, gnu::always_inline]]
    static inline long ptrace(enum __ptrace_request request, pid_t pid = 0, void *addr = nullptr,
                              void *data = nullptr)
    {
        return sys::gen::syscall<SYS_ptrace, long>(request, pid, addr, data);
    }

    // SYS_prctl: 157
    [[nodiscard, gnu::always_inline]]
    static inline long prctl(int option, unsigned long arg2 = 0, unsigned long arg3 = 0,
                             unsigned long arg4 = 0, unsigned long arg5 = 0)
    {
        return sys::gen::syscall<SYS_prctl, long>(option, arg2, arg3, arg4, arg5);
    }

    // SYS_timer_create: 222
    [[nodiscard, gnu::always_inline]]
    static inline int timer_create(clockid_t clockid, struct sigevent *sevp, timer_t *timerid)
    {
        return sys::gen::syscall<SYS_timer_create, int>(clockid, sevp, timerid);
    }

    // SYS_timer_settime: 223
    [[nodiscard, gnu::always_inline]]
    static inline int timer_settime(timer_t timerid, int flags, const struct itimerspec *new_value,
                                   struct itimerspec *old_value)
    {
        return sys::gen::syscall<SYS_timer_settime, int>(timerid, flags, new_value, old_value);
    }

    // SYS_exit_group: 231
    [[noreturn, gnu::always_inline]]
    static inline void exit_group(int status)
    {
        for (;;)
            sys::gen::syscall<SYS_exit_group, long>(status);
        __builtin_unreachable();
    }

    // SYS_openat: 257
    [[nodiscard, gnu::always_inline]]
    static inline int openat(int dirfd, const char *path, int flags, mode_t mode = 0)
    {
        return sys::gen::syscall<SYS_openat, int>(dirfd, path, flags, mode);
    }

    // SYS_readlinkat: 267
    [[nodiscard, gnu::always_inline]]
    static inline int readlinkat(int dirfd, const char *path, char *buffer, int buffer_size)
    {
        return sys::gen::syscall<SYS_readlinkat, int>(dirfd, path, buffer, buffer_size);
    }

    // SYS_process_vm_readv: 310
    [[nodiscard, gnu::always_inline]]
    static inline ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov,
                                           unsigned long liovcnt, const struct iovec *remote_iov,
                                           unsigned long riovcnt, unsigned long flags)
    {
        return sys::gen::syscall<SYS_process_vm_readv, ssize_t>(pid, local_iov, liovcnt, remote_iov,
                                                                riovcnt, flags);
    }

    // SYS_process_vm_writev: 311
    [[nodiscard, gnu::always_inline]]
    static inline ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov,
                                            unsigned long liovcnt, const struct iovec *remote_iov,
                                            unsigned long riovcnt, unsigned long flags)
    {
        return sys::gen::syscall<SYS_process_vm_writev, ssize_t>(pid, local_iov, liovcnt, remote_iov,
                                                                 riovcnt, flags);
    }

    // SYS_userfaultfd: 323
    [[nodiscard, gnu::always_inline]]
    static inline int userfaultfd(int flags)
    {
        return sys::gen::syscall<SYS_userfaultfd, int>(flags);
    }

    // SYS_clone3: 435
    [[nodiscard, gnu::always_inline]]
    static inline int clone3(struct clone_args *args, size_t size)
    {
        return sys::gen::syscall<SYS_clone3, int>(args, size);
    }

    // SYS_memfd_secret: 447
    [[nodiscard, gnu::always_inline]]
    static inline int memfd_secret(unsigned int flags)
    {
        return sys::gen::syscall<SYS_memfd_secret, int>(flags);
    }
}

namespace utils {
    template <typename Result>
    struct result_type {
        using signed_t = std::conditional_t<std::is_pointer_v<Result>, intptr_t, Result>;
        using unsigned_t = std::make_unsigned_t<signed_t>;
        constexpr static const auto error_limit_v = static_cast<unsigned_t>(
            static_cast<signed_t>(-0x1000)
        );

        template <typename T> constexpr static auto to_unsigned(T value)
        {
            return cpp::force_cast<unsigned_t>(value);
        }
        
        template <typename T> constexpr static auto to_signed(T value)
        {
            return cpp::force_cast<signed_t>(value);
        }
    };

    template <typename OnFail = decltype(&__syscall_failed)>
    [[gnu::always_inline]]
    static inline void assert(bool expression, OnFail failed = &__syscall_failed)
    {
        if (expression) [[likely]]
            return;
        failed();
        __builtin_unreachable();
    }

    template <typename Result, typename OnFail = decltype(&__syscall_failed)>
    [[gnu::always_inline]]
    static inline bool is_ok(Result result)
    {
        auto unsigned_v = result_type<Result>::to_unsigned(result);
        if (unsigned_v <= result_type<Result>::error_limit_v) [[likely]]
            return true;
        return false;
    }

    template <typename Result, typename OnFail = decltype(&__syscall_failed)>
    [[gnu::always_inline]]
    static inline Result check(Result result, OnFail failed = &__syscall_failed)
    {
        auto unsigned_v = result_type<Result>::to_unsigned(result);
        if (unsigned_v <= result_type<Result>::error_limit_v) [[likely]]
            return result;
        failed();
        __builtin_unreachable();
    }

    template <typename Result, typename Expected, typename OnFail = decltype(&__syscall_failed)>
    [[gnu::always_inline]]
    static inline Result check_exact(Result result, Expected expected, OnFail failed = &__syscall_failed)
    {
        auto unsigned_v = result_type<Result>::to_unsigned(result);
        auto expected_v = result_type<Result>::to_unsigned(expected);
        if (unsigned_v == expected_v) [[likely]]
            return result;
        failed();
        __builtin_unreachable();
    }

    template <typename Result, typename Expected, typename OnFail = decltype(&__syscall_failed)>
    [[gnu::always_inline]]
    static inline Result check_ok_or_exact(Result result, Expected expected, OnFail failed = &__syscall_failed)
    {
        auto unsigned_v = result_type<Result>::to_unsigned(result);
        auto expected_v = result_type<Result>::to_unsigned(expected);
        if (unsigned_v <= result_type<Result>::error_limit_v || unsigned_v == expected_v) [[likely]]
            return result;
        failed();
        __builtin_unreachable();
    }

    template <typename T, typename U>
    constexpr static inline T align_up(T value, U to)
    {
        T to_typed = static_cast<T>(to);
        if (value & (to_typed - 1))
            return value + to_typed - (value & (to_typed - 1));
        else
            return value;
    }

    template <typename T>
    consteval static inline T page_align_up(T value)
    {
        if (value & static_cast<T>(0xfff))
            return value + static_cast<T>(0x1000) - (value & static_cast<T>(0xfff));
        else
            return value;
    }

    [[gnu::always_inline]]
    static inline size_t strlen(const char *string)
    {
        size_t length = 0;
        while (string[length]) ++length;
        return length;
    }

    [[noreturn, gnu::always_inline]]
    static inline void exit_with_message(const char *message)
    {
        std::ignore = sys::write(STDERR_FILENO, "\x1b[31m", 5);
        std::ignore = sys::write(STDERR_FILENO, message, utils::strlen(message));
        std::ignore = sys::write(STDERR_FILENO, "\x1b[0m\n", 5);
        sys::exit_group(EXIT_FAILURE);
        __builtin_trap();
    }

    [[noreturn, gnu::always_inline]]
    static inline void exit_with_success(const char *message)
    {
        std::ignore = sys::write(STDERR_FILENO, "\x1b[32m", 5);
        std::ignore = sys::write(STDERR_FILENO, message, utils::strlen(message));
        std::ignore = sys::write(STDERR_FILENO, "\x1b[0m\n", 5);
        sys::exit_group(EXIT_SUCCESS);
        __builtin_trap();
    }
}
