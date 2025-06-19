#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <liburing.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_CQES 16384
#define MAX_SQES 16384

#include "generated.inc.c"

static inline int set_errno(int result)
{
    errno = result < 0 ? -result : 0;
    return result;
}

struct io_thread_arg {
    int from_fd;
    int to_fd;
    const char *name;
};

static void *io_thread(void *thread_arg)
{
    const struct io_thread_arg *arg = (const struct io_thread_arg *) thread_arg;
    int from_fd = arg->from_fd;
    int to_fd = arg->to_fd;
    const char *name = arg->name;

    prctl(PR_SET_NAME, name);
    for (;;) {
        // For some reason, using splice() here sometimes hangs the IORING_OP_SPLICE in pipe_lock in iter_file_splice_write.
        // Then, a further splice is needed to actually wake up the listener, which is annoying. This does not appear to occur
        // if we use the "old" read-write approach.
        // (sched_yield()-ing immediately tends to make this significantly more reproducible!)
        //   ssize_t bytes = splice(from_fd, NULL, to_fd, NULL, 0x1000, 0);
        //   if (bytes > 0 || (bytes < 0 && errno == EINTR))
        //       ;
        //   else if (bytes == 0 || (bytes < 0 && errno == EPIPE))
        //       return NULL;
        //   else if (bytes < 0)
        //       err(EXIT_FAILURE, "failed to splice from file descriptor %d into file descriptor %d (%s)", from_fd, to_fd, name);

        char buffer[1024];
        ssize_t bytes = read(from_fd, buffer, sizeof(buffer));
        if (bytes < 0 && errno == EINTR)
            continue;
        else if (bytes < 0 && errno != EPIPE)
            err(EXIT_FAILURE, "failed to read from file descriptor %d (%s)", from_fd, name);
        else if (bytes <= 0)
            return NULL;

        size_t offset = 0;
        while (bytes) {
            ssize_t out = write(to_fd, buffer + offset, bytes);
            if (out < 0 && errno == EINTR)
                continue;
            else if (out < 0 && errno != EPIPE)
                err(EXIT_FAILURE, "failed to write to file descriptor %d (%s)", to_fd, name);
            else if (out <= 0)
                return NULL;
            bytes -= out;
            offset += out;
        }
    }
}

static int make_pipe(const char *name, int fd, bool write)
{
    struct stat sb;
    if (fstat(fd, &sb))
        err(EXIT_FAILURE, "failed to fstat file descriptor %d", fd);
    if (S_ISFIFO(sb.st_mode))
        return fd; // Already a pipe

    int pipe_fds[2];
    if (pipe(pipe_fds))
        err(EXIT_FAILURE, "failed to create pipe");

    int renamed_fd = dup(fd);
    if (renamed_fd < 0)
        err(EXIT_FAILURE, "failed to duplicate file descriptor %d", fd);

    struct io_thread_arg *arg = malloc(sizeof(*arg));
    if (!arg)
        err(EXIT_FAILURE, "failed to allocate memory");
    arg->name = name;

    int replacement;
    if (write) {
        // This is a pipe that the program wants to write to.
        // Thus, splice from the read end into the original fd.
        // We want to use the write end as the replacement.
        arg->from_fd = pipe_fds[0];
        arg->to_fd = renamed_fd;
        replacement = pipe_fds[1];
    } else {
        // This is a pipe that the program wants to read from.
        // Splice from the original fd into the write end.
        // Use the read end as the replacement.
        arg->from_fd = renamed_fd;
        arg->to_fd = pipe_fds[1];
        replacement = pipe_fds[0];
    }

    if (dup2(replacement, fd) != fd)
        err(EXIT_FAILURE, "failed to replace file descriptor %d", fd);
    if (close(replacement))
        err(EXIT_FAILURE, "failed to close unused file descriptor");

    pthread_t thread;
    if ((errno = pthread_create(&thread, NULL, io_thread, arg)))
        err(EXIT_FAILURE, "failed to create IO thread");
    if ((errno = pthread_detach(thread)))
        err(EXIT_FAILURE, "failed to detach IO thread");

    return renamed_fd;
}

int main(void)
{
    // Unbuffer everything.
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    // Assert that we don't hold CAP_NET_ADMIN.
    // This is needed for conditionals in our io_uring machine.
    cap_t caps = cap_get_proc();
    cap_flag_value_t net_admin;
    if (caps == NULL)
        err(EXIT_FAILURE, "failed to query process capabilities");
    if (cap_get_flag(caps, CAP_NET_ADMIN, CAP_EFFECTIVE, &net_admin))
        err(EXIT_FAILURE, "failed to query capability set");
    if (net_admin)
        errx(EXIT_FAILURE, "please don't run this with elevated privileges");
    if (cap_free(caps))
        err(EXIT_FAILURE, "failed to free capability set");

    // Make stdin and stdout pipes (so we can use splice).
    make_pipe("stdin", STDIN_FILENO, false);
    make_pipe("stdout", STDOUT_FILENO, true);

    // Set up the io_uring
    struct io_uring ring = { 0 };
    struct io_uring_params params = { 0 };
    params.cq_entries = MAX_CQES;
    params.flags = IORING_SETUP_COOP_TASKRUN | IORING_SETUP_CQSIZE;
    if (set_errno(io_uring_queue_init_params(MAX_SQES, &ring, &params)) < 0)
        err(EXIT_FAILURE, "failed to initialize io_uring");
    if (!(params.features & IORING_FEAT_LINKED_FILE))
        errx(EXIT_FAILURE, "kernels prior to 5.17 lack sane linked file handling (IORING_FEAT_LINKED_FILE)");
    if (!(params.features & IORING_FEAT_CQE_SKIP))
        errx(EXIT_FAILURE, "kernels prior to 5.17 lack CQE skipping (IORING_FEAT_CQE_SKIP)");
    if (!(params.features & IORING_FEAT_RW_CUR_POS))
        errx(EXIT_FAILURE, "kernels prior to 5.6 lack proper read/write offset support (IORING_FEAT_RW_CUR_POS)");
    if (set_errno(io_uring_register_files_sparse(&ring, 128)) < 0)
        err(EXIT_FAILURE, "failed to set up file set for io_uring");

    // Set up the register space
    int mem_fd = memfd_create("memfd", MFD_CLOEXEC);
    if (mem_fd < 0)
        err(EXIT_FAILURE, "failed to create memfd");
    if (ftruncate(mem_fd, 0x1000))
        err(EXIT_FAILURE, "failed to truncate memfd");

    // Set up the eventfd for maths
    int event_fd = eventfd(0, EFD_CLOEXEC);
    if (event_fd < 0)
        err(EXIT_FAILURE, "failed to create eventfd");

    // Set up the pipe for direct moves
    int pipe_fds[2];
    if (pipe(pipe_fds))
        err(EXIT_FAILURE, "failed to create pipe");

    // Map the file descriptors into the io_uring
    int fixed_fds[] = { STDIN_FILENO, STDOUT_FILENO, mem_fd, event_fd, pipe_fds[0], pipe_fds[1] };
    const size_t fixed_fd_count = sizeof(fixed_fds) / sizeof(fixed_fds[0]);
    if (set_errno(io_uring_register_files_update(&ring, 0, fixed_fds, fixed_fd_count)) != fixed_fd_count)
        err(EXIT_FAILURE, "failed to register file descriptors with io_uring");

    // Close all the file descriptors that we will only access from io_uring.
    const int close_fds[] = { STDIN_FILENO, mem_fd, pipe_fds[0], pipe_fds[1] };
    for (size_t fd_index = 0; fd_index < sizeof(close_fds) / sizeof(close_fds[0]); ++fd_index)
        if (close(close_fds[fd_index]))
            err(EXIT_FAILURE, "failed to close file descriptor");

    // Register scratch and constants as fixed buffers
    const size_t buffer_count = sizeof(buffers) / sizeof(buffers[0]);
    if (set_errno(io_uring_register_buffers(&ring, buffers, buffer_count)))
        err(EXIT_FAILURE, "failed to register buffers with io_uring");

    // The main loop. We can't re-queue things infinitely with io_uring yet, so this needs to happen in the "driver" code
    struct io_uring_cqe *cqe = NULL;
    uint64_t exit_code;
    for (;;) {
        // Copy the SQEs into the actual submission rings
        for (size_t i = 0; i < SQE_COUNT; ++i) {
            struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
            if (!sqe)
                err(EXIT_FAILURE, "failed to allocate SQE");
            memcpy(sqe, &sqes[i], sizeof(*sqe));
        }

        // Submit our SQEs
        if (set_errno(io_uring_submit(&ring)) < 0)
            err(EXIT_FAILURE, "failed to submit SQEs to io_uring");

        // Wait for CQEs to appear.
        for (;;) {
            if (set_errno(io_uring_wait_cqe(&ring, &cqe)) < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                    err(EXIT_FAILURE, "failed to wait for CQEs");
                continue;
            }
            if (!cqe)
                errx(EXIT_FAILURE, "failed to retrieve CQE from io_uring");
            struct io_uring_cqe local = *cqe;
            io_uring_cqe_seen(&ring, cqe);

            if (local.res == -ECANCELED)
                ; // Canceled operations are just fine, we can ignore the CQE.
            else if (local.user_data & 1)
                ; // These are explicitly marked as "allowed to produce CQEs", and we have to ignore the result.
            else if (!local.user_data)
                break; // This is the "tail" CQE that tells us to resubmit the SQEs. Just leave the handler loop.
            else if (local.res >= 0)
                goto done; // Something completed successfully, it must be an exit instruction.
            else
                errx(EXIT_FAILURE, "internal error"); // Unexpected CQE - something went wrong
        }
    }

done:
    if (read(event_fd, &exit_code, sizeof(exit_code)) != sizeof(exit_code))
        err(EXIT_FAILURE, "failed to read exit code");

    // Allow a little bit of time for pending writes from the IO threads
    for (;;) {
        int bytes = 0;
        if (ioctl(STDOUT_FILENO, FIONREAD, &bytes))
            err(EXIT_FAILURE, "failed to query pipe status");
        if (bytes <= 0)
            break;
        usleep(100ul * 1000ul);
    }

    return exit_code & 0xff;
}
