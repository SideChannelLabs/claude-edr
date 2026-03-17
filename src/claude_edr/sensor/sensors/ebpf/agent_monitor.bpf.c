/*
 * agent_monitor.bpf.c - eBPF program for monitoring AI coding agent process trees
 *
 * Uses RAW_TRACEPOINT_PROBE for sched events (kernel-version stable)
 * and TRACEPOINT_PROBE for syscall events.
 *
 * Captures:
 *   - Process execution (sched_process_exec) - tracks agent child processes
 *   - File opens (sys_enter_openat) - what files MCP servers access
 *   - Network connections (sys_enter_connect) - where MCP servers connect
 *   - Pipe/socket I/O (write/read/sendto/recvfrom/sendmsg/recvmsg) - MCP JSON-RPC traffic
 *   - Process exit (sched_process_exit) - cleanup tracked PIDs
 *
 * PID filtering: only monitors processes in tracked agent process trees.
 * Userspace seeds the tracked_pids map with agent root PIDs.
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/uio.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>

/* Max bytes to capture from pipe write buffers (MCP JSON-RPC) */
#define MAX_PIPE_BUF 4096

/* Max path length to capture from openat */
#define MAX_PATH_LEN 256

/* Event types sent to userspace */
#define EVENT_EXEC      1
#define EVENT_OPENAT    2
#define EVENT_CONNECT   3
#define EVENT_PIPE_WRITE 4
#define EVENT_EXIT      5
#define EVENT_SSL_WRITE 6
#define EVENT_SSL_READ  7

/* ── Event structures ─────────────────────────────────────────── */

struct exec_event {
    u32 event_type;
    u32 pid;
    u32 ppid;
    u32 uid;
    u64 timestamp_ns;
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH_LEN];
};

struct openat_event {
    u32 event_type;
    u32 pid;
    u32 ppid;
    u64 timestamp_ns;
    int flags;
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH_LEN];
};

struct connect_event {
    u32 event_type;
    u32 pid;
    u64 timestamp_ns;
    u16 family;
    u16 port;
    u32 addr_v4;
    u8  addr_v6[16];
    char comm[TASK_COMM_LEN];
};

struct pipe_event {
    u32 event_type;
    u32 pid;
    u64 timestamp_ns;
    u32 fd;
    u32 count;
    u32 buf_len;  /* actual bytes captured (may be < count) */
    char comm[TASK_COMM_LEN];
    char buf[MAX_PIPE_BUF];
};

struct exit_event {
    u32 event_type;
    u32 pid;
    u64 timestamp_ns;
    int exit_code;
    char comm[TASK_COMM_LEN];
};

struct ssl_event {
    u32 event_type;
    u32 pid;
    u64 timestamp_ns;
    u32 len;       /* bytes written/read */
    u32 buf_len;   /* bytes captured */
    char comm[TASK_COMM_LEN];
    char buf[MAX_PIPE_BUF];
};

/* ── BPF Maps ─────────────────────────────────────────────────── */

/* Tracked PIDs: pid -> root_agent_pid (0 = is root agent itself) */
BPF_HASH(tracked_pids, u32, u32, 4096);

/* Tracked IPC fds: (pid << 32 | fd) -> 1 for MCP stdio pipes/sockets */
BPF_HASH(tracked_pipe_fds, u64, u8, 1024);

/* Ring buffer for events to userspace */
BPF_PERF_OUTPUT(events);

/* Per-CPU scratch buffers for large event structs (>512 byte BPF stack limit) */
BPF_PERCPU_ARRAY(pipe_scratch, struct pipe_event, 1);
BPF_PERCPU_ARRAY(ssl_scratch, struct ssl_event, 1);

/* Scratch space for pipe read - stores (buf_ptr, fd) between entry/return */
struct pipe_read_args {
    u64 buf_ptr;
    u32 fd;
};
BPF_HASH(pipe_read_args_map, u32, struct pipe_read_args, 256);

/* Scratch space for recvmsg - stores (buf_ptr, fd) between entry/return */
struct recvmsg_args {
    u64 buf_ptr;
    u32 fd;
};
BPF_HASH(recvmsg_args_map, u32, struct recvmsg_args, 256);

/* Scratch space for recvfrom - stores (buf_ptr, fd) between entry/return */
struct recvfrom_args {
    u64 buf_ptr;
    u32 fd;
};
BPF_HASH(recvfrom_args_map, u32, struct recvfrom_args, 256);

/* Scratch space for SSL read - stores (buf_ptr, len) between entry/return */
struct ssl_args {
    u64 buf_ptr;
    u32 len;
};
BPF_HASH(ssl_write_args, u32, struct ssl_args, 256);
BPF_HASH(ssl_read_args, u32, struct ssl_args, 256);

/* ── Helper: check if PID is tracked ──────────────────────────── */

static inline int is_tracked(u32 pid) {
    return tracked_pids.lookup(&pid) != NULL;
}

/* ── Raw Tracepoint: sched_process_exec ──────────────────────── */
/* Proto: (struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
   Uses RAW_TRACEPOINT_PROBE for kernel-version stability. */

RAW_TRACEPOINT_PROBE(sched_process_exec) {
    struct task_struct *task = (struct task_struct *)ctx->args[0];
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];

    u32 pid;
    bpf_probe_read_kernel(&pid, sizeof(pid), &task->tgid);

    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    u32 ppid;
    bpf_probe_read_kernel(&ppid, sizeof(ppid), &parent->tgid);

    /* Check if this process OR its parent is tracked */
    u32 *root_pid_ptr = tracked_pids.lookup(&ppid);
    if (!root_pid_ptr && !is_tracked(pid)) {
        return 0;
    }

    /* Auto-track: child inherits parent's root agent PID */
    u32 root_pid = root_pid_ptr ? *root_pid_ptr : pid;
    /* If parent is a root agent (value=0), use parent's PID as root */
    if (root_pid == 0) root_pid = ppid;
    tracked_pids.update(&pid, &root_pid);

    /* Emit exec event */
    struct exec_event evt = {};
    evt.event_type = EVENT_EXEC;
    evt.pid = pid;
    evt.ppid = ppid;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    /* Read filename from bprm */
    const char *filename;
    bpf_probe_read_kernel(&filename, sizeof(filename), &bprm->filename);
    bpf_probe_read_kernel_str(&evt.filename, sizeof(evt.filename), filename);

    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

/* ── Raw Tracepoint: sched_process_exit ──────────────────────── */
/* Proto: (struct task_struct *p) */

RAW_TRACEPOINT_PROBE(sched_process_exit) {
    struct task_struct *task = (struct task_struct *)ctx->args[0];

    u32 pid;  /* TGID = process ID */
    bpf_probe_read_kernel(&pid, sizeof(pid), &task->tgid);

    if (!is_tracked(pid)) return 0;

    /* Only clean up when the thread group leader exits, not worker threads.
       Python/Node use worker threads for I/O; their exit must NOT untrack
       the whole process.  task->pid = TID, task->tgid = TGID. */
    u32 tid;
    bpf_probe_read_kernel(&tid, sizeof(tid), &task->pid);
    if (tid != pid) return 0;

    struct exit_event evt = {};
    evt.event_type = EVENT_EXIT;
    evt.pid = pid;
    evt.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    events.perf_submit(ctx, &evt, sizeof(evt));

    /* Remove from tracked set */
    tracked_pids.delete(&pid);
    return 0;
}

/* ── Tracepoint: sys_enter_openat ─────────────────────────────── */

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid)) return 0;

    int flags = args->flags;

    /* Only emit for WRITE operations (O_WRONLY=1, O_RDWR=2, O_CREAT=0x40,
       O_TRUNC=0x200). Read-only opens (Python imports, node_modules) are
       extremely noisy (~10k/sec) and flood the perf buffer. */
    int write_flags = 0x1 | 0x2 | 0x40 | 0x200;  /* O_WRONLY|O_RDWR|O_CREAT|O_TRUNC */
    if (!(flags & write_flags))
        return 0;

    struct openat_event evt = {};
    evt.event_type = EVENT_OPENAT;
    evt.pid = pid;
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.flags = flags;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename),
                            (const char *)args->filename);

    /* Skip noisy system paths even for writes */
    char prefix[8];
    bpf_probe_read_kernel(&prefix, sizeof(prefix), evt.filename);
    if (prefix[0] == '/') {
        if (prefix[1] == 'p' && prefix[2] == 'r' && prefix[3] == 'o' && prefix[4] == 'c')
            return 0;  /* /proc/... */
        if (prefix[1] == 's' && prefix[2] == 'y' && prefix[3] == 's')
            return 0;  /* /sys/... */
        if (prefix[1] == 'd' && prefix[2] == 'e' && prefix[3] == 'v')
            return 0;  /* /dev/... */
        if (prefix[1] == 't' && prefix[2] == 'm' && prefix[3] == 'p')
            return 0;  /* /tmp/... */
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(&evt.ppid, sizeof(evt.ppid), &task->real_parent->tgid);

    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

/* ── Tracepoint: sys_enter_connect ────────────────────────────── */

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid)) return 0;

    /* Read sockaddr to get address family */
    struct sockaddr sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), (void *)args->uservaddr);

    struct connect_event evt = {};
    evt.event_type = EVENT_CONNECT;
    evt.pid = pid;
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.family = sa.sa_family;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    if (sa.sa_family == AF_INET) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), (void *)args->uservaddr);
        evt.port = __builtin_bswap16(sin.sin_port);
        evt.addr_v4 = sin.sin_addr.s_addr;
    } else if (sa.sa_family == AF_INET6) {
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), (void *)args->uservaddr);
        evt.port = __builtin_bswap16(sin6.sin6_port);
        bpf_probe_read_kernel(&evt.addr_v6, sizeof(evt.addr_v6),
                              &sin6.sin6_addr);
    } else {
        /* Skip non-IP connections (AF_UNIX, etc.) */
        return 0;
    }

    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

/* ── Tracepoint: sys_enter_write (pipe capture) ───────────────── */
/* Captures write() calls on tracked pipe fds for MCP JSON-RPC */

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid)) return 0;

    u32 fd = args->fd;
    u64 key = ((u64)pid << 32) | fd;

    /* Only capture writes on tracked pipe fds */
    if (!tracked_pipe_fds.lookup(&key)) return 0;

    /* Use per-CPU scratch buffer (too large for BPF stack) */
    u32 zero = 0;
    struct pipe_event *evt = pipe_scratch.lookup(&zero);
    if (!evt) return 0;

    evt->event_type = EVENT_PIPE_WRITE;
    evt->pid = pid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->fd = fd;
    evt->count = args->count;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    /* Capture buffer contents (up to 4000 bytes).
       The BPF verifier requires an explicit AND mask to prove the size
       arg to bpf_probe_read_user is bounded and non-negative.
       The asm volatile barrier prevents clang from proving the AND is
       redundant and optimizing it away. */
    u32 to_read = args->count;
    if (to_read > 4000) to_read = 4000;
    asm volatile("" : "+r"(to_read));
    to_read &= (MAX_PIPE_BUF - 1);
    evt->buf_len = to_read;
    bpf_probe_read_user(&evt->buf, to_read, (void *)args->buf);

    events.perf_submit(args, evt, sizeof(*evt));
    return 0;
}

/* ── Tracepoint: sys_enter_writev (vectored pipe capture) ──────── */
/* Captures writev() calls on tracked pipe fds.
   Bun/Node.js often uses writev() instead of write() for pipe I/O.
   We read from the first iovec entry only (sufficient for JSON-RPC). */

TRACEPOINT_PROBE(syscalls, sys_enter_writev) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid)) return 0;

    u32 fd = args->fd;
    u64 key = ((u64)pid << 32) | fd;

    /* Only capture writes on tracked pipe fds */
    if (!tracked_pipe_fds.lookup(&key)) return 0;

    /* Read first iovec entry from userspace vector array */
    struct iovec iov = {};
    if (bpf_probe_read_user(&iov, sizeof(iov), (void *)args->vec) < 0)
        return 0;

    if (!iov.iov_base || iov.iov_len == 0)
        return 0;

    /* Use per-CPU scratch buffer */
    u32 zero = 0;
    struct pipe_event *evt = pipe_scratch.lookup(&zero);
    if (!evt) return 0;

    evt->event_type = EVENT_PIPE_WRITE;
    evt->pid = pid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->fd = fd;
    evt->count = (u32)iov.iov_len;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    /* Capture buffer from first iovec (same verifier pattern as write) */
    u32 to_read = (u32)iov.iov_len;
    if (to_read > 4000) to_read = 4000;
    asm volatile("" : "+r"(to_read));
    to_read &= (MAX_PIPE_BUF - 1);
    evt->buf_len = to_read;
    bpf_probe_read_user(&evt->buf, to_read, iov.iov_base);

    events.perf_submit(args, evt, sizeof(*evt));
    return 0;
}

/* ── Tracepoint: sys_enter_read / sys_exit_read (pipe read capture) ── */
/* Captures read() on tracked pipe fds (MCP server stdin).
   Uses entry/exit pair: entry saves buf pointer, exit reads filled buffer.

   IMPORTANT: The fd check is in sys_exit_read, NOT sys_enter_read.
   This handles the race where the MCP server's read() is already blocking
   when the scanner discovers it and registers fds in tracked_pipe_fds.
   If we checked fds at entry time, we'd miss the first request entirely
   because read() was called before the fd was registered. */

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid)) return 0;

    /* Save buf pointer for ALL reads by tracked PIDs.
       The fd filtering happens in sys_exit_read instead, so we capture
       reads that started before fds were registered in the BPF map. */
    struct pipe_read_args pra = {};
    pra.buf_ptr = (u64)args->buf;
    pra.fd = args->fd;
    pipe_read_args_map.update(&pid, &pra);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct pipe_read_args *pra = pipe_read_args_map.lookup(&pid);
    if (!pra) return 0;

    /* Check fd tracking HERE (not in entry) to handle the race where
       fds get registered between read() entry and exit. */
    u64 key = ((u64)pid << 32) | pra->fd;
    if (!tracked_pipe_fds.lookup(&key)) {
        pipe_read_args_map.delete(&pid);
        return 0;
    }

    long ret = args->ret;
    if (ret <= 0) {
        pipe_read_args_map.delete(&pid);
        return 0;
    }

    u32 zero = 0;
    struct pipe_event *evt = pipe_scratch.lookup(&zero);
    if (!evt) {
        pipe_read_args_map.delete(&pid);
        return 0;
    }

    evt->event_type = EVENT_PIPE_WRITE;  /* Reuse: same JSON-RPC parsing */
    evt->pid = pid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->fd = pra->fd;
    evt->count = (u32)ret;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    u32 to_read = (u32)ret;
    if (to_read > 4000) to_read = 4000;
    asm volatile("" : "+r"(to_read));
    to_read &= (MAX_PIPE_BUF - 1);
    evt->buf_len = to_read;
    bpf_probe_read_user(&evt->buf, to_read, (void *)pra->buf_ptr);

    events.perf_submit(args, evt, sizeof(*evt));
    pipe_read_args_map.delete(&pid);
    return 0;
}

/* ── Tracepoint: sys_enter_sendmsg (socket send capture) ──────── */
/* Captures sendmsg() on tracked fds. Claude Code uses socketpair()
   for MCP servers, so JSON-RPC requests go via sendmsg not write. */

TRACEPOINT_PROBE(syscalls, sys_enter_sendmsg) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid)) return 0;

    u32 fd = args->fd;
    u64 key = ((u64)pid << 32) | fd;

    /* Only capture on tracked fds */
    if (!tracked_pipe_fds.lookup(&key)) return 0;

    /* Read msghdr to get iovec */
    struct user_msghdr mh = {};
    bpf_probe_read_user(&mh, sizeof(mh), (void *)args->msg);

    if (!mh.msg_iov || mh.msg_iovlen == 0) return 0;

    /* Read first iovec */
    struct iovec iov = {};
    bpf_probe_read_user(&iov, sizeof(iov), mh.msg_iov);

    if (!iov.iov_base || iov.iov_len == 0) return 0;

    u32 zero = 0;
    struct pipe_event *evt = pipe_scratch.lookup(&zero);
    if (!evt) return 0;

    evt->event_type = EVENT_PIPE_WRITE;  /* Reuse: same JSON-RPC parsing */
    evt->pid = pid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->fd = fd;
    evt->count = (u32)iov.iov_len;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    u32 to_read = (u32)iov.iov_len;
    if (to_read > 4000) to_read = 4000;
    asm volatile("" : "+r"(to_read));
    to_read &= (MAX_PIPE_BUF - 1);
    evt->buf_len = to_read;
    bpf_probe_read_user(&evt->buf, to_read, iov.iov_base);

    events.perf_submit(args, evt, sizeof(*evt));
    return 0;
}

/* ── Tracepoint: sys_enter_recvmsg / sys_exit_recvmsg ──────────── */
/* Captures recvmsg() on tracked fds. MCP server responses may come
   via recvmsg on socketpair instead of read on pipe.
   Same deferred fd-check pattern as read hooks above. */

TRACEPOINT_PROBE(syscalls, sys_enter_recvmsg) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid)) return 0;

    u32 fd = args->fd;

    /* Read msghdr to get iovec buf pointer */
    struct user_msghdr mh = {};
    bpf_probe_read_user(&mh, sizeof(mh), (void *)args->msg);

    if (!mh.msg_iov || mh.msg_iovlen == 0) return 0;

    struct iovec iov = {};
    bpf_probe_read_user(&iov, sizeof(iov), mh.msg_iov);

    if (!iov.iov_base) return 0;

    /* Save buf pointer for ALL recvmsg by tracked PIDs.
       fd check deferred to exit hook (same race fix as read). */
    struct recvmsg_args rma = {};
    rma.buf_ptr = (u64)iov.iov_base;
    rma.fd = fd;
    recvmsg_args_map.update(&pid, &rma);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvmsg) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct recvmsg_args *rma = recvmsg_args_map.lookup(&pid);
    if (!rma) return 0;

    /* Check fd tracking HERE (deferred from entry) */
    u64 key = ((u64)pid << 32) | rma->fd;
    if (!tracked_pipe_fds.lookup(&key)) {
        recvmsg_args_map.delete(&pid);
        return 0;
    }

    long ret = args->ret;
    if (ret <= 0) {
        recvmsg_args_map.delete(&pid);
        return 0;
    }

    u32 zero = 0;
    struct pipe_event *evt = pipe_scratch.lookup(&zero);
    if (!evt) {
        recvmsg_args_map.delete(&pid);
        return 0;
    }

    evt->event_type = EVENT_PIPE_WRITE;  /* Reuse: same JSON-RPC parsing */
    evt->pid = pid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->fd = rma->fd;
    evt->count = (u32)ret;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    u32 to_read = (u32)ret;
    if (to_read > 4000) to_read = 4000;
    asm volatile("" : "+r"(to_read));
    to_read &= (MAX_PIPE_BUF - 1);
    evt->buf_len = to_read;
    bpf_probe_read_user(&evt->buf, to_read, (void *)rma->buf_ptr);

    events.perf_submit(args, evt, sizeof(*evt));
    recvmsg_args_map.delete(&pid);
    return 0;
}

/* ── Tracepoint: sys_enter_sendto (socket send capture) ────────── */
/* Captures sendto() on tracked fds. Python socket.send() maps to
   sendto(fd, buf, len, flags, NULL, 0) on Linux. This covers both
   send() and sendto() since send() is just sendto() with NULL addr. */

TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid)) return 0;

    u32 fd = args->fd;
    u64 key = ((u64)pid << 32) | fd;

    /* Only capture on tracked fds */
    if (!tracked_pipe_fds.lookup(&key)) return 0;

    u32 zero = 0;
    struct pipe_event *evt = pipe_scratch.lookup(&zero);
    if (!evt) return 0;

    evt->event_type = EVENT_PIPE_WRITE;  /* Reuse: same JSON-RPC parsing */
    evt->pid = pid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->fd = fd;
    evt->count = (u32)args->len;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    u32 to_read = (u32)args->len;
    if (to_read > 4000) to_read = 4000;
    asm volatile("" : "+r"(to_read));
    to_read &= (MAX_PIPE_BUF - 1);
    evt->buf_len = to_read;
    bpf_probe_read_user(&evt->buf, to_read, (void *)args->buff);

    events.perf_submit(args, evt, sizeof(*evt));
    return 0;
}

/* ── Tracepoint: sys_enter_recvfrom / sys_exit_recvfrom ──────── */
/* Captures recvfrom() on tracked fds. Python socket.recv() maps to
   recvfrom(fd, buf, size, flags, NULL, NULL) on Linux.
   Same deferred fd-check pattern as read and recvmsg hooks. */

TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid)) return 0;

    /* Save buf pointer for ALL recvfrom by tracked PIDs.
       fd check deferred to exit hook (same race fix as read). */
    struct recvfrom_args rfa = {};
    rfa.buf_ptr = (u64)args->ubuf;
    rfa.fd = args->fd;
    recvfrom_args_map.update(&pid, &rfa);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct recvfrom_args *rfa = recvfrom_args_map.lookup(&pid);
    if (!rfa) return 0;

    /* Check fd tracking HERE (deferred from entry) */
    u64 key = ((u64)pid << 32) | rfa->fd;
    if (!tracked_pipe_fds.lookup(&key)) {
        recvfrom_args_map.delete(&pid);
        return 0;
    }

    long ret = args->ret;
    if (ret <= 0) {
        recvfrom_args_map.delete(&pid);
        return 0;
    }

    u32 zero = 0;
    struct pipe_event *evt = pipe_scratch.lookup(&zero);
    if (!evt) {
        recvfrom_args_map.delete(&pid);
        return 0;
    }

    evt->event_type = EVENT_PIPE_WRITE;  /* Reuse: same JSON-RPC parsing */
    evt->pid = pid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->fd = rfa->fd;
    evt->count = (u32)ret;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    u32 to_read = (u32)ret;
    if (to_read > 4000) to_read = 4000;
    asm volatile("" : "+r"(to_read));
    to_read &= (MAX_PIPE_BUF - 1);
    evt->buf_len = to_read;
    bpf_probe_read_user(&evt->buf, to_read, (void *)rfa->buf_ptr);

    events.perf_submit(args, evt, sizeof(*evt));
    recvfrom_args_map.delete(&pid);
    return 0;
}

/* ── Uprobe: SSL_write entry ──────────────────────────────────── */
/* int SSL_write(SSL *ssl, const void *buf, int num)
   Captures plaintext buffer before BoringSSL/OpenSSL encrypts it. */

int ssl_write_entry(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid)) return 0;

    /* buf = arg2 (RSI), num = arg3 (RDX) on x86_64 */
    struct ssl_args sa = {};
    sa.buf_ptr = PT_REGS_PARM2(ctx);
    sa.len = (u32)PT_REGS_PARM3(ctx);
    ssl_write_args.update(&pid, &sa);

    u32 zero = 0;
    struct ssl_event *evt = ssl_scratch.lookup(&zero);
    if (!evt) return 0;

    evt->event_type = EVENT_SSL_WRITE;
    evt->pid = pid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->len = sa.len;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    u32 to_read = sa.len;
    if (to_read > 4000) to_read = 4000;
    asm volatile("" : "+r"(to_read));
    to_read &= (MAX_PIPE_BUF - 1);
    evt->buf_len = to_read;
    bpf_probe_read_user(&evt->buf, to_read, (void *)sa.buf_ptr);

    events.perf_submit(ctx, evt, sizeof(*evt));
    return 0;
}

/* ── Uprobe: SSL_read return ──────────────────────────────────── */
/* int SSL_read(SSL *ssl, void *buf, int num)
   We attach to ENTRY to save buf pointer, then RETURN to read
   the decrypted data after OpenSSL fills the buffer. */

int ssl_read_entry(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid)) return 0;

    struct ssl_args sa = {};
    sa.buf_ptr = PT_REGS_PARM2(ctx);
    sa.len = (u32)PT_REGS_PARM3(ctx);
    ssl_read_args.update(&pid, &sa);
    return 0;
}

int ssl_read_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct ssl_args *sa = ssl_read_args.lookup(&pid);
    if (!sa) return 0;

    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) {
        ssl_read_args.delete(&pid);
        return 0;
    }

    u32 zero = 0;
    struct ssl_event *evt = ssl_scratch.lookup(&zero);
    if (!evt) {
        ssl_read_args.delete(&pid);
        return 0;
    }

    evt->event_type = EVENT_SSL_READ;
    evt->pid = pid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->len = (u32)ret;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    u32 to_read = (u32)ret;
    if (to_read > 4000) to_read = 4000;
    asm volatile("" : "+r"(to_read));
    to_read &= (MAX_PIPE_BUF - 1);
    evt->buf_len = to_read;
    bpf_probe_read_user(&evt->buf, to_read, (void *)sa->buf_ptr);

    events.perf_submit(ctx, evt, sizeof(*evt));

    ssl_read_args.delete(&pid);
    return 0;
}
