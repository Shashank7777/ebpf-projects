#!/usr/bin/python3
# Optimized File System Monitoring using eBPF

from bcc import BPF
import time
import json
import psutil  # Install via `pip install psutil`

# eBPF Program (C) embedded as a string
ebpf_program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/limits.h>

struct event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[NAME_MAX];
    int syscall;
};

BPF_PERF_OUTPUT(events);

// Ignore common system daemons in kernel space
static inline bool is_ignored_process(char *comm) {
    return (comm[0] == 's' && comm[1] == 's' && comm[2] == 'h') ||  // sshd
           (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's') ||  // systemd
           (comm[0] == 'd' && comm[1] == 'b' && comm[2] == 'u') ||  // dbus-daemon
           (comm[0] == 'p' && comm[1] == 'o' && comm[2] == 'l') ||  // polkitd
           (comm[0] == 'g' && comm[1] == 'd' && comm[2] == 'b');    // gdbus
}

// Custom function for 'open' syscall
int trace_open(struct pt_regs *ctx, const char __user *filename, int flags) {
    struct event_t event = {};
    u32 pid = bpf_get_current_pid_tgid();

    event.pid = pid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    if (is_ignored_process(event.comm)) return 0;  // Ignore system daemons

    bpf_probe_read_user_str(event.filename, sizeof(event.filename), filename);
    event.syscall = 2;  // "open" syscall
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Custom function for 'read' syscall
int trace_read(struct pt_regs *ctx, int fd, void *buf, size_t count) {
    struct event_t event = {};
    u32 pid = bpf_get_current_pid_tgid();

    event.pid = pid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    if (is_ignored_process(event.comm)) return 0;

    event.syscall = 0;  // "read" syscall
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Custom function for 'write' syscall
int trace_write(struct pt_regs *ctx, int fd, const void *buf, size_t count) {
    struct event_t event = {};
    u32 pid = bpf_get_current_pid_tgid();

    event.pid = pid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    if (is_ignored_process(event.comm)) return 0;

    event.syscall = 1;  // "write" syscall
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Define system call names
syscall_names = {0: "READ", 1: "WRITE", 2: "OPEN"}

# Load eBPF program with increased buffer size
bpf = BPF(text=ebpf_program)
bpf["events"].open_perf_buffer(lambda cpu, data, size: print_event(cpu, data, size), page_cnt=256)

# Attach probes to system calls
bpf.attach_kprobe(event=bpf.get_syscall_fnname("open"), fn_name="trace_open")
bpf.attach_kprobe(event=bpf.get_syscall_fnname("read"), fn_name="trace_read")
bpf.attach_kprobe(event=bpf.get_syscall_fnname("write"), fn_name="trace_write")

# List to store logs
file_logs = {}
last_event_time = {}

# Event callback function
def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    process_name = event.comm.decode()

    # Ignore system daemons in user space (extra layer of filtering)
    ignore_processes = {"rsyslogd", "gdbus", "dbus-daemon", "polkitd", "systemd-timesyncd", "systemd", "journalctl"}
    if process_name in ignore_processes:
        return

    # Get user ID (UID) and ignore system processes
    try:
        uid = psutil.Process(event.pid).uids().real
        if uid == 0:
            return
    except psutil.NoSuchProcess:
        return

    # Rate limit: Only allow 1 log per 2 seconds per (PID, syscall)
    key = (event.pid, event.syscall)
    current_time = time.time()
    if key in last_event_time and (current_time - last_event_time[key] < 2):  # Increased to 2 seconds
        return
    last_event_time[key] = current_time  # Update last event time

    log_entry = {
        "PID": event.pid,
        "Process": process_name,
        "Syscall": syscall_names.get(event.syscall, "UNKNOWN"),
        "Filename": event.filename.decode() if event.syscall == 2 else "N/A",
        "Timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    # Store log
    file_logs[event.pid] = log_entry
    print(f"[{log_entry['Timestamp']}] PID {log_entry['PID']}: {log_entry['Process']} {log_entry['Syscall']} {log_entry['Filename']}")

# Start Monitoring
print("Monitoring file system activity... Press Ctrl+C to stop.")

try:
    while True:
        bpf.perf_buffer_poll()
except KeyboardInterrupt:
    print(" Exiting...")
