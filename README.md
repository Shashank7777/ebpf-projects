### File Monitor

This program monitors file system activity in real-time using eBPF (Extended Berkeley Packet Filter). It hooks into syscalls (open, read, and write) and logs file operations performed by different processes on the system.
🛠️ How It Works

- Attaches eBPF Probes to Syscalls:
        Hooks into open(), read(), and write() syscalls in the Linux kernel.
        Captures process ID (PID), process name (comm), syscall type (OPEN, READ, WRITE), and filename (for open).

- Filters Out Unwanted System Processes:
        Excludes system daemons (systemd, dbus-daemon, polkitd, etc.).
        Ignores root (UID 0) processes to reduce noise.

- Efficient Logging with Rate-Limiting:
        Limits logs to one per process/syscall every 2 seconds to prevent flooding.

- Real-Time Monitoring in Terminal:
        Displays logs in human-readable format.


📌 Functions and Their Purpose
1. trace_open() 
```c
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
```
🔹 Purpose:

- This function triggers whenever a file is opened (open() syscall).
- Retrieves the process ID (pid) and process name (comm).
- Reads the filename being opened (bpf_probe_read_user_str()).
- Sends data to user-space for logging.

2. trace_read()
```c
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
```
🔹 Purpose:

- Captures read() system calls when a process reads from a file.
- Retrieves the PID and process name of the process performing the read.
- Sends the event to user-space for logging.

🔹 Limitation:

- Does NOT capture filenames because read() uses file descriptors (fd) instead of direct filenames.

3. trace_write() 
```c
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
```
🔹 Purpose:
- Captures write() system calls, triggered when a process writes to a file.
- Retrieves the process ID and process name.
- Sends the event to user-space for logging.

🔹 Limitation:
- Does NOT show filenames because write() only interacts with file descriptors (fd).

4. is_ignored_process() 
```c
static inline bool is_ignored_process(char *comm) {
    return (comm[0] == 's' && comm[1] == 's' && comm[2] == 'h') ||  // sshd
           (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's') ||  // systemd
           (comm[0] == 'd' && comm[1] == 'b' && comm[2] == 'u');    // dbus-daemon
}
```
🔹 Purpose:
- Prevents system background processes (like systemd, dbus, polkitd) from being logged.
- Reduces log spam by ignoring unnecessary events.

5. print_event() (Logs and Filters Events)
```python
def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    process_name = event.comm.decode()

    # Ignore system daemons
    ignore_processes = {"rsyslogd", "gdbus", "dbus-daemon", "polkitd", "systemd-timesyncd", "systemd", "journalctl"}
    if process_name in ignore_processes:
        return

    # Ignore system processes (UID 0)
    try:
        uid = psutil.Process(event.pid).uids().real
        if uid == 0:
            return
    except psutil.NoSuchProcess:
        return

    # Rate-limit logs (1 log per 2 seconds per process/syscall)
    key = (event.pid, event.syscall)
    current_time = time.time()
    if key in last_event_time and (current_time - last_event_time[key] < 2):
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
```
🔹 Purpose:
- Receives events from the eBPF program.
- Filters out system daemons.
- Ignores root (UID 0) processes.
- Applies rate-limiting (1 log per syscall per process every 2 seconds).
