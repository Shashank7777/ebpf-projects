- Monitors file operations (open, read, write)
- Filters out system daemons (systemd, dbus-daemon, polkitd, etc.)
- Ignores root (system) processes to reduce noise
- Rate-limits logs (1 event per 2 seconds per process)
- Displays the process name, PID, syscall type, and filename (for open)

📌 How It Works

- eBPF Hooks into Syscalls:
        Attaches to open, read, and write syscalls in the Linux kernel.
        Captures process name, PID, syscall type, and filename (for open).

- Filters Out Unwanted Processes:
        System daemons like systemd, dbus-daemon, and polkitd are ignored.
        Root-level processes (UID 0) are skipped.

- Rate-Limiting for Efficient Logging:
        Limits logs to one per syscall per process every 2 seconds to prevent spam.

- Real-Time Output:
        Logs system activity in human-readable format in the terminal.
