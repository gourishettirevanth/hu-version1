import asyncio
import websockets
import json
from bcc import BPF
import time
import psutil
import socket
import re
import signal
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from jinja2 import Template
from ctypes import Structure, c_uint, c_char, string_at
from datetime import datetime

connected_clients = set()

# -------------------- CPU Monitoring --------------------

cpu_bpf_text = """
#include <uapi/linux/ptrace.h>
BPF_HASH(start, u32);
BPF_HASH(cpu_time, u32, u64);

TRACEPOINT_PROBE(sched, sched_switch) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    u32 prev_pid = args->prev_pid;
    u64 *tsp = start.lookup(&prev_pid);
    if (tsp) {
        u64 delta = ts - *tsp;
        u64 *time = cpu_time.lookup(&prev_pid);
        if (time) {
            *time += delta;
        } else {
            cpu_time.update(&prev_pid, &delta);
        }
        start.delete(&prev_pid);
    }

    start.update(&pid, &ts);
    return 0;
}
"""

cpu_bpf = BPF(text=cpu_bpf_text)

# -------------------- Network Monitoring --------------------

network_bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>
 
struct data_t {
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char task[TASK_COMM_LEN];
    u8 event_type; // 0 = connect, 1 = accept
};
 
BPF_PERF_OUTPUT(events);
 
int trace_connect(struct pt_regs *ctx, struct sock *sk) {
    struct data_t data = {};
    u16 dport = 0, sport = 0;

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), &sk->__sk_common.skc_daddr);

    data.dport = ntohs(dport);
    data.sport = sport;
    data.event_type = 0;
    bpf_get_current_comm(&data.task, sizeof(data.task));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
 
int trace_accept_return(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (sk == NULL) return 0;

    struct data_t data = {};
    u16 dport = 0, sport = 0;

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();

    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), &sk->__sk_common.skc_daddr);

    data.sport = sport;
    data.dport = ntohs(dport);
    data.event_type = 1;
    bpf_get_current_comm(&data.task, sizeof(data.task));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

network_bpf = BPF(text=network_bpf_text)
network_bpf.attach_kprobe(event="tcp_connect", fn_name="trace_connect")
network_bpf.attach_kretprobe(event="inet_csk_accept", fn_name="trace_accept_return")

network_events = []

def handle_network_event(cpu, data, size):
    event = network_bpf["events"].event(data)
    event_dict = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "pid": event.pid,
        "comm": event.task.decode('utf-8', 'replace'),
        "event_type": "connect" if event.event_type == 0 else "accept",
        "saddr": socket.inet_ntoa(event.saddr.to_bytes(4, byteorder='big')),
        "daddr": socket.inet_ntoa(event.daddr.to_bytes(4, byteorder='big')),
        "sport": event.sport,
        "dport": event.dport,
        "protocol": "TCP"
    }
    network_events.append(event_dict)

network_bpf["events"].open_perf_buffer(handle_network_event)

# -------------------- Enhanced User Activity Monitoring --------------------

user_bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_ARGS 5
#define ARG_LEN  64

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char argv[MAX_ARGS][ARG_LEN];
};

BPF_PERF_OUTPUT(events);

int tracepoint__syscalls__sys_enter_execve(struct tracepoint__syscalls__sys_enter_execve *ctx) {
    struct data_t data = {};
    const char **argv = (const char **)(ctx->argv);

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) != 0)
            break;
        if (!argp)
            break;
        if (bpf_probe_read_user_str(&data.argv[i], sizeof(data.argv[i]), argp) <= 0)
            break;
    }

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

user_bpf = BPF(text=user_bpf_text)

class ExecData(Structure):
    _fields_ = [
        ("pid", c_uint),
        ("uid", c_uint),
        ("comm", c_char * 16),
        ("argv", (c_char * 64) * 5)
    ]

userActivityEvents = []

SUSPICIOUS_PATTERNS = [
    r"/root", r"/etc", r"/boot", r"/proc", r"/sys",
    r"rm\s+-rf\s+/", r"chmod\s+777", r"chown\s+root", r"/etc/passwd",
    r"ncat", r"nc", r"tcpdump", r"curl", r"wget", r"python.*http\.server"
]

def is_suspicious(arg_line):
    return any(re.search(pattern, arg_line) for pattern in SUSPICIOUS_PATTERNS)

def user_activity_event_handler(cpu, data, size):
    event = ExecData.from_buffer_copy(string_at(data, size))
    args = []
    for arg in event.argv:
        arg_str = bytes(arg).decode(errors="ignore").rstrip("\x00")
        if arg_str:
            args.append(arg_str)
    arg_line = " ".join(args)
    comm_str = event.comm.decode(errors="ignore").strip()
    userActivityEvents.append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "pid": event.pid,
        "uid": event.uid,
        "comm": comm_str,
        "args": arg_line,
        "suspicious": is_suspicious(arg_line)
    })

user_bpf["events"].open_perf_buffer(user_activity_event_handler)
# -------------------- Process Manipulation--------------------
bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
 
struct data_t {
    u32 pid;
    u32 uid;
    u64 syscall_id;
    u64 arg1;
    u64 arg2;
    u64 arg3;
    char comm[16];
    char filename[256];
};
 
BPF_HASH(privileged_pids, u32, u8);
BPF_PERF_OUTPUT(events);
 
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;
    data.uid = bpf_get_current_uid_gid();
    data.syscall_id = args->id;
    data.arg1 = args->args[0];
    data.arg2 = args->args[1];
    data.arg3 = args->args[2];
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
 
    if (args->id == 105 && args->args[0] == 0) {
        u8 mark = 1;
        privileged_pids.update(&pid, &mark);
        __builtin_memcpy(&data.filename, "setuid(0)", 10);
        events.perf_submit(args, &data, sizeof(data));
        return 0;
    }
 
    if (args->id == 117 && args->args[2] == 0) {
        u8 mark = 1;
        privileged_pids.update(&pid, &mark);
        __builtin_memcpy(&data.filename, "setresuid(..., ..., 0)", 24);
        events.perf_submit(args, &data, sizeof(data));
        return 0;
    }
 
    u8 *marked = privileged_pids.lookup(&pid);
 
    if (!marked) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        u32 ppid = 0;
        bpf_probe_read_kernel(&ppid, sizeof(ppid), &task->real_parent->tgid);
        u8 *parent_marked = privileged_pids.lookup(&ppid);
        if (parent_marked) {
            u8 mark = 1;
            privileged_pids.update(&pid, &mark);
            marked = &mark;
        }
    }
 
    if (marked) {
        if (args->id == 59) {
            bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->args[0]);
            events.perf_submit(args, &data, sizeof(data));
        } else if (args->id == 257) {
            bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->args[1]);
            events.perf_submit(args, &data, sizeof(data));
        } else if (args->id == 1) {
            __builtin_memcpy(&data.filename, "-", 2);
            events.perf_submit(args, &data, sizeof(data));
        }
    }
 
    return 0;
}
"""
 
priv_bpf = BPF(text=bpf_code)
priv_bpf.attach_tracepoint("raw_syscalls:sys_enter", "tracepoint__raw_syscalls__sys_enter")
 
syscall_map = {
    105: "setuid",
    117: "setresuid",
    59: "execve",
    257: "openat",
    1: "write",
}
privilegedEvents = []
def handle_priv_event(cpu, data, size):
    event = priv_bpf["events"].event(data)
    syscall = syscall_map.get(event.syscall_id, f"unknown ({event.syscall_id})")
    filename = event.filename.decode('utf-8', 'replace').strip('\x00')
    insight = ""

    if event.syscall_id in [105, 117]:
        insight = "Privilege escalation attempt to UID 0"
    elif event.syscall_id == 59:
        if filename.startswith("/tmp"):
            insight = "⚠️ Execve from /tmp — Possible malicious execution"
        else:
            insight = "Privileged process executed a program"
    elif event.syscall_id == 257:
        insight = "Privileged process opened a file"
    elif event.syscall_id == 1:
        insight = "Privileged process wrote to a file"

    payload = {
        "time": datetime.utcnow().isoformat() + "Z",
        "pid": event.pid,
        "uid": event.uid,
        "comm": event.comm.decode('utf-8', 'replace'),
        "syscall": syscall,
        "filename": filename,
        "args": [event.arg1, event.arg2, event.arg3],
        "insight": insight
    }
    privilegedEvents.append(payload)
priv_bpf["events"].open_perf_buffer(handle_priv_event)
# -------------------- WebSocket Handler --------------------

def sendAlarm(cpu_alarms):
    # Email credentials
    FROM = "kernellens@gmail.com"
    TO = "revanth20030920@gmail.com"
    SUBJECT = "High CPU utilization detected - Please investigate"

    # HTML Template (you can also load this from a file if needed)
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>{{ alert_type }} Alert</title>
        <style>
            body {
                font-family: 'Segoe UI', Arial, sans-serif;
                background-color: #f5f7fa;
                margin: 0;
                padding: 0;
            }
            .container {
                background-color: #fff;
                max-width: 500px;
                margin: 40px auto;
                padding: 32px 36px 24px 36px;
                border-radius: 10px;
                box-shadow: 0 2px 12px rgba(26, 42, 73, 0.08);
                border: 1px solid #e3e8ee;
                border-left: 6px solid #86bc25;
            }
            .logo {
                text-align: center;
                margin-bottom: 18px;
            }
            .logo-text {
                font-size: 2.2em;
                font-weight: 700;
                letter-spacing: 1.5px;
                font-family: 'Segoe UI', Arial, sans-serif;
                color: #1a2a49;
            }
            .logo-text .accent {
                color: #86bc25;
                font-weight: 700;
            }
            .header {
                background-color: #1a2a49;
                color: #fff;
                padding: 20px 0 16px 0;
                border-radius: 10px 10px 0 0;
                text-align: center;
                margin: -32px -36px 28px -36px;
            }
            h2 {
                margin: 0;
                font-size: 1.6em;
                font-weight: 600;
                letter-spacing: 0.5px;
            }
            ul {
                list-style: none;
                padding: 0;
                margin: 0 0 12px 0;
            }
            li {
                margin-bottom: 14px;
                font-size: 1.08em;
            }
            strong {
                color: #86bc25;
                font-weight: 600;
            }
            .footer {
                margin-top: 32px;
                font-size: 0.96em;
                color: #6c757d;
                text-align: center;
            }
            .greeting {
                margin-bottom: 18px;
                font-size: 1.05em;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">
                <span class="logo-text">Kernel<span class="accent">Lens</span></span>
            </div>
            <div class="header">
                <h2>{{ alert_type }} Detected</h2>
            </div>
            <div class="greeting">
                Dear Team,<br>
                {{ message }}
            </div>
            {% for data in cpu_alarms %}
                <h4>Process information</h4>
                <ul>
                    <li><strong>PID:</strong> {{ data.pid }}</li>
                    <li><strong>Command:</strong> {{ data.comm }}</li>
                    <li><strong>CPU Usage:</strong> {{ data.cpu }}%</li>
                    <li><strong>Threshold:</strong> {{ data.threshold }}%</li>
                    <li><strong>Triggered At:</strong> {{ data.triggeredAt }}</li>
                </ul>
            {% endfor %}
            <div class="footer">
                This is an automated alert from your monitoring system.
            </div>
        </div>
    </body>
    </html>
    """

    # Render HTML with Jinja2
    template = Template(html_template)
    html_content = template.render(
        alert_type="CPU Alert",
        message="High CPU utilization has been detected for the following process. Kindly investigate the cause to prevent potential performance issues.",
        cpu_alarms=cpu_alarms
    )

    # Create MIME message
    msg = MIMEMultipart('alternative')
    msg['From'] = FROM
    msg['To'] = TO
    msg['Subject'] = SUBJECT

    msg.attach(MIMEText(html_content, 'html'))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(FROM, "mnuk anac sniv vlvc")  # Use app password
        server.sendmail(FROM, TO, msg.as_string())
        server.quit()
        print("Successfully sent the mail")
    except Exception as e:
        print("Failed to send mail:", e)

async def handler(websocket):
    print(f"✅ Client connected: {websocket.remote_address}")
    connected_clients.add(websocket)
    try:
        while True:
            cpu_data = []
            cpu_alarms = []
            now = time.strftime("%Y-%m-%d %H:%M:%S")

            for k, v in cpu_bpf["cpu_time"].items():
                pid = k.value
                cpu_time_ns = v.value
                cpu_time_sec = cpu_time_ns / 1e9

                try:
                    proc = psutil.Process(pid)
                    comm = proc.name()
                    cpu_data.append({
                        "timestamp": now,
                        "pid": pid,
                        "comm": comm,
                        "cpu_time": round(cpu_time_sec, 4)
                    })

                    if cpu_time_sec > 1000.0:
                        data = {
                            "pid": pid,
                            "comm": comm,
                            "cpu": round(cpu_time_sec, 4),
                            "threshold": 1000.0,
                            "triggeredAt": now
                        }
                        cpu_alarms.append(data)
                except psutil.NoSuchProcess:
                    continue

            current_network = list(network_events)
            network_events.clear()

            current_user_activity = list(userActivityEvents)
            userActivityEvents.clear()

            current_privileged = list(privilegedEvents)
            privilegedEvents.clear()
            data = {
                "cpuUtilization": cpu_data,
                "cpuAlarms": cpu_alarms,
                "networkPackets": current_network,
                "userActivity": current_user_activity,
                "privilegedEvents": current_privileged
            }
            if len(data["cpuAlarms"]) > 0:
                sendAlarm(data["cpuAlarms"])
            await websocket.send(json.dumps(data))
            await asyncio.sleep(5)
    except websockets.exceptions.ConnectionClosed:
        print(f"❌ Client disconnected: {websocket.remote_address}")
    finally:
        connected_clients.remove(websocket)

# -------------------- Server --------------------

async def main():
    print("🔁 WebSocket server running on ws://localhost:6790")
    async with websockets.serve(handler, "localhost", 6790):
        while True:
            network_bpf.perf_buffer_poll(timeout=100)
            user_bpf.perf_buffer_poll(timeout=100)
            priv_bpf.perf_buffer_poll(timeout=100)
            await asyncio.sleep(0.1)

if __name__ == "__main__":
    asyncio.run(main())
