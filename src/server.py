import asyncio
import json
import ssl
import subprocess
import psutil
from aiohttp import web
from config import *
from datetime import datetime
from typing import Any, Dict, List
from pathlib import Path

if os.environ.get("HOST_PROC"):
    psutil.PROCFS_PATH = os.environ["HOST_PROC"]
if os.environ.get("HOST_SYS"):
    psutil.SYSFS_PATH = os.environ["HOST_SYS"]


async def handle_monitor(request: web.Request) -> web.Response:
    """Serve the monitor page."""
    path = Path(__file__).parent.joinpath("monitor.html")
    return web.FileResponse(path)


def run_host_command(command) -> str:
    """Run a command in the host namespace using nsenter."""
    try:
        # Use nsenter to run command in host namespace
        nsenter_cmd = ["nsenter", "--target", "1", "--mount", "--pid", "--"] + command
        return subprocess.check_output(nsenter_cmd, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running command {command}: {e}")
        return ""


def clean_process_name(proc: psutil.Process) -> str:
    """Clean and format process name for display."""
    try:
        name = proc.name()
        cmdline = proc.cmdline()

        # Handle Python processes specially
        if name in ["python", "python3"]:
            if len(cmdline) > 1:
                return os.path.basename(cmdline[1])

        # Common process name mappings
        name_mappings = {
            "sshd": "SSH Daemon",
            "containerd": "Container Daemon",
            "dockerd": "Docker Daemon",
            "systemd": "System Daemon",
            "multipathd": "Multipath Daemon",
            "tailscaled": "Tailscale Daemon",
        }

        return name_mappings.get(name, name.replace("-", " ").capitalize())
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "Unknown"


def get_process_list() -> List[Dict[str, Any]]:
    """Get list of running processes with detailed information using psutil."""
    processes = []
    try:
        # Get process information
        for proc in psutil.process_iter(
            ["pid", "name", "status", "cpu_percent", "memory_percent"]
        ):
            try:
                pinfo = proc.info

                status_mapping = {
                    psutil.STATUS_RUNNING: "Running",
                    psutil.STATUS_SLEEPING: "Sleeping",
                    psutil.STATUS_STOPPED: "Stopped",
                    psutil.STATUS_ZOMBIE: "Zombie",
                    psutil.STATUS_DEAD: "Dead",
                    psutil.STATUS_WAKING: "Waking",
                    psutil.STATUS_IDLE: "Idle",
                    psutil.STATUS_LOCKED: "Locked",
                    psutil.STATUS_WAITING: "Waiting",
                }

                status = status_mapping.get(pinfo.get("status"), "Unknown")

                processes.append(
                    {
                        "pid": pinfo["pid"],
                        "name": clean_process_name(proc),
                        "cpu_percent": pinfo.get("cpu_percent", 0.0) or 0.0,
                        "memory_percent": pinfo.get("memory_percent", 0.0) or 0.0,
                        "status": status,
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                print(f"Error processing pid {pinfo.get('pid', 'unknown')}: {e}")
                continue

        # Sort by CPU usage by default
        return sorted(processes, key=lambda x: x["cpu_percent"], reverse=True)
    except Exception as e:
        print(f"Error collecting process data: {e}")
        return []


def get_current_users() -> List[Dict[str, Any]]:
    """Get information about currently logged-in users from host."""
    users = []
    try:
        who_output = run_host_command(["who", "-u"])

        for line in who_output.splitlines():
            try:
                parts = line.split()
                if len(parts) >= 6:
                    username = parts[0]

                    try:
                        uid_output = run_host_command(["id", "-u", username])
                        uid = uid_output.strip()

                        ps_output = run_host_command(
                            ["ps", "-U", uid, "-o", "%cpu,%mem", "--no-headers"]
                        )
                        ps_lines = ps_output.splitlines()

                        # Calculate total CPU and memory usage
                        total_cpu = 0.0
                        total_mem = 0.0
                        for ps_line in ps_lines:
                            try:
                                cpu, mem = map(float, ps_line.strip().split())
                                total_cpu += cpu
                                total_mem += mem
                            except ValueError:
                                continue

                        users.append(
                            {
                                "name": username,
                                "terminal": parts[1],
                                "host": (
                                    parts[2]
                                    if len(parts) > 2 and parts[2] != ":"
                                    else "localhost"
                                ),
                                "started": " ".join(
                                    parts[3:5]
                                ),  # Include both date and time
                                "cpu_usage": min(100.0, total_cpu),
                                "memory_usage": min(100.0, total_mem),
                                "process_count": len(ps_lines),
                            }
                        )
                    except Exception as e:
                        print(f"Error getting stats for user {username}: {e}")
                        continue

            except Exception as e:
                print(f"Error processing user line: {e}")
                continue

        return sorted(users, key=lambda x: x["cpu_usage"], reverse=True)
    except Exception as e:
        print(f"Error collecting user data: {e}")
        return []


def get_last_logins(n: int = LAST_LOGINS_COUNT) -> List[Dict[str, str]]:
    """Get list of last n logged users."""
    users = []
    try:
        if os.path.exists("/var/log/wtmp"):
            output = subprocess.check_output(
                ["last", "-n", str(n)], universal_newlines=True
            )
            for line in output.splitlines():
                if line and not line.startswith("wtmp"):
                    parts = line.split()
                    if len(parts) >= 5:
                        users.append(
                            {
                                "name": parts[0],
                                "terminal": parts[1],
                                "host": (
                                    parts[2]
                                    if not parts[2].startswith(":")
                                    else "localhost"
                                ),
                                "login_time": " ".join(parts[3:6]),
                            }
                        )
    except Exception:
        pass
    return users


def get_system_logs(n: int = SYSTEM_LOG_LINES) -> List[str]:
    """Get last n lines of system logs."""
    logs = []
    try:
        log_file = "/var/log/syslog"
        if os.path.exists(log_file):
            with open(log_file, "r") as f:
                logs = f.readlines()[-n:]
    except Exception:
        logs = ["System logs not available"]
    return logs


def get_process_summary() -> Dict[str, int]:
    """Get process summary using psutil."""
    summary = {
        "running": 0,
        "sleeping": 0,
        "stopped": 0,
        "zombie": 0,
        "idle": 0,
        "total": 0,
    }

    try:
        for proc in psutil.process_iter(["status"]):
            try:
                status = proc.info["status"]
                summary["total"] += 1

                if status == psutil.STATUS_RUNNING:
                    summary["running"] += 1
                elif status == psutil.STATUS_SLEEPING:
                    summary["sleeping"] += 1
                elif status == psutil.STATUS_STOPPED:
                    summary["stopped"] += 1
                elif status == psutil.STATUS_ZOMBIE:
                    summary["zombie"] += 1
                elif status == psutil.STATUS_IDLE:
                    summary["idle"] += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return summary
    except Exception as e:
        print(f"Error collecting process summary: {e}")
        return {"running": 0, "sleeping": 0, "stopped": 0, "zombie": 0, "total": 0}


def get_system_stats() -> Dict[str, Any]:
    """Collect comprehensive system statistics."""
    try:
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        boot_time = psutil.boot_time()
        uptime = datetime.now() - datetime.fromtimestamp(boot_time)

        stats = {
            "cpu": psutil.cpu_percent(interval=1),
            "memory": {
                "total": memory.total,
                "available": memory.available,
                "used": memory.used,
                "free": memory.free,
                "percent": memory.percent,
            },
            "disk": {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": disk.percent,
            },
            "load_avg": psutil.getloadavg(),
            "processes": get_process_list(),
            "process_summary": get_process_summary(),
            "current_users": get_current_users(),
            "last_logins": get_last_logins(),
            "uptime": f"{uptime.days}d {uptime.seconds//3600}h {(uptime.seconds//60)%60}m",
            "system_logs": get_system_logs(),
        }
        return stats
    except Exception as e:
        print(f"Error collecting system stats: {e}")
        return {}


async def handle_websocket(request):
    """Handle WebSocket connections for real-time monitoring."""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    print("WebSocket connection established")

    authenticated = False

    try:
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    command = data.get("command")

                    # Handle authentication
                    if command == "login":
                        username = data.get("username")
                        password = data.get("password")
                        if (
                            username == DEFAULT_USERNAME
                            and password == DEFAULT_PASSWORD
                        ):
                            authenticated = True
                            await ws.send_json({"type": "auth", "status": "success"})
                        else:
                            await ws.send_json(
                                {
                                    "type": "auth",
                                    "status": "error",
                                    "message": "Invalid credentials",
                                }
                            )

                    # Handle stats request (only if authenticated)
                    elif command == "stats":
                        if authenticated:
                            stats = get_system_stats()
                            await ws.send_json({"type": "stats", "data": stats})
                        else:
                            await ws.send_json(
                                {"type": "error", "message": "Not authenticated"}
                            )

                except json.JSONDecodeError:
                    print("Invalid JSON received")
                    continue

            elif msg.type == web.WSMsgType.ERROR:
                print(f"WebSocket error: {ws.exception()}")
                break

    finally:
        print("WebSocket connection closed")
        return ws


def create_ssl_context() -> ssl.SSLContext:
    """Create SSL context for secure connections."""
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        os.path.join(CERT_DIR, "localhost.crt"), os.path.join(CERT_DIR, "localhost.key")
    )
    return ssl_context


def init_app() -> web.Application:
    """Initialize the application with routes."""
    app = web.Application()

    # Add routes
    app.router.add_get("/monitor", handle_monitor)
    app.router.add_get("/ws", handle_websocket)

    return app


def main() -> None:
    """Start the server."""
    ssl_context = create_ssl_context()
    app = init_app()

    print(f"Server starting at https://localhost:{DEFAULT_PORT}")
    web.run_app(app, port=DEFAULT_PORT, ssl_context=ssl_context)


if __name__ == "__main__":
    main()
