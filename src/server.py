import asyncio
import json
import ssl
import subprocess
import psutil
import base64
from aiohttp import web
from aiohttp_session import setup, get_session
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from cryptography import fernet
from config import *
from datetime import datetime
from typing import Any, Dict, List


async def check_auth(request: web.Request) -> bool:
    """Check if user is authenticated."""
    session = await get_session(request)
    return session.get("authenticated", False)


async def login(request: web.Request) -> web.Response:
    """Handle login requests."""
    if await check_auth(request):
        return web.Response(
            status=web.HTTPFound.status_code, headers={"Location": "/monitor"}
        )

    if request.method == "GET":
        path = os.path.join(BASE_DIR, "login.html")
        return web.FileResponse(path)

    if request.method == "POST":
        try:
            data = await request.post()
            username = data.get("username")
            password = data.get("password")

            if username == DEFAULT_USERNAME and password == DEFAULT_PASSWORD:
                session = await get_session(request)
                session["authenticated"] = True
                session["username"] = username
                return web.Response(
                    status=web.HTTPFound.status_code, headers={"Location": "/monitor"}
                )
            return web.Response(
                status=web.HTTPUnauthorized.status_code, text="Invalid credentials"
            )
        except Exception:
            return web.Response(
                status=web.HTTPInternalServerError.status_code,
                text="Internal server error",
            )


async def logout(request: web.Request) -> web.Response:
    """Handle logout requests."""
    session = await get_session(request)
    session.invalidate()
    return web.Response(
        status=web.HTTPFound.status_code, headers={"Location": "/login"}
    )


async def monitor(request: web.Request) -> web.Response:
    """Serve the monitor page with authentication check."""
    if not await check_auth(request):
        return web.Response(
            status=web.HTTPFound.status_code, headers={"Location": "/login"}
        )
    path = os.path.join(BASE_DIR, "monitor.html")
    return web.FileResponse(path)


def get_process_list() -> List[Dict[str, Any]]:
    """Get list of running processes with detailed information."""
    processes = []
    try:
        for proc in psutil.process_iter(
            ["pid", "name", "cpu_percent", "memory_percent", "status"]
        ):
            try:
                pinfo = {
                    "pid": proc.info["pid"],
                    "name": proc.info["name"],
                    "cpu_percent": proc.info["cpu_percent"] or 0.0,
                    "memory_percent": proc.info["memory_percent"] or 0.0,
                    "status": proc.info["status"],
                }
                # Update CPU and memory usage
                pinfo["cpu_percent"] = proc.cpu_percent(interval=None)
                pinfo["memory_percent"] = proc.memory_percent()
                processes.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception:
        pass
    return processes


def get_current_users() -> List[Dict[str, Any]]:
    """Get detailed information about currently logged-in users."""
    users = []
    try:
        # Get the number of CPU cores for normalizing CPU percentage
        cpu_count = psutil.cpu_count() or 1

        for user in psutil.users():
            try:
                user_processes = [
                    p
                    for p in psutil.process_iter(
                        ["username", "name", "cpu_percent", "memory_percent"]
                    )
                    if p.info["username"] == user.name
                ]

                # Normalize CPU usage by dividing by number of cores
                cpu_usage = (
                    sum(p.info["cpu_percent"] or 0 for p in user_processes) / cpu_count
                )
                memory_usage = sum(
                    p.info["memory_percent"] or 0 for p in user_processes
                )
                process_count = len(user_processes)

                users.append(
                    {
                        "name": user.name if user.name else "Unknown",
                        "terminal": user.terminal if user.terminal else "N/A",
                        "host": user.host if user.host else "localhost",
                        "started": datetime.fromtimestamp(user.started).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
                        "cpu_usage": round(cpu_usage, 1),
                        "memory_usage": round(memory_usage, 1),
                        "process_count": process_count,
                        "pid": user.pid if hasattr(user, "pid") else None,
                    }
                )
            except (AttributeError, ValueError):
                continue
    except Exception:
        pass
    return users


def get_last_logins(n: int = 10) -> List[Dict[str, str]]:
    """Get list of last n logged users using wtmp."""
    users = []
    try:
        wtmp_path = "/var/log/wtmp"
        if os.path.exists(wtmp_path):
            output = subprocess.check_output(
                ["last", "-n", str(n)], universal_newlines=True
            )
            for line in output.splitlines():
                if line and not line.startswith("wtmp"):
                    parts = line.split()
                    if len(parts) >= 5:
                        try:
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
                            continue
    except Exception:
        pass
    return users


def get_uptime() -> str:
    """Get system uptime in a human-readable format."""
    try:
        uptime = datetime.now() - datetime.fromtimestamp(psutil.boot_time())
        days = uptime.days
        hours, remainder = divmod(uptime.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{days} days, {hours} hours, {minutes} minutes, {seconds} seconds"
    except Exception:
        return "Uptime unavailable"


def get_process_summary() -> Dict[str, int]:
    """Get summary of processes by their states with total count."""
    summary = {"total": 0}
    try:
        for proc in psutil.process_iter(["status"]):
            try:
                status = proc.info["status"]
                summary[status] = summary.get(status, 0) + 1
                summary["total"] += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass
    return summary


def get_system_logs(n: int = SYSTEM_LOG_LINES) -> List[str]:
    """Get last n system log entries"""
    logs = []
    try:
        with open("/var/log/syslog", "r") as f:
            logs = f.readlines()[-n:]
    except Exception:
        logs = ["System logs not available"]
    return logs


def get_memory_info() -> Dict[str, Any]:
    """Get detailed memory information."""
    memory = psutil.virtual_memory()
    return {
        "total": memory.total,
        "available": memory.available,
        "used": memory.used,
        "free": memory.free,
        "percent": memory.percent,
        "cached": memory.cached if hasattr(memory, "cached") else 0,
        "buffers": memory.buffers if hasattr(memory, "buffers") else 0,
    }


def get_disk_info(path: str = "/") -> Dict[str, Any]:
    """Get detailed disk information for specified path."""
    disk = psutil.disk_usage(path)
    return {
        "total": disk.total,
        "used": disk.used,
        "free": disk.free,
        "percent": disk.percent,
    }


async def get_system_stats() -> Dict[str, Any]:
    """Collect comprehensive system statistics."""
    try:
        stats = {
            "cpu": psutil.cpu_percent(interval=1),
            "memory": get_memory_info(),
            "disk": get_disk_info("/"),
            "load_avg": psutil.getloadavg(),
            "processes": get_process_list(),
            "current_users": get_current_users(),
            "last_logins": get_last_logins(LAST_LOGINS_COUNT),
            "uptime": get_uptime(),
            "process_summary": get_process_summary(),
            "system_logs": get_system_logs(SYSTEM_LOG_LINES),
        }
        return stats
    except Exception:
        return {}


async def send_stats(request: web.Request) -> web.WebSocketResponse:
    """Send system stats to WebSocket client."""
    if not await check_auth(request):
        raise web.HTTPUnauthorized(reason="Authentication required")

    print("Client connected")
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    async for msg in ws:
        if msg.type == web.WSMsgType.text and msg.data == "stats":
            data = await get_system_stats()
            response = ["stats", data]
            await ws.send_str(json.dumps(response))
        elif msg.type == web.WSMsgType.binary:
            # Ignore binary messages
            continue
        elif msg.type == web.WSMsgType.close:
            break

    return ws


async def handle_root(request) -> web.Response:
    """
    Handle root path requests.
    Redirects to monitor if authenticated, login if not.
    """
    if await check_auth(request):
        return web.Response(
            status=web.HTTPFound.status_code, headers={"Location": "/monitor"}
        )
    return web.Response(
        status=web.HTTPFound.status_code, headers={"Location": "/login"}
    )


async def handle_static(request: web.Request) -> web.FileResponse:
    """Serve static files."""
    filename = request.match_info["filename"]
    static_path = os.path.join(BASE_DIR, "static")
    return web.FileResponse(os.path.join(static_path, filename))


def init_app() -> web.Application:
    """Initialize the application with session handling."""
    app = web.Application()

    # Setup session handling
    fernet_key = fernet.Fernet.generate_key()
    secret_key = base64.urlsafe_b64decode(fernet_key)
    storage = EncryptedCookieStorage(
        secret_key=secret_key, cookie_name=SESSION_COOKIE_NAME, max_age=SESSION_EXPIRY
    )
    setup(app, storage)

    # Add routes
    app.add_routes(
        [
            web.get("/", handle_root),
            web.get("/login", login),
            web.post("/login", login),
            web.get("/logout", logout),
            web.get("/ws", send_stats),
            web.get("/monitor", monitor),
            web.get("/static/{filename:.*}", handle_static),
        ]
    )

    return app


def create_ssl_context() -> ssl.SSLContext:
    """Create SSL context for secure WebSocket connection."""
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert_file = os.path.join(CERT_DIR, "localhost.crt")
    key_file = os.path.join(CERT_DIR, "localhost.key")
    ssl_context.load_cert_chain(cert_file, key_file)
    return ssl_context


def run() -> None:
    """Start WebSocket server."""
    ssl_context = create_ssl_context()
    app = init_app()
    web.run_app(app, port=DEFAULT_PORT, ssl_context=ssl_context)


if __name__ == "__main__":
    print(f"Server started at wss://localhost:{DEFAULT_PORT}")
    run()
