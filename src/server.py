import asyncio
import json
import ssl
import subprocess #I'm gonna need this to fetch processes.
import psutil
import base64
from aiohttp import web
from aiohttp_session import setup, get_session
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from cryptography import fernet
from config import *


async def check_auth(request):
    """Check if user is authenticated."""
    session = await get_session(request)
    return session.get("authenticated", False)


async def login(request):
    """Handle login requests."""
    # If already authenticated, redirect to monitor
    if await check_auth(request):
        return web.Response(
            status=web.HTTPFound.status_code, headers={"Location": "/monitor"}
        )

    if request.method == "GET":
        path = os.path.join(BASE_DIR, "login.html")
        return web.FileResponse(path)

    if request.method == "POST":
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


async def logout(request):
    """Handle logout requests."""
    session = await get_session(request)
    session.invalidate()
    return web.Response(
        status=web.HTTPFound.status_code, headers={"Location": "/login"}
    )


async def hello(request):
    text = "Hello"
    return web.Response(text=text)


async def monitor(request):
    """Serve the monitor page with authentication check."""
    if not await check_auth(request):
        return web.Response(
            status=web.HTTPFound.status_code, headers={"Location": "/login"}
        )
    path = os.path.join(BASE_DIR, "monitor.html")
    return web.FileResponse(path)

def command_output_in_lines(command):#have command be a String
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE)
    output = result.stdout
    output_in_lines= output.splitlines()
    nice_output = ""
    for line in output_in_lines:
        line = str(line)
        line = line[2:-1]#because there was an initial "b'" and a final "'" which I dont really understand ¯\_(ツ)_/¯ 
        nice_output += line + "<br>"
    return nice_output

def get_users():
    return command_output_in_lines("who")

def get_processes():
    return command_output_in_lines("ps")

def get_uptime():
    return command_output_in_lines("uptime")

def get_last_n_logins(n):
    n = str(n) #just to be sure.
    arguments = "last -n" +n 
    return command_output_in_lines(arguments)

def get_last_n_system_log(n):
    n = str(n)
    # arguments = "tail -"+n+" 50 /var/log/system.log" #THIS FUNCTION NEEDS ATTENTION
    arguments = "log show --predicate \"eventType == logEvent\" --info --last 50m | tail -n "+n

    return command_output_in_lines(arguments)

def get_process_summary():
    arguments_ps = "ps -eo state | sort | uniq -c"   
    argument_sum = "ps aux | wc -l"
    ps_in_lines = command_output_in_lines(arguments_ps)
    sum_in_lines = command_output_in_lines(argument_sum)
    result = ps_in_lines + "\n\nTotal number of processes:  " + sum_in_lines
    return result


async def get_system_stats():
    """Collect system statistics.
        I can simply add stuff I want here I guess..
    """
    stats = {
        "cpu": psutil.cpu_percent(interval=1),
        "memory": psutil.virtual_memory()._asdict(),
        "disk": psutil.disk_usage("/")._asdict(),
        "load_avg": psutil.getloadavg(),
        "ps": get_processes(),
        "users":get_users(),
        "uptime":get_uptime(),
        "n_logins":get_last_n_logins(10), #if we want to add an input function for this.
        "ps_summary":get_process_summary(),
        "n_sys_logs":get_last_n_system_log(50),
    }
    return stats


async def send_stats(request):
    """Send system stats to WebSocket client."""
    if not await check_auth(request):
        return web.WebSocketResponse(status=web.HTTPUnauthorized.status_code)

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


async def handle_root(request):
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


def init_app():
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
        ]
    )

    return app


def create_ssl_context():
    """Create SSL context for secure WebSocket connection."""
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert_file = os.path.join(CERT_DIR, "localhost.crt")
    key_file = os.path.join(CERT_DIR, "localhost.key")
    ssl_context.load_cert_chain(cert_file, key_file)
    return ssl_context


def run():
    """Start WebSocket server."""
    ssl_context = create_ssl_context()
    app = init_app()
    web.run_app(app, port=DEFAULT_PORT, ssl_context=ssl_context)


if __name__ == "__main__":
    print(f"Server started at wss://localhost:{DEFAULT_PORT}")
    run()
