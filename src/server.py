import asyncio
import json
import ssl
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
            return web.Response(status=302, headers={"Location": "/monitor"})

        return web.Response(status=401, text="Invalid credentials")


async def logout(request):
    """Handle logout requests."""
    session = await get_session(request)
    session.invalidate()
    return web.Response(status=302, headers={"Location": "/login"})


async def hello(request):
    text = "Hello"
    return web.Response(text=text)


async def monitor(request):
    """Serve the monitor page with authentication check."""
    if not await check_auth(request):
        return web.Response(status=302, headers={"Location": "/login"})
    path = os.path.join(BASE_DIR, "monitor.html")
    return web.FileResponse(path)


async def get_system_stats():
    """Collect system statistics."""
    stats = {
        "cpu": psutil.cpu_percent(interval=1),
        "memory": psutil.virtual_memory()._asdict(),
        "disk": psutil.disk_usage("/")._asdict(),
        "load_avg": psutil.getloadavg(),
    }
    return stats


async def send_stats(request):
    """Send system stats to WebSocket client."""
    if not await check_auth(request):
        return web.WebSocketResponse(status=401)

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
    web.run_app(app, port=8765, ssl_context=ssl_context)


if __name__ == "__main__":
    print("Server started at wss://localhost:8765")
    run()
