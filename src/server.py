import asyncio
import json
import pathlib
import ssl

import subprocess #I'm gonna need this to fetch processes.

import psutil
from aiohttp import web


async def hello(request):
    text = "Hello"
    return web.Response(text=text)


async def monitor(request):
    path = pathlib.Path(__file__).parents[0].joinpath("monitor.html")
    print("Serving {path}".format(path=path))
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


def create_ssl_context():
    """Create SSL context for secure WebSocket connection."""
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert_file = pathlib.Path(__file__).parents[1].joinpath("cert/localhost.crt")
    key_file = pathlib.Path(__file__).parents[1].joinpath("cert/localhost.key")
    ssl_context.load_cert_chain(cert_file, key_file)
    return ssl_context


def run():
    """Start WebSocket server."""
    ssl_context = create_ssl_context()
    app = web.Application()
    app.add_routes(
        [
            web.get("/ws", send_stats),
            web.get("/monitor", monitor),
            web.get("/hello", hello),
        ]
    )
    web.run_app(app, port=8765, ssl_context=ssl_context)


if __name__ == "__main__":
    print("Server started at wss://localhost:8765")
    run()
