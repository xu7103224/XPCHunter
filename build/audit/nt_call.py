#!/usr/bin/env python3
"""通过 stdio 直接调用 ntdrive MCP 工具（opencode 未重启时的临时通道）。

用法：
    python build/audit/nt_call.py <tool> ['{"json":"args"}']
    python build/audit/nt_call.py kd_state '{"vm":"win10dev"}'

只依赖标准库。注意：kd 停断点时 guest 冻结，先 kd_go 再部署文件/命令。
"""
import json
import subprocess
import sys
import threading
import time

EXE = r"C:\Users\Administrator\.local\bin\ntdrive-mcp.exe"


def call(tool, args, wait=30.0):
    p = subprocess.Popen(
        [EXE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    msgs = []

    def reader(stream):
        for line in iter(stream.readline, b""):
            msgs.append(line.decode("utf-8", "replace").strip())

    threading.Thread(target=reader, args=(p.stdout,), daemon=True).start()

    def send(obj):
        p.stdin.write((json.dumps(obj) + "\n").encode())
        p.stdin.flush()

    send({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "nt_call", "version": "1"},
        },
    })
    time.sleep(0.6)
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    })

    deadline = time.time() + wait
    result = None
    while time.time() < deadline:
        for m in list(msgs):
            try:
                obj = json.loads(m)
            except Exception:
                continue
            if obj.get("id") == 2:
                result = obj
                break
        if result:
            break
        time.sleep(0.2)

    p.kill()
    if result is None:
        return {"error": "timeout", "raw": msgs[-5:]}
    if "error" in result:
        return {"error": result["error"]}
    content = result.get("result", {}).get("content", [])
    texts = [c.get("text", "") for c in content if c.get("type") == "text"]
    joined = "\n".join(texts)
    try:
        return json.loads(joined)
    except Exception:
        return {"text": joined, "is_error": result.get("result", {}).get("isError")}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    tool = sys.argv[1]
    if len(sys.argv) > 2 and sys.argv[2].startswith("@"):
        with open(sys.argv[2][1:], "r", encoding="utf-8") as f:
            args = json.load(f)
    else:
        args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    wait = float(sys.argv[3]) if len(sys.argv) > 3 else 30.0
    out = call(tool, args, wait)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
