# -*- coding: utf-8 -*-
"""ida-pro-mcp 的 stdio 客户端。

ZCode 里的 ida-pro-mcp 是 `idalib-mcp.exe --stdio` 形态，没有可直连的本地端口。
逆向时经常需要把"反汇编 → 提取表/常量 → 生成 C 代码"做成脚本，避免把整段
反汇编灌进对话上下文。这个客户端就是为此准备的：自己起一个服务实例，
用 JSON-RPC 调它的 tool（idb_open / get_bytes / disasm / ...），结果留在脚本里。

用法：
    from ida_mcp_client import Ida
    ida = Ida()
    db = ida.open_db(r"E:\\Work\\tmp\\copy.i64")     # 每次用**独立副本**：同一 IDB 不能被两个 worker 同时打开
    data = ida.get_bytes(db, 0x14005E354, 0x258D)    # 自动切块并校验长度
    print(ida.disasm(db, 0x14005E354, 50))
    ida.close()

注意：
  * get_bytes 的单次返回会按输出上限截断，且单字节十六进制不带前导零（`0x8`），
    解析正则必须用 {1,2} 位；本模块的 get_bytes 已处理（截断则拆半重取）。
  * 每个脚本进程退出后 worker 仍按 idle_ttl_sec 存活，因此复用同一 IDB 路径会
    "Failed to open database"，所以 open_db 默认给每次调用复制一份新副本。
"""

import json
import os
import queue
import re
import shutil
import subprocess
import threading
import time
import uuid

EXE = r"E:\DevTools\IDA Professional 9.2\mcp\ida-pro-mcp\.venv\Scripts\idalib-mcp.exe"
CWD = r"E:\DevTools\IDA Professional 9.2\mcp\ida-pro-mcp"


class Ida:
    def __init__(self, exe=EXE, cwd=CWD):
        self.p = subprocess.Popen([exe, "--stdio"], cwd=cwd,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True,
                                  encoding="utf-8", bufsize=1)
        self.id = 0
        self.q = queue.Queue()
        threading.Thread(target=self._reader, daemon=True).start()
        self.call("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                 "clientInfo": {"name": "xpch-extract", "version": "1"}})
        self.notify("notifications/initialized", {})
        self._tmpdir = os.environ.get("TEMP", r"C:\Windows\Temp")

    # ---------- 传输 ----------
    def _reader(self):
        for line in self.p.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self.q.put(json.loads(line))
            except Exception:
                pass

    def _send(self, obj):
        self.p.stdin.write(json.dumps(obj) + "\n")
        self.p.stdin.flush()

    def notify(self, method, params):
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def call(self, method, params, timeout=300):
        self.id += 1
        mid = self.id
        self._send({"jsonrpc": "2.0", "id": mid, "method": method, "params": params})
        t0 = time.time()
        while True:
            try:
                msg = self.q.get(timeout=1)
            except queue.Empty:
                if time.time() - t0 > timeout:
                    raise TimeoutError("%s timed out" % method)
                continue
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError("%s: %s" % (method, msg["error"]))
                return msg.get("result")

    def tool(self, name, args, timeout=300):
        r = self.call("tools/call", {"name": name, "arguments": args}, timeout)
        txt = "\n".join(c.get("text", "") for c in r.get("content", []))
        try:
            return json.loads(txt)
        except Exception:
            return txt

    # ---------- 常用封装 ----------
    def open_db(self, idb_path, session="ext", copy=True, ttl=180):
        """打开 IDB。copy=True 时复制一份独立副本（同一 IDB 不能被两个 worker 同时打开）。"""
        path = idb_path
        if copy:
            path = os.path.join(self._tmpdir, "ida_%s.i64" % uuid.uuid4().hex[:8])
            shutil.copyfile(idb_path, path)
        op = self.tool("idb_open", {"input_path": path, "preferred_session_id": session,
                                    "idle_ttl_sec": ttl})
        if not isinstance(op, dict) or not isinstance(op.get("session"), dict):
            raise RuntimeError("idb_open failed: %s" % str(op)[:200])
        return op["session"]["session_id"]

    def _raw_region(self, db, addr, size):
        b = self.tool("get_bytes", {"database": db,
                                    "regions": [{"addr": hex(addr), "size": size}]})
        bb = b[0] if isinstance(b, list) else b
        if isinstance(bb, dict) and "result" in bb:
            bb = bb["result"]
        if isinstance(bb, list):
            bb = bb[0]
        if not isinstance(bb, dict) or "data" not in bb:
            raise RuntimeError("get_bytes unexpected: %s" % str(b)[:200])
        return bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{1,2})", bb["data"]))

    def get_bytes(self, db, addr, size):
        """取 size 字节；工具按输出上限截断时拆半重取，保证长度精确。"""
        got = self._raw_region(db, addr, size)
        if len(got) == size:
            return got
        if size <= 16:
            raise RuntimeError("short read %d/%d at %#x" % (len(got), size, addr))
        half = size // 2
        return self.get_bytes(db, addr, half) + self.get_bytes(db, addr + half, size - half)

    def disasm(self, db, addr, count=100, offset=0):
        return self.tool("disasm", {"database": db, "addr": hex(addr),
                                    "max_instructions": count, "offset": offset})

    def close(self):
        try:
            self.p.stdin.close()
        except Exception:
            pass
        self.p.terminate()
