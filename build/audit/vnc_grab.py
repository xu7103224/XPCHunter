"""极简 RFB (VNC) 客户端：抓取 VMware 控制台一帧并存为 PNG。

用法: python vnc_grab.py <host> <port> <out.png>
只实现 No-Auth + Raw encoding，够用即可。
"""
import socket
import struct
import sys

from PIL import Image


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError("连接被对端关闭（已收 %d/%d 字节）" % (len(buf), n))
        buf += chunk
    return buf


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5960
    out = sys.argv[3] if len(sys.argv) > 3 else "vnc.png"

    s = socket.create_connection((host, port), timeout=20)
    s.settimeout(30)

    ver = recv_exact(s, 12)
    print("server version:", ver)
    s.sendall(b"RFB 003.008\n")

    ntypes = recv_exact(s, 1)[0]
    types = recv_exact(s, ntypes) if ntypes else b""
    print("security types:", list(types))
    if ntypes == 0:
        raise RuntimeError("服务端拒绝连接: " + recv_exact(s, 4).hex())
    if 1 not in types:
        raise RuntimeError("只提供安全类型 %s，未设置 None(1)，需要密码" % list(types))
    s.sendall(bytes([1]))  # None

    result = struct.unpack(">I", recv_exact(s, 4))[0]
    if result != 0:
        raise RuntimeError("SecurityResult = %d" % result)

    s.sendall(bytes([1]))  # shared

    w, h = struct.unpack(">HH", recv_exact(s, 4))
    pf = recv_exact(s, 16)
    (bpp, depth, big_endian, true_colour,
     rmax, gmax, bmax, rshift, gshift, bshift) = struct.unpack(">BBBBHHHBBB", pf[:13])
    namelen = struct.unpack(">I", recv_exact(s, 4))[0]
    name = recv_exact(s, namelen).decode("latin-1", "replace")
    print("desktop %dx%d bpp=%d depth=%d be=%d truecolour=%d name=%r"
          % (w, h, bpp, depth, big_endian, true_colour, name))

    # SetEncodings: 只要 Raw(0)，保证解析简单
    s.sendall(struct.pack(">BBH", 2, 0, 1) + struct.pack(">i", 0))
    # FramebufferUpdateRequest: incremental=0, 全屏
    s.sendall(struct.pack(">BBHHHH", 3, 0, 0, 0, w, h))

    while True:
        mtype = recv_exact(s, 1)[0]
        if mtype == 0:  # FramebufferUpdate
            recv_exact(s, 1)
            nrects = struct.unpack(">H", recv_exact(s, 2))[0]
            canvas = Image.new("RGB", (w, h))
            for _ in range(nrects):
                x, y, rw, rh = struct.unpack(">HHHH", recv_exact(s, 8))
                enc = struct.unpack(">i", recv_exact(s, 4))[0]
                if enc != 0:
                    raise RuntimeError("未预期的编码 %d" % enc)
                data = recv_exact(s, rw * rh * (bpp // 8))
                img = Image.frombytes("RGBA" if bpp == 32 else "RGB", (rw, rh), data)
                if bpp == 32:
                    img = img.convert("RGB")
                # 服务端像素格式里 24 位真彩通常就是 RGB 顺序，直接贴
                canvas.paste(img, (x, y))
            canvas.save(out)
            print("saved:", out)
            return
        if mtype == 1:  # SetColourMapEntries
            recv_exact(s, 3)
            n = struct.unpack(">H", recv_exact(s, 2))[0]
            recv_exact(s, n * 6)
            continue
        if mtype == 2:  # Bell
            continue
        if mtype == 3:  # ServerCutText
            recv_exact(s, 3)
            n = struct.unpack(">I", recv_exact(s, 4))[0]
            recv_exact(s, n)
            continue
        raise RuntimeError("未知消息类型 %d" % mtype)


if __name__ == "__main__":
    main()
