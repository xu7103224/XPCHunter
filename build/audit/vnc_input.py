"""极简 RFB (VNC) 输入客户端：可靠的鼠标点击 / 键盘按键 / 文本输入。

用法:
  python vnc_input.py <host> <port> click  <x> <y>
  python vnc_input.py <host> <port> dblclick <x> <y>
  python vnc_input.py <host> <port> move   <x> <y>
  python vnc_input.py <host> <port> key    <name> [<name> ...]
  python vnc_input.py <host> <port> type   <text>

与 con_click 相比：显式分三次发送 PointerEvent（移动 / 按下 / 抬起），
中间加小延时，避免 VMware VNC 丢掉「抬起」事件导致按钮卡在按下状态。
"""
import socket
import struct
import sys
import time

KEYSYMS = {
    'enter': 0xFF0D, 'return': 0xFF0D, 'tab': 0xFF09, 'esc': 0xFF1B,
    'escape': 0xFF1B, 'space': 0x20, 'backspace': 0xFF08, 'delete': 0xFF9F,
    'up': 0xFF52, 'down': 0xFF54, 'left': 0xFF51, 'right': 0xFF53,
    'home': 0xFF50, 'end': 0xFF57, 'win': 0xFFEB, 'alt': 0xFFE9,
    'ctrl': 0xFFE3, 'shift': 0xFFE1,
}


def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError('连接被对端关闭')
        buf += chunk
    return buf


def connect(host, port):
    s = socket.create_connection((host, port), timeout=20)
    s.settimeout(20)
    recv_exact(s, 12)
    s.sendall(b'RFB 003.008\n')
    ntypes = recv_exact(s, 1)[0]
    types = recv_exact(s, ntypes) if ntypes else b''
    if 1 not in types:
        raise RuntimeError('需要密码，security types=%s' % list(types))
    s.sendall(bytes([1]))
    if struct.unpack('>I', recv_exact(s, 4))[0] != 0:
        raise RuntimeError('SecurityResult 非 0')
    s.sendall(bytes([1]))          # shared
    recv_exact(s, 4)               # width, height
    recv_exact(s, 16)              # pixel format
    namelen = struct.unpack('>I', recv_exact(s, 4))[0]
    recv_exact(s, namelen)
    return s


def pointer(s, x, y, mask):
    s.sendall(struct.pack('>BBHH', 5, mask, x, y))


def click(s, x, y, double=False):
    pointer(s, x, y, 0)
    time.sleep(0.08)
    pointer(s, x, y, 1)
    time.sleep(0.12)
    pointer(s, x, y, 0)
    time.sleep(0.12)
    if double:
        pointer(s, x, y, 1)
        time.sleep(0.08)
        pointer(s, x, y, 0)
        time.sleep(0.12)
    time.sleep(0.15)


def key(s, keysym, down):
    s.sendall(struct.pack('>BBHI', 4, 1 if down else 0, 0, keysym))


def press_key(s, name):
    ks = KEYSYMS.get(name.lower())
    if ks is None:
        raise RuntimeError('未知按键 %r' % name)
    key(s, ks, True)
    time.sleep(0.06)
    key(s, ks, False)
    time.sleep(0.10)


def type_text(s, text):
    for ch in text:
        key(s, ord(ch), True)
        time.sleep(0.03)
        key(s, ord(ch), False)
        time.sleep(0.05)


def combo(s, *names):
    """按下并保持所有修饰键，点按最后一个键，再释放修饰键。"""
    def sym(n):
        n = n.lower()
        if n in KEYSYMS:
            return KEYSYMS[n]
        if len(n) == 1:
            return ord(n)
        raise RuntimeError('未知按键 %r' % n)
    ks = [sym(n) for n in names]
    mods, last = ks[:-1], ks[-1]
    for m in mods:
        key(s, m, True)
        time.sleep(0.05)
    key(s, last, True)
    time.sleep(0.06)
    key(s, last, False)
    time.sleep(0.05)
    for m in reversed(mods):
        key(s, m, False)
        time.sleep(0.05)


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5960
    cmd = sys.argv[3]
    s = connect(host, port)
    try:
        if cmd in ('click', 'dblclick', 'move'):
            x, y = int(sys.argv[4]), int(sys.argv[5])
            if cmd == 'move':
                pointer(s, x, y, 0)
            else:
                click(s, x, y, double=(cmd == 'dblclick'))
            print('%s (%d,%d) ok' % (cmd, x, y))
        elif cmd == 'key':
            for name in sys.argv[4:]:
                press_key(s, name)
            print('key %s ok' % sys.argv[4:])
        elif cmd == 'type':
            type_text(s, sys.argv[4])
            print('type ok')
        elif cmd == 'combo':
            combo(s, *sys.argv[4:])
            print('combo %s ok' % sys.argv[4:])
        else:
            raise RuntimeError('未知子命令 %r' % cmd)
    finally:
        s.close()


if __name__ == '__main__':
    main()
