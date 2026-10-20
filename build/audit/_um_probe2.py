import re

PATH = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\samples\PCHunter_2024.09.02\PCHunter64.exe'
d = open(PATH, 'rb').read()

print('=== UTF-16LE 里的设备名 / 驱动名 ===')
# UTF-16LE: 字符间隔 0x00
for pat in ['\\\\.\\', '\\Device', 'View++', 'PCHunter', '.sys', '\\??\\']:
    b = pat.encode('utf-16-le')
    n = d.count(b)
    print('  %-12s %d' % (pat, n))
    if n:
        for m in re.finditer(re.escape(b), d):
            s = d[m.start():m.start() + 160]
            # 截到双零
            out = []
            for i in range(0, len(s) - 1, 2):
                c = s[i] | (s[i + 1] << 8)
                if c == 0:
                    break
                out.append(chr(c) if 32 <= c < 127 else '?')
            print('      0x%X: %s' % (m.start(), ''.join(out)))

print()
print('=== 含 DeviceIoControl 的上下文（ASCII） ===')
for m in re.finditer(b'DeviceIoControl', d):
    print('  0x%X' % m.start())

print()
print('=== View++ 的 ASCII 上下文 ===')
for m in re.finditer(b'View\\+\\+', d):
    st = max(0, m.start() - 40)
    print('  0x%X: %r' % (m.start(), d[st:m.start() + 60]))