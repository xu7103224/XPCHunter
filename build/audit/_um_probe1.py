import re, struct, sys

PATH = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\samples\PCHunter_2024.09.02\PCHunter64.exe'
d = open(PATH, 'rb').read()

pats = [b'\\\\.\\', b'DeviceIoControl', b'CreateFile', b'\\Device', b'View++',
        b'pchunter', b'PCHunter', b'.sys', b'\\??\\', b'\\\\?\\']
for p in pats:
    print('%-20s %d' % (p.decode('latin1', 'replace'), d.count(p)))

print()
print('--- 设备名候选 ---')
seen = set()
for m in re.finditer(rb'\\\\\.\\[ -~]{1,60}', d):
    s = m.group().decode('latin1')
    if s not in seen:
        seen.add(s)
        print(' ', s)

print()
print('--- 含 .sys 的串 ---')
for m in re.finditer(rb'[ -~]{4,80}\.sys', d):
    s = m.group().decode('latin1')
    print(' ', s)