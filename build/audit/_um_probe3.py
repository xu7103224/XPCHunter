import re, struct

PATH = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\samples\PCHunter_2024.09.02\PCHunter64.exe'
d = open(PATH, 'rb').read()

# 驱动侧 DispatchDeviceControl 的 IOCTL 码：从原始驱动读
DRV = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\samples\PCHunter_2024.09.02\View++_Driver64.sys'
kd = open(DRV, 'rb').read()

print('=== 原始驱动中出现的 IOCTL 常量（0x220000 段）===')
cands = set()
for m in re.finditer(rb'\xC7[\x44\x84\x8C\x94\x9C\xA4\xAC\xB4\xBC][\x24\x5C\x64]..([\x00-\x03]\x22[\x00-\x04]\x00)', kd):
    v = struct.unpack('<I', m.group(1))[0]
    cands.add(v)
for m in re.finditer(rb'\xBA(....)', kd):
    v = struct.unpack('<I', m.group(1))[0]
    if 0x220000 <= v <= 0x22FFFF:
        cands.add(v)
for v in sorted(cands)[:40]:
    print('  0x%08X' % v)

print()
print('=== 用户态里 0x22xxxx 类型的立即数 ===')
uc = set()
for m in re.finditer(rb'\xBA(....)', d):
    v = struct.unpack('<I', m.group(1))[0]
    if 0x220000 <= v <= 0x22FFFF or (v >> 16) in (0x22,):
        uc.add(v)
for v in sorted(uc)[:40]:
    print('  0x%08X' % v)
print('  共', len(uc))