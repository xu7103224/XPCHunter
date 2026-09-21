# 验证 minifilter 注册结构与操作表在新产物中的正确性
import pefile, struct
from capstone import *

SYS = r'build\bin\Release\x64\XPCHunterDrv.sys'
data = open(SYS, 'rb').read()
pe = pefile.PE(SYS)
IB = pe.OPTIONAL_HEADER.ImageBase
secs = [(s.Name.rstrip(b'\x00').decode(), s.VirtualAddress, max(s.Misc_VirtualSize, s.SizeOfRawData), s.PointerToRawData) for s in pe.sections]

def off2va(off):
    for nm, va, sz, raw in secs:
        if raw <= off < raw + sz:
            return IB + va + (off - raw)
    return None
def va2off(va):
    for nm, sva, sz, raw in secs:
        if IB + sva <= va < IB + sva + sz:
            return raw + (va - (IB + sva))
    return None

print(f'产物大小: {len(data):,}')
print()
print('=== 导入检查 ===')
for s in [b'FltRegisterFilter', b'FltStartFiltering', b'FltUnregisterFilter']:
    print(f'  {s.decode():22s}', '✓' if s in data else '✗')

# 搜索 FLT_REGISTRATION：Size=0x68, Version=0x0202, Flags=1
print()
print('=== FLT_REGISTRATION 结构搜索 ===')
pat = struct.pack('<HH I', 0x68, 0x0202, 1)
idx = 0
found = []
while True:
    i = data.find(pat, idx)
    if i < 0:
        break
    found.append(i)
    idx = i + 1
print(f'  匹配到 {len(found)} 处候选')

for i in found:
    va = off2va(i)
    if va is None:
        continue
    size, ver, flags, ctx, opreg, unload = struct.unpack_from('<HH I Q Q Q', data, i)
    print(f'  @ 文件偏移 {i:#x} (VA {va:#x})')
    print(f'      Size={size} Version={ver:#x} Flags={flags}')
    print(f'      ContextRegistration      = {ctx:#x}')
    print(f'      OperationRegistration    = {opreg:#x}')
    print(f'      FilterUnloadCallback     = {unload:#x}')
    # 解析操作表
    if opreg:
        o = va2off(opreg)
        if o:
            print('      --- 操作回调表 ---')
            for k in range(4):
                b = o + k * 32
                mf = data[b]
                fl = struct.unpack_from('<I', data, b + 4)[0]
                pre, post = struct.unpack_from('<QQ', data, b + 8)
                if mf == 0x80 and pre == 0 and post == 0:
                    print(f'        [{k}] MajorFunction=0x80 (IRP_MJ_OPERATION_END) — 终止符 ✓')
                    break
                print(f'        [{k}] MajorFunction={mf:#x} Flags={fl} Pre={pre:#x} Post={post:#x}')
    # 检查 unload 回调地址对应的符号
    if unload:
        print(f'      FilterUnloadCallback 指向 VA {unload:#x}')
