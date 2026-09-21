# 原始 vs 复刻：FLT_REGISTRATION 与操作回调表逐字段对比
import pefile, struct

def load(path):
    pe = pefile.PE(path)
    return pe, open(path, 'rb').read(), pe.OPTIONAL_HEADER.ImageBase

def va2off(pe, va):
    rva = va - pe.OPTIONAL_HEADER.ImageBase
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return None

ORIG = r'samples\PCHunter_2024.09.02\View++_Driver64.sys'
NEW = r'build\bin\Release\x64\XPCHunterDrv.sys'
FIELDS = ['Size', 'Version', 'Flags', 'ContextRegistration', 'OperationRegistration',
          'FilterUnloadCallback', 'InstanceSetupCallback', 'InstanceQueryTeardownCallback',
          'InstanceTeardownStartCallback', 'InstanceTeardownCompleteCallback',
          'GenerateFileNameCallback', 'NormalizeNameComponentCallback',
          'NormalizeContextCleanupCallback', 'TransactionNotificationCallback',
          'NormalizeNameComponentExCallback']

po, do, ibo = load(ORIG)
pn, dn, ibn = load(NEW)

# 符号名映射（用 map 解析复刻地址 -> 名字）
import re
mp = open(r'build\bin\Release\x64\XPCHunterDrv.map', encoding='utf-8', errors='ignore').read()
named = {}
for m in re.finditer(r'\s([A-Za-z_]\w*)\s+([0-9a-f]{16})\s+f\s', mp):
    named[int(m.group(2), 16)] = m.group(1)

def show(path_label, pe, data, ib, reg_va):
    o = va2off(pe, reg_va)
    vals = []
    size, ver, flags = struct.unpack_from('<HHI', data, o)
    vals += [f'{size} ({size:#x})', f'{ver:#x}', flags]
    ptrs = struct.unpack_from('<12Q', data, o + 8)
    vals += list(ptrs)
    print(f'--- {path_label} Registration @ {reg_va:#x}')
    for name, v in zip(FIELDS, vals):
        extra = ''
        if isinstance(v, int) and v and name != 'Flags':
            extra = f'  -> {named.get(v, hex(v))}'
        print(f'    {name:34s} = {v if not isinstance(v,int) else hex(v)}{extra}')
    return vals

vo = show('原始', po, do, ibo, 0x14008D600)
vn = show('复刻', pn, dn, ibn, 0x1400907D0)

print()
print('=== 逐字段对比 ===')
allok = True
for name, a, b in zip(FIELDS, vo, vn):
    if name == 'Flags':
        ok = a == b
    elif isinstance(a, int) or isinstance(b, int):
        # 指针只比较"是否为空"（地址不同属正常）
        ok = (a == 0) == (b == 0)
    else:
        ok = a == b
    if not ok:
        allok = False
    print(f'  {name:34s} {"一致 ✓" if ok else f"不一致 ✗  原始={a} 复刻={b}"}')

# 操作回调表
print()
print('=== 操作回调表 ===')
def show_ops(label, pe, data, ops_va):
    o = va2off(pe, ops_va)
    out = []
    for k in range(4):
        b = o + k * 32
        mf = data[b]
        fl = struct.unpack_from('<I', data, b + 4)[0]
        pre, post = struct.unpack_from('<QQ', data, b + 8)
        out.append((mf, fl, pre, post))
        tag = ' (终止符)' if mf == 0x80 else ''
        pre_n = named.get(pre, '') if label == '复刻' else ''
        print(f'  {label} [{k}] MajorFunction={mf:#04x} Flags={fl} Pre={pre:#x} {pre_n}{tag}')
        if mf == 0x80:
            break
    return out

oo = show_ops('原始', po, do, 0x14008D5C0)
on = show_ops('复刻', pn, dn, 0x140090840)

print()
same = (len(oo) == len(on) and all(
    (a[0], a[1], (a[2] == 0) == (b[2] == 0)) == (b[0], b[1], True) for a, b in zip(oo, on)))
print('操作回调表结构与原始一致:', '✓' if same else '✗（需检查）')
