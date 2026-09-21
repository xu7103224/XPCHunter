# 从复刻产物导出函数名与大小：.map 提供名称，.pdata 提供函数边界
import re, struct, json

SYS = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\build\bin\Release\x64\XPCHunterDrv.sys'
MAP = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\build\bin\Release\x64\XPCHunterDrv.map'
OUT = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\build\audit\_new_funcs.json'

data = open(SYS, 'rb').read()
import pefile
pe = pefile.PE(SYS)
IB = pe.OPTIONAL_HEADER.ImageBase
pdata = [s for s in pe.sections if s.Name.rstrip(b'\x00') == b'.pdata'][0]
raw = pdata.get_data()
pd = {}
for i in range(len(raw) // 12):
    b, e, u = struct.unpack_from('<III', raw, i * 12)
    pd[b + IB] = e + IB
print(f'复刻 .pdata 条目: {len(pd)}')

# 解析 map 的 publics 段（函数带 f 标记）
lines = open(MAP, encoding='utf-8', errors='ignore').read().split('\n')
pub_re = re.compile(r'^\s+([0-9a-f]{4}):([0-9a-f]{8})\s+(\S+)\s+([0-9a-f]{16})\s+(f?)\s+(\S+)\s*$')
funcs = {}
allsyms = []
idx_static = next((i for i, l in enumerate(lines) if l.strip().startswith('Static symbols')), len(lines))
for l in lines[:idx_static]:
    m = pub_re.match(l)
    if not m:
        continue
    seg, off, name, addr, flag, obj = m.groups()
    if name.startswith('$') or name.startswith('__') or name.startswith('?'):
        continue
    a = int(addr, 16)
    allsyms.append((a, name, seg, flag, obj))

# 按地址排序，用于推算未在 .pdata 中的叶函数大小
allsyms.sort()
print(f'map 中符号数（已过滤 CRT 内部）: {len(allsyms)}')

for i, (a, name, seg, flag, obj) in enumerate(allsyms):
    size = None
    method = ''
    if a in pd:
        size = pd[a] - a
        method = 'pdata'
    else:
        nxt = None
        for j in range(i + 1, len(allsyms)):
            if allsyms[j][2] == seg:
                nxt = allsyms[j][0]
                break
        if nxt and nxt > a:
            size = nxt - a
            method = 'delta'
    funcs[name] = {'addr': a, 'size': size, 'method': method, 'obj': obj, 'seg': seg}

json.dump(funcs, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False)
print('已写入', OUT)

by_pdata = sum(1 for v in funcs.values() if v['method'] == 'pdata')
by_delta = sum(1 for v in funcs.values() if v['method'] == 'delta')
none_ = sum(1 for v in funcs.values() if v['size'] is None)
print(f'  来自 .pdata（精确）: {by_pdata}')
print(f'  来自地址差（近似）: {by_delta}')
print(f'  无法确定大小: {none_}')

for n in ['CheckProcessAccess', 'DriverEntry', 'DriverUnload', 'InitCallbackFunctions',
          'MiniFilterNormalizeName', 'ParseNtRelocSection', 'EnumProcessHandleInfo']:
    v = funcs.get(n)
    print(f"  {n:32s} {('addr={:#x} size={} via {}'.format(v['addr'], hex(v['size']) if v['size'] else '?', v['method'])) if v else '未导出'}")
