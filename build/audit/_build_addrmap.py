# 建立「原始函数地址 <-> 我方符号名」的映射表。
# 依据：源码注释中的 `对应原始驱动 0x...` / `对应原始驱动 sub_...` 标注。
# 输出 build/audit/_addr_map.json，供逐函数差分使用。
import json
import os
import re
import glob

ROOT = 'XPCHunterDrv/src'

# 我方重编译产物：读符号地址 + 函数体首字节
import sys as _sys
_sys.path.insert(0, r'E:\Work\Dev\Windows\ai\UnicornForDriver\.dsh\skills\windows-driver-emulation\scripts')
from wdrvemu.peparse import parse_file as _pf
REB = _pf('build/bin/Release/x64/XPCHunterDrv.sys')

# 我方符号名 -> 地址（从链接 map 读）
MAP = 'build/bin/Release/x64/XPCHunterDrv.map'
sym_addr = {}
rx = re.compile(r'^\s*([0-9a-f]{4}):([0-9a-f]{8})\s+(\S+)\s+([0-9a-f]{16})\s+f?')
for line in open(MAP, 'r', encoding='latin1'):
    m = rx.match(line)
    if m:
        name = m.group(3)
        addr = int(m.group(4), 16)
        if addr and name not in sym_addr:
            sym_addr[name] = addr

# 源码注释 -> (我方函数名, 原始地址)
# 形态：注释行含 "0x140xxxxxx" 或 "sub_140xxxxxx"，其后一行是函数定义
pairs = {}
fake = []
defre = re.compile(r'^[A-Za-z_][\w \*]*?\b([A-Za-z_]\w*)\s*\(')
addre = re.compile(r'\b(?:0x|sub_)(140[0-9A-Fa-f]{6})\b')

for path in sorted(glob.glob(os.path.join(ROOT, '**', '*.c'), recursive=True)):
    lines = open(path, 'rb').read().decode('utf-8', 'replace').split('\n')
    # 只认「紧邻函数定义的一组连续注释行」——注释块与函数签名之间不得有空行。
    # 一组注释块里取**第一处**出现的地址（通常就是 `对应原始驱动 0x...`）。
    i = 0
    while i < len(lines):
        ln = lines[i]
        if not ln.lstrip().startswith('//'):
            i += 1
            continue
        blk_start = i
        while i < len(lines) and lines[i].lstrip().startswith('//'):
            i += 1
        blk_end = i - 1
        if i >= len(lines) or not lines[i].strip():
            continue            # 注释块后是空行 -> 不是函数前言
        dm = defre.match(lines[i])
        if not dm:
            continue
        pending = None
        for j in range(blk_start, blk_end + 1):
            mm = addre.search(lines[j])
            if mm:
                pending = int('0x' + mm.group(1), 16)
                break
        if pending is not None:
            fn = dm.group(1)
            if fn in sym_addr:
                pairs.setdefault(pending, []).append((fn, sym_addr[fn], f'{path}:{i+1}'))

print(f'链接符号总数        : {len(sym_addr)}')
print(f'建立映射的原始地址数  : {len(pairs)}')

# 我方函数体首字节，用于识别纯转发壳（0xE9 = jmp rel32）。
# 一副本里 Cmd* 常是 `jmp Dispatch*` 的壳，注释若同时提到两者会产生一对多。
def _first_byte(va):
    rva = va - REB.image_base
    for s in REB.sections:
        if s.virtual_address <= rva < s.virtual_address + s.virtual_size:
            return REB.raw[s.pointer_to_raw_data + (rva - s.virtual_address)]
    return None


def _resolve(cands):
    alive = [c for c in cands if _first_byte(c[1]) != 0xE9]
    if alive:
        pref = [c for c in alive if 'Dispatch' in c[0]]
        return (pref or alive)[0]
    return cands[0]


resolved = {a: (c[0] if len(c) == 1 else _resolve(c)) for a, c in pairs.items()}

multi = {k: v for k, v in pairs.items() if len(v) > 1}
print(f'一对多、已排除「jmp 转发壳」后裁决: {len(multi)}')
for k, v in list(multi.items())[:12]:
    print(f'  {hex(k)} 取 {resolved[k][0]:<32} 候选={[x[0] for x in v]}')

json.dump({hex(k): resolved[k] for k in resolved},
          open('build/audit/_addr_map.json', 'w', encoding='utf-8'),
          ensure_ascii=False, indent=1)
json.dump({k: hex(v) for k, v in sym_addr.items()},
          open('build/audit/_sym_addr.json', 'w', encoding='utf-8'),
          ensure_ascii=False, indent=1)
print('\n已写出 _addr_map.json / _sym_addr.json')