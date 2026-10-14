# 全量扫描「宏覆盖」类缺陷：
# xpc_gt_enum.h 末尾的「EPROCESS 字段别名」宏块按**索引**命名
# （#define GtEprocessFieldN <某枚举>  // index N），
# 而调用点常按**值**使用（GtEprocessFieldNNN | mask）。
# 本脚本对每个调用点：
#   1. 解析宏链得到「我方实际计算出的索引值」；
#   2. 找出该调用点所属函数在**原始驱动**里的全部常量槽；
#   3. 若我方值不在原始槽集合里，但在原始槽集合中存在
#      「只差 mask 之外的位」或「把宏名尾数当值」的候选，则报疑似宏覆盖。
import re, json, glob, struct
from capstone import *

# ---- 1. 解析我方枚举与宏 ----
h = open('XPCHunterDrv/inc/xpc_gt_enum.h', encoding='utf-8').read()
vals = {m.group(1): int(m.group(2), 0)
        for m in re.finditer(r'^\s*(\w+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*,', h, re.M)}
defs = {}
for m in re.finditer(r'^\s*#define\s+(\w+)\s+(\S+)(.*)$', h, re.M):
    mm = re.match(r'^(\w+)(\|(0x[0-9A-Fa-f]+|\d+))?$', m.group(2))
    if mm:
        defs[m.group(1)] = (mm.group(1), int(mm.group(3), 0) if mm.group(3) else None)

def res(name, d=0):
    if d > 12: return None
    if name in vals: return vals[name]
    t = defs.get(name)
    if t is None: return None
    b = res(t[0], d + 1)
    if b is None: return None
    return b | t[1] if t[1] is not None else b

# ---- 2. 原始驱动的常量槽 ----
P = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
d = open(P, 'rb').read()
pe = struct.unpack_from('<I', d, 0x3c)[0]
n = struct.unpack_from('<H', d, pe + 6)[0]
sec = pe + 24 + struct.unpack_from('<H', d, pe + 20)[0]
secs = []
for i in range(n):
    o = sec + i * 40
    vsz, va, rsz, ra = struct.unpack_from('<IIII', d, o + 8)
    secs.append((va, vsz, ra, rsz))
def off(va):
    va -= 0x140000000
    for sva, vsz, ra, rsz in secs:
        if sva <= va < sva + max(vsz, rsz): return ra + (va - sva)
md = Cs(CS_ARCH_X86, CS_MODE_64)
orig_funcs = {f['start']: f for f in json.load(open('build/audit/_orig_funcs_ida.json'))}

def orig_slots(va):
    """收集该函数所有传给 GtRead/GtWrite/GtAlloc 的常量索引。
    跟踪：mov ecx,imm / lea ecx,[reg-imm]（reg 若为已知常量）/ mov ecx,reg（常量传播）。
    在 jmp 处**不清空** last —— 因为原始常把 `mov ecx,imm; jmp call` 分开写。"""
    f = orig_funcs.get(va)
    if not f: return None
    out = set()
    regs = {}          # 已跟踪的寄存器常量
    last = None
    for x in md.disasm(d[off(va):][:f['size']], va):
        ops = x.op_str
        if x.mnemonic == 'mov':
            m = re.match(r'(\w+), (0x[0-9a-f]+)$', ops)
            if m:
                regs[m.group(1)] = int(m.group(2), 16)
                if m.group(1) in ('ecx',):
                    last = int(m.group(2), 16)
                continue
            m = re.match(r'(\w+), (\w+)$', ops)
            if m and m.group(2) in regs:
                regs[m.group(1)] = regs[m.group(2)]
                if m.group(1) == 'ecx':
                    last = regs[m.group(1)]
                continue
            if ops.startswith('ecx, '):
                last = None
            continue
        if x.mnemonic == 'lea':
            m = re.match(r'ecx, \[(\w+) - (0x[0-9a-f]+)\]$', ops)
            if m and m.group(1) in regs:
                last = (regs[m.group(1)] - int(m.group(2), 16)) & 0xFFFFFFFF
                continue
            m = re.match(r'ecx, \[(\w+) \+ (0x[0-9a-f]+)\]$', ops)
            if m and m.group(1) in regs:
                last = (regs[m.group(1)] + int(m.group(2), 16)) & 0xFFFFFFFF
                continue
            if ops.startswith('ecx, '):
                last = None
            continue
        if x.mnemonic == 'call':
            if ops in ('0x140029efc', '0x140029ff4', '0x140029eec') and last is not None:
                out.add(last)
            # 调用可能改变寄存器：保守清空（但保留 ecx 的 last 以便 jmp-call 模式已收集）
            last = None
            continue
    return out

# ---- 3. 我方调用点 -> 所属函数 -> 原始地址 ----
amap = json.load(open('build/audit/_addr_map.json', encoding='utf-8'))
addr_of = {}
for a, v in amap.items():
    addr_of[v[0]] = int(a, 16)

files = [(f, open(f, encoding='utf-8', errors='replace').read())
         for f in glob.glob('XPCHunterDrv/src/**/*.c', recursive=True)]
CALL = re.compile(r'Gt(?:Read|Write|Alloc)\(\s*\(GLOBAL_TABLE_INDEX\)?\s*([^)]*)\)')
FUNC = re.compile(r'^[A-Za-z_][\w \*]*?\b([A-Za-z_]\w*)\s*\(', re.M)

susp = []
for path, src in files:
    # 建立"行号 -> 所属函数名"
    fn_at = []
    for m in FUNC.finditer(src):
        fn_at.append((m.start(), m.group(1)))
    lines = src.split('\n')
    for m in CALL.finditer(src):
        expr = m.group(1)
        if '|' not in expr: continue
        # 计算我方值
        v = None
        for t in expr.split('|'):
            t = t.strip().strip('()')
            if not t: continue
            if re.fullmatch(r'0x[0-9A-Fa-f]+|\d+', t):
                x = int(t, 0)
            else:
                x = res(t)
            if x is None: v = None; break
            v = x if v is None else (v | x)
        if v is None: continue
        ln = src[:m.start()].count('\n')
        # 所属函数
        name = None
        for s, nm in fn_at:
            if s <= m.start(): name = nm
            else: break
        if name is None or name not in addr_of: continue
        oslots = orig_slots(addr_of[name])
        if not oslots or v in oslots: continue
        susp.append((name, hex(addr_of[name]), expr.strip()[:46], hex(v),
                     sorted(hex(x) for x in oslots)[:8], path.split('\\')[-1], ln + 1))

print(f'扫描完成：{len(susp)} 处疑似宏覆盖/取错槽（我方算出的值不在该函数原始槽集合中）\n')
for name, addr, expr, v, slots, fn, ln in susp[:60]:
    print(f'{addr:>12} {name[:28]:<28} 我方={v:<7} 原始槽={slots}')
    print(f'{"":>12}   expr: {expr}   @{fn}:{ln}')