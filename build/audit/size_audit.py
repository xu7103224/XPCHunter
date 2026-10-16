# size_audit.py — 比较「原始函数字节数」与「我方函数字节数」，找出实现缺失/伪造的重灾区。
# 数据来源：
#   原始侧：用 capstone 从头函数表读取每个映射地址的函数长度（到下一个函数的距离，用 IDA 名字表更准）
#   我方侧：链接 map 中的函数符号（无长度，故用相邻符号差）
# 判据：比值（我方/原始）明显 <1（漏实现）或 >3（伪造膨胀）即为嫌疑。
import json, os, re, struct, sys
sys.path.insert(0, r'E:\Work\Dev\Windows\ai\UnicornForDriver\.dsh\skills\windows-driver-emulation\scripts')
from capstone import *
from wdrvemu import parse_file

ROOT = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter'
ORIG = os.path.join(ROOT, 'samples/PCHunter_2024.09.02/View++_Driver64.sys')
REB  = os.path.join(ROOT, 'build/bin/Release/x64/XPCHunterDrv.sys')
MAP  = os.path.join(ROOT, 'build/bin/Release/x64/XPCHunterDrv.map')
AM   = os.path.join(ROOT, 'build/audit/_addr_map.json')

am = json.load(open(AM, encoding='utf-8'))

# 我方符号地址（map）→ 用于估算我方函数大小
sym = {}
for line in open(MAP, encoding='latin1'):
    m = re.match(r'^\s*[0-9a-f]{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{16})\s+f?', line)
    if m:
        sym.setdefault(m.group(1), int(m.group(2), 16))

# 我方地址升序 → 相邻差即长度估计
addrs = sorted(set(sym.values()))
def reb_size(a):
    i = addrs.index(a)
    return (addrs[i+1]-a) if i+1 < len(addrs) else 0

pe = parse_file(ORIG)
d  = open(ORIG, 'rb').read()
def orig_size(a):
    off = pe.rva_to_file_offset(a - pe.image_base)
    if off is None: return 0
    # 用 capstone 顺序解码直到遇到 ret/int3 填充后大段 0xCC
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = False
    total = 0
    for ins in md.disasm(d[off:off+8192], a):
        total += ins.size
        if ins.mnemonic == 'ret': break
    return total

rows = []
for k, v in am.items():
    oa = int(k, 16)
    name, ra, where = v[0], v[1], v[2]
    osz = orig_size(oa)
    rsz = reb_size(ra) if ra else 0
    if osz and rsz:
        rows.append((osz/max(rsz,1), osz, rsz, oa, name, where))

rows.sort(reverse=True)
print("=== 我方远大于原始（疑伪造/膨胀）ratio>2.5 ===")
for r,osz,rsz,oa,name,where in rows:
    if r > 2.5:
        print(f"  {r:6.2f}  orig={osz:5} reb={rsz:5}  {oa:#x} {name:<36} {where}")
print()
print("=== 我方远小于原始（疑漏实现）ratio<0.35 ===")
for r,osz,rsz,oa,name,where in sorted(rows):
    if r < 0.35:
        print(f"  {r:6.2f}  orig={osz:5} reb={rsz:5}  {oa:#x} {name:<36} {where}")