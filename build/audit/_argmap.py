"""精确的栈参数映射器。
栈参数布局（MS x64，rbp 锚点 = entry_rsp - delta）：
  形参 1..4 在 rcx/rdx/r8/r9；形参 5 起依次在 [entry_rsp + 0x28 + 8*(N-5)]
  因 rbp = entry_rsp - delta，故 [rbp + delta + 0x28 + 8*(N-5)]
用法: python _argmap.py <fn_hex> <size> <delta_hex>
"""
import struct, re, sys
from capstone import *
d=open('samples/PCHunter_2024.09.02/View++_Driver64.sys','rb').read()
pe=struct.unpack_from('<I',d,0x3c)[0]
nsec=struct.unpack_from('<H',d,pe+6)[0]
sec=pe+24+struct.unpack_from('<H',d,pe+20)[0]
secs=[]
for i in range(nsec):
    o=sec+i*40; vsz,va,rsz,ra=struct.unpack_from('<IIII',d,o+8); secs.append((va,vsz,ra,rsz))
def off(va):
    va-=0x140000000
    for sva,vsz,ra,rsz in secs:
        if sva<=va<sva+max(vsz,rsz): return ra+(va-sva)
md=Cs(CS_ARCH_X86,CS_MODE_64)

fn=int(sys.argv[1],16); size=int(sys.argv[2],0); delta=int(sys.argv[3],0)
# 形参 N(>=5) 位于 rbp + delta + 0x28 + 8*(N-5)
# rbp = entry_rsp + delta  =>  entry_rsp = rbp - delta
# 形参 5 位于 entry_rsp + 0x28；形参 N 位于 entry_rsp + 0x28 + 8*(N-5)
def arg_of(disp):
    for N in range(5,16):
        if disp == (-delta) + 0x28 + 8*(N-5): return N
    # 形参 1..4 的 home 槽：entry_rsp + 8*K  (K=1..4)
    for K in range(1,5):
        if disp == (-delta) + 8*K: return K
    return None
c=d[off(fn):off(fn)+size]
seen={}
for x in md.disasm(c,fn):
    for m in re.finditer(r'\[rbp \+ (0x[0-9a-f]+)\]',x.op_str):
        v=int(m.group(1),16); seen.setdefault(v,[]).append(f'{x.address:#x} {x.mnemonic} {x.op_str}')
    for m in re.finditer(r'\[rbp - (0x[0-9a-f]+)\]',x.op_str):
        v=-(int(m.group(1),16)); seen.setdefault(v,[]).append(f'{x.address:#x} {x.mnemonic} {x.op_str}')
print(f'=== {fn:#x} size={size} delta={delta:+#x} ===')
for v in sorted(seen):
    if v>0:
        N=arg_of(v)
        tag=f'形参{N}' if N else f'其他正偏移'
    else:
        tag=f'局部 var_{0xB8+v:X}' if v>-0xB8 else '局部'
    print(f'  rbp{v:+#05x}  {tag:12s} x{len(seen[v])}  {seen[v][0]}')