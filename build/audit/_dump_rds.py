# 用 capstone 把 ReadDiskSectors(0x140078A30, 0x518 字节) 完整反汇编落盘，
# 供后续按条重写；同时标注每条 call 的目标与 mov ecx,imm 的 GT 索引。
import struct, sys
from capstone import *
P='samples/PCHunter_2024.09.02/View++_Driver64.sys'
d=open(P,'rb').read()
pe=struct.unpack_from('<I',d,0x3c)[0]
n=struct.unpack_from('<H',d,pe+6)[0]
sec=pe+24+struct.unpack_from('<H',d,pe+20)[0]
secs=[]
for i in range(n):
    o=sec+i*40
    vsz,va,rsz,ra=struct.unpack_from('<IIII',d,o+8); secs.append((va,vsz,ra,rsz))
def off(va):
    va-=0x140000000
    for sva,vsz,ra,rsz in secs:
        if sva<=va<sva+max(vsz,rsz): return ra+(va-sva)
A,SZ=0x140078A30,0x518
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
out=[]
for ins in md.disasm(d[off(A):off(A)+SZ],A):
    out.append(f"{ins.address:#x}  {ins.bytes.hex(' '):<24} {ins.mnemonic:<8} {ins.op_str}")
open('build/audit/asm/ReadDiskSectors.asm','w',encoding='utf-8').write('\n'.join(out))
print(f"写出 {len(out)} 条指令 -> build/audit/asm/ReadDiskSectors.asm")
