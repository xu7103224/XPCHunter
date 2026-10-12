import struct
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
md=Cs(CS_ARCH_X86,CS_MODE_64)
A=0x140050774
raw=d[off(A):off(A)+0x310]
INS=list(md.disasm(raw,A))
print("== prologue ==")
for ins in INS[:14]:
    print(f'  {ins.address:#x}  {ins.bytes.hex(" "):<22} {ins.mnemonic} {ins.op_str}')
print("== mem operands touching descriptor fields (rsp-relative cmp/movzx/mov) ==")
import re
for ins in INS:
    ops=ins.op_str
    if ('rsp' in ops or 'rbp' in ops) and ins.mnemonic in ('cmp','test','mov','movzx','add','sub'):
        print(f'  {ins.address:#x}  {ins.bytes.hex(" "):<22} {ins.mnemonic} {ops}')
