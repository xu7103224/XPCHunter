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
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
A=0x140069D54
INS=list(md.disasm(d[off(A):off(A)+0x300],A))
print("== prologue / rbp setup ==")
for ins in INS[:18]:
    print(f'  {ins.address:#x}  {ins.bytes.hex(" "):<24} {ins.mnemonic} {ins.op_str}')
print("== 8th-arg (context) movs ==")
for ins in INS:
    if ins.mnemonic=='mov' and 'rsp' in ins.op_str and '+ 0x38]' in ins.op_str:
        print(f'  {ins.address:#x}  {ins.bytes.hex(" "):<24} {ins.mnemonic} {ins.op_str}')
print("== rbp-relative byte tests ==")
for ins in INS:
    if ins.mnemonic in ('test','cmp') and '[rbp' in ins.op_str:
        print(f'  {ins.address:#x}  {ins.bytes.hex(" "):<24} {ins.mnemonic} {ins.op_str}')
