import struct
from capstone import *
from capstone.x86 import *
d=open('samples/PCHunter_2024.09.02/View++_Driver64.sys','rb').read()
pe=struct.unpack_from('<I',d,0x3c)[0]
nsec=struct.unpack_from('<H',d,pe+6)[0]
sec=pe+24+struct.unpack_from('<H',d,pe+20)[0]
secs=[]
for i in range(nsec):
    o=sec+i*40
    vsz,va,rsz,ra=struct.unpack_from('<IIII',d,o+8)
    secs.append((va,vsz,ra,rsz))
def off(va):
    va-=0x140000000
    for sva,vsz,ra,rsz in secs:
        if sva<=va<sva+max(vsz,rsz): return ra+(va-sva)
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True

def analyze(name, fn, size, desc_base_reg, desc_disp):
    """desc: descriptor base = <reg> + <disp> (as seen after lea rdx,[rbp+X] passed to ReadPESectionEntry)"""
    c=d[off(fn):off(fn)+size]
    ins=list(md.disasm(c,fn))
    # find the lea that loads the descriptor pointer into rdx right before call ReadPESectionEntry
    print(f'--- {name} @ {hex(fn)} ---')
    # collect accesses rbp-relative with index (rbp + reg*4 + disp) = Dst[...] accesses
    for x in ins:
        for op in x.operands:
            if op.type==X86_OP_MEM and op.mem.base and op.mem.index:
                b=x.reg_name(op.mem.base); ix=x.reg_name(op.mem.index)
                if b=='rbp':
                    # Dst array base = disp; index register's source
                    yield_off = op.mem.disp - desc_disp
                    print(f'  {x.address:#x}: {x.mnemonic} {x.op_str}   -> Dst index from reg {ix} (Dst array at rbp+{op.mem.disp:#x})')

for n,a,s,db,dd in [('PNEPC',0x140039214,0x3cc,'rbp',0),]:
    analyze(n,a,s,db,dd)