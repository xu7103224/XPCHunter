import struct, sys
from capstone import *
from capstone.x86 import *
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
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True

def fields(fn,size,listing_base,desc_addr):
    """desc_addr = the actual rbp-relative address of the SectionInfo descriptor."""
    c=d[off(fn):off(fn)+size]
    ins=list(md.disasm(c,fn))
    out=[]
    for x in ins:
        for op in x.operands:
            if op.type==X86_OP_MEM and op.mem.base and x.reg_name(op.mem.base)=='rbp':
                if op.mem.index:
                    # Dst[...] array access: base disp is the Dst array
                    continue
                desc_off = op.mem.disp - desc_addr
                if -0x30 <= desc_off <= 0x140:
                    out.append((desc_off, f'{x.address:#x} {x.mnemonic} {x.op_str}'))
    return out

targets = {
 'PNEPC  ': (0x140039214, 0x3cc, -0x50),
 'PCFS   ': (0x140033fa8, 0x3f8, -0x60),
 'PCCS   ': (0x140034e7c, 0x43e, -0x60),
 'V3(ref)': (0x140035AFC, 0x30D, -0x60),
}
for name,(fn,size,da) in targets.items():
    print(f'===== {name} descbase=rbp{da:+#x} =====')
    seen={}
    for o,t in fields(fn,size,0,da):
        seen.setdefault(o,[]).append(t)
    for o in sorted(seen):
        print(f'  +0x{o:03X}  x{len(seen[o]):<2} {seen[o][0]}')