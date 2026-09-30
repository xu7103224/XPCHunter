import struct, sys
from capstone import *
from capstone.x86 import *

P='samples/PCHunter_2024.09.02/View++_Driver64.sys'
d=open(P,'rb').read()
pe=struct.unpack_from('<I',d,0x3c)[0]
nsec=struct.unpack_from('<H',d,pe+6)[0]
opt=pe+24
sec=opt+struct.unpack_from('<H',d,pe+20)[0]
secs=[]
for i in range(nsec):
    o=sec+i*40
    vsz,va,rsz,ra=struct.unpack_from('<IIII',d,o+8)
    secs.append((va,vsz,ra,rsz))
def off_of(va):
    va-=0x140000000
    for sva,vsz,ra,rsz in secs:
        if sva<=va<sva+max(vsz,rsz): return ra+(va-sva)
    return None

md=Cs(CS_ARCH_X86, CS_MODE_64)
md.detail=True

def dump(start, size, only=None):
    o=off_of(start)
    code=d[o:o+size]
    for ins in md.disasm(code, start): reg_va=0
    
    for ins in md.disasm(code, start):
        txt=f'{ins.address:#x}: {ins.mnemonic}'
        if ins.op_str: txt+=' '+ins.op_str
        # 提取内存操作数位移
        disps=[]
        for op in ins.operands:
            if op.type==X86_OP_MEM:
                m=op.mem
                base=ins.reg_name(m.base) if m.base else ''
                idx=ins.reg_name(m.index) if m.index else ''
                disps.append(f'[mem base={base} index={idx} scale={m.scale} disp={m.disp:#x}]')
        if only and not any(only in t for t in [txt]): 
            if disps: pass
            else: continue
        print(txt)
        for x in disps: print('      ',x)

if __name__=='__main__':
    cmd=sys.argv[1]
    if cmd=='pnepc':
        dump(0x140039214, 0x3cc)
    elif cmd=='pcfs':
        dump(0x140033fa8, 0x3f8)
    elif cmd=='pccs':
        dump(0x140034e7c, 0x43e)