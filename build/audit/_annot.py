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

def annot(fn,size,desc,rbp_lea_note=''):
    c=d[off(fn):off(fn)+size]
    for x in md.disasm(c,fn):
        t=f'{x.address:#010x} {x.mnemonic:7} {x.op_str}'
        outs=[]
        for m in re.finditer(r'\[rbp \+ (0x[0-9a-f]+)\]',x.op_str):
            outs.append(f'desc+{int(m.group(1),16)+desc:#x}')
        for m in re.finditer(r'\[rbp - (0x[0-9a-f]+)\]',x.op_str):
            outs.append(f'desc-{-(int(m.group(1),16))-desc:#x}' if False else f'desc+{-(int(m.group(1),16))+desc:#x}')
        for m in re.finditer(r'\[rbp \+ (\w+)\*4 \+ (0x[0-9a-f]+)\]',x.op_str):
            outs.append(f'Dst[{m.group(1)}] 数组基=desc+{int(m.group(2),16)+desc:#x}')
        for m in re.finditer(r'\[rbp - (0x[0-9a-f]+) \+ (\w+)\*4\]',x.op_str):
            outs.append(f'Dst[{m.group(2)}]')
        if outs: t+='   ; '+' | '.join(outs)
        print(t)

if __name__=='__main__':
    mode=sys.argv[1]
    if mode=='v3':
        annot(0x140035AFC,0x30D,-0x60)
    elif mode=='pnepc':
        annot(0x140039214,0x3CC,-0x50)
    elif mode=='pcfs':
        annot(0x140033FA8,0x3F8,-0x60)
    elif mode=='pccs':
        annot(0x140034E7C,0x43E,-0x60)