"""为解析器族生成权威注解清单（capstone 字节级，desc 偏移 = disp - desc_base）
用法: python _famannot.py <name>
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

FUNCS = {
 'V3':   (0x140035AFC, 0x30D),
 'PNEPC':(0x140039214, 0x3CC),
 'PCFS': (0x140033FA8, 0x3F8),
 'PCCS': (0x140034E7C, 0x43E),
}

name=sys.argv[1]
fn,size=FUNCS[name]
c=d[off(fn):off(fn)+size]
ins=list(md.disasm(c,fn))
# 自动找 desc 基址：call ReadPESectionEntry 前的 lea rdx,[rbp-X]
desc=None
for i,x in enumerate(ins):
    if x.mnemonic=='call':
        for y in reversed(ins[max(0,i-4):i]):
            if y.mnemonic=='lea' and y.op_str.startswith('rdx,'):
                m=re.search(r'\[rbp - (0x[0-9a-f]+)\]',y.op_str)
                if m: desc=-int(m.group(1),16)
                else:
                    m2=re.search(r'\[rbp \+ (0x[0-9a-f]+)\]',y.op_str)
                    if m2: desc=int(m2.group(1),16)
                break
        if desc is not None: break
# Dst 数组基址：lea rcx,[rbp+X] 后跟 memset
dstbase=None
for i,x in enumerate(ins):
    if x.mnemonic=='call' and '1400013f0' in x.op_str or (x.mnemonic=='call' and i>0 and ins[i-2].op_str.startswith('rcx')):
        pass
for i,x in enumerate(ins):
    if x.mnemonic=='lea' and re.match(r'rcx, \[rbp \+ 0x([0-9a-f]+)\]',x.op_str):
        m=re.match(r'rcx, \[rbp \+ 0x([0-9a-f]+)\]',x.op_str)
        dstbase=int(m.group(1),16); break
print(f'# {name} @ {fn:#x}  size={size}  desc=rbp{desc:+#x}  Dst=rbp+{dstbase:#x}' if desc is not None and dstbase is not None
      else f'# {name} @ {fn:#x}  size={size}  desc={desc} dst={dstbase}')
for x in ins:
    t=f'{x.address:#010x} {x.mnemonic:7} {x.op_str}'
    notes=[]
    for m in re.finditer(r'\[rbp \+ (0x[0-9a-f]+)\]',x.op_str):
        do=int(m.group(1),16)-desc
        notes.append(f'C+{do:#x}')
    for m in re.finditer(r'\[rbp - (0x[0-9a-f]+)\]',x.op_str):
        do=-(int(m.group(1),16))-desc
        notes.append(f'C+{do:#x}')
    for m in re.finditer(r'\[rbp \+ (\w+)\*4 \+ 0x([0-9a-f]+)\]',x.op_str):
        notes.append(f'ARR[{m.group(1)}]')
    if notes: t+='   ; '+' '.join(notes)
    print(t)