import struct, re
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

CASES = {
 'V3':   (0x140035AFC, 0x30D, -0x60, 0xc0),
 'PNEPC':(0x140039214, 0x3CC, -0x50, 0xd0),
 'PCFS': (0x140033FA8, 0x3F8, -0x60, 0xc0),
 'PCCS': (0x140034E7C, 0x43E, -0x60, 0xc0),
}
for name,(fn,size,desc,dst) in CASES.items():
    c=d[off(fn):off(fn)+size]
    ins=list(md.disasm(c,fn))
    print(f'===== {name} (desc=rbp{desc:+#x}, Dst=rbp+{dst:#x}) =====')
    for i,x in enumerate(ins):
        m=re.search(r'\[rbp \+ (\w+)\*4 \+ 0x%x\]'%dst, x.op_str)
        if not m: continue
        idx=m.group(1)
        # 回溯最多 6 条，找最近一次写 idx 的 mov
        src=None
        for y in reversed(ins[max(0,i-6):i]):
            if y.mnemonic!='mov': continue
            ops=y.op_str.split(',')
            if len(ops)==2 and ops[0].strip()==idx:
                src=y.op_str; break
        kind='写Dst' if x.op_str.strip().startswith('dword ptr [rbp') else '读Dst'
        # 从 src 解析 desc 偏移
        do=None
        mm=re.search(r'\[rbp \+ (0x[0-9a-f]+)\]', src or '')
        if mm: do=int(mm.group(1),16)+desc
        mm=re.search(r'\[rbp - (0x[0-9a-f]+)\]', src or '')
        if mm: do=-(int(mm.group(1),16))+desc
        tag=f'desc+0x{do:03X}' if do is not None else '?'
        print(f'  {x.address:#010x} {kind}: {x.op_str}')
        print(f'             索引 {idx} <- {src}   => 字段 {tag}')