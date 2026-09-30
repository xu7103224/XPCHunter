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
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True

def regs_of(ins):
    return {}

def analyze(name, fn, size):
    c=d[off(fn):off(fn)+size]
    ins=list(md.disasm(c,fn))
    # 1) 找 call ReadPESectionEntry，取上一句 lea rdx,[...] 作为 SectionInfo 基址
    base_expr=None; ctx_expr=None
    for i,x in enumerate(ins):
        if x.mnemonic=='call' and 'ReadPESectionEntry' in x.op_str:
            for y in reversed(ins[max(0,i-4):i]):
                if y.mnemonic=='lea' and y.op_str.startswith('rdx,'):
                    base_expr=y.op_str; break
            break
    print(f'===== {name} =====')
    print(f'  SectionInfo 基址表达式: {base_expr}')
    if not base_expr: return
    m=re.search(r'\[rbp - (0x[0-9a-f]+)\]',base_expr)
    base = -int(m.group(1),16) if m else 0
    if not m:
        m2=re.search(r'\[rbp \+ (0x[0-9a-f]+)\]',base_expr)
        base = int(m2.group(1),16) if m2 else 0
    print(f'  → desc 基址 = rbp{base:+#x}')
    # 2) 收集所有 [rbp ± disp] 访问并换算成 desc 偏移
    seen={}
    for x in ins:
        for op in x.operands:
            if op.type==X86_OP_MEM and op.mem.base and x.reg_name(op.mem.base)=='rbp':
                do=op.mem.disp-base
                if op.mem.index:
                    # Dst 数组：记录数组基址
                    seen.setdefault(('DST',do),[]).append(f'{x.address:#x} {x.mnemonic} {x.op_str}')
                else:
                    seen.setdefault(('F',do),[]).append(f'{x.address:#x} {x.mnemonic} {x.op_str}')
    for k in sorted(seen, key=lambda t:(t[0],t[1])):
        kk,do=k
        tag='Dst数组' if kk=='DST' else '字段'
        print(f'  desc+0x{do:03X} [{tag}] x{len(seen[k])}  {seen[k][0]}')

analyze('ParseNtExportSectionsV3', 0x140035AFC, 0x30D)
analyze('ParseCallbackFunctionSections', 0x140033FA8, 0x3F8)
analyze('ParseCallbackContextSections', 0x140034E7C, 0x43E)
analyze('ParseNtExportSectionsForProcessContext', 0x140039214, 0x3CC)