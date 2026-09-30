"""权威字段提取：对每个解析器，自动定位 SectionEntry 缓冲区基址，
并把所有 [rbp±disp] 访问换算成 SectionEntry 相对偏移。
SectionEntry 基址 = call ReadPESectionEntry 前那个 lea rdx,[rbp-X]。
"""
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

FUNCS=[('ParseNtExportSectionsV3',0x140035AFC,0x30D),
       ('ParseNtFileForCallbackContext',0x14003E1F4,0x30D),
       ('ParseNtSectionsForContextTable',0x140046FEC,0x2FF),
       ('ParseNtExportSectionsForProcessContext',0x140039214,0x3CC),
       ('ParseCallbackFunctionSections',0x140033FA8,0x3F8),
       ('ParseCallbackContextSections',0x140034E7C,0x43E)]

READPES=0x14008A54C
for name,fn,size in FUNCS:
    ins=list(md.disasm(d[off(fn):off(fn)+size], fn))
    # 找所有 call ReadPESectionEntry
    bases=[]
    for i,x in enumerate(ins):
        if x.mnemonic=='call':
            tgt=None
            if x.operands and x.operands[0].type==X86_OP_IMM: tgt=x.operands[0].imm
            if tgt==READPES:
                base=None
                for y in reversed(ins[max(0,i-5):i]):
                    if y.mnemonic=='lea' and y.op_str.startswith('rdx,'):
                        m=re.search(r'\[rbp - (0x[0-9a-f]+)\]',y.op_str)
                        if m: base=-int(m.group(1),16)
                        else:
                            m2=re.search(r'\[rbp \+ (0x[0-9a-f]+)\]',y.op_str)
                            if m2: base=int(m2.group(1),16)
                        break
                bases.append((x.address,base))
    uniq=sorted(set(b[1] for b in bases if b[1] is not None))
    print(f'===== {name} @ {fn:#x} =====')
    print(f'  SectionEntry 基址候选: ' + ', '.join(f'rbp{b:+#x}' for b in uniq))
    if len(uniq)!=1:
        print('  (多基址，逐 call 处理)')
    # 收集字段：把每处 rbp 访问按"最近的 lea rdx 基址"归属
    cur_base = uniq[0] if len(uniq)==1 else None
    fields={}
    for i,x in enumerate(ins):
        if x.mnemonic=='call' and x.operands and x.operands[0].type==X86_OP_IMM and x.operands[0].imm==READPES:
            for y in reversed(ins[max(0,i-5):i]):
                if y.mnemonic=='lea' and y.op_str.startswith('rdx,'):
                    m=re.search(r'\[rbp - (0x[0-9a-f]+)\]',y.op_str)
                    if m: cur_base=-int(m.group(1),16)
                    else:
                        m2=re.search(r'\[rbp \+ (0x[0-9a-f]+)\]',y.op_str)
                        cur_base=int(m2.group(1),16) if m2 else cur_base
                    break
        if cur_base is None: continue
        for op in x.operands:
            if op.type==X86_OP_MEM and op.mem.base and x.reg_name(op.mem.base)=='rbp' and not op.mem.index:
                do=op.mem.disp-cur_base
                fields.setdefault(do,[]).append((x.address,f'{x.mnemonic} {x.op_str}'))
    for do in sorted(fields):
        print(f'  +0x{do:03X}  x{len(fields[do]):<2} {fields[do][0][1]}')