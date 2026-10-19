#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""更宽的 GtWrite 写入点扫描：mov ecx,<slot> 之后 25 条内出现 call GtWrite。
用法: python gt_writers_wide.py <slot_hex> [slot_hex ...]
"""
import json, os, struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
HERE=os.path.dirname(os.path.abspath(__file__))
ORIG=os.path.join(HERE,'..','..','samples','PCHunter_2024.09.02','View++_Driver64.sys')
BASE=0x140000000; GW=0x140029FF4; GR=0x140029EFC
def load_text():
    d=open(ORIG,'rb').read()
    pe=struct.unpack_from('<I',d,0x3c)[0]
    n=struct.unpack_from('<H',d,pe+6)[0]
    sec=pe+24+struct.unpack_from('<H',d,pe+20)[0]
    for i in range(n):
        o=sec+i*40
        nm=d[o:o+8].rstrip(b'\x00').decode('latin1')
        vsz,va,rsz,ra=struct.unpack_from('<IIII',d,o+8)
        if nm=='.text': return d[ra:ra+rsz], BASE+va
    raise SystemExit('no text')
targets={int(a,16) for a in sys.argv[1:]}
text,tva=load_text()
md=Cs(CS_ARCH_X86,CS_MODE_64)
insns=list(md.disasm(text,tva))
funcs=json.load(open(os.path.join(HERE,'_orig_funcs_ida.json'),encoding='utf-8'))
fmap=sorted((f['start'],f['end'],f['name']) for f in funcs)
def owner(a):
    for s,e,nm in fmap:
        if s<=a<e: return nm
    return '?'
for i,ins in enumerate(insns):
    if ins.mnemonic!='mov' or not ins.op_str.startswith('ecx, '): continue
    try: slot=int(ins.op_str.split(', ')[1],0)
    except ValueError: continue
    if slot not in targets: continue
    for j in range(i+1,min(i+26,len(insns))):
        p=insns[j]
        if p.mnemonic=='call':
            t=int(p.op_str,16) if p.op_str.startswith('0x') else 0
            if t==GW: print('W 0x%X  GT[0x%X]  %s'%(ins.address,slot,owner(ins.address))); break
            if t==GR: break
            if j-i>3 and t not in (GW,GR): pass
        if p.mnemonic in ('ret','jmp'): break
