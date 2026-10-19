#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""InitProcessNotify 离线差分（原始 0x14001EFA0 vs 我方）。"""
import os,sys,struct,re
HERE=os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0,HERE); sys.path.insert(0,os.path.join(HERE,'..','..'))
from kernel_sim import KernelSim, MASK64
from pe_image_layout import image_layout
from unicorn.x86_const import UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RAX
ORIG=os.path.join(HERE,'..','..','samples','PCHunter_2024.09.02','View++_Driver64.sys')
MINE=os.path.join(HERE,'..','..','build','bin','Release','x64','XPCHunterDrv.sys')
MP=os.path.join(HERE,'..','bin','Release','x64','XPCHunterDrv.map')
def _sym(name):
    for ln in open(MP,encoding='utf-8',errors='ignore'):
        m=re.match(r'\s+0001:[0-9a-f]{8}\s+'+name+r'\s+([0-9a-f]{16})\s+f',ln)
        if m: return int(m.group(1),16)
    return 0
def run(drv,fn,rd,wr):
    sim=KernelSim(drv); sim.skip_stack_cookie_check(); w=[]
    def gr(uc,s):
        i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
        uc.reg_write(UC_X86_REG_RAX,s._gt_values.get(i,0)&MASK64); s._do_ret(uc)
    def gw(uc,s):
        i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
        v=uc.reg_read(UC_X86_REG_RDX)&MASK64
        s._gt_values[i]=v; w.append((i,v)); uc.reg_write(UC_X86_REG_RAX,v); s._do_ret(uc)
    sim.intercept(rd,gr); sim.intercept(wr,gw)
    d=open(os.path.join(HERE,'gt_orig_19045.bin'),'rb').read()
    for i in range(len(d)//8):
        v=struct.unpack_from('<Q',d,i*8)[0]
        if v: sim.set_gt(i,v)
    k=sim.call(fn,(),count=300000000)
    return k,w
ko,wo=run(ORIG,0x14001EFA0,0x140029EFC,0x140029FF4)
km,wm=run(MINE,_sym('InitProcessNotify'),_sym('GtRead'),_sym('GtWrite'))
so={(i,v) for i,v in wo}; sm={(i,v) for i,v in wm}
print('ORIG writes',len(wo),'MINE writes',len(wm))
print('only ORIG:',[(hex(i),hex(v)) for i,v in sorted(so-sm)])
print('only MINE:',[(hex(i),hex(v)) for i,v in sorted(sm-so)])
print('=>','IDENTICAL' if so==sm else 'DIFFERENT')
