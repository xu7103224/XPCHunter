#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HookSyscallNtDeleteKey 离线差分（原始 0x14001D850 vs 我方）。"""
import os,sys,struct,re
HERE=os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0,HERE); sys.path.insert(0,os.path.join(HERE,'..','..'))
from kernel_sim import KernelSim, MASK64
from pe_image_layout import image_layout
from unicorn.x86_const import UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RAX
ORIG=os.path.join(HERE,'..','..','samples','PCHunter_2024.09.02','View++_Driver64.sys')
MINE=os.path.join(HERE,'..','..','build','bin','Release','x64','XPCHunterDrv.sys')
NT=os.path.join(HERE,'ntoskrnl_guest.exe')
MP=os.path.join(HERE,'..','bin','Release','x64','XPCHunterDrv.map')
def _sym(name):
    for ln in open(MP,encoding='utf-8',errors='ignore'):
        m=re.match(r'\s+0001:[0-9a-f]{8}\s+'+name+r'\s+([0-9a-f]{16})\s+f',ln)
        if m: return int(m.group(1),16)
    return 0
def run(drv,fn,rd,wr,img):
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
    b=sim.scratch((len(img)+0xFFF)&~0xFFF); sim.uc.mem_write(b,img)
    sim.set_gt(0x20,b); sim.set_gt(0x21,len(img))
    kbase=0xfffff80412e00000
    k=sim.call(fn,(b,len(img),0,kbase),count=300000000)
    return k,w
img,sz,_=image_layout(NT)
ko,wo=run(ORIG,0x14001D850,0x140029EFC,0x140029FF4,img)
km,wm=run(MINE,_sym('HookSyscallNtDeleteKey'),_sym('GtRead'),_sym('GtWrite'),img)
print('ORIG',ko,len(wo),[(hex(i),hex(v)) for i,v in wo])
print('MINE',km,len(wm),[(hex(i),hex(v)) for i,v in wm])
print('=>','IDENTICAL' if {(i,v) for i,v in wo}=={(i,v) for i,v in wm} else 'DIFFERENT')
