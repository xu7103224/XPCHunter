import os,sys,struct,re
HERE='build/audit'
sys.path.insert(0,HERE); sys.path.insert(0,'.')
from kernel_sim import KernelSim, MASK64
from pe_image_layout import image_layout
from unicorn.x86_const import *
ORIG='samples/PCHunter_2024.09.02/View++_Driver64.sys'
MINE='build/bin/Release/x64/XPCHunterDrv.sys'
NT=os.path.join(HERE,'ntoskrnl_guest.exe')
img,sz,_=image_layout(NT)
def ma(n):
    mp='build/bin/Release/x64/XPCHunterDrv.map'
    for ln in open(mp,encoding='utf-8',errors='ignore'):
        if re.match(r'\s+0001:[0-9a-f]{8}\s+'+n+r'\s+([0-9a-f]{16})\s+f',ln):
            return int(re.match(r'\s+0001:[0-9a-f]{8}\s+\S+\s+([0-9a-f]{16})',ln).group(1),16)
def run(drv,fn,rd,wr,readpese,init,label):
    sim=KernelSim(drv); sim.skip_stack_cookie_check()
    def gr(uc,s):
        i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
        uc.reg_write(UC_X86_REG_RAX,s._gt_values.get(i,0)&MASK64); s._do_ret(uc)
    def gw(uc,s):
        i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
        v=uc.reg_read(UC_X86_REG_RDX)&MASK64
        s._gt_values[i]=v; uc.reg_write(UC_X86_REG_RAX,v); s._do_ret(uc)
    sim.intercept(rd,gr); sim.intercept(wr,gw)
    d=open(os.path.join(HERE,'gt_orig_live.bin'),'rb').read()
    for i in range(len(d)//8):
        v=struct.unpack_from('<Q',d,i*8)[0]
        if v: sim.set_gt(i,v)
    b=sim.scratch((len(img)+0xFFF)&~0xFFF); sim.uc.mem_write(b,img)
    sim.set_gt(0x20,b); sim.set_gt(0x21,len(img))
    steps=[]
    def onread(uc,s):
        ctx=uc.reg_read(UC_X86_REG_RCX)
        rp=struct.unpack('<Q',uc.mem_read(ctx+8,8))[0]
        en=struct.unpack('<Q',uc.mem_read(ctx+0x10,8))[0]
        steps.append(('read', rp-b, en-b))
        s._do_ret(uc)
    def oninit(uc,s):
        base=uc.reg_read(UC_X86_REG_RCX); size=uc.reg_read(UC_X86_REG_RDX)&0xFFFFFFFF
        steps.append(('init', base-b, size))
        s._do_ret(uc)
    sim.intercept(readpese,onread); sim.intercept(init,oninit)
    k=sim.call(fn,(b,len(img),0,b),count=300000000)
    print('%s kind=%s steps=%d'%(label,k,len(steps)))
    for e in steps[:16]: print('   ',e)
run(ORIG,0x14001CC4C,0x140029EFC,0x140029FF4,0x14008A54C,0x14008A7E4,'ORIG')
run(MINE,ma('DisableHookProtection'),0x14001ED90,0x14001EDA0,0x1400547E0,0x140054780,'MINE')
