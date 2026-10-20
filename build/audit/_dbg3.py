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
mp='build/bin/Release/x64/XPCHunterDrv.map'
def ma(name):
    for ln in open(mp,encoding='utf-8',errors='ignore'):
        if re.match(r'\s+0001:[0-9a-f]{8}\s+'+name+r'\s+([0-9a-f]{16})\s+f',ln):
            return int(re.match(r'\s+0001:[0-9a-f]{8}\s+\S+\s+([0-9a-f]{16})',ln).group(1),16)
def cov(drv,fn,rd,wr,lim):
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
    b=sim.scratch((len(img)+0xFFF)&~0xFFF)
    sim.uc.mem_write(b,img); sim.set_gt(0x20,b); sim.set_gt(0x21,len(img))
    sim.call(fn,(),count=200000000)
    return {int(x)-fn for x in sim.blocks if fn<=int(x)<fn+lim}
for name,ova,lim in [('MiniFilterPreDirEnum',0x140015A48,0x4E0)]:
    m=ma(name); print('MINE=0x%X'%m)
    o=cov(ORIG,ova,0x140029EFC,0x140029FF4,lim)
    n=cov(MINE,m,0x14001ED60,0x14001ED60,lim)
    print('ORIG 块种类=%d  MINE 块种类=%d'%(len(o),len(n)))
    print('ORIG 独有:',[hex(x) for x in sorted(o-n)])
    print('MINE 独有:',[hex(x) for x in sorted(n-o)])
