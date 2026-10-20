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
def run(drv,fn,rd,wr,lim):
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
    rel=[x-fn for x in sim.blocks if fn<=x<fn+lim]
    return rel
for name,ova,size_lim in [('MiniFilterPreDirEnum',0x140015A48,0x4E0),('MiniFilterPreSetInfo',0x140015F34,0x4D0)]:
    m=ma(name)
    o=run(ORIG,ova,0x140029EFC,0x140029FF4,size_lim)
    n=run(MINE,m,0x14001ED60,0x14001ED60,size_lim)
    so={};sn={}
    for x in o: so[x]=so.get(x,0)+1
    for x in n: sn[x]=sn.get(x,0)+1
    print('%s  ORIG块=%d 种=%d | MINE块=%d 种=%d'%(name,len(o),len(so),len(n),len(sn)))
    only_o=sorted(set(so)-set(sn))[:12]; only_n=sorted(set(sn)-set(so))[:12]
    print('   仅 ORIG 有: ',[hex(x) for x in only_o])
    print('   仅 MINE 有: ',[hex(x) for x in only_n])
