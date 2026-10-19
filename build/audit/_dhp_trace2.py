import os,sys,struct,re
HERE='build/audit'
sys.path.insert(0,HERE); sys.path.insert(0,'.')
from kernel_sim import KernelSim, MASK64
from pe_image_layout import image_layout
from unicorn.x86_const import *
MINE='build/bin/Release/x64/XPCHunterDrv.sys'
NT=os.path.join(HERE,'ntoskrnl_guest.exe')
def ma(n):
    mp='build/bin/Release/x64/XPCHunterDrv.map'
    for ln in open(mp,encoding='utf-8',errors='ignore'):
        if re.match(r'\s+0001:[0-9a-f]{8}\s+'+n+r'\s+([0-9a-f]{16})\s+f',ln):
            return int(re.match(r'\s+0001:[0-9a-f]{8}\s+\S+\s+([0-9a-f]{16})',ln).group(1),16)
img,sz,_=image_layout(NT)
sim=KernelSim(MINE); sim.skip_stack_cookie_check(); w=[]
def gr(uc,s):
    i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
    uc.reg_write(UC_X86_REG_RAX,s._gt_values.get(i,0)&MASK64); s._do_ret(uc)
def gw(uc,s):
    i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
    v=uc.reg_read(UC_X86_REG_RDX)&MASK64
    s._gt_values[i]=v; w.append((i,v)); uc.reg_write(UC_X86_REG_RAX,v); s._do_ret(uc)
sim.intercept(0x14001ED90,gr); sim.intercept(0x14001EDA0,gw)
d=open(os.path.join(HERE,'gt_orig_live.bin'),'rb').read()
for i in range(len(d)//8):
    v=struct.unpack_from('<Q',d,i*8)[0]
    if v: sim.set_gt(i,v)
b=sim.scratch((len(img)+0xFFF)&~0xFFF); sim.uc.mem_write(b,img)
sim.set_gt(0x20,b); sim.set_gt(0x21,len(img))
fn=ma('DisableHookProtection')
print('MINE fn=0x%X'%fn)
seq=[]
# 记录所有块，看看到哪个偏移
k=sim.call(fn,(b,len(img),0,b),count=300000000)
rel=sorted({x-fn for x in sim.blocks if fn<=x<fn+0x260})
print('kind',k,'writes',[(hex(i),hex(v)) for i,v in w])
print('blocks visited (%d):'%len(rel),[hex(x) for x in rel])
