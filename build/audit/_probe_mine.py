import os,sys,struct,re
HERE='build/audit'
sys.path.insert(0,HERE); sys.path.insert(0,'.')
from kernel_sim import KernelSim, MASK64
from pe_image_layout import image_layout
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RAX
MINE='build/bin/Release/x64/XPCHunterDrv.sys'
NT=os.path.join(HERE,'ntoskrnl_guest.exe')
img,sz,_=image_layout(NT)
mp='build/bin/Release/x64/XPCHunterDrv.map'
def mine_addr(name):
    for ln in open(mp,encoding='utf-8',errors='ignore'):
        if re.match(r'\s+0001:[0-9a-f]{8}\s+'+name+r'\s+([0-9a-f]{16})\s+f',ln):
            return int(re.match(r'\s+0001:[0-9a-f]{8}\s+\S+\s+([0-9a-f]{16})',ln).group(1),16)
    return None
fn=mine_addr('MiniFilterPreClose')
print('fn=0x%X'%fn)
sim=KernelSim(MINE); sim.skip_stack_cookie_check()
writes=[]
def gr(uc,s):
    i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
    uc.reg_write(UC_X86_REG_RAX,s._gt_values.get(i,0)&MASK64); s._do_ret(uc)
def gw(uc,s):
    i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
    v=uc.reg_read(UC_X86_REG_RDX)&MASK64
    s._gt_values[i]=v; writes.append((i,v)); uc.reg_write(UC_X86_REG_RAX,v); s._do_ret(uc)
sim.intercept(0x14001ED60,gr); sim.intercept(0x14001ED60,gw)
d=open(os.path.join(HERE,'gt_orig_live.bin'),'rb').read()
for i in range(len(d)//8):
    v=struct.unpack_from('<Q',d,i*8)[0]
    if v: sim.set_gt(i,v)
base=sim.scratch((len(img)+0xFFF)&~0xFFF)
sim.uc.mem_write(base,img); sim.set_gt(0x20,base); sim.set_gt(0x21,len(img))
seen={}
def hook(uc,addr,size,ud): seen[addr]=seen.get(addr,0)+1
sim.uc.hook_add(UC_HOOK_CODE,hook,begin=fn,end=fn+0x900)
kind,r=sim.call(fn,(),count=200000000)
print('kind',kind,'writes',[(hex(i),hex(v)) for i,v in writes])
# 打印 GT[0x336] 读取点与备用支路关键块
import collections
print('top blocks:',sorted(seen.items(),key=lambda x:-x[1])[:12])
