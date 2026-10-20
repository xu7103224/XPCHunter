import os,sys,struct,re
HERE='build/audit'
sys.path.insert(0,HERE); sys.path.insert(0,'.')
from kernel_sim import KernelSim, MASK64
from pe_image_layout import image_layout
from unicorn import UC_HOOK_CODE
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
m=ma('MiniFilterPreDirEnum'); print('MINE DirEnum=0x%X'%m)
sim=KernelSim(MINE); sim.skip_stack_cookie_check()
reads=[]
def gr(uc,s):
    i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
    v=s._gt_values.get(i,0)&MASK64
    reads.append((i,v)); uc.reg_write(UC_X86_REG_RAX,v); s._do_ret(uc)
def gw(uc,s):
    i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
    v=uc.reg_read(UC_X86_REG_RDX)&MASK64
    s._gt_values[i]=v; uc.reg_write(UC_X86_REG_RAX,v); s._do_ret(uc)
sim.intercept(0x14001ED60,gr); sim.intercept(0x14001ED60,gw)
d=open(os.path.join(HERE,'gt_orig_live.bin'),'rb').read()
for i in range(len(d)//8):
    v=struct.unpack_from('<Q',d,i*8)[0]
    if v: sim.set_gt(i,v)
base=sim.scratch((len(img)+0xFFF)&~0xFFF)
sim.uc.mem_write(base,img); sim.set_gt(0x20,base); sim.set_gt(0x21,len(img))
seq=[]
sim.uc.hook_add(UC_HOOK_CODE,lambda uc,a,sz,ud: seq.append((a,uc.reg_read(UC_X86_REG_RIP))),begin=m,end=m+0x4E0)
kind,r=sim.call(m,(),count=1000000)
print('kind',kind)
print('reads',[(hex(i),hex(v)) for i,v in reads])
print('seq len',len(seq))
import subprocess
for a in [x[0] for x in seq[-14:]]:
    print('  0x%X'%a)
