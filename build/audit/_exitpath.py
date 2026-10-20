import os,sys,struct
HERE='build/audit'
sys.path.insert(0,HERE); sys.path.insert(0,'.')
from kernel_sim import KernelSim, MASK64
from pe_image_layout import image_layout
from unicorn.x86_const import *
ORIG='samples/PCHunter_2024.09.02/View++_Driver64.sys'
NT=os.path.join(HERE,'ntoskrnl_guest.exe')
img,sz,_=image_layout(NT)
sim=KernelSim(ORIG); sim.skip_stack_cookie_check()
def gr(uc,s):
    i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
    uc.reg_write(UC_X86_REG_RAX,s._gt_values.get(i,0)&MASK64); s._do_ret(uc)
def gw(uc,s):
    i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
    v=uc.reg_read(UC_X86_REG_RDX)&MASK64
    s._gt_values[i]=v; uc.reg_write(UC_X86_REG_RAX,v); s._do_ret(uc)
sim.intercept(0x140029EFC,gr); sim.intercept(0x140029FF4,gw)
d=open(os.path.join(HERE,'gt_orig_live.bin'),'rb').read()
for i in range(len(d)//8):
    v=struct.unpack_from('<Q',d,i*8)[0]
    if v: sim.set_gt(i,v)
b=sim.scratch((len(img)+0xFFF)&~0xFFF)
sim.uc.mem_write(b,img); sim.set_gt(0x20,b); sim.set_gt(0x21,len(img))
k=sim.call(0x140015A48,(),count=200000000)
F=0x140015A48
tail=[int(x)-F for x in sim.blocks if F<=int(x)<F+0x4E0][-24:]
print('kind',k)
print('最后 24 个块偏移:',[hex(x) for x in tail])
print('是否到 0xF01(收尾) :', 0xF01 in tail or 0xF08 in tail)
