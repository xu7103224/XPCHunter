import os,sys,struct
HERE='build/audit'
sys.path.insert(0,HERE); sys.path.insert(0,'.')
from kernel_sim import KernelSim, MASK64
from pe_image_layout import image_layout
from unicorn import UC_HOOK_CODE
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
base=sim.scratch((len(img)+0xFFF)&~0xFFF)
sim.uc.mem_write(base,img); sim.set_gt(0x20,base); sim.set_gt(0x21,len(img))
OUT=[]
def snap(uc,a):
    rbp=uc.reg_read(UC_X86_REG_RBP)
    def q(o): return struct.unpack('<Q',uc.mem_read(rbp+o,8))[0]
    def u(o): return struct.unpack('<I',uc.mem_read(rbp+o,4))[0]
    OUT.append((a,uc.reg_read(UC_X86_REG_EDI)&0xFFFFFFFF,uc.reg_read(UC_X86_REG_R15),
                q(0xE8),q(0x40),q(0x78),q(0x60),u(0xC0),q(0x48),q(0x28)))
sim.uc.hook_add(UC_HOOK_CODE,lambda uc,addr,size,ud: snap(uc,0x8A8),begin=0x1400158A8,end=0x1400158A8)
sim.uc.hook_add(UC_HOOK_CODE,lambda uc,addr,size,ud: snap(uc,0x85E),begin=0x14001585E,end=0x14001585E)
kind,r=sim.call(0x1400152D4,(),count=200000000)
print('kind',kind)
print('addr  edi     r15          typePtr     [40]      [78]      [60]      [C0]   [48]     [28]')
for e in OUT[:14]:
    print('0x%X 0x%-6X 0x%-11X 0x%-10X 0x%-8X 0x%-8X 0x%-8X 0x%-6X 0x%-8X 0x%X'%e)
