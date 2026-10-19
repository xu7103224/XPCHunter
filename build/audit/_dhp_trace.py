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
b=sim.scratch((len(img)+0xFFF)&~0xFFF); sim.uc.mem_write(b,img)
sim.set_gt(0x20,b); sim.set_gt(0x21,len(img))
# 拦截关键点
log=[]
def at(a,tag):
    def f(uc,s):
        log.append((tag, uc.reg_read(UC_X86_REG_EAX)&0xFFFFFFFF if False else 0))
    return f
# 第一段：命中 0x558 处
def hit1(uc,s):
    log.append(('first558', uc.reg_read(UC_X86_REG_RCX)))
sim.intercept(0x14001CD0F, hit1)
def off1(uc,s):
    log.append(('secBase', uc.reg_read(UC_X86_REG_EBX)))
sim.intercept(0x14001CD20, off1)
def typechk(uc,s):
    eax=uc.reg_read(UC_X86_REG_RAX)&0xFFFFFFFF
    dx=uc.reg_read(UC_X86_REG_RDX)&0xFFFF
    log.append(('type',dx,eax))
sim.intercept(0x14001CD9F, typechk)
def fieldchk(uc,s):
    log.append(('field88', struct.unpack('<Q',uc.mem_read(uc.reg_read(UC_X86_REG_RBP)+0x18,8))[0],
                struct.unpack('<I',uc.mem_read(uc.reg_read(UC_X86_REG_RBP)+8,4))[0]))
sim.intercept(0x14001CDAE, fieldchk)
k=sim.call(0x14001CC4C,(b,len(img),0,b),count=300000000)
print('kind',k)
for e in log[:20]: print('  ',e)
print('total',len(log))
