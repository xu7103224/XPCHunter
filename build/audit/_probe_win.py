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
out=[]
for a in (0x140015AEC,0x140015B03,0x140015B16,0x140015B47,0x140015B4F):
    sim.uc.hook_add(UC_HOOK_CODE,lambda uc,addr,size,ud,a=a: out.append((a,
        uc.reg_read(UC_X86_REG_RAX)&0xFFFFFFFF, uc.reg_read(UC_X86_REG_RBX)&0xFFFFFFFF,
        uc.reg_read(UC_X86_REG_R13)&0xFFFFFFFF, uc.reg_read(UC_X86_REG_R14)&0xFFFFFFFF,
        uc.reg_read(UC_X86_REG_RSI), uc.reg_read(UC_X86_REG_R15))),begin=a,end=a)
sim.call(0x140015A48,(),count=200000000)
print('PeBase=0x%X PeSize=0x%X'%(base,len(img)))
for a,rax,rbx,r13,r14,rsi,r15 in out:
    print('  0x%X rax=0x%X rbx=0x%X r13=0x%X r14=0x%X rsi=0x%X r15=0x%X'%(a,rax,rbx,r13,r14,rsi,r15))
print('end-start = 0x%X'%(out[-1][6]-out[-1][5]) if out else '')
