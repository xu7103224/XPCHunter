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
st={}
def epi(uc,s):
    st['rsi']=uc.reg_read(UC_X86_REG_RSI)-b
    st['r15']=uc.reg_read(UC_X86_REG_R15)-b
    st['r10']=uc.reg_read(UC_X86_REG_R10)
    st['dil']=(uc.reg_read(UC_X86_REG_RDI))&0xFF
    st['r8']=uc.reg_read(UC_X86_REG_R8)&0xFF
    st['r9']=uc.reg_read(UC_X86_REG_R9)&0xFF
    st['dl']=uc.reg_read(UC_X86_REG_RDX)&0xFF
    st['n']=st.get('n',0)+1
sim.intercept(0x140015F01, epi)
sim.intercept(0x140015EF5, lambda uc,s: st.__setitem__('adv',st.get('adv',0)+1))
sim.call(0x140015A48,(),count=200000000)
print(st)
