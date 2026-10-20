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
st={'max':0,'n':0,'last':0}
def top(uc,s):
    r=uc.reg_read(UC_X86_REG_RSI)
    st['n']+=1; st['last']=r
    if r>st['max']: st['max']=r
sim.intercept(0x140015B5E, top)     # 循环顶
def adv(uc,s):  # 0x140015EF5 前进
    st['adv']=st.get('adv',0)+1
sim.intercept(0x140015EF5, adv)
kind=sim.call(0x140015A48,(),count=200000000)
print('kind',kind)
print('loop-top hits=%d  max rsi offset=0x%X  last=0x%X  advance hits=%d'%(
    st['n'], st['max']-b, st['last']-b, st.get('adv',0)))
print('PeBase=0x%X  End offset=0x%X'%(b,len(img)))
