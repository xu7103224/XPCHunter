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
st={'max':0,'last':None,'epi':0}
def h(uc,a,sz,ud):
    try:
        r=uc.reg_read(UC_X86_REG_RSI)
        if r>st['max']: st['max']=r
        st['last']=r
    except Exception:
        pass
sim.uc.hook_add(UC_HOOK_CODE,h,begin=0x140015A48,end=0x140015F34)
def e(uc,a,sz,ud): st['epi']+=1
sim.uc.hook_add(UC_HOOK_CODE,e,begin=0x140015F01,end=0x140015F02)
sim.call(0x140015A48,(),count=200000000)
print('PeBase=0x%X End=0x%X'%(base,base+len(img)))
print('max rsi=0x%X (offset 0x%X)  last=0x%X  epilogue=%d'%(st['max'],st['max']-base,st['last'],st['epi']))
print('pattern offset 0x601204 reached?', st['max']-base >= 0x601204)
