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
log=[]
def h(uc,a,sz,ud):
    r=uc.reg_read(UC_X86_REG_RSI)
    try: val=struct.unpack('<I',uc.mem_read(r+0x11,4))[0]
    except Exception: val=-1
    log.append((r-base,val))
sim.uc.hook_add(UC_HOOK_CODE,h,begin=0x140015c3b,end=0x140015c3b)
vis={'min':1<<60,'max':0,'at601204':0}
def v(uc,a,sz,ud):
    r=uc.reg_read(UC_X86_REG_RSI)
    o=r-base
    if o<vis['min']: vis['min']=o
    if o>vis['max']: vis['max']=o
    if o==0x601204: vis['at601204']+=1
sim.uc.hook_add(UC_HOOK_CODE,v,begin=0x140015b6b,end=0x140015b6b)
sim.call(0x140015A48,(),count=200000000)
print('visited offsets: min=0x%X max=0x%X  at 0x601204: %d'%(vis['min'],vis['max'],vis['at601204']))
print('C3B hits=%d'%len(log))
for o,val in log[:8]: print('   offset=0x%X  [0x11]=0x%X'%(o,val))
