import os,sys,struct
HERE='build/audit'
sys.path.insert(0,HERE); sys.path.insert(0,'.')
from kernel_sim import KernelSim, MASK64
from pe_image_layout import image_layout
from unicorn.x86_const import UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RAX,UC_X86_REG_RIP
ORIG='samples/PCHunter_2024.09.02/View++_Driver64.sys'
NT=os.path.join(HERE,'ntoskrnl_guest.exe')
img,sz,_=image_layout(NT)
sim=KernelSim(ORIG); sim.skip_stack_cookie_check()
calls=[]
def gr(uc,s):
    i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
    uc.reg_write(UC_X86_REG_RAX,s._gt_values.get(i,0)&MASK64); s._do_ret(uc)
def gw(uc,s):
    i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
    v=uc.reg_read(UC_X86_REG_RDX)&MASK64
    s._gt_values[i]=v; calls.append((i,v)); uc.reg_write(UC_X86_REG_RAX,v); s._do_ret(uc)
sim.intercept(0x140029EFC,gr); sim.intercept(0x140029FF4,gw)
d=open(os.path.join(HERE,'gt_orig_live.bin'),'rb').read()
for i in range(len(d)//8):
    v=struct.unpack_from('<Q',d,i*8)[0]
    if v: sim.set_gt(i,v)
base=sim.scratch((len(img)+0xFFF)&~0xFFF)
sim.uc.mem_write(base,img)
sim.set_gt(0x20,base); sim.set_gt(0x21,len(img))
print('buf=0x%X size=0x%X'%(base,len(img)))
kind,r=sim.call(0x1400152D4,(),count=50000000)
print('kind',kind,'ret',hex(r&MASK64))
print('gt reads:',[(hex(i),hex(v&MASK64)) for i,v in sim.gt_reads][:20])
print('blocks executed:',len(sim.blocks))
if sim.blocks:
    print('first blocks:',[hex(a) for a,_ in sim.blocks[:10]])
    print('last blocks:',[hex(a) for a,_ in sim.blocks[-6:]])
print('notes',sim.notes[:5])
