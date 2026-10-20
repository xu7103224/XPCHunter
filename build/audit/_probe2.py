import os,sys,struct
HERE='build/audit'
sys.path.insert(0,HERE); sys.path.insert(0,'.')
from kernel_sim import KernelSim, MASK64
from pe_image_layout import image_layout
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RAX
ORIG='samples/PCHunter_2024.09.02/View++_Driver64.sys'
NT=os.path.join(HERE,'ntoskrnl_guest.exe')
img,sz,_=image_layout(NT)
sim=KernelSim(ORIG); sim.skip_stack_cookie_check()
writes=[]
def gr(uc,s):
    i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
    uc.reg_write(UC_X86_REG_RAX,s._gt_values.get(i,0)&MASK64); s._do_ret(uc)
def gw(uc,s):
    i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
    v=uc.reg_read(UC_X86_REG_RDX)&MASK64
    s._gt_values[i]=v; writes.append((i,v)); uc.reg_write(UC_X86_REG_RAX,v); s._do_ret(uc)
sim.intercept(0x140029EFC,gr); sim.intercept(0x140029FF4,gw)
d=open(os.path.join(HERE,'gt_orig_live.bin'),'rb').read()
for i in range(len(d)//8):
    v=struct.unpack_from('<Q',d,i*8)[0]
    if v: sim.set_gt(i,v)
base=sim.scratch((len(img)+0xFFF)&~0xFFF)
sim.uc.mem_write(base,img)
sim.set_gt(0x20,base); sim.set_gt(0x21,len(img))
pts={0x140015452:'模式命中48',0x14001548d:'48 89 08',0x1400154f0:'块A解码',0x1400154fd:'A解码失败',
     0x14001554d:'A写候选',0x1400155e5:'块B解码',0x14001575b:'B结束',0x140015856:'备用支路',
     0x14001569f:'写块1',0x1400157fb:'写块2',0x140015a24:'尾写',0x1400159e3:'前进'}
cnt={k:0 for k in pts}
def hook(uc,addr,size,ud):
    if addr in cnt: cnt[addr]+=1
sim.uc.hook_add(UC_HOOK_CODE,hook,begin=0x1400152D4,end=0x140015A47)
kind,r=sim.call(0x1400152D4,(),count=200000000)
print('kind',kind,'writes',len(writes))
for k,nm in pts.items(): print('  %-12s 0x%X : %d'%(nm,k,cnt[k]))
