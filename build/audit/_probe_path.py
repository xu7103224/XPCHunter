import os,sys,struct
HERE='build/audit'
sys.path.insert(0,HERE); sys.path.insert(0,'.')
from kernel_sim import KernelSim, MASK64
from pe_image_layout import image_layout
from unicorn.x86_const import *
ORIG='samples/PCHunter_2024.09.02/View++_Driver64.sys'
NT=os.path.join(HERE,'ntoskrnl_guest.exe')
img,sz,_=image_layout(NT)
def run(fn,pts):
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
    cnt={a:0 for a in pts}
    for a in pts:
        def mk(a):
            def f(uc,s):
                cnt[a]+=1
                uc.reg_write(UC_X86_REG_RIP, 0x140015EF5)  # 立刻去前进
            return f
        sim.intercept(a,mk(a))
    sim.call(fn,(),count=200000000)
    return cnt
c=run(0x140015A48,[0x140015EA0,0x140015EF5,0x140015EEA,0x140015EF0])
print('DirEnum path:',{hex(k):v for k,v in c.items()})
