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
pts=[0x140015C29,0x140015C2F,0x140015C35,0x140015C3B,0x140015C44,0x140015C55,0x140015C82,0x140015C8B]
cnt={a:0 for a in pts}
hits=[]
for a in pts:
    def mk(a):
        def f(uc,addr,size,ud):
            cnt[a]+=1
            if a==0x140015C44:
                rsi=uc.reg_read(UC_X86_REG_RSI); r9=uc.reg_read(UC_X86_REG_R9)
                edx=uc.reg_read(UC_X86_REG_RDX)&0xFFFFFFFF
                if len(hits)<6: hits.append((rsi,r9&0xFF,edx))
        return f
    sim.uc.hook_add(UC_HOOK_CODE,mk(a),begin=a,end=a)
kind,r=sim.call(0x140015A48,(),count=200000000)
print('ORIG DirEnum')
for a in pts: print('  0x%X : %d'%(a,cnt[a]))
print('  0x140015C44 命中样本 (rsi,r9b,edx):',[(hex(x),y,hex(z)) for x,y,z in hits])
