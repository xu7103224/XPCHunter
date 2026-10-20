import os,sys,struct,re,time
HERE='build/audit'
sys.path.insert(0,HERE); sys.path.insert(0,'.')
from kernel_sim import KernelSim, MASK64
from pe_image_layout import image_layout
from unicorn.x86_const import *
ORIG='samples/PCHunter_2024.09.02/View++_Driver64.sys'
MINE='build/bin/Release/x64/XPCHunterDrv.sys'
NT=os.path.join(HERE,'ntoskrnl_guest.exe')
img,sz,_=image_layout(NT)
mp='build/bin/Release/x64/XPCHunterDrv.map'
def ma(n):
    for ln in open(mp,encoding='utf-8',errors='ignore'):
        if re.match(r'\s+0001:[0-9a-f]{8}\s+'+n+r'\s+([0-9a-f]{16})\s+f',ln):
            return int(re.match(r'\s+0001:[0-9a-f]{8}\s+\S+\s+([0-9a-f]{16})',ln).group(1),16)
def run(drv,fn,rd,wr,cnt):
    sim=KernelSim(drv); sim.skip_stack_cookie_check(); w=[]
    def gr(uc,s):
        i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
        uc.reg_write(UC_X86_REG_RAX,s._gt_values.get(i,0)&MASK64); s._do_ret(uc)
    def gw(uc,s):
        i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
        v=uc.reg_read(UC_X86_REG_RDX)&MASK64
        s._gt_values[i]=v; w.append((i,v)); uc.reg_write(UC_X86_REG_RAX,v); s._do_ret(uc)
    sim.intercept(rd,gr); sim.intercept(wr,gw)
    d=open(os.path.join(HERE,'gt_orig_live.bin'),'rb').read()
    for i in range(len(d)//8):
        v=struct.unpack_from('<Q',d,i*8)[0]
        if v: sim.set_gt(i,v)
    b=sim.scratch((len(img)+0xFFF)&~0xFFF)
    sim.uc.mem_write(b,img); sim.set_gt(0x20,b); sim.set_gt(0x21,len(img))
    return sim.call(fn,(),count=cnt), w
for name,ova,lim in [('MiniFilterPreClose',0x1400152D4,0x774),('MiniFilterPreDirEnum',0x140015A48,0x4E0),('MiniFilterPreSetInfo',0x140015F34,0x4D0)]:
    m=ma(name); t=time.time()
    ko,wo=run(ORIG,ova,0x140029EFC,0x140029FF4,3000000000)
    km,wm=run(MINE,m,0x14001ED60,0x14001ED60,3000000000)
    ok={(i,v) for i,v in wo}=={(i,v) for i,v in wm}
    print('%s  (%.0fs)'%(name,time.time()-t))
    print('   ORIG %s writes=%d %s'%(ko,len(wo),[(hex(i),hex(v)) for i,v in wo]))
    print('   MINE %s writes=%d %s'%(km,len(wm),[(hex(i),hex(v)) for i,v in wm]))
    print('   =>','IDENTICAL' if ok else 'DIFFERENT',flush=True)
