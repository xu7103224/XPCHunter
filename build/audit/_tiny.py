import os,sys,struct,re
HERE='build/audit'
sys.path.insert(0,HERE); sys.path.insert(0,'.')
from kernel_sim import KernelSim, MASK64
from unicorn.x86_const import *
ORIG='samples/PCHunter_2024.09.02/View++_Driver64.sys'
MINE='build/bin/Release/x64/XPCHunterDrv.sys'
mp='build/bin/Release/x64/XPCHunterDrv.map'
def ma(n):
    for ln in open(mp,encoding='utf-8',errors='ignore'):
        if re.match(r'\s+0001:[0-9a-f]{8}\s+'+n+r'\s+([0-9a-f]{16})\s+f',ln):
            return int(re.match(r'\s+0001:[0-9a-f]{8}\s+\S+\s+([0-9a-f]{16})',ln).group(1),16)
def build():
    buf=bytearray(0x800)
    struct.pack_into('<H',buf,0,0x5A4D)
    struct.pack_into('<I',buf,0x3C,0x40)
    struct.pack_into('<I',buf,0x40,0x00004550)
    struct.pack_into('<H',buf,0x44,0x8664)
    struct.pack_into('<H',buf,0x46,0)          # NumberOfSections = 0
    struct.pack_into('<H',buf,0x54,0xE0)       # SizeOfOptionalHeader
    pat=bytes.fromhex('488d81b800000048894008488900488d81a0000000')
    buf[0x100:0x100+len(pat)]=pat
    return bytes(buf)
def run(drv,fn,rd,wr):
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
    img=build()
    b=sim.scratch(0x1000); sim.uc.mem_write(b,img)
    sim.set_gt(0x20,b); sim.set_gt(0x21,len(img))
    k=sim.call(fn,(),count=200000000)
    return k,w
for name,ova in [('MiniFilterPreDirEnum',0x140015A48),('MiniFilterPreSetInfo',0x140015F34)]:
    m=ma(name)
    ko,wo=run(ORIG,ova,0x140029EFC,0x140029FF4)
    km,wm=run(MINE,m,0x14001ED60,0x14001ED60)
    print('%s'%name)
    print('   ORIG %s writes=%s'%(ko,[(hex(i),hex(v)) for i,v in wo]))
    print('   MINE %s writes=%s'%(km,[(hex(i),hex(v)) for i,v in wm]))
