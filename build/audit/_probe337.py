import os,sys,struct
HERE='build/audit'
sys.path.insert(0,HERE); sys.path.insert(0,'.')
from kernel_sim import KernelSim, MASK64
from pe_image_layout import image_layout
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RAX,UC_X86_REG_RBP,UC_X86_REG_R8,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_RBX,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15,UC_X86_REG_R9,UC_X86_REG_R12
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
sim.uc.mem_write(base,img); sim.set_gt(0x20,base); sim.set_gt(0x21,len(img))
LOG=[]
def rd(uc,a):
    rbp=uc.reg_read(UC_X86_REG_RBP)
    def q(off): return struct.unpack('<Q',uc.mem_read(rbp+off,8))[0]
    def d32(off): return struct.unpack('<I',uc.mem_read(rbp+off,4))[0]
    LOG.append(dict(addr=a,rsi=uc.reg_read(UC_X86_REG_RSI)&0xFFFFFFFF,r13=uc.reg_read(UC_X86_REG_R13),
        edi=uc.reg_read(UC_X86_REG_RDI)&0xFFFFFFFF,ebx=uc.reg_read(UC_X86_REG_RBX)&0xFFFFFFFF,
        r14=uc.reg_read(UC_X86_REG_R14)&0xFFFFFFFF,r15=uc.reg_read(UC_X86_REG_R15)&0xFFFFFFFF,
        f0=d32(0xe0),f38=d32(0x28),f40=d32(0x30),f50=q(0x40),f70=q(0x60),f78=q(0x78),f88=q(0x48),
        r8=uc.reg_read(UC_X86_REG_R8)))
for a in (0x1400158c5,0x140015904,0x14001590c,0x14001592c,0x140015959,0x14001599b,0x140015a24):
    sim.uc.hook_add(UC_HOOK_CODE,lambda uc,addr,size,ud,a=a: rd(uc,a),begin=a,end=a)
kind,r=sim.call(0x1400152D4,(),count=200000000)
print('writes',[(hex(i),hex(v)) for i,v in writes])
print('--- events (last 40) ---')
for e in LOG[-40:]:
    print('  @0x%X rsi=0x%X r13=0x%X edi=%d ebx=0x%X r14=0x%X r15=0x%X f0=%d f38=0x%X f40=0x%X f50=0x%X f70=0x%X f78=0x%X f88=0x%X r8=0x%X'%(
      e['addr'],e['rsi'],e['r13'],e['edi'],e['ebx'],e['r14'],e['r15'],e['f0'],e['f38'],e['f40'],e['f50'],e['f70'],e['f78'],e['f88'],e['r8']))
