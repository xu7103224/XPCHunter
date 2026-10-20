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
def probe(fn,guard,pts,label):
    sim=KernelSim(ORIG); sim.skip_stack_cookie_check()
    w=[]
    def gr(uc,s):
        i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
        uc.reg_write(UC_X86_REG_RAX,s._gt_values.get(i,0)&MASK64); s._do_ret(uc)
    def gw(uc,s):
        i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
        v=uc.reg_read(UC_X86_REG_RDX)&MASK64
        s._gt_values[i]=v; w.append((i,v)); uc.reg_write(UC_X86_REG_RAX,v); s._do_ret(uc)
    sim.intercept(0x140029EFC,gr); sim.intercept(0x140029FF4,gw)
    d=open(os.path.join(HERE,'gt_orig_live.bin'),'rb').read()
    for i in range(len(d)//8):
        v=struct.unpack_from('<Q',d,i*8)[0]
        if v: sim.set_gt(i,v)
    base=sim.scratch((len(img)+0xFFF)&~0xFFF)
    sim.uc.mem_write(base,img); sim.set_gt(0x20,base); sim.set_gt(0x21,len(img))
    cnt={a:0 for a in pts}
    for a in pts:
        sim.uc.hook_add(UC_HOOK_CODE,lambda uc,addr,size,ud,a=a: cnt.__setitem__(a,cnt[a]+1),begin=a,end=a)
    kind,r=sim.call(fn,(),count=200000000)
    print('%s kind=%s writes=%d'%(label,kind,len(w)))
    for a in pts: print('   0x%X : %d'%(a,cnt[a]))
probe(0x140015A48,None,{0x140015AAB:'x'}.keys(),'DirEnum') if False else None
probe(0x140015A48,0x140015AAB,[0x140015AAB,0x140015B6B,0x140015B75,0x140015DB3,0x140015EF5,0x140015C29,0x140015C8B,0x140015BD8,0x140015C55,0x140015ECE],'DirEnum')
print('---')
probe(0x140015F34,0x140015FB8,[0x140015FB8,0x140015FDC,0x140016071,0x14001607A,0x1400160B0,0x14001633B,0x1400161BB,0x140016315,0x1400163DB],'SetInfo')
