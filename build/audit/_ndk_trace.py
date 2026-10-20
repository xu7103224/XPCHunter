import sys,struct,re
sys.path.insert(0,'build/audit')
from kernel_sim import KernelSim, MASK64
from pe_image_layout import image_layout
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import *
img,sz,_=image_layout('build/audit/ntoskrnl_guest.exe')
MP='build/bin/Release/x64/XPCHunterDrv.map'
def _sym(name):
    for ln in open(MP,encoding='utf-8',errors='ignore'):
        m=re.match(r'\s+0001:[0-9a-f]{8}\s+'+name+r'\s+([0-9a-f]{16})\s+f',ln)
        if m: return int(m.group(1),16)
    return 0
def rd(uc,a,n): return int.from_bytes(uc.mem_read(a,n),'little')
def go(drv,fn,rdA,wrA,pt,tag):
    sim=KernelSim(drv); sim.skip_stack_cookie_check()
    def gr(uc,s):
        i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
        uc.reg_write(UC_X86_REG_RAX,s._gt_values.get(i,0)&MASK64); s._do_ret(uc)
    def gw(uc,s):
        i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
        v=uc.reg_read(UC_X86_REG_RDX)&MASK64
        s._gt_values[i]=v; uc.reg_write(UC_X86_REG_RAX,v); s._do_ret(uc)
    sim.intercept(rdA,gr); sim.intercept(wrA,gw)
    d=open('build/audit/gt_orig_19045.bin','rb').read()
    for i in range(len(d)//8):
        v=struct.unpack_from('<Q',d,i*8)[0]
        if v: sim.set_gt(i,v)
    b=sim.scratch((len(img)+0xFFF)&~0xFFF); sim.uc.mem_write(b,img)
    sim.set_gt(0x20,b); sim.set_gt(0x21,len(img))
    rows=[]
    def h(uc,addr,size,ud):
        if len(rows)>=20: return
        base=uc.reg_read(UC_X86_REG_RSP)+0x90
        try:
            rows.append('rp=0x%X ty=%04X f88=%X f78=%X'%(
                rd(uc,base-0x48,8)-b, rd(uc,rd(uc,base+0x118,8)+6,2),
                rd(uc,base+0x88,8), rd(uc,base+0x78,4)))
        except Exception as e: rows.append('ERR '+str(e))
    sim.uc.hook_add(UC_HOOK_CODE,h,begin=pt,end=pt)
    k=sim.call(fn,(b,len(img),0,0xfffff80412e00000),count=300000000)
    print(tag,k,'rows',len(rows))
    for r in rows: print('   ',r)
go('samples/PCHunter_2024.09.02/View++_Driver64.sys',0x14001D850,0x140029EFC,0x140029FF4,0x14001D90A,'ORIG')
go('build/bin/Release/x64/XPCHunterDrv.sys',_sym('HookSyscallNtDeleteKey'),_sym('GtRead'),_sym('GtWrite'),0x1400757A0,'MINE')
