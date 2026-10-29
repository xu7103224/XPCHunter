import os,sys,struct
HERE='build/audit'
sys.path.insert(0,HERE); sys.path.insert(0,'.')
from kernel_sim import KernelSim, MASK64
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import *
ORIG='samples/PCHunter_2024.09.02/View++_Driver64.sys'

img=open(os.path.join(HERE,'win32kfull.sys'),'rb').read()
# expand to image layout (section VA aligned)
pe=struct.unpack_from('<I',img,0x3c)[0]
nsec=struct.unpack_from('<H',img,pe+6)[0]
opt=struct.unpack_from('<H',img,pe+20)[0]
sec=pe+24+opt
sz_=struct.unpack_from('<I',img,pe+24+56)[0]  # SizeOfImage
buf=bytearray(sz_)
for i in range(nsec):
    o=sec+i*40
    vsz,va,rsz,ra=struct.unpack_from('<IIII',img,o+8)
    buf[va:va+rsz]=img[ra:ra+rsz]
print('image size 0x%X' % sz_)

sim=KernelSim(ORIG); sim.skip_stack_cookie_check()
def gr(uc,s):
    i=uc.reg_read(UC_X86_REG_RCX)&0xFFFFFFFF
    uc.reg_write(UC_X86_REG_RAX,s._gt_values.get(i,0)&MASK64); s._do_ret(uc)
sim.intercept(0x140029EFC,gr)

base=sim.scratch((len(buf)+0xFFF)&~0xFFF)
sim.uc.mem_write(base,bytes(buf))

SEEN=[]
def snap(uc,addr,size,ud):
    # 在 ReadPESectionEntry 返回后抓描述符类型
    pass

# hook at the point right after ReadPESectionEntry inside FindObjectOperationDataSection
# 0x1400369DA call; 返回地址 0x1400369DF
def after_read(uc,addr,size,ud):
    # hook 在 0x1400369DF（ReadPESectionEntry 返回后），此时 rsp 已恢复
    rsp=uc.reg_read(UC_X86_REG_RSP)
    desc = rsp + 0x90
    try:
        dataptr=struct.unpack('<Q', uc.mem_read(desc+0x118, 8))[0]
        t=struct.unpack('<H', uc.mem_read(dataptr+6, 2))[0]
        f78=struct.unpack('<I', uc.mem_read(desc+0x38, 4))[0]
        f88=struct.unpack('<Q', uc.mem_read(desc+0x50, 8))[0]
        flen=struct.unpack('<I', uc.mem_read(desc+0xF0, 4))[0]
        ctx=uc.reg_read(UC_X86_REG_RCX)
        SEEN.append((t,f78,f88,flen))
    except Exception as e:
        SEEN.append(('ERR',str(e),0))
DESC={'p':0}
def at_read(uc,addr,size,ud):
    DESC['p']=uc.reg_read(UC_X86_REG_RDX)
sim.uc.hook_add(UC_HOOK_CODE, at_read, begin=0x1400369DA, end=0x1400369DA)

def after_read2(uc,addr,size,ud):
    desc=DESC['p']
    try:
        dataptr=struct.unpack('<Q', uc.mem_read(desc+0x118, 8))[0]
        t=struct.unpack('<H', uc.mem_read(dataptr+6, 2))[0]
        f78=struct.unpack('<I', uc.mem_read(desc+0x38, 4))[0]
        f88=struct.unpack('<Q', uc.mem_read(desc+0x50, 8))[0]
        flen=struct.unpack('<I', uc.mem_read(desc+0xF0, 4))[0]
        ctx=uc.reg_read(UC_X86_REG_RCX)
        SEEN.append((t,f78,f88,flen))
    except Exception as e:
        SEEN.append(('ERR:'+str(e),0,0,0))
sim.uc.hook_add(UC_HOOK_CODE, after_read2, begin=0x1400369DF, end=0x1400369DF)

args=(base+0xDED60, base+sz_, base)
kind,r=sim.call(0x140036970, args, count=200000000)
print('kind',kind,'ret',hex(r) if isinstance(r,int) else r)
print('decoded types (%d):' % len(SEEN))
for i,(t,f78,f88,flen) in enumerate(SEEN):
    if isinstance(t,str): print('  %2d ERROR %s' % (i,t))
    else: print('  %2d type=0x%X f78=0x%X f88=0x%X len=%d' % (i,t,f78,f88,flen))
