#!/usr/bin/env python3
"""差分第二段扫描的逐条序列（原始 vs 我方）。"""
import os,sys,struct
HERE=os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0,HERE)
from kernel_sim import KernelSim
ORIG='samples/PCHunter_2024.09.02/View++_Driver64.sys'
MINE='build/bin/Release/x64/XPCHunterDrv.sys'
STREAM=open(os.path.join(HERE,'nt4k.bin'),'rb').read()
SRC_OFFSET=0x66EDC0
PROF={'ORIG':dict(path=ORIG,read_entry=0x14008A54C,init_ctx=0x14008A7E4),
      'MINE':dict(path=MINE,read_entry=0x1400541E0,init_ctx=0x140054180)}
def scan(sim,p,start,size,limit=0x46):
    uc=sim.uc; ctx=sim.scratch(0x200); ent=sim.scratch(0x200)
    sim.call(p['init_ctx'],(start,size,2,0),stack_words=(0,0,0,0,-1&0xFFFFFFFFFFFFFFFF,0,0,ctx))
    out=[]
    for i in range(limit):
        k,r=sim.call(p['read_entry'],(ctx,ent),count=800000)
        if k!='OK' or r!=0: out.append(('STOP',r)); break
        b=sim.read(ent,0x120); rp=struct.unpack_from('<Q',sim.read(ctx,0x48),8)[0]
        f0=struct.unpack_from('<I',b,0xF0)[0]
        t=struct.unpack_from('<Q',b,0x118)[0]
        ty=struct.unpack_from('<H',sim.read(t,8),6)[0] if t else 0
        out.append(dict(i=i,off=rp-start,b0=sim.read(rp,1)[0],f0=f0,ty=ty,
                        f50=struct.unpack_from('<Q',b,0x50)[0],
                        f88=struct.unpack_from('<Q',b,0x88)[0],
                        f78=struct.unpack_from('<I',b,0x78)[0],
                        f38=struct.unpack_from('<I',b,0x38)[0],rp=rp))
        uc.mem_write(ctx+8,struct.pack('<Q',(rp+f0)&0xFFFFFFFFFFFFFFFF))
    return out
def run(lb,p):
    sim=KernelSim(p['path']); sim.skip_stack_cookie_check()
    sva=sim.scratch(0x4000,STREAM)
    pib=sva-SRC_OFFSET
    first=scan(sim,p,sva,len(STREAM))
    tgt=None
    for r in first:
        if isinstance(r,tuple): break
        if r['ty']==0x558 and (r['f50']&0x4000000) and r['f38']:
            tgt=(r['f38']-pib+r['rp']+r['f0'])&0xFFFFFFFF; break
    print(f'=== {lb} TargetOffset=0x{tgt:x} ===')
    if tgt is None: print('  no first hit'); return
    avail=SRC_OFFSET+len(STREAM)-tgt
    for r in scan(sim,p,pib+tgt,avail):
        if isinstance(r,tuple): print('  STOP',r); break
        print("  #%2d off=0x%02x b0=0x%02x f0=%d ty=0x%x f88=0x%x f78=%d f38=%d"
              %(r['i'],r['off'],r['b0'],r['f0'],r['ty'],r['f88'],r['f78'],r['f38']))
run('ORIG',PROF['ORIG']); run('MINE',PROF['MINE'])
