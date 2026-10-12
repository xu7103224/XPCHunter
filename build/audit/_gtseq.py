import struct,sys
from capstone import *
P='samples/PCHunter_2024.09.02/View++_Driver64.sys'
d=open(P,'rb').read()
pe=struct.unpack_from('<I',d,0x3c)[0]
n=struct.unpack_from('<H',d,pe+6)[0]
sec=pe+24+struct.unpack_from('<H',d,pe+20)[0]
secs=[]
for i in range(n):
    o=sec+i*40
    vsz,va,rsz,ra=struct.unpack_from('<IIII',d,o+8); secs.append((va,vsz,ra,rsz))
def off(va):
    va-=0x140000000
    for sva,vsz,ra,rsz in secs:
        if sva<=va<sva+max(vsz,rsz): return ra+(va-sva)
md=Cs(CS_ARCH_X86, CS_MODE_64)
CALLS={'0x140029efc':'R','0x140029ff4':'W'}
def seq(a,ln=1200):
    raw=d[off(a):off(a)+ln]
    regs={}; out=[]
    for ins in md.disasm(raw,a):
        if ins.mnemonic=='mov' and ', ' in ins.op_str:
            dst,src=ins.op_str.split(', ',1)
            dst=dst.strip()
            if src.startswith('0x'): regs[dst]=int(src,16)
            elif src in regs: regs[dst]=regs[src]
        if ins.mnemonic=='call':
            if ins.op_str in CALLS: out.append((CALLS[ins.op_str], regs.get('ecx')))
            else: out.append(('call', ins.op_str))
        if ins.mnemonic=='ret': break
    return out
if __name__=='__main__':
    for a in sys.argv[1:]:
        addr=int(a,16)
        s=seq(addr)
        gts=[(k,hex(v) if v else '?') for k,v in s if k in ('R','W')]
        calls=[v for k,v in s if k=='call']
        print(f'{hex(addr)}: GT={gts}')
        print(f'         calls={calls}')
