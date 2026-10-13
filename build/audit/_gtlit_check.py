# 检查源码里的十进制 GT 字面量：在原始驱动中是否存在对该**字面量值**的访问，
# 或只存在对其**十六进制重解释**（dec -> hex 字符串相同数字）的访问。
# 若后者成立而前者不成立，则该字面量极可能是"把 0xNNNN 写成了十进制 NNNN"。
import re, glob, struct
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
md=Cs(CS_ARCH_X86,CS_MODE_64)
text=[s for s in secs if s[0]<=0x90000][-1]
# 收集原始驱动所有 mov ecx, imm32 的立即数（GT 索引）
used=set()
start=off(0x140001000)
for ins in md.disasm(d[start:start+0x8bb7a],0x140001000):
    if ins.mnemonic=='mov' and ins.op_str.startswith('ecx, 0x'):
        try: used.add(int(ins.op_str.split(', ')[1],16))
        except: pass
print(f'原始驱动中作为 ecx 立即数出现的 GT 索引共 {len(used)} 个')

# 源码里的十进制字面量
lits={}
for f in glob.glob('XPCHunterDrv/src/**/*.c', recursive=True):
    t=open(f,'rb').read().decode('utf-8','replace')
    for m in re.finditer(r'Gt(?:Read|Write|Alloc)\(\s*(\d{2,})\s*[,)]', t):
        v=int(m.group(1))
        lits.setdefault(v,[]).append(f)
print(f'源码中十进制字面量索引 {len(lits)} 个（去重）')
susp=[]
for v, files in sorted(lits.items()):
    if v in used: continue                  # 原样存在 -> 正常
    hexstr=('%x'%v)
    if hexstr.isdigit():
        alt=int(hexstr, 16)
        if alt in used:
            susp.append((v, alt, files))
print(f'\n疑似"十六进制误写为十进制"的索引: {len(susp)} 个')
for v, alt, files in susp[:60]:
    print(f'  {v} (0x{v:X}) -> 应为 0x{alt:x} ({alt})   于 {sorted(set(files))[:2]}')
