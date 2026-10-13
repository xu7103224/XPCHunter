# 精确定界版：用 brace 匹配取函数体，再提取其 GT 索引集合，与原始静态扫描比对。
import re, json, struct
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
funcs={f['start']:f for f in json.load(open('build/audit/_orig_funcs_ida.json'))}

def orig_gt(va):
    f=funcs.get(va)
    if not f: return None
    reads=[]; writes=[]; last=None
    for ins in md.disasm(d[off(va):][:f['size']], va):
        if ins.mnemonic=='mov' and ins.op_str.startswith('ecx, '):
            s=ins.op_str.split(', ')[1]
            last=int(s,16) if s.startswith('0x') else None
        elif ins.mnemonic=='mov' and ins.op_str.startswith('ecx, r'):
            last=None
        if ins.mnemonic=='call':
            if ins.op_str=='0x140029efc' and last is not None: reads.append(last)
            elif ins.op_str=='0x140029ff4' and last is not None: writes.append(last)
            last=None
    return reads, writes

def body_of(path, decl_line):
    """从声明行起做 brace 匹配，返回精确函数体文本。"""
    src=open(path,'rb').read().decode('utf-8','replace')
    lines=src.split('\n')
    i=decl_line-1
    # 找到签名所在（可能跨行）
    depth=0; started=False; out=[]
    for j in range(i, min(i+2000, len(lines))):
        out.append(lines[j])
        for ch in lines[j]:
            if ch=='{': depth+=1; started=True
            elif ch=='}':
                depth-=1
                if started and depth==0:
                    return '\n'.join(out)
    return '\n'.join(out)

amap=json.load(open('build/audit/_addr_map.json',encoding='utf-8'))
rows=[]
for a_hex,(name,sym,where) in amap.items():
    a=int(a_hex,16); r=orig_gt(a)
    if not r: continue
    oreads, owrites=r
    if not oreads and not owrites: continue
    path,ln=where.rsplit(':',1)
    body=body_of(path,int(ln))
    my=set()
    for m in re.finditer(r'Gt(?:Read|Write|Alloc)\(\s*(?:\(GLOBAL_TABLE_INDEX\))?(0x[0-9A-Fa-f]+|\d+)', body):
        my.add(int(m.group(1),0))
    oset=set(oreads)|set(owrites)
    overlap=oset & my
    rows.append((a_hex,name,sorted(oset),sorted(my),len(overlap),len(oset)))
# 输出"重叠率低"的
rows.sort(key=lambda x:(x[4]/max(x[5],1), -x[5]))
print(f'{"地址":>12} {"函数":<36} {"重叠":>6} {"原始索引数":>8}')
for a_hex,name,oset,my,ov,no in rows:
    if no and ov/max(no,1) < 0.5:
        print(f'{a_hex:>12} {name[:36]:<36} {ov}/{no:<24} 原始={[hex(x) for x in oset][:6]}')
        print(f'{"":>12} {"":<36}  我方={[hex(x) for x in my][:6]}')
