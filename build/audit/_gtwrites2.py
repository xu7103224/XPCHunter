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

# ---- 枚举/别名解析（把 GtXxx 名字还原成索引值）----
import re as _re
_h=open('XPCHunterDrv/inc/xpc_gt_enum.h','rb').read().decode('utf-8','replace')
_vals={}
for _m in _re.finditer(r'^\s*(\w+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*,', _h, _re.M):
    _vals[_m.group(1)]=int(_m.group(2),0)
_defs={}
for _m in _re.finditer(r'^\s*#define\s+(\w+)\s+(\S+)(.*)$', _h, _re.M):
    _mm=_re.match(r'^(\w+)(\|(0x[0-9A-Fa-f]+|\d+))?$', _m.group(2))
    if _mm: _defs[_m.group(1)]=(_mm.group(1), int(_mm.group(3),0) if _mm.group(3) else None)

def _res(name, d=0):
    if d>12: return None
    if name in _vals: return _vals[name]
    t=_defs.get(name)
    if t is None: return None
    b=_res(t[0], d+1)
    if b is None: return None
    return b | t[1] if t[1] is not None else b

_TOK=_re.compile(r'Gt(?:Read|Write|Alloc)\(\s*(?:\(GLOBAL_TABLE_INDEX\))?\s*([A-Za-z_]\w*|0x[0-9A-Fa-f]+|\d+)\s*(?:(\|)\s*(0x[0-9A-Fa-f]+|\d+)\s*)?')
def my_gt(body):
    """提取 GT 索引；支持 `A | B | C` 多项 OR 串联。"""
    out=set()
    for m in re.finditer(r'Gt(?:Read|Write|Alloc)\(', body):
        # 从 '(' 之后取第一个参数：截到 ',' 或 ')'（跳过可能出现的 (GLOBAL_TABLE_INDEX) 前缀）
        j=m.end()
        expr=''
        depth=0
        while j < len(body):
            ch=body[j]
            if ch=='(' : depth+=1
            elif ch==')':
                if depth==0: break
                depth-=1
            elif ch==',' and depth==0: break
            expr+=ch
            j+=1
        expr=expr.replace('(GLOBAL_TABLE_INDEX)','').replace('(enum _GLOBAL_TABLE_INDEX)','')
        # 取表达式的第一"项"：以 | 分隔，每项可能是名字/字面量（可含括号）
        terms=[t.strip() for t in expr.split('|')]
        v=None
        for t in terms:
            t=t.strip().strip('()')
            if not t: continue
            if re.fullmatch(r'0x[0-9A-Fa-f]+|\d+', t):
                val=int(t,0)
            else:
                val=_res(t)
            if val is None:
                v=None; break        # 任一项无法解析则不猜
            v = val if v is None else (v | val)
        if v is not None:
            out.add(v)
    return out

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



# ---- 我方：带上"被调内部函数"的索引（传递一层）----
def my_gt_closure(body, all_bodies_by_name):
    s = my_gt(body)
    for m in re.finditer(r'([A-Za-z_]\w*)\s*\(', body):
        fn = m.group(1)
        b = all_bodies_by_name.get(fn)
        if b:
            s |= my_gt(b)
    return s

# 预收集所有函数体（供传递闭包用）
ALL_BODIES={}
for _a,(_n,_s,_w) in json.load(open('build/audit/_addr_map.json',encoding='utf-8')).items():
    _p,_l=_w.rsplit(':',1)
    try: ALL_BODIES[_n]=body_of(_p,int(_l))
    except Exception: pass

amap=json.load(open('build/audit/_addr_map.json',encoding='utf-8'))
rows=[]
for a_hex,(name,sym,where) in amap.items():
    a=int(a_hex,16); r=orig_gt(a)
    if not r: continue
    oreads, owrites=r
    if not oreads and not owrites: continue
    path,ln=where.rsplit(':',1)
    body=body_of(path,int(ln))
    my=my_gt_closure(body, ALL_BODIES)
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
