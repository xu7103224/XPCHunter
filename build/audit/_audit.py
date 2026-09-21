# 全量审计：将 IDA 中原始的 1516 个函数逐个与复刻源码对照
import json, re, glob, os, collections

ORIG = r'build\audit\_orig_funcs_ida.json'
SRC_GLOBS = ['XPCHunterDrv/src/**/*.c', 'XPCHunterDrv/inc/*.h']

orig = json.load(open(ORIG, encoding='utf-8'))
print(f'原始函数: {len(orig)}')

# ---- 解析源码中的所有函数定义 ----
func_re = re.compile(
    r'^[A-Za-z_][A-Za-z0-9_ \*]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{]*?\)\s*$')
src_defs = {}          # name -> (file, line)
src_bodies = {}        # name -> 源码行列表
for f in glob.glob('XPCHunterDrv/src/**/*.c', recursive=True):
    lines = open(f, encoding='utf-8', errors='ignore').read().split('\n')
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.strip() and not ln.startswith((' ', '\t', '/', '#', '{', '}')) and '(' in ln:
            # 收集签名直到 ')' 结尾
            j = i
            sig = ''
            while j < len(lines) and j < i + 6:
                sig += lines[j] + '\n'
                if ')' in lines[j]:
                    break
                j += 1
            m = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(', sig)
            k = j + 1
            while k < len(lines) and lines[k].strip() == '':
                k += 1
            if m and k < len(lines) and lines[k].strip() == '{':
                name = m.group(1)
                if name not in ('if', 'for', 'while', 'switch', 'return', 'sizeof'):
                    src_defs.setdefault(name, (f, i + 1))
                    # 抓函数体
                    depth = 0
                    body = []
                    p = k
                    while p < len(lines):
                        depth += lines[p].count('{') - lines[p].count('}')
                        body.append(lines[p])
                        if depth == 0 and p >= k:
                            break
                        p += 1
                    src_bodies[name] = body
                    i = p + 1
                    continue
        i += 1

print(f'源码中解析到的函数定义: {len(src_defs)}')

def is_trivial(name):
    b = src_bodies.get(name)
    if not b:
        return False
    txt = '\n'.join(b)
    txt = re.sub(r'//[^\n]*', '', txt)
    txt = re.sub(r'/\*.*?\*/', '', txt, flags=re.S).strip()
    if txt.startswith('{'):
        txt = txt[1:-1].strip()
    return bool(re.fullmatch(r'(return\s+[-0-9xXa-fA-FuUlL\(\)\| ]*\s*;)?', txt))

# ---- 分类 ----
LIB_OR_THUNK = []
missing = []
present = []
trivial_list = []
for r in orig:
    n = r['name']
    if r['thunk'] or r['lib'] or n.startswith('_') or n in ('INIT',):
        LIB_OR_THUNK.append(r)
        continue
    if n in src_defs:
        present.append(r)
        if is_trivial(n):
            trivial_list.append(r)
    else:
        missing.append(r)

print()
print(f'排除（thunk/库函数）: {len(LIB_OR_THUNK)}')
print(f'源码中存在同名实现   : {len(present)}')
print(f'源码中找不到同名实现 : {len(missing)}')
print(f'  其中"平凡函数体"   : {len(trivial_list)}')
print()

print('=' * 88)
print(f'【A】源码中找不到同名实现的原始函数（共 {len(missing)} 个，按大小降序）')
print('=' * 88)
for r in sorted(missing, key=lambda x: -x['size'])[:60]:
    print(f"  {r['size']:6d}B  {r['name']:52s} {r['start']:#x}")
if len(missing) > 60:
    print(f'  ... 其余 {len(missing)-60} 个见 JSON')

print()
print('=' * 88)
print(f'【B】同名存在但函数体是"返回常量"的（共 {len(trivial_list)} 个，按原始大小降序）')
print('=' * 88)
for r in sorted(trivial_list, key=lambda x: -x['size']):
    f, ln = src_defs[r['name']]
    print(f"  {r['size']:6d}B  {r['name']:52s} {f}:{ln}")

json.dump({'missing': missing, 'trivial': trivial_list, 'present': present},
          open(r'build\audit\_audit_result.json', 'w', encoding='utf-8'), ensure_ascii=False)
print()
print('详细结果已写入 build\\_audit_result.json')
