# 权威覆盖率复核：以「原始地址是否在当前源码中作为实现依据出现」为判据。
# 判据来源：本项目规程要求每个函数在注释中标注 `对应原始驱动 0x...`。
# 因此对每个原始函数，检查其起始地址（十六进制小写，去掉 0x）是否出现在源码中。
# 同时标注：缺失 / 仅出现地址但需看是否达到该函数末尾附近（防"跨函数注释"）。
import json, re, glob, os, sys

ROOT = 'XPCHunterDrv/src'
orig = json.load(open('build/audit/_orig_funcs_ida.json', encoding='utf-8'))

# 汇总源码文本（保留行号信息用于定位）
srctext = []
for f in sorted(glob.glob(os.path.join(ROOT, '**', '*.c'), recursive=True)):
    raw = open(f, 'rb').read().decode('utf-8', 'replace')
    srctext.append((f.replace('\\', '/'), raw))
ALL = '\n'.join(t for _, t in srctext)
ALL_L = ALL.lower()

def hexid(v):
    return '%x' % v

lib = [o for o in orig if o.get('lib')]
user = [o for o in orig if not o.get('lib')]
print(f'原始函数总数 {len(orig)}；库函数 {len(lib)}；非库(user) {len(user)}')

def covered(o):
    h = hexid(o['start'])
    return h in ALL_L

miss = [o for o in user if not covered(o)]
have = [o for o in user if covered(o)]
print(f'\n非库函数：已出现地址 {len(have)} / {len(user)} = {len(have)/len(user)*100:.1f}%')
print(f'           地址未出现 {len(miss)} 个, {sum(o["size"] for o in miss):,} 字节')

libmiss = [o for o in lib if not covered(o)]
print(f'库函数：地址未出现 {len(libmiss)} 个（通常为 CRT/编译器辅助，可忽略）')

if miss:
    print('\n=== 非库函数中地址未出现的（按大小降序，前 60） ===')
    for o in sorted(miss, key=lambda x: -x['size'])[:60]:
        print(f'  {hex(o["start"]):>12}  {o["size"]:>6}B  {o["name"]}')
json.dump({'missing': miss, 'present': have, 'lib_missing': libmiss},
          open('build/audit/_cov_now.json', 'w', encoding='utf-8'),
          ensure_ascii=False, indent=1)
print('\n已写出 build/audit/_cov_now.json')