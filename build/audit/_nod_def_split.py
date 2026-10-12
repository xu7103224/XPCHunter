# 把 _cov_now2.json 的 nodef（名字命中但无同名定义）分成两类：
#  A. 真实内核 API 导入（Flt*/Ke*/Ob*/Nt*/Ps*/Mm*/Io*/Zw*/Se*/Rtl*/wcs*/swprintf 等）
#     —— 这些是外部依赖，源码里只应有调用，无需定义。
#  B. 疑似"我方函数但改名/缺失" —— 需人工核对。
import json, re

d = json.load(open('build/audit/_cov_now2.json', encoding='utf-8'))
orig = {o['name']: o for o in json.load(open('build/audit/_orig_funcs_ida.json', encoding='utf-8'))}

API_PREFIX = ('Flt', 'Ke', 'Ob', 'Nt', 'Zw', 'Ps', 'Mm', 'Io', 'Se', 'Rtl', 'Ex', 'Cm',
              'Lpc', 'Dbg', 'Hal', 'Wmi', 'FsRtl', 'Flt', 'Ki', 'Psp', 'Vf', 'Po',
              'Probe', 'Etw', 'FastIo', 'Exp', 'Sep', 'Mi', 'Sk', 'Kf', 'Csr')
API_EXACT = ('_wcsicmp', 'swprintf', 'wcsncat', 'wcsrchr', 'wcslen', 'wcscpy', 'wcscmp',
             '_guard_check_icall_nop', '__C_specific_handler', 'strcpy', 'strcmp',
             'memset', 'memmove', 'memcpy', 'sprintf', 'vsprintf')

api, mine = [], []
for n in d['nodef']:
    base = n.lstrip('_')
    if n in API_EXACT or base.startswith(API_PREFIX):
        api.append(n)
    else:
        mine.append((n, orig.get(n, {}).get('start', 0), orig.get(n, {}).get('size', 0)))

print(f'nodef 共 {len(d["nodef"])}')
print(f'  A. 内核/CRT 导入（无需定义）: {len(api)}')
print(f'  B. 疑似我方函数（改名或缺失）: {len(mine)}')
print()
print('=== B 类明细（按大小降序）===')
for n, a, s in sorted(mine, key=lambda x: -x[2]):
    print(f'  {hex(a) if a else "?":>12}  {s:>5}B  {n}')