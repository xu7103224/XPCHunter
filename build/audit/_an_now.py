# 临时分析：把最新差分的"非一致"函数按源文件/类型分组，用于评估剩余工作量
import json, collections

d = json.load(open('build/audit/_diff_final.json'))
res = d['results']
bad = [r for r in res if r.get('verdict') not in ('identical', 'both_blocked')]
print('需处理的差异函数: %d / %d' % (len(bad), len(res)))

byfile = collections.Counter()
for r in bad:
    w = (r.get('where') or '')
    w = w.replace(chr(92), '/')
    f = w.split('/')[-1].split(':')[0] if w else '?'
    byfile[f] += 1
print()
print('=== 差异按源文件分布（前 14）===')
for f, n in byfile.most_common(14):
    print('  %-28s %3d' % (f, n))

print()
print('=== 差异类型 ===')
for k, v in collections.Counter(r['verdict'] for r in bad).most_common():
    print('  %-22s %3d' % (k, v))

print()
print('=== 加载路径相关差异 ===')
keys = ('SsdtHook', 'DriverEntry', 'SyscallTable', 'ContextMgmt', 'Protocol', 'SSDT')
for r in bad:
    w = (r.get('where') or '').replace(chr(92), '/')
    if any(k in w for k in keys):
        short = w.split('XPCHunterDrv/')[-1] if 'XPCHunterDrv/' in w else w
        print('  %-18s %-36s %s' % (r['verdict'], r['name'], short))
