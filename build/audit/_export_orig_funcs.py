# 从 IDA 数据库导出原始驱动的全部函数（名称 + 地址范围 + 大小）
import idapro, json, sys

DB = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\samples\PCHunter_2024.09.02\View++_Driver64.sys.i64'
OUT = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\build\audit\_orig_funcs_ida.json'

rc = idapro.open_database(DB, False)
print('open_database rc =', rc)
if rc != 0:
    sys.exit(1)

import idautils, ida_funcs, ida_name, ida_bytes, ida_segment

rows = []
for ea in idautils.Functions():
    f = ida_funcs.get_func(ea)
    if not f:
        continue
    name = ida_funcs.get_func_name(ea) or ''
    flags = f.flags
    is_thunk = bool(flags & 0x00000080) if hasattr(ida_funcs, 'FUNC_THUNK') else False
    try:
        is_thunk = ida_funcs.is_func_thunk(ea)
    except Exception:
        pass
    rows.append({
        'name': name,
        'start': f.start_ea,
        'end': f.end_ea,
        'size': f.end_ea - f.start_ea,
        'thunk': bool(is_thunk),
        'lib': bool(flags & ida_funcs.FUNC_LIB) if hasattr(ida_funcs, 'FUNC_LIB') else False,
        'segment': ida_segment.get_segm_name(ida_segment.getseg(ea)) if ida_segment.getseg(ea) else '',
    })

print('函数总数:', len(rows))
named = [r for r in rows if r['name'] and not r['name'].startswith('sub_')]
subs = [r for r in rows if r['name'].startswith('sub_')]
print('  已命名:', len(named))
print('  仍为 sub_:', len(subs))
print('  其中 thunk:', sum(1 for r in rows if r['thunk']))
print('  其中库函数:', sum(1 for r in rows if r['lib']))
print('  代码总字节:', f"{sum(r['size'] for r in rows):,}")

json.dump(rows, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False)
print('已写入', OUT)

# 抽查几个已知函数
by_name = {r['name']: r for r in rows}
for n in ['CheckProcessAccess', 'DriverEntry', 'DriverUnload', 'InitCallbackFunctions',
          'MiniFilterNormalizeName', 'ParseNtRelocSection', 'EnumProcessHandleInfo']:
    r = by_name.get(n)
    print(f"  {n:32s} {'{:#x}..{:#x} size={}'.format(r['start'], r['end'], hex(r['size'])) if r else '未找到'}")

idapro.close_database()
print('closed')
