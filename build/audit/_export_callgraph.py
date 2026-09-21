# 导出原始驱动全部 1516 个函数的"被调用函数名集合"，用于调用图匹配
import idapro, json, sys, collections

DB = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\samples\PCHunter_2024.09.02\View++_Driver64.sys.i64'
OUT = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\build\audit\_orig_callgraph.json'

rc = idapro.open_database(DB, False)
print('open rc =', rc)
if rc != 0:
    sys.exit(1)

import idautils, ida_funcs, ida_name, idc

# 建立地址 -> 函数名 映射
addr2name = {}
for ea in idautils.Functions():
    addr2name[ea] = ida_funcs.get_func_name(ea) or f'sub_{ea:x}'

result = {}
for ea in idautils.Functions():
    f = ida_funcs.get_func(ea)
    if not f:
        continue
    name = addr2name.get(ea, '')
    callees = set()
    for item in idautils.CodeRefsFrom(ea, 1):
        pass
    # 遍历函数体内所有指令的调用目标
    cur = ea
    while cur < f.end_ea:
        for xref in idautils.CodeRefsFrom(cur, 0):
            tgt = addr2name.get(xref)
            if tgt and tgt != name:
                callees.add(tgt)
        nxt = idc.next_head(cur, f.end_ea)
        if nxt <= cur:
            break
        cur = nxt
    result[name] = {
        'start': hex(ea),
        'size': f.end_ea - ea,
        'callees': sorted(callees),
    }

print('导出函数数:', len(result))
json.dump(result, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False)
print('写入', OUT)

# 抽查
for n in ['ScanProcessVadMemory', 'ParseNtSectionHeaders2', 'InitCallbackFunctionTable', 'DriverEntry']:
    r = result.get(n)
    if r:
        print(f"  {n}: {len(r['callees'])} 个被调用者 -> {r['callees'][:8]}")

idapro.close_database()
print('closed')
