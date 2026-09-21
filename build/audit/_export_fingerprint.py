# 导出原始每个函数的"立即数常量集合"（含全局表索引），作为强指纹
import idapro, json, sys, collections

DB = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\samples\PCHunter_2024.09.02\View++_Driver64.sys.i64'
OUT = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\build\audit\_orig_fingerprint.json'

rc = idapro.open_database(DB, False)
print('open rc =', rc)
if rc != 0:
    sys.exit(1)

import idautils, ida_funcs, ida_ua, ida_idp

addr2name = {ea: (ida_funcs.get_func_name(ea) or f'sub_{ea:x}') for ea in idautils.Functions()}

result = {}
for ea in idautils.Functions():
    f = ida_funcs.get_func(ea)
    if not f:
        continue
    name = addr2name[ea]
    callees, consts = set(), set()
    cur = ea
    while cur < f.end_ea:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, cur) > 0:
            for op in insn.ops:
                if op.type == ida_ua.o_imm:
                    consts.add(int(op.value))
                elif op.type in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far):
                    t = addr2name.get(op.addr)
                    if t and t != name:
                        callees.add(t)
        nxt = ida_ua.decode_insn(insn, cur) and (cur + insn.size)
        if not nxt or nxt <= cur:
            break
        cur = nxt
    result[name] = {'start': hex(ea), 'size': f.end_ea - ea,
                    'callees': sorted(callees),
                    'consts': sorted(c for c in consts if 0 < c < 0x100000)}

print('导出:', len(result))
json.dump(result, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False)
print('写入', OUT)

for n in ['ScanProcessVadMemory', 'FindKernelPageSection', 'FindKernelDataSectionV2',
          'ParseNtSectionHeaders2', 'InitCallbackFunctionTable', 'ScanPESectionPatternsEx']:
    r = result.get(n)
    if r:
        print(f"  {n} ({r['size']}B): consts={r['consts'][:12]}")

idapro.close_database()
print('closed')
