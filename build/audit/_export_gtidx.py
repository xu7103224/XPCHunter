# 提取每个原始函数读写的全局表索引集合（最强指纹）
import idapro, json, sys

DB = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\samples\PCHunter_2024.09.02\View++_Driver64.sys.i64'
OUT = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\build\audit\_orig_gtidx.json'

rc = idapro.open_database(DB, False)
print('open rc =', rc)
if rc != 0:
    sys.exit(1)

import idautils, ida_funcs, ida_ua

addr2name = {ea: (ida_funcs.get_func_name(ea) or f'sub_{ea:x}') for ea in idautils.Functions()}

# 先找到 GtRead / GtWrite 的函数地址
gt_read = gt_write = gt_alloc = None
for ea in idautils.Functions():
    n = addr2name.get(ea, '')
    if n == 'GtRead':
        gt_read = ea
    elif n == 'GtWrite':
        gt_write = ea
    elif n == 'GtAlloc':
        gt_alloc = ea
print('GtRead=%s GtWrite=%s GtAlloc=%s' % (hex(gt_read) if gt_read else None,
                                           hex(gt_write) if gt_write else None,
                                           hex(gt_alloc) if gt_alloc else None))

GT_FUNCS = {gt_read, gt_write, gt_alloc} - {None}

result = {}
for ea in idautils.Functions():
    f = ida_funcs.get_func(ea)
    if not f:
        continue
    name = addr2name[ea]
    reads, writes = set(), set()
    last_ecx = None
    cur = ea
    while cur < f.end_ea:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, cur) > 0:
            mnem = insn.get_canon_mnem()
            # 记录 mov ecx, imm
            if mnem == 'mov' and insn.ops[0].type == ida_ua.o_reg and insn.ops[0].reg == 1:  # ecx
                last_ecx = int(insn.ops[1].value) if insn.ops[1].type == ida_ua.o_imm else None
            elif insn.ops[0].type in (ida_ua.o_near, ida_ua.o_mem) and insn.ops[0].addr in GT_FUNCS and last_ecx:
                tgt = insn.ops[0].addr
                if tgt == gt_write:
                    writes.add(last_ecx)
                elif tgt == gt_read:
                    reads.add(last_ecx)
                elif tgt == gt_alloc:
                    writes.add(last_ecx)
            # call 指令
            elif mnem == 'call' and insn.ops[0].type in (ida_ua.o_near, ida_ua.o_mem):
                if insn.ops[0].addr in GT_FUNCS and last_ecx:
                    if insn.ops[0].addr == gt_write:
                        writes.add(last_ecx)
                    elif insn.ops[0].addr == gt_read:
                        reads.add(last_ecx)
            if mnem not in ('mov', 'movzx', 'movsx', 'lea') and not mnem.startswith('j'):
                if mnem not in ('call',):
                    pass
            # 非 mov 指令后 ecx 可能被破坏，保守起见仅在 mov/call 之间保持
        nxt = cur + insn.size if insn.size else cur + 1
        if nxt <= cur:
            break
        cur = nxt
    result[name] = {'start': hex(ea), 'size': f.end_ea - ea,
                    'gt_reads': sorted(reads), 'gt_writes': sorted(writes)}

print('导出:', len(result))
json.dump(result, open(OUT, 'w', encoding='utf-8'), ensure_ascii=False)
print('写入', OUT)

for n in ['ParseNtDebugSection', 'ParseNtSectionHeaders2', 'ScanProcessVadMemory',
          'InitCallbackFunctionTable', 'DriverEntry', 'InitSdstTable']:
    r = result.get(n)
    if r:
        print(f"  {n}: reads={r['gt_reads'][:8]} writes={r['gt_writes'][:8]}")

idapro.close_database()
print('closed')
