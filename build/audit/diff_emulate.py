#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用 windows-driver-emulation skill 对「原始驱动 vs 我方重编译驱动」做差分验证。

思路：同一个模拟器、同一套内核模型、同样的输入，分别跑两个驱动，
比对运行时可观测量（映射结果、API 调用序列、执行指令数、停止原因）。
差异处即"复刻可能跑偏"的候选点。

用法：
  python diff_emulate.py <original.sys> <rebuilt.sys> [--limit N] [--json out.json]
"""
import argparse
import json
import os
import sys

SKILL = r'E:\Work\Dev\Windows\ai\UnicornForDriver\.dsh\skills\windows-driver-emulation\scripts'
sys.path.insert(0, SKILL)

from wdrvemu import analyze  # noqa: E402


def run_one(path, limit):
    rep = analyze(path, run=True, instruction_limit=limit, trace_limit=200000)
    e = rep.emulation
    d = {
        'path': path,
        'size': os.path.getsize(path),
        'image_base': rep.summary['image']['preferred_base'],
        'entry_rva': rep.summary['image']['entry_point_rva'],
        'sections': rep.summary['image']['sections'],
        'mapping': {
            'base': rep.summary['mapping']['base'],
            'size': rep.summary['mapping']['size'],
            'relocs_applied': rep.summary['mapping']['relocations_applied'],
            'relocs_failed': rep.summary['mapping']['relocations_failed'],
            'imports_resolved': rep.summary['mapping']['imports_resolved'],
            'imports_unresolved': rep.summary['mapping']['imports_unresolved'],
            'in_ps_loaded_module_list': rep.summary['mapping'].get('registered_in_ps_loaded_module_list'),
        },
        'emu': {
            'completed': e.completed,
            'status_name': e.status_name,
            'instructions': e.instructions,
            'unique_instructions': e.covered_instructions,
            'api_call_count': len(e.api_calls or []),
            'apis_called': rep.summary.get('apis_called', []),
            'stop_reason': (e.stop_reason or '')[:200],
            'bugcheck': e.bugcheck_name,
            'driver_object': e.driver_object or {},
        },
        'imports_by_dll': rep.summary.get('imports', {}),
        'detected_subsystems': rep.summary.get('detected_subsystems', []),
        'api_calls': [(c['name'], [a for a in c['args'] if a]) for c in (e.api_calls or [])],
    }
    return d


def compare(a, b):
    print('=' * 88)
    print('差分验证：原始 vs 重编译')
    print('=' * 88)
    print(f'  原始   : {a["path"]}  ({a["size"]:,} 字节)')
    print(f'  重编译 : {b["path"]}  ({b["size"]:,} 字节)')
    print()
    rows = [
        ('镜像基址',    a['image_base'],            b['image_base']),
        ('入口 RVA',    a['entry_rva'],             b['entry_rva']),
        ('节区数',      len(a['sections']),         len(b['sections'])),
        ('映射基址',    a['mapping']['base'],       b['mapping']['base']),
        ('重定位施加',  a['mapping']['relocs_applied'], b['mapping']['relocs_applied']),
        ('重定位失败',  a['mapping']['relocs_failed'],  b['mapping']['relocs_failed']),
        ('导入已解析',  a['mapping']['imports_resolved'],   b['mapping']['imports_resolved']),
        ('导入未解析',  a['mapping']['imports_unresolved'], b['mapping']['imports_unresolved']),
        ('链入模块表',  a['mapping']['in_ps_loaded_module_list'], b['mapping']['in_ps_loaded_module_list']),
        ('DriverEntry 完成', a['emu']['completed'],  b['emu']['completed']),
        ('执行指令数',  a['emu']['instructions'],   b['emu']['instructions']),
        ('唯一指令数',  a['emu']['unique_instructions'], b['emu']['unique_instructions']),
        ('API 调用数',  a['emu']['api_call_count'], b['emu']['api_call_count']),
        ('bugcheck',   a['emu']['bugcheck'],       b['emu']['bugcheck']),
    ]
    for label, va, vb in rows:
        same = '  一致' if va == vb else '  <<< 不一致'
        print(f'  {label:<18} 原始={str(va):<24} 重编译={str(vb):<24}{same}')

    print('\n  API 调用序列比对：')
    ca = [n for n, _ in a['api_calls']]
    cb = [n for n, _ in b['api_calls']]
    only_a = [x for x in ca if x not in cb]
    only_b = [x for x in cb if x not in ca]
    print(f'    原始   : {ca}')
    print(f'    重编译 : {cb}')
    if only_a:
        print(f'    仅原始有   : {only_a}')
    if only_b:
        print(f'    仅重编译有 : {only_b}')
    if not only_a and not only_b:
        print('    -> 调用集合一致')

    print('\n  停止原因：')
    print(f'    原始   : {a["emu"]["stop_reason"][:150]}')
    print(f'    重编译 : {b["emu"]["stop_reason"][:150]}')

    print('\n  导入分布：')
    print(f'    原始   : {a["imports_by_dll"]}')
    print(f'    重编译 : {b["imports_by_dll"]}')
    print(f'\n  识别出的子系统：\n    原始   : {a["detected_subsystems"]}\n    重编译 : {b["detected_subsystems"]}')
    return {'original': a, 'rebuilt': b}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('original')
    ap.add_argument('rebuilt')
    ap.add_argument('--limit', type=int, default=500000)
    ap.add_argument('--json', default='')
    args = ap.parse_args()

    a = run_one(args.original, args.limit)
    b = run_one(args.rebuilt, args.limit)
    out = compare(a, b)
    if args.json:
        json.dump(out, open(args.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        print(f'\n已写出 {args.json}')


if __name__ == '__main__':
    main()