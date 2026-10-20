#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""检查所有 `for(;;)` 无界循环是否都有可达退出路径（break/goto/return）。
按花括号配平取循环体，再在体内搜索退出语句。"""
import os, re, glob

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
bad = []
total = 0
for path in sorted(glob.glob(os.path.join(ROOT, 'XPCHunterDrv', 'src', '**', '*.c'), recursive=True)):
    text = open(path, encoding='utf-8', errors='ignore').read()
    for m in re.finditer(r'for\s*\(\s*;\s*;\s*\)[^{;\n]*\n?\s*\{', text):
        total += 1
        start = m.end() - 1          # 指向 '{'
        depth = 0
        i = start
        while i < len(text):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = text[start:i + 1]
        # 去除注释与字符串里的关键字干扰（粗略）
        clean = re.sub(r'//[^\n]*', '', body)
        clean = re.sub(r'/\*.*?\*/', '', clean, flags=re.S)
        clean = re.sub(r'"[^"\n]*"', '""', clean)
        has_exit = re.search(r'\b(break|return|goto)\b', clean) is not None
        line = text[:m.start()].count('\n') + 1
        if not has_exit:
            bad.append((os.path.relpath(path, ROOT), line))
print('for(;;) 循环总数:', total)
print('无退出路径:', len(bad))
for p, ln in bad:
    print('   !! %s:%d' % (p, ln))