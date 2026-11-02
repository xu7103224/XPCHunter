#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""frontend.c CLI 链 → CliMain.c 机械拆分。

规则（零语义改动）：
  1. 每个 CLI 块整体搬移，函数体逐字保留；仅在块前插入
     `if (!(<原始条件>)) return FE_CLI_NEXT;`，块尾补 `return FE_CLI_NEXT;`
     （仅当块内无 return 时——原块几乎都以 return 结束）。
  2. 调度器按原源码顺序走链，首个非 FE_CLI_NEXT 即返回——
     保持 strstr 首匹配语义（--restorehooks-cli 先于 --hooks-cli 是承重的）。
  3. RunHeadless / RunProcListCli 原样搬移。
  4. frontend.c 删除被搬区域，WinMain 在原位置调用 FeCliDispatch。
"""
import re, sys, io

SRC = '../XPCHunterUM/src/frontend.c'
OUT_CLI = '../XPCHunterUM/src/CliMain.c'
OUT_HDR = '../XPCHunterUM/inc/CliMain.h'

src = open(SRC, encoding='utf-8', errors='ignore').read()
lines = src.split('\n')

def find_line(pred, start=0):
    for i in range(start, len(lines)):
        if pred(lines[i]):
            return i
    return -1

# ---- 定位关键边界 ----
i_runheadless = find_line(lambda l: l.startswith('static int RunHeadless'))
i_winmain     = find_line(lambda l: l.startswith('int WINAPI WinMain'))
# 控制台附加块结束 / CLI 链开始：第一条 CLI 判定
i_chain_first = find_line(lambda l: l.lstrip().startswith('if (lpCmdLine && strstr(lpCmdLine, "--proclist-cli"))'), i_winmain)
# 链尾：--scan-cli 块结束后、icc.dwSize 之前
i_gui_start   = find_line(lambda l: l.lstrip().startswith('icc.dwSize'), i_winmain)
assert i_runheadless > 0 and i_winmain > 0 and i_chain_first > 0 and i_gui_start > 0, '边界定位失败'

print('RunHeadless=%d, WinMain=%d, 链首=%d, GUI=%d' %
      (i_runheadless + 1, i_winmain + 1, i_chain_first + 1, i_gui_start + 1))

# ---- 提取 RunHeadless + RunProcListCli（i_runheadless .. i_winmain-1，含尾部注释）----
run_block = '\n'.join(lines[i_runheadless:i_winmain]).rstrip('\n')

# ---- 提取 CLI 链并切块 ----
chain_lines = lines[i_chain_first:i_gui_start]

blocks = []           # (name_hint, cond_text, body_lines, leading_comments)
i = 0
pending_comments = []
in_comment = False
n = len(chain_lines)
while i < n:
    l = chain_lines[i]
    ls = l.strip()
    if in_comment or ls == '' or ls.startswith('/*') or ls.startswith('*') or ls.startswith('*/'):
        pending_comments.append(l)
        if ls.startswith('/*') and '*/' not in ls:
            in_comment = True
        elif in_comment and '*/' in ls:
            in_comment = False
        i += 1
        continue
    if ls.startswith('if (lpCmdLine'):
        # 条件 = 'if ' 到行尾；'{' 可能在行尾或下一行
        cond = ls[3:].strip()
        if cond.endswith('{'):
            cond = cond[:-1].strip()
        has_brace = ls.endswith('{')
        brace_next = (not has_brace) and i + 1 < n and chain_lines[i + 1].lstrip().startswith('{')
        body = []
        if has_brace or brace_next:
            depth = 1
            i += 1
            if brace_next:
                body.append(chain_lines[i])   # '{' 行本身保留在体内
                i += 1
            while i < n and depth > 0:
                bl = chain_lines[i]
                depth += bl.count('{') - bl.count('}')
                if depth <= 0:
                    tail = bl.split('}')[0]
                    if tail.strip():
                        body.append(tail)
                    i += 1          # 闭合行已消费，跳过（否则外层把 } 当独立块）
                    break
                body.append(bl)
                i += 1
        else:
            i += 1
            if i < n:
                body.append(chain_lines[i])
                i += 1
        # 命名：取条件中第一个 "--xxx"
        m = re.search(r'"(--[a-z0-9-]+)', cond)
        hint = m.group(1)[2:] if m else ('tab' if '--tab ' in cond else 'misc')
        blocks.append({'cond': cond, 'body': body, 'hint': hint,
                       'comments': pending_comments[:]})
        pending_comments = []
        continue
    # 非块非注释的散落语句（不应存在）——保留为独立透传块
    blocks.append({'cond': None, 'body': [l], 'hint': 'pass',
                   'comments': pending_comments[:]})
    pending_comments = []
    i += 1

print('切块数: %d' % len(blocks))
for k, b in enumerate(blocks):
    nm = b['hint'] if b['cond'] else '(pass)'
    print('  %2d. %-22s %s' % (k + 1, nm, b['body'][0].strip()[:60] if b['body'] else ''))

# ---- 生成 CliMain.c ----
def camel(hint):
    parts = re.split(r'[-0-9]+', hint)
    out = ''.join(p.capitalize() for p in parts if p)
    return 'Cli' + (out or 'X')

o = io.StringIO()
o.write('''// ============================================================================
// CliMain.c — 命令行（--xxx-cli）分发与处理
//
// 【2026-10-28 由 frontend.c 机械拆分】拆分规则与验收方式见
//   docs/archive/reversing/frontend拆分_2026-10-28.md。本文件全部处理函数的
//   函数体逐字取自原 frontend.c WinMain 内的 CLI if 链，仅做三处机械变换：
//     1) 每块包成独立函数，块首插入
//          if (!(<原始条件>)) return FE_CLI_NEXT;
//        块尾若无 return 补 return FE_CLI_NEXT（保持"继续匹配"语义）；
//     2) FeCliDispatch 按【原源码顺序】走链，首个非 FE_CLI_NEXT 即返回
//        —— strstr 首匹配语义是承重的（--restorehooks-cli 先于 --hooks-cli）；
//     3) 原块内引用的静态变量改为 extern（g_Client / g_StartTab）。
//   外观与行为不得有任何变化；验收 = 全部 CLI 输出与拆分前基线逐字节一致
//   （build/cli_baseline/cli_base_t1.txt）。
// ============================================================================
#include "XPCHunterUM.h"
#include "CliMain.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

''')
# externs（g_Client/g_StartTab 定义在 frontend.c，已去静态）
o.write('extern XPCH_CLIENT g_Client;\nextern int g_StartTab;\n\n')
o.write('BOOL FeIsSkipped(ULONG cmd);\nBOOL SendOne(ULONG cmd, ULONG outSize, char *detail, size_t detailLen);\n\n')
# RunHeadless/RunProcListCli 原样（保持 static）
o.write(run_block + '\n\n')
# 处理函数
for k, b in enumerate(blocks):
    fn = '%s_%02d' % (camel(b['hint']), k + 1)
    b['fn'] = fn
    for c in b['comments']:
        o.write(c.rstrip('\n') + '\n')
    o.write('static int %s(const char *lpCmdLine)\n{\n' % fn)
    if b['cond']:
        o.write('    if (!(%s))\n        return FE_CLI_NEXT;\n' % b['cond'])
    else:
        o.write('    if (!lpCmdLine)\n        return FE_CLI_NEXT;\n')
    wrote_ret = False
    for bl in b['body']:
        o.write(bl.rstrip('\n') + '\n')
        if re.match(r'\s*return\b', bl):
            wrote_ret = True
    if not wrote_ret:
        o.write('    return FE_CLI_NEXT;\n')
    o.write('}\n\n')
# 调度器（原序）
o.write('''// ============================================================================
// 分发表：按原 frontend.c WinMain if 链的【源码顺序】排列。
// 首个命中（处理函数返回非 FE_CLI_NEXT）即其退出码；全不命中返回 FE_CLI_NONE
// ——WinMain 据此落入 GUI 路径。
// ============================================================================
int FeCliDispatch(const char *lpCmdLine)
{
    int r;
''')
for b in blocks:
    o.write('    if ((r = %s(lpCmdLine)) != FE_CLI_NEXT)\n        return r;\n' % b['fn'])
o.write('    return FE_CLI_NONE;\n}\n')

open(OUT_CLI, 'w', encoding='utf-8', newline='\n').write(o.getvalue())
print('已写 %s (%d 行)' % (OUT_CLI, o.getvalue().count('\n')))

# ---- 生成 CliMain.h ----
h = io.StringIO()
h.write('''// ============================================================================
// CliMain.h — CLI 分发接口（由 frontend.c 机械拆分产出，2026-10-28）
// ============================================================================
#ifndef XPCH_CLIMAIN_H
#define XPCH_CLIMAIN_H

/* CLI 处理函数的哨兵返回值：
 *   FE_CLI_NEXT  本条命令行不匹配该处理器，继续走链
 *   FE_CLI_NONE  全链无命中，调用方（WinMain）落入 GUI 路径
 * 其余返回值 = 该 CLI 入口的进程退出码（与拆分前一致） */
#define FE_CLI_NEXT  (-2)
#define FE_CLI_NONE  (-1)

/* 按 frontend.c 原 WinMain if 链的源码顺序分发；返回退出码或 FE_CLI_NONE */
int FeCliDispatch(const char *lpCmdLine);

#endif /* XPCH_CLIMAIN_H */
''')
open(OUT_HDR, 'w', encoding='utf-8', newline='\n').write(h.getvalue())
print('已写 %s' % OUT_HDR)

# ---- 改写 frontend.c ----
new_lines = lines[:i_runheadless] + lines[i_winmain:]   # 去掉 RunHeadless/RunProcListCli
# WinMain 起点（原 i_winmain 现在平移了 del_len）
nw = i_runheadless          # WinMain 在删除后落于此下标
# 重新在 new_lines 里定位：控制台块之后插入 dispatch、删除链体
nl = new_lines
j_chain = None
for i in range(nw, len(nl)):
    if nl[i].lstrip().startswith('if (lpCmdLine && strstr(lpCmdLine, "--proclist-cli"))'):
        j_chain = i
        break
j_gui = None
for i in range(nw, len(nl)):
    if nl[i].lstrip().startswith('icc.dwSize'):
        j_gui = i
        break
assert j_chain and j_gui, 'frontend.c 内边界丢失'
disp = [
    '    /* CLI 分发已拆至 CliMain.c（2026-10-28）。调度器按原 if 链的源码顺序',
    '       走链：命中返回退出码，全不命中（FE_CLI_NONE）落入下方 GUI 路径。 */',
    '    {',
    '        int CliRc = FeCliDispatch(lpCmdLine);',
    '        if (CliRc != FE_CLI_NONE)',
    '            return CliRc;',
    '    }',
    '',
]
new_lines = nl[:j_chain] + disp + nl[j_gui:]
# 去静态
out = '\n'.join(new_lines)
out = out.replace('static XPCH_CLIENT g_Client;', 'XPCH_CLIENT g_Client; /* 2026-10-28 去静态：CliMain.c 共用 */')
out = out.replace('static int  g_StartTab = 0;', 'int  g_StartTab = 0;   /* 2026-10-28 去静态：CliMain.c 的 --tab 块写入 */')
out = out.replace('static BOOL SendOne(', 'BOOL SendOne(')
out = out.replace('static BOOL FeIsSkipped(', 'BOOL FeIsSkipped(')
# WinMain 前插入声明
out = out.replace('int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow)',
                  'int FeCliDispatch(const char *lpCmdLine);\n\nint WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow)', 1)
# include CliMain.h（放在首个 include 后）
m = re.search(r'^#include "[^"]+"$', out, re.M)
if m:
    out = out[:m.end()] + '\n#include "CliMain.h"' + out[m.end():]
open(SRC, 'w', encoding='utf-8', newline='\n').write(out)
print('frontend.c 已改写: %d 行' % out.count('\n'))
