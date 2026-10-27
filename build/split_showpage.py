#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ShowPage → 每页 PageShow 函数 + 注册表循环（机械转换）。

每页段（ShowWindow 组 + 按钮组 + 按需刷新）原样搬入对应页面模块，
isX 标志替换为 visible 参数；Hooks 的 page==2 特例与 Network 的
按需刷新保留在段内。ShowPage 本体变成注册表循环 + 提示行 + WM_SIZE。
"""
import re

SRC = '../XPCHunterUM/src/frontend.c'
BS = chr(92)

src = open(SRC, encoding='utf-8', errors='ignore').read()
lines = src.split('\n')

# 定位 ShowPage
i_sp = None
for i, l in enumerate(lines):
    if l.startswith('static void ShowPage') and not l.rstrip().endswith(';'):
        i_sp = i; break
# 结束：配对
j = i_sp
while '{' not in lines[j]: j += 1
depth = 0; k = j
while k < len(lines):
    depth += lines[k].count('{') - lines[k].count('}')
    if depth <= 0: break
    k += 1
SP_A, SP_B = i_sp, k
print('ShowPage: %d..%d' % (SP_A + 1, SP_B + 1))

body = lines[SP_A:SP_B + 1]

# 按页切分：以 ShowWindow(g_h 组头为界
PAGE_OF_FLAG = {
    'isProc': ('FeProcPage.c', 'FeProcPagePageShow'),
    'isKernel': ('FeKernelPage.c', 'FeKernelPagePageShow'),
    'isStartup': ('FeStartupPage.c', 'FeStartupPagePageShow'),
    'isServices': ('FeServicePage.c', 'FeServicePagePageShow'),
    'isRegistry': ('FeRegistryPage.c', 'FeRegistryPagePageShow'),
    'isFile': ('FeFilePage.c', 'FeFilePagePageShow'),
    'isOther': ('FeOtherPage.c', 'FeOtherPagePageShow'),
    'isExam': ('FeExamPage.c', 'FeExamPagePageShow'),
    'isFireeye': ('FeFireeyePage.c', 'FeFireeyePagePageShow'),
    'isSetting': ('FeSettingPage.c', 'FeSettingPagePageShow'),
    'isTrojan': ('FeTrojanPage.c', 'FeTrojanPagePageShow'),
    'isHooks': ('FeHookPage.c', 'FeHookPagePageShow'),
    'isNetwork': ('FeNetworkPage.c', 'FeNetworkPagePageShow'),
}

# 头部（isX 标志计算）到第一个页段
first_seg = None
for i, l in enumerate(body):
    m = re.match(r'\s*if \(g_h(\w+)', l)
    if m:
        first_seg = i; break
head = body[:first_seg]

# 切段：每段从 `if (g_hXxx)` 或 `{`（按钮组）开始，到下一个段开始前
segs = []          # (flag_or_page, lines)
i = first_seg
cur_flag = None
seg = []
while i < len(body):
    l = body[i]
    m = re.search(r'(is\w+)\s*\? SW_SHOW', l)
    if m and m.group(1) != cur_flag:
        if seg: segs.append((cur_flag, seg))
        cur_flag = m.group(1)
        seg = []
    seg.append(l)
    i += 1
if seg: segs.append((cur_flag, seg))

print('页段数: %d' % len(segs))
for fl, seg in segs:
    print('  %-10s %d 行  首行: %s' % (fl, len(seg), seg[0].strip()[:50]))

# 生成各页 PageShow 函数并追加到页面模块
MODULE_APPEND = {}
TAIL_MARKERS = []   # 需要留在 ShowPage 的尾部段（hint/g_MainTab/WM_SIZE）
for fl, seg in segs:
    if fl not in PAGE_OF_FLAG:
        TAIL_MARKERS.append((fl, seg)); continue
    fname, fn = PAGE_OF_FLAG[fl]
    out = []
    out.append('')
    out.append('/* ============================================================================')
    out.append(' * %s — 主 Tab 切换时的显隐/按需刷新（由 ShowPage 机械拆出）' % fn)
    out.append(' * ============================================================================ */')
    out.append('void %s(HWND hWnd, int page)' % fn)
    out.append('{')
    for l in seg:
        t = l
        # isX ? SW_SHOW : SW_HIDE → visible ? ...
        t = re.sub(r'\b%s\s*\?\s*SW_SHOW\s*:\s*SW_HIDE' % re.escape(fl), 'visible ? SW_SHOW : SW_HIDE', t)
        # isX && ... → visible && ...
        t = re.sub(r'\(%s && ' % re.escape(fl), '(visible && ', t)
        out.append(t)
    out.append('}')
    MODULE_APPEND.setdefault(fname, []).append('\n'.join(out))

for fname, blocks in MODULE_APPEND.items():
    p = '../XPCHunterUM/src/' + fname
    cur = open(p, encoding='utf-8', errors='ignore').read()
    cur = open(p, encoding='utf-8', errors='ignore').read()
    open(p, 'w', encoding='utf-8', newline='\n').write(cur)
    print('%s 追加 %d 个 PageShow' % (fname, len(blocks)))

# 重写 ShowPage：注册表循环 + hint + g_MainTab + WM_SIZE
new_sp = []
new_sp.append(lines[SP_A])
new_sp.append('{')
new_sp.append('    /* 统一页面注册表：每页的显隐/按需刷新在各自模块的 PageShow 中实现。 */')
new_sp.append('    static const FE_PAGE_SHOW_FN g_PageShows[] = {')
seen = set()
for pid, nm, mod in [(0,'Process','FeProcPage'),(1,'Kernel','FeKernelPage'),(2,'Ring0','FeHookPage'),
                     (3,'Ring3','FeHookPage'),(4,'Network','FeNetworkPage'),(5,'Registry','FeRegistryPage'),
                     (6,'Startup','FeStartupPage'),(7,'Services','FeServicePage'),(8,'File','FeFilePage'),
                     (9,'Exam','FeExamPage'),(10,'Setting','FeSettingPage'),(11,'Fireeye','FeFireeyePage'),
                     (12,'Trojan','FeTrojanPage'),(13,'Other','FeOtherPage')]:
    new_sp.append('        %sPageShow,   /* %d (%s) */' % (mod, pid, nm))
new_sp.append('    };')
new_sp.append('    for (int i = 0; i < (int)(sizeof(g_PageShows)/sizeof(g_PageShows[0])); i++)')
new_sp.append('        g_PageShows[i](hWnd, page);')
new_sp.append('')
# 尾部段：hint / g_MainTab / WM_SIZE —— 从原 body 末尾摘出
tail = []
for l in reversed(body):
    t = l.strip()
    tail.insert(0, l)
    if t.startswith('if (g_hPageHint)'):
        break
tail_lines = tail
# 只保留 hint / g_MainTab / WM_SIZE 相关（去掉各页 ShowWindow 残留）
skip = False
for l in tail_lines:
    t = l.strip()
    if t.startswith('if (g_hPageHint)'): skip = False
    if re.search(r'ShowWindow\(g_h\w+,\s*(is\w+|\(is\w+)', t): continue
    if re.search(r'HWND \w+ = GetDlgItem', t): continue
    if re.search(r'if \([abcdehr]\) ShowWindow', t): continue
    if t.startswith('HWND ') and 'GetDlgItem' in t: continue
    new_sp.append(l.rstrip())
new_sp.append('}')

# 替换 frontend.c 中的 ShowPage
new_lines = lines[:SP_A] + new_sp + lines[SP_B + 1:]
out = '\n'.join(new_lines)
# ShowPage 里残留的 isX 声明删除（已无引用者）——保守起见仅删除无引用的
open(SRC, 'w', encoding='utf-8', newline='\n').write(out)
print('frontend.c: %d 行（ShowPage 已变注册表循环）' % out.count('\n'))
