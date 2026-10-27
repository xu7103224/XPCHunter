#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""frontend.c 第二轮拆分：按页把 UI 代码（含静态变量）移入与 Views 文件对齐的页面模块。

规则：
  1. 函数体逐字搬移（含前置注释块）；
  2. 页面静态变量随页搬移，跨模块引用的一律去 static；
  3. 跨模块引用的函数一律去 static；
  4. FePages.h 汇总全部 extern（= 统一页面注册表的声明面）；
  5. frontend.c 保留：公共 UI 助手、主窗口（g_hMainWnd/g_hMainTabs/g_hPageHint/
     g_MainTab/g_MainTabNames/g_hStatus）、ShowPage、WndProc、WinMain、CLI 分发调用。
"""
import re, os

SRC = '../XPCHunterUM/src/frontend.c'
BS = chr(92)

def strip_str(line):
    out=[]; i=0; n=len(line)
    while i<n:
        c=line[i]
        if c=='"':
            i+=1
            while i<n and line[i]!='"':
                if line[i]==BS: i+=1
                i+=1
            i+=1
        elif c=="'":
            i+=1
            while i<n and line[i]!="'":
                if line[i]==BS: i+=1
                i+=1
            i+=1
        else:
            out.append(c); i+=1
    return ''.join(out)

src = open(SRC, encoding='utf-8', errors='ignore').read()
lines = src.split('\n')
NL = len(lines)

# ---------- 函数定义（字符串感知的花括号配对） ----------
defs = {}
i = 0
while i < NL:
    l = lines[i]
    m = re.match(r'^(?:static\s+)?(?:const\s+)?(?:[\w]+\s+\*? *|LRESULT CALLBACK +)(\w+)\s*\(', l)
    if m and not l.rstrip().endswith(';') and 'WINAPI' not in l.split('(')[0]:
        name = m.group(1)
        j = i
        while j < NL and '{' not in strip_str(lines[j]): j += 1
        if j < NL:
            depth = 0; k = j; done = False
            while k < NL:
                sl = strip_str(lines[k])
                depth += sl.count('{') - sl.count('}')
                if depth <= 0: done = True; break
                k += 1
            if done:
                defs.setdefault(name, (i, k))
                i = k + 1; continue
    i += 1

# ---------- 页面归属 ----------
ASSIGN = {
    # Process / Detail
    'CreateProcColumns':'FeProcPage.c','DetailSetText':'FeProcPage.c','DetailAddRow':'FeProcPage.c',
    'SetupDetailColumns':'FeProcPage.c','DoRefreshDetail':'FeProcPage.c','DoKillSelected':'FeProcPage.c',
    'DoRefreshProcs':'FeProcPage.c','DoProcessOp':'FeProcPage.c','DoProcessContextMenu':'FeProcPage.c',
    'DetailColumnQword':'FeProcPage.c','DetailColumnText':'FeProcPage.c',
    # Startup
    'SuSetText':'FeStartupPage.c','CreateSuColumns':'FeStartupPage.c','DoRefreshStartup':'FeStartupPage.c',
    'DoStartupOp':'FeStartupPage.c','DoStartupContextMenu':'FeStartupPage.c',
    # Services
    'SvSetText':'FeServicePage.c','CreateSvColumns':'FeServicePage.c','DoRefreshServices':'FeServicePage.c',
    'DoServiceFireeye':'FeServicePage.c','SvGetSelectedEntry':'FeServicePage.c','DoServiceOp':'FeServicePage.c',
    'DoServiceContextMenu':'FeServicePage.c',
    # Network
    'CreateNwColumns':'FeNetworkPage.c','NwAddRow':'FeNetworkPage.c','NwInsertNode':'FeNetworkPage.c',
    'NwFindNode':'FeNetworkPage.c','BuildNwTree':'FeNetworkPage.c','NwNodeName':'FeNetworkPage.c',
    'DoRefreshNetwork':'FeNetworkPage.c','NwRestoreTdi':'FeNetworkPage.c','NwSelectNode':'FeNetworkPage.c',
    # Registry
    'RgSetText':'FeRegistryPage.c','CreateRgColumns':'FeRegistryPage.c','DoRefreshRegistry':'FeRegistryPage.c',
    # Files
    'FlSetText':'FeFilePage.c','CreateFlColumns':'FeFilePage.c','DoRefreshFiles':'FeFilePage.c',
    # Other
    'OtAddRow':'FeOtherPage.c','DoRefreshOther':'FeOtherPage.c',
    # Examination
    'ExSetText':'FeExamPage.c','DoRefreshExamination':'FeExamPage.c','DoExportExamination':'FeExamPage.c',
    # Fireeye
    'FeSetText':'FeFireeyePage.c','DoFireeyeAnalyse':'FeFireeyePage.c','DoFireeyeRecords':'FeFireeyePage.c',
    # Setting
    'StSetText':'FeSettingPage.c','DoRefreshSetting':'FeSettingPage.c','DoApplyForbid':'FeSettingPage.c',
    # Trojan
    'TrSetText':'FeTrojanPage.c','DoTrojanScan':'FeTrojanPage.c','DoTrojanBackup':'FeTrojanPage.c',
    # Hooks
    'HkSetText':'FeHookPage.c','DoRefreshHooks':'FeHookPage.c','DoRestoreOverHooks':'FeHookPage.c',
    'DoRestoreCallbackTable':'FeHookPage.c',
    # Kernel
    'CreateKmColumns':'FeKernelPage.c','KmSetText':'FeKernelPage.c','DoRefreshKernel':'FeKernelPage.c',
    'DoCopyKmColumn':'FeKernelPage.c','KmSelectedDriverName':'FeKernelPage.c','DoDriverOp':'FeKernelPage.c',
    'DoModuleOp':'FeKernelPage.c','PromptProc':'FeKernelPage.c','DoPromptText':'FeKernelPage.c',
    'DoModuleSearch':'FeKernelPage.c','DoModuleContextMenu':'FeKernelPage.c',
    'DoLocateDriverInRegistry':'FeKernelPage.c','DoDriverContextMenu':'FeKernelPage.c',
}
STAY = {'FeInsertColumnA','CmdName','SetStatus','AddRow','SetSubItemText','FeIsSkipped',
        'FeShapeOf','SendOne','GetSelectedPid','DoConnect','DoScan','DoSend',
        'CreateListColumns','ShowPage','WndProc','WinMain','FeCliDispatch'}

# ---------- 静态变量解析（142-181 区） ----------
var_defs = []       # (line_idx, decl_text_without_static, [names], is_hwnd_block)
var_decl_text = {}
for i,l in enumerate(lines):
    m = re.match(r'^static\s+(.+?);(\s*/\*.*)?$', l)
    if m and i < 400 and '(' not in m.group(1):
        names = re.findall(r'(\w+)', m.group(1).split('=',1)[0] if '=' in m.group(1) else m.group(1))
        names = [n for n in names if n not in ('static','HWND','int','BOOL','char','LONG','WCHAR','ULONG','const')]
        if not names: continue
        var_defs.append((i, m.group(1), names))
        var_decl_text[i] = m.group(1)

def var_page(n):
    if n in ('g_Client',): return 'frontend.c'
    if n in ('g_hMainWnd','g_hMainTabs','g_hPageHint','g_MainTab','g_MainTabNames','g_hStatus'): return 'frontend.c'
    if n.startswith('g_hSu'): return 'FeStartupPage.c'
    if n.startswith('g_hSv'): return 'FeServicePage.c'
    if n.startswith('g_hNw') or n=='g_NwNode': return 'FeNetworkPage.c'
    if n.startswith('g_hRg') or n in ('g_RgTab','g_RgPath'): return 'FeRegistryPage.c'
    if n.startswith('g_hFl'): return 'FeFilePage.c'
    if n.startswith('g_hOt'): return 'FeOtherPage.c'
    if n.startswith('g_hEx') or n=='g_ExamLoaded': return 'FeExamPage.c'
    if n.startswith('g_hFe') or n=='g_FeHasJob': return 'FeFireeyePage.c'
    if n.startswith('g_hSt') or n=='g_StObjReady': return 'FeSettingPage.c'
    if n.startswith('g_hTr') or n=='g_TrLoaded': return 'FeTrojanPage.c'
    if n.startswith('g_hHk'): return 'FeHookPage.c'
    if n.startswith('g_hKm') or n in ('g_KmTab','g_KmOnlyLoaded'): return 'FeKernelPage.c'
    if n in ('g_PromptBuf','g_PromptOk'): return 'FeKernelPage.c'
    if n.startswith('g_hProc') or n.startswith('g_hTabs') or n.startswith('g_hDetail') or n=='g_DetailTab': return 'FeProcPage.c'
    if n in ('g_hList','g_hCmd','g_hSize'): return 'FeProcPage.c'
    return 'frontend.c'

# ---------- 计算跨模块引用（决定去 static） ----------
def refs_of(sym, exclude_ranges):
    out = False
    for m in re.finditer(r'\b'+re.escape(sym)+r'\b', src):
        ln = src[:m.start()].count('\n')
        if any(a <= ln <= b for a, b in exclude_ranges):
            continue
        out = True; break
    return out

moved_ranges = [(defs[n][0], defs[n][1]) for n in ASSIGN if n in defs]

# ---------- 生成各页面模块 ----------
page_files = {}
for fname in sorted(set(ASSIGN.values())):
    page_files[fname] = []

used_names = set()
for name, (a, b) in sorted(defs.items(), key=lambda kv: kv[1][0]):
    tgt = ASSIGN.get(name)
    if not tgt: continue
    page_files[tgt].append((a, b, name))

# 每个模块需要搬的静态变量行
var_move = {}
for li, dtxt, vnames in var_defs:
    for vn in vnames:
        pg = var_page(vn)
        if pg != 'frontend.c':
            var_move.setdefault(pg, []).append((li, vn))

# 生成文件内容
GEN = {}
for fname, funcs in page_files.items():
    body = []
    body.append('// ============================================================================')
    body.append('// %s — %s 页 UI（2026-10-28 由 frontend.c 机械拆分，函数体逐字保留）' % (fname, fname.replace('Fe','').replace('Page.c','')))
    body.append('// 注册表：ShowPage（frontend.c）通过 FePages.h 的声明调用本文件的 PageShow。')
    body.append('// ============================================================================')
    body.append('#include "XPCHunterUM.h"')
    body.append('#include "FePages.h"')
    body.append('')
    # 静态变量（去 static if 跨模块引用）
    moved_vars = var_move.get(fname, [])
    for li, vn in moved_vars:
        pass
    # 按行号顺序输出静态行（保留原注释），去 static
    seen_lines = set()
    for li, vn in moved_vars:
        if li in seen_lines: continue
        seen_lines.add(li)
        l = lines[li]
        mod = l.replace('static ', '', 1) if l.lstrip().startswith('static') else l
        # 跨模块引用检测：变量在 frontend.c 剩余部分或其它模块被引用
        cross = False
        for vn2 in re.findall(r'\b(g_\w+)\b', mod):
            if vn2.startswith('g_h') or vn2 in ('g_RgTab','g_RgPath','g_NwNode','g_ExamLoaded','g_FeHasJob','g_StObjReady','g_TrLoaded','g_KmTab','g_KmOnlyLoaded','g_PromptBuf','g_PromptOk','g_DetailTab'):
                for m2 in re.finditer(r'\b'+re.escape(vn2)+r'\b', src):
                    ln2 = src[:m2.start()].count('\n')
                    in_own = any(defs[n2][0] <= ln2 <= defs[n2][1] for n2 in ASSIGN if ASSIGN[n2]==fname and n2 in defs)
                    if not in_own:
                        cross = True; break
        if cross:
            mod = mod.replace('HWND ', 'HWND ', 1)
        body.append(mod.rstrip())
    body.append('')
    # 函数
    for a, b, name in funcs:
        # 前置注释块（函数头上方连续注释）
        cstart = a
        while cstart - 1 >= 0 and (lines[cstart-1].lstrip().startswith('/*') or
              lines[cstart-1].lstrip().startswith('*') or
              lines[cstart-1].lstrip().startswith('*/') or
              (lines[cstart-1].lstrip().startswith('//')) or
              (lines[cstart-1].strip()=='' and cstart-1 > 0 and (lines[cstart-2].lstrip().startswith('/*') or lines[cstart-2].lstrip().startswith('*')))):
            cstart -= 1
            if lines[cstart].strip()=='' and cstart > 0 and not (lines[cstart-1].lstrip().startswith('/*') or lines[cstart-1].lstrip().startswith('*')):
                break
        for x in range(max(cstart, 0), b + 1):
            body.append(lines[x])
        body.append('')
    GEN[fname] = '\n'.join(body) + '\n'

# 去静上下文已并入 FePages.h 生成：全部搬移函数与变量均 non-static
# （生成时把函数定义行的 'static ' 去掉）
for fname in GEN:
    GEN[fname] = re.sub(r'^static ', '', GEN[fname], flags=re.M)

# ---------- FePages.h ----------
hp = []
hp.append('// ============================================================================')
hp.append('// FePages.h — 页面模块统一注册表（2026-10-28 由 frontend.c 拆分产出）')
hp.append('//   每个页面模块导出：控件句柄（extern）+ Create*/Refresh*/Op* 函数。')
hp.append('//   ShowPage（frontend.c）按主 Tab 编号调用对应 Fe<X>PageShow。')
hp.append('// ============================================================================')
hp.append('#ifndef XPCH_FEPAGES_H')
hp.append('#define XPCH_FEPAGES_H')
hp.append('')
hp.append('#include "XPCHunterUM.h"')
hp.append('#include <commctrl.h>')
hp.append('')
# 页面注册表：页名 -> Show 函数
PAGES = [
    (0,  'Process',  'FeProcPage'),
    (1,  'Kernel',   'FeKernelPage'),
    (2,  'Ring0',    'FeHookPage'),
    (3,  'Ring3',    'FeHookPage'),
    (4,  'Network',  'FeNetworkPage'),
    (5,  'Registry', 'FeRegistryPage'),
    (6,  'Startup',  'FeStartupPage'),
    (7,  'Services', 'FeServicePage'),
    (8,  'File',     'FeFilePage'),
    (9,  'Exam',     'FeExamPage'),
    (10, 'Setting',  'FeSettingPage'),
    (11, 'Fireeye',  'FeFireeyePage'),
    (12, 'Trojan',   'FeTrojanPage'),
    (13, 'Other',    'FeOtherPage'),
]
hp.append('/* 页面注册表：主 Tab 编号 -> 显隐/按需刷新入口（各页模块实现） */')
hp.append('typedef void (*FE_PAGE_SHOW_FN)(HWND hWnd, int page);')
hp.append('')
for pid, nm, mod in PAGES:
    hp.append('void %sPageShow(HWND hWnd, int page);   /* 主 Tab %d (%s) */' % (mod, pid, nm))
hp.append('')
# 每页 extern：控件 + 函数
for fname, funcs in sorted(page_files.items()):
    hp.append('/* ---- %s ---- */' % fname)
    seen = set()
    for li, vn in var_move.get(fname, []):
        if li in seen: continue
        seen.add(li)
        # 用解析出的声明文本（去初始化器）构造，避免对原始行做正则替换的边界问题
        dtxt = var_decl_text.get(li, '')
        dtxt = re.sub(r'\s*=\s*[^;]*$', '', dtxt.strip()).strip()
        mod = 'extern ' + dtxt + ';'
        hp.append(mod)
    for a, b, name in funcs:
        j = a
        while j <= b and '{' not in lines[j]: j += 1
        sig = ' '.join(lines[a:j+1])
        sig = sig.split('{')[0]
        sig = re.sub(r'\s+', ' ', sig.replace('static ', '', 1)).strip()
        if not sig.endswith(';'): sig += ';'
        hp.append(sig)
    hp.append('')
hp.append('#endif /* XPCH_FEPAGES_H */')
open('../XPCHunterUM/inc/FePages.h', 'w', encoding='utf-8', newline='\n').write('\n'.join(hp))
print('FePages.h: %d 行' % len(hp))

# ---------- 写页面文件 ----------
for fname, content in GEN.items():
    open('../XPCHunterUM/src/' + fname, 'w', encoding='utf-8', newline='\n').write(content)
    print('%s: %d 行' % (fname, content.count('\n')))

# ---------- 改写 frontend.c ----------
drop = set()
for name in ASSIGN:
    if name in defs:
        a, b = defs[name]
        for x in range(a, b + 1): drop.add(x)
# 静态变量行：仅当该行全部变量都属于搬移页
for li, dtxt, vnames in var_defs:
    if all(var_page(v) != 'frontend.c' for v in vnames):
        drop.add(li)
out_lines = [l for i, l in enumerate(lines) if i not in drop]
out = '\n'.join(out_lines)
# 去静态：留在 frontend.c 的助手被页面模块引用
for fn in ('FeInsertColumnA','CmdName','SetStatus','AddRow','SetSubItemText','GetSelectedPid'):
    out = re.sub(r'^static\s+((?:const\s+)?[\w\*]+\s+'+fn+r'\()', r'\1', out, flags=re.M)
# include FePages.h
m = re.search(r'^#include "CliMain\.h"$', out, re.M)
if m:
    out = out[:m.end()] + '\n#include "FePages.h"' + out[m.end():]
open(SRC, 'w', encoding='utf-8', newline='\n').write(out)
print('frontend.c: %d 行' % out.count('\n'))
