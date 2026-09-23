# 按"函数作用域"重命名局部变量（避免同名变量在不同函数里角色不同而误改）
# 用法：在下面的 RENAMES 列表里填 (文件, 函数名, 旧名, 新名)，然后运行本脚本。
# 特性：
#   - 只在该函数的花括号范围内替换，使用词边界匹配（不会碰注释外的相似名）
#   - 替换前检查：① 旧名必须出现在该函数内；② 新名不得已被该函数内的其它声明占用
#   - 打印每条的替换次数，便于核对（不打印就说明静默失败）
import os
import re
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "..", "..", "XPCHunterDrv", "src"))

FUNC_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_ \t\*]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(')

RENAMES = [
    # ---- 上下文类：统一命名为 DecodeContext（0x48 字节解码上下文）----
    ("DriverEntry.c",            "InitEprocessOffsetsWin81",           "PeSectionReadContext", "DecodeContext"),
    ("services/SyscallTable.c",  "FindKernelPESectionByType",          "SectionChar",          "DecodeContext"),
    ("services/SyscallTable.c",  "ParseNtSectionsForShadowSsdt",       "SectionContext",       "DecodeContext"),
    ("kernel/PeSectionParse.c",  "ScanProcessPESections",              "SectionContext",       "DecodeContext"),
    ("kernel/PeSectionParse.c",  "ParseNtSectionsForProcessMemory",    "SectionContext",       "DecodeContext"),
    ("kernel/PeSectionParse.c",  "ParseNtSectionsForModuleBase",       "SectionContext",       "DecodeContext"),
    ("kernel/PeSectionParse.c",  "ParseNtSectionsForRelocBase",        "SectionContext",       "DecodeContext"),
    ("kernel/PeSectionParse.c",  "ParseProcessMemSections",            "SectionContext",       "DecodeContext"),
    ("kernel/PeSectionParse.c",  "FindKernelDataSectionOffsetEx",      "SectionContext",       "DecodeContext"),
    ("kernel/PeSectionParse.c",  "FindKernelDataSectionOffsetV2",      "SectionContext",       "DecodeContext"),
    ("kernel/PeSectionParse.c",  "FindKernelDataSectionOffsetV3",      "SectionContext",       "DecodeContext"),
    ("kernel/PeSectionParse.c",  "FindKernelDataSectionOffsetWin8",    "SectionContext",       "DecodeContext"),
    ("services/SSDT.c",          "ScanPESectionPatterns",              "CumulativeSize",       "DecodeContext"),
    ("services/SsdtHook.c",      "FindNdisExportsBySectionScanV2",     "SectionType3",         "DecodeContext"),
    ("services/SsdtHook.c",      "FindNdisExportsBySectionScanV2",     "ReadCtx2",             "DecodeContext2"),
    ("services/SsdtHook.c",      "ScanTextSectionPattern",             "FieldValue",           "DecodeContext"),
    ("services/SsdtHook.c",      "ScanDataSectionPattern",             "FieldValue",           "DecodeContext"),
    ("services/SsdtHook.c",      "ScanPageSectionPattern",             "FieldValue",           "DecodeContext"),
    ("services/SsdtHook.c",      "ParseKernelDataSectionRelocs",       "CumulativeSize",       "DecodeContext"),
    ("services/SsdtHook.c",      "ParseNtHeadersForSsdtTargets2",      "PESectionContext",     "DecodeContext"),
    ("services/SsdtHook.c",      "ParseNtHeadersForSsdtTargets",       "ReadCtx",              "DecodeContext"),
    ("services/SsdtHook.c",      "ParseNtHeadersForSsdtTargets",       "ReadCtx2",             "DecodeContext2"),
    ("services/SsdtHook.c",      "ScanInitSectionPattern",             "ReadCtx2",             "DecodeContext2"),
    ("services/SsdtHook.c",      "FindNdisExportsBySectionScan",       "v18b",                 "DecodeContext"),
    # ---- 描述符类：ReadContext 实为描述符（0x120 字节），按角色命名 ----
    # 这些函数里 SectionEntry 已被一个 int 计数器占用，故描述符改名为 SectionInfo
    ("services/SsdtHook.c",      "FindNdisExportsBySectionScanV2",     "ReadContext",          "SectionInfo"),
    ("services/SsdtHook.c",      "ScanTextSectionPattern",             "ReadContext",          "SectionInfo"),
    ("services/SsdtHook.c",      "ScanDataSectionPattern",             "ReadContext",          "SectionInfo"),
    ("services/SsdtHook.c",      "ScanPageSectionPattern",             "ReadContext",          "SectionInfo"),
    # ---- int SectionEntry 实为"累计的 RVA 偏移"，与描述符同名易混，按用途改名 ----
    ("services/SsdtHook.c",      "FindNdisExportsBySectionScanV2",     "SectionEntry",         "RvaOffset"),
    ("services/SsdtHook.c",      "ScanTextSectionPattern",             "SectionEntry",         "RvaOffset"),
    ("services/SsdtHook.c",      "ScanDataSectionPattern",             "SectionEntry",         "RvaOffset"),
    ("services/SsdtHook.c",      "ScanPageSectionPattern",             "SectionEntry",         "RvaOffset"),
    # ---- 上下文类：SectionContext（死写已删、类型已改）统一为 DecodeContext ----
    ("services/SyscallTable.c",  "ParseNtSectionsForShadowSsdt",       "SectionContext",       "DecodeContext"),
    ("kernel/PeSectionParse.c",  "ScanProcessPESections",              "SectionContext",       "DecodeContext"),
    ("kernel/PeSectionParse.c",  "ParseNtSectionsForProcessMemory",    "SectionContext",       "DecodeContext"),
    ("kernel/PeSectionParse.c",  "ParseNtSectionsForModuleBase",       "SectionContext",       "DecodeContext"),
    ("kernel/PeSectionParse.c",  "ParseNtSectionsForRelocBase",        "SectionContext",       "DecodeContext"),
    ("kernel/PeSectionParse.c",  "ParseProcessMemSections",            "SectionContext",       "DecodeContext"),
    ("kernel/PeSectionParse.c",  "FindKernelDataSectionOffsetEx",      "SectionContext",       "DecodeContext"),
    ("kernel/PeSectionParse.c",  "FindKernelDataSectionOffsetV2",      "SectionContext",       "DecodeContext"),
    ("kernel/PeSectionParse.c",  "FindKernelDataSectionOffsetV3",      "SectionContext",       "DecodeContext"),
    ("kernel/PeSectionParse.c",  "FindKernelDataSectionOffsetWin8",    "SectionContext",       "DecodeContext"),
]


def func_span(lines, fname):
    """返回 (start, end) 行号（0 基，闭区间）；找不到返回 None"""
    depth = 0
    cur = None
    for i, l in enumerate(lines):
        if depth <= 0:
            m = FUNC_RE.match(l)
            if m and not l.rstrip().endswith(';'):
                cur = (m.group(1), i)
        depth += l.count('{') - l.count('}')
        if cur and cur[1] != i and depth <= 0 and '{' in ''.join(lines[cur[1]:i + 1]):
            if cur[0] == fname:
                return (cur[1], i)
            cur = None
    return None


changed_files = set()
for rel, fname, old, new in RENAMES:
    p = os.path.join(ROOT, rel.replace('/', os.sep))
    lines = open(p, encoding='utf-8', errors='replace').read().splitlines(True)
    span = func_span(lines, fname)
    if span is None:
        print("  ✗ %-28s %-32s 未找到函数" % (rel, fname))
        continue
    s, e = span
    body = ''.join(lines[s:e + 1])
    pat = re.compile(r'\b' + re.escape(old) + r'\b')
    cnt = len(pat.findall(body))
    if cnt == 0:
        print("  · %-28s %-32s %s 不在该函数内（跳过）" % (rel, fname, old))
        continue
    # 新名冲突检查（该函数内是否已有同名声明）
    if re.search(r'\b' + re.escape(new) + r'\b', body):
        print("  ✗ %-28s %-32s 新名 %s 已在该函数内存在，跳过" % (rel, fname, new))
        continue
    newbody = pat.sub(new, body)
    lines[s:e + 1] = [newbody]
    open(p, 'w', encoding='utf-8').write(''.join(lines))
    changed_files.add(rel)
    print("  ✓ %-28s %-32s %-22s -> %-18s %d 处" % (rel, fname, old, new, cnt))

print("\n涉及文件：", ", ".join(sorted(changed_files)) if changed_files else "（无）")