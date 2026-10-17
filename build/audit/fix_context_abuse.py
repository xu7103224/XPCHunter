"""修复「PE 解码上下文」相关的两类系统性缺陷（2026-10-17 实机取证后）。

类 A：上下文局部被声明成 8 字节标量（`__int64 PeContext;`），而
      `InitPESectionReadEntryContext(..., &PeContext)` 会写 0x48 字节
      → 覆盖相邻栈槽 → 实机 0x7E。
      修法：改为 `PE_DECODE_CONTEXT PeContext;`，并把 `PeContext = 0;` 换成 memset。

类 B：把「累计长度」直接写在上下文的读指针槽里
      （`PeContext.ReadPtr = EntryBuffer[..]; PeContext.ReadPtr += SectionSize;`）
      → 64 位内核读指针被 32 位值覆盖 → 下一次 ReadPESectionEntry 读野地址 → 0x7E。
      修法：累计量改用独立局部 `CumulativeSize`，并补上 64 位读指针推进。
"""
import os
import re

FILES = ['XPCHunterDrv/src/features/PeParse.c',
         'XPCHunterDrv/src/kernel/ContextMgmt.c']

report = []


def fix(path):
    raw = open(path, encoding='utf-8', errors='replace', newline='').read()
    crlf = '\r\n' in raw
    text = raw.replace('\r\n', '\n')
    before = text

    # ---- 类 A：上下文声明过小 ----
    text, n1 = re.subn(
        r'\n(\s*)__int64 PeContext;\s*(?://[^\n]*\n\s*//[^\n]*\n\s*//[^\n]*)?',
        lambda m: '\n%sPE_DECODE_CONTEXT PeContext;' % m.group(1),
        text)

    # ---- 类 A：PeContext = 0;  ->  memset ----
    text, n2 = re.subn(r'(\n\s*)PeContext = 0;', r'\1memset(&PeContext, 0, sizeof(PeContext));', text)

    # ---- 类 B：累计量别名到读指针 ----
    text, n3 = re.subn(r'PeContext\.ReadPtr = (EntryBuffer\[[^\]]+\]);', r'CumulativeSize = \1;', text)
    text, n4 = re.subn(r'PeContext\.ReadPtr \+= SectionSize;', 'CumulativeSize += SectionSize;', text)
    text, n5 = re.subn(r'EntryBuffer\[([^\]]+)\] = \(ULONG\)PeContext\.ReadPtr;',
                       r'EntryBuffer[\1] = (ULONG)CumulativeSize;', text)
    text, n6 = re.subn(r'\(int\)PeContext\.ReadPtr', '(int)CumulativeSize', text)

    # ---- 类 B：在累计量初始化之后补上 64 位读指针推进 ----
    adv = ('CumulativeSize = EntryBuffer[0x40 >> 2];')
    text, n7 = re.subn(
        r'(\n(\s*)CumulativeSize = EntryBuffer\[0x40 >> 2\];)',
        lambda m: m.group(1) + '\n' + m.group(2) +
                  'PeContext.ReadPtr += *(unsigned int *)((PUCHAR)EntryBuffer + 0xF0);'
                  '   /* 【修正 2026-10-17】推进读指针（64 位）：原实现把累计量写进读指针槽 */',
        text)

    # ---- 类 B：为使用到 CumulativeSize 的函数补声明 ----
    if 'CumulativeSize' in text and 'CumulativeSize;' not in text:
        text, n8 = re.subn(r'(\n\s*)PE_DECODE_CONTEXT PeContext;',
                           r'\1PE_DECODE_CONTEXT PeContext;\n\1__int64 CumulativeSize = 0;',
                           text, count=1)
    else:
        n8 = 0

    if text != before:
        out = text.replace('\n', '\r\n') if crlf else text
        open(path, 'w', encoding='utf-8', newline='').write(out)
    report.append((path, n1, n2, n3, n4, n5, n6, n7, n8))


for f in FILES:
    if os.path.exists(f):
        fix(f)

for r in report:
    print('%-48s 声明=%d memset=%d 累加赋值=%d 累加+=%d 写回=%d (int)cast=%d 推进=%d 补声明=%d' % r)
