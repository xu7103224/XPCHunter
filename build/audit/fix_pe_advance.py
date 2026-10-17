"""为「无界 PE 走查循环」补上读指针推进语句。

背景（实机取证 2026-10-17）：
  `ReadPESectionEntry` 只把读指针读进局部 r9 并 ++，**不回写** 上下文 +0x08；
  成功路径把描述符 +0xF0 置 1。所以「边读边扫」的循环必须由调用方
  `ctx[+0x08] += entry[+0xF0]`，否则下一次调用仍解码同一处 → 死循环
  （已在 HookSyscallNtQueryInformationProcess 上实机命中并取证）。

只处理「读调用出现在循环条件里」的干净形态：
      while (!ReadPESectionEntry(&Ctx, Entry)) { ... }
在循环体首行插入推进语句。按循环起始行去重，倒序插入。保留原行尾风格。
"""
import os
import re

SRC = 'XPCHunterDrv/src'
ADV = re.compile(r'\+\s*0x08\s*\)\s*\+=')
LOOP = re.compile(r'\b(while|for)\s*\(')
CAST = re.compile(r'^\(\s*[A-Za-z_]\w*\s*\*+\s*\)')
MARK = '【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08'


def find_call(text, fname):
    """返回 [(args, end_idx)]，args 为顶层逗号切分的实参。"""
    out = []
    for m in re.finditer(re.escape(fname) + r'\s*\(', text):
        i = m.end() - 1
        depth = 0
        cur = ''
        args = []
        for ch in text[i:]:
            if ch == '(':
                depth += 1
                if depth == 1:
                    continue
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    args.append(cur)
                    break
            elif ch == ',' and depth == 1:
                args.append(cur)
                cur = ''
                continue
            cur += ch
        out.append(([a.strip() for a in args], i))
    return out


def loop_body(lines, loop_start):
    depth = 0
    started = False
    body = []
    for k in range(loop_start, min(len(lines), loop_start + 200)):
        body.append(lines[k])
        depth += lines[k].count('{') - lines[k].count('}')
        if '{' in lines[k]:
            started = True
        if started and depth <= 0:
            break
    return body


def strip_cast(expr):
    while True:
        m = CAST.match(expr)
        if not m:
            return expr
        expr = expr[m.end():].strip()


def main():
    changed, skipped = [], []
    for root, _, fs in os.walk(SRC):
        for f in sorted(fs):
            if not f.endswith('.c'):
                continue
            p = os.path.join(root, f)
            raw = open(p, encoding='utf-8', errors='replace', newline='').read()
            crlf = '\r\n' in raw
            lines = raw.replace('\r\n', '\n').split('\n')
            done_loops = set()
            edits = []
            for i, line in enumerate(lines):
                if 'ReadPESectionEntry' not in line:
                    continue
                loop_start = None
                for j in range(i, -1, -1):
                    if LOOP.search(lines[j]):
                        loop_start = j
                        break
                if loop_start is None or loop_start in done_loops:
                    continue
                brace = None
                for k in range(loop_start, min(len(lines), loop_start + 8)):
                    if '{' in lines[k]:
                        brace = k
                        break
                if brace is None:
                    continue
                header = '\n'.join(lines[loop_start:brace + 1])
                if 'ReadPESectionEntry' not in header:
                    done_loops.add(loop_start)
                    skipped.append((p, loop_start + 1, lines[loop_start].strip()[:70]))
                    continue
                calls = find_call(header, 'ReadPESectionEntry')
                if not calls or len(calls[0][0]) < 2:
                    done_loops.add(loop_start)
                    skipped.append((p, loop_start + 1, 'arg-parse-fail'))
                    continue
                if ADV.search('\n'.join(loop_body(lines, loop_start))):
                    done_loops.add(loop_start)
                    continue
                ctx = strip_cast(calls[0][0][0])
                ent = strip_cast(calls[0][0][1])
                ind = '    '
                for k in range(brace + 1, min(len(lines), brace + 4)):
                    if lines[k].strip():
                        ind = re.match(r'\s*', lines[k]).group(0)
                        break
                adv = (ind + '*(ULONG64 *)((PUCHAR)' + ctx + ' + 0x08) += '
                       '*(unsigned int *)((PUCHAR)' + ent + ' + 0xF0);   /* ' + MARK + ' */')
                edits.append((brace + 1, adv))
                changed.append((p, loop_start + 1, ctx, ent))
                done_loops.add(loop_start)
            if edits:
                for pos, txt in sorted(edits, reverse=True):
                    lines.insert(pos, txt)
                out = '\n'.join(lines)
                if crlf:
                    out = out.replace('\n', '\r\n')
                open(p, 'w', encoding='utf-8', newline='').write(out)

    print('自动修复循环数:', len(changed))
    for p, ls, ctx, ent in changed:
        print('   %s:%d  ctx=%s entry=%s' % (p, ls, ctx, ent))
    print('需人工判断:', len(skipped))
    for p, ls, t in skipped:
        print('   %s:%d  %s' % (p, ls, t))


if __name__ == '__main__':
    main()
