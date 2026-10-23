path = r"E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\samples\PCHunter_2024.09.02\View++_Driver64.sys"
d = open(path, "rb").read()

# 在 .rdata/.data 里扫 UTF-16LE 的短串，找 tdi / td / tdx 相关
cands = [b"tdi.sys", b"td.sys", "tdi".encode("utf-16-le"), "td".encode("utf-16-le"),
         "tdi.sys".encode("utf-16-le"), "td.sys".encode("utf-16-le"),
         "TDI".encode("utf-16-le")]

print("=== UTF-16LE 候选 ===")
for c in cands:
    idx = 0
    hits = []
    while True:
        i = d.find(c, idx)
        if i < 0:
            break
        hits.append(i)
        idx = i + 1
        if len(hits) > 6:
            break
    print("%-24r -> %s" % (c, [hex(h) for h in hits]))

print()
print("=== 前 5 个 UTF-16 短串（含 td）上下文 ===")
target = "td".encode("utf-16-le")
i = 0
shown = 0
while shown < 8:
    i = d.find(target, i + 1)
    if i < 0:
        break
    # 必须 2 字节对齐
    if i % 2:
        continue
    seg = d[i:i + 24]
    try:
        t = seg.decode("utf-16-le", "replace").split("\0")[0]
    except Exception:
        t = "?"
    if t.isprintable() and len(t) <= 10:
        print("0x%X  %r" % (i, t))
        shown += 1