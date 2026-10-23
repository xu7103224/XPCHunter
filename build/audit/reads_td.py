import struct

# 原版驱动里 S_td 位于 RVA 0x971A0（来自我方 map，布局同源）
# 但更可靠的做法：直接扫原版 .rdata 找 "tdi" / "td" 的 UTF-16 串
path = r"E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\samples\PCHunter_2024.09.02\View++_Driver64.sys"
d = open(path, "rb").read()

pe = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, pe + 6)[0]
optsz = struct.unpack_from("<H", d, pe + 20)[0]
opt = pe + 24
imgbase = struct.unpack_from("<Q", d, opt + 24)[0]
off = opt + optsz
secs = []
for i in range(nsec):
    s = d[off + i * 40: off + (i + 1) * 40]
    name = s[:8].rstrip(b"\0").decode(errors="replace")
    vs, va, rs, ro = struct.unpack_from("<IIII", s, 8)
    secs.append((name, va, vs, ro, rs))

def va2file(va):
    rva = va - imgbase
    for name, sva, vs, ro, rs in secs:
        if sva <= rva < sva + max(vs, rs):
            return ro + (rva - sva)
    return None

for label, va in [("S_td", 0x1400971A0)]:
    f = va2file(va)
    if f is None:
        print(label, "RVA not mapped")
        continue
    raw = d[f:f + 32]
    try:
        txt = raw.decode("utf-16-le", "replace")
    except Exception:
        txt = repr(raw)
    print("%s @VA 0x%X file 0x%X bytes=%s" % (label, va, f, raw.hex()))
    print("   utf16:", repr(txt.split("\0")[0]))