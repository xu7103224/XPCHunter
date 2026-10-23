"""模拟我方 LookupExportByName，在 tdi.sys 上分别查两个名字，定位差异。"""
import struct

p = r"E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\build\audit\tdi_sys.bin"
d = open(p, "rb").read()
SrcSize = len(d)

e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, e_lfanew + 6)[0]
optsz = struct.unpack_from("<H", d, e_lfanew + 20)[0]
opt = e_lfanew + 24
SizeOfImage = struct.unpack_from("<I", d, opt + 56)[0]
SectionAlignment = struct.unpack_from("<I", d, opt + 32)[0]
FileAlignment = struct.unpack_from("<I", d, opt + 36)[0]
exp_rva, exp_size = struct.unpack_from("<II", d, opt + 112)

secs = []
so = opt + optsz
for i in range(nsec):
    s = d[so + i * 40: so + (i + 1) * 40]
    vs, va, rs, ro = struct.unpack_from("<IIII", s, 8)
    secs.append((va, vs, ro, rs))

VaMask = SectionAlignment - 1
ImageLimit = ~VaMask & (VaMask + SizeOfImage)


def rva2file(rva):
    for va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None


# 展开镜像（模拟 ReadNtFileToBuffer）：按 VirtualAddress 摆放
img = bytearray(ImageLimit)
SizeOfHeaders = struct.unpack_from("<I", d, opt + 60)[0]
img[:min(SizeOfHeaders, SrcSize)] = d[:min(SizeOfHeaders, SrcSize)]
for i in range(nsec):
    s = d[so + i * 40: so + (i + 1) * 40]
    vs, va, rs, ro = struct.unpack_from("<IIII", s, 8)
    copy = min(vs, rs)
    img[va:va + copy] = d[ro:ro + copy]

PeBase = bytes(img)
PeSize = ImageLimit

# 复刻我方 LookupExportByName 的检查顺序
def lookup(name_bytes):
    log = []
    if PeSize < 64:
        return None, log + ["SizeTooSmall"]
    nt = struct.unpack_from("<I", PeBase, 0x3C)[0]
    if nt + 24 > PeSize:
        return None, log + ["NTHeaderOOB"]
    ExportDirRva, ExportDirSize = struct.unpack_from("<II", PeBase, nt + 24 + 112)
    EndRva = ExportDirRva + ExportDirSize
    log.append("ExportDirRva=0x%X Size=0x%X EndRva=0x%X" % (ExportDirRva, ExportDirSize, EndRva))
    if ExportDirRva >= PeSize or ExportDirRva + 40 >= PeSize or ExportDirSize >= PeSize or EndRva >= PeSize:
        return None, log + ["GateFailed"]
    ef = ExportDirRva
    nfuncs, nnames, funcs_rva, names_rva, ords_rva = struct.unpack_from("<IIIII", PeBase, ef + 20)
    log.append("nfunc=%d nnames=%d funcs=0x%X names=0x%X ords=0x%X" % (nfuncs, nnames, funcs_rva, names_rva, ords_rva))
    if funcs_rva < ExportDirRva or names_rva < ExportDirRva or ords_rva < ExportDirRva:
        return None, log + ["TableRvaBelowExportDir"]
    if (4 * nfuncs + funcs_rva > EndRva or
            2 * nfuncs + names_rva > EndRva or
            4 * nnames + ords_rva > EndRva):
        return None, log + ["TableOOB"]
    for i in range(nnames):
        nrva = struct.unpack_from("<I", PeBase, names_rva + i * 4)[0]
        if ExportDirRva <= nrva < EndRva:
            end = PeBase.index(b"\0", nrva)
            nm = PeBase[nrva:end]
            if nm == name_bytes:
                ordv = struct.unpack_from("<H", PeBase, ords_rva + i * 2)[0]
                frva = struct.unpack_from("<I", PeBase, funcs_rva + ordv * 4)[0]
                log.append("FOUND %r ord=%d rva=0x%X" % (nm.decode(), ordv, frva))
                return frva, log
    return None, log + ["NotFound"]


for nm in [b"DllInitialize", b"TdiDeregisterPnPHandlers"]:
    print("=" * 20, nm.decode())
    rva, log = lookup(nm)
    for l in log:
        print("   ", l)
    print("    ->", ("0x%X" % rva) if rva is not None else "None")
    print()