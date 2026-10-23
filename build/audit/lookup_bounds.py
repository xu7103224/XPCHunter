import struct

p = r"E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\build\audit\tdi_sys.bin"
d = open(p, "rb").read()
SrcSize = len(d)

e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
nt = e_lfanew
nsec = struct.unpack_from("<H", d, nt + 6)[0]
optsz = struct.unpack_from("<H", d, nt + 20)[0]
opt = nt + 24
magic = struct.unpack_from("<H", d, opt)[0]

if magic == 0x20B:
    dd_off = opt + 112
    SizeOfImage = struct.unpack_from("<I", d, opt + 56)[0]
    SizeOfHeaders = struct.unpack_from("<I", d, opt + 60)[0]
    SectionAlignment = struct.unpack_from("<I", d, opt + 32)[0]
    FileAlignment = struct.unpack_from("<I", d, opt + 36)[0]
else:
    dd_off = opt + 96
    SizeOfImage = struct.unpack_from("<I", d, opt + 56)[0]
    SizeOfHeaders = struct.unpack_from("<I", d, opt + 60)[0]
    SectionAlignment = struct.unpack_from("<I", d, opt + 32)[0]
    FileAlignment = struct.unpack_from("<I", d, opt + 36)[0]

exp_rva, exp_size = struct.unpack_from("<II", d, dd_off)

secs = []
so = opt + optsz
for i in range(nsec):
    s = d[so + i * 40: so + (i + 1) * 40]
    vs, va, rs, ro = struct.unpack_from("<IIII", s, 8)
    secs.append((va, vs, ro, rs))


def rva2file(rva):
    for va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None


VaMask = SectionAlignment - 1
RawMask = FileAlignment - 1
ImageLimit = ~VaMask & (VaMask + SizeOfImage)

print("=== ReadNtFileToBuffer 结果推断 ===")
print("SrcSize        = 0x%X (%d)" % (SrcSize, SrcSize))
print("SizeOfImage    = 0x%X" % SizeOfImage)
print("SectionAlignment=0x%X FileAlignment=0x%X" % (SectionAlignment, FileAlignment))
print("ImageLimit     = 0x%X   <- 作为 PeSize 传给 LookupExportByName" % (ImageLimit,))
print("SizeOfHeaders  = 0x%X" % SizeOfHeaders)

HeaderEnd = e_lfanew + 40 * nsec + optsz + 24
print("HeaderEnd      = 0x%X (需 <= SizeOfHeaders: %s)" % (HeaderEnd, HeaderEnd <= SizeOfHeaders))

f = rva2file(exp_rva)
print()
print("=== LookupExportByName 边界验算（PeSize=ImageLimit）===")
PeSize = ImageLimit
print("Check A: ExportDirRva(0x%X) >= PeSize(0x%X) ? %s" % (exp_rva, PeSize, exp_rva >= PeSize))
print("Check B: ExportDirRva+40 >= PeSize ? %s" % (exp_rva + 40 >= PeSize))
EndRva_exp = exp_rva + exp_size
print("Check C: ExportDirSize(0x%X) >= PeSize ? %s" % (exp_size, exp_size >= PeSize))
print("Check D: EndRva(0x%X) >= PeSize ? %s" % (EndRva_exp, EndRva_exp >= PeSize))

nfuncs, nnames, funcs_rva, names_rva, ords_rva = struct.unpack_from("<IIIII", d, f + 20)
print()
print("NumberOfFunctions = %d" % nfuncs)
print("NumberOfNames     = %d" % nnames)
print("AddressOfFunctions= 0x%X" % funcs_rva)
print("AddressOfNames    = 0x%X" % names_rva)
print("AddressOfNameOrdinals=0x%X" % ords_rva)
print()
print("Check E: AddressOfFunctions >= ExportDirRva ? %s" % (funcs_rva >= exp_rva))
print("Check F: AddressOfNames     >= ExportDirRva ? %s" % (names_rva >= exp_rva))
print("Check G: AddressOfNameOrdinals >= ExportDirRva ? %s" % (ords_rva >= exp_rva))
print()
print("--- 我方代码里的三个上界检查（注意乘数）---")
c1 = 4 * nfuncs + funcs_rva
c2 = 2 * nfuncs + names_rva
c3 = 4 * nnames + ords_rva
print("Check H: 4*nFunc + FuncTable  = 0x%X > EndRva(0x%X) ? %s" % (c1, EndRva_exp, c1 > EndRva_exp))
print("Check I: 2*nFunc + NameTable  = 0x%X > EndRva(0x%X) ? %s   <-- 乘数应为 4*nNames" % (c2, EndRva_exp, c2 > EndRva_exp))
print("Check J: 4*nNames + OrdTable  = 0x%X > EndRva(0x%X) ? %s   <-- 乘数应为 2*nNames" % (c3, EndRva_exp, c3 > EndRva_exp))
print()
print("若按正确乘数：")
c2b = 4 * nnames + names_rva
c3b = 2 * nnames + ords_rva
print("  4*nNames + NameTable  = 0x%X > 0x%X ? %s" % (c2b, EndRva_exp, c2b > EndRva_exp))
print("  2*nNames + OrdTable   = 0x%X > 0x%X ? %s" % (c3b, EndRva_exp, c3b > EndRva_exp))