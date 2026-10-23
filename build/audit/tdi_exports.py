import struct

p = r"E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\build\audit\tdi_sys.bin"
d = open(p, "rb").read()
print("size", len(d))

# DOS
e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
print("e_lfanew", hex(e_lfanew), "sig", d[e_lfanew:e_lfanew + 4])

nt = e_lfanew
machine, nsec = struct.unpack_from("<HH", d, nt + 4)
optsz = struct.unpack_from("<H", d, nt + 20)[0]
opt = nt + 24
magic = struct.unpack_from("<H", d, opt)[0]
print("machine %04X nsec %d optsz %d magic %04X" % (machine, nsec, optsz, magic))

# export dir is DataDirectory[0]; offset in optional header differs PE32/PE32+
if magic == 0x20B:
    dd_off = opt + 112
else:
    dd_off = opt + 96
exp_rva, exp_size = struct.unpack_from("<II", d, dd_off)
print("ExportDir RVA 0x%X size 0x%X" % (exp_rva, exp_size))

if exp_rva == 0:
    print("NO EXPORT DIRECTORY")
    raise SystemExit

# section table
secs = []
so = opt + optsz
for i in range(nsec):
    s = d[so + i * 40: so + (i + 1) * 40]
    name = s[:8].rstrip(b"\0").decode(errors="replace")
    vs, va, rs, ro = struct.unpack_from("<IIII", s, 8)
    secs.append((name, va, vs, ro, rs))
    print("  %-10s va=0x%X vs=0x%X raw=0x%X rs=0x%X" % (name, va, vs, ro, rs))


def rva2file(rva):
    for name, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None


f = rva2file(exp_rva)
if f is None:
    print("export dir not mapped")
    raise SystemExit

# IMAGE_EXPORT_DIRECTORY
(nfuncs, nnames, funcs_rva, names_rva, ords_rva) = struct.unpack_from("<IIIII", d, f + 20)
print()
print("NumberOfFunctions=%d NumberOfNames=%d" % (nfuncs, nnames))

names_f = rva2file(names_rva)
ords_f = rva2file(ords_rva)
funcs_f = rva2file(funcs_rva)
print()
print("=== export names ===")
found = []
for i in range(nnames):
    nrva = struct.unpack_from("<I", d, names_f + i * 4)[0]
    nf = rva2file(nrva)
    if nf is None:
        continue
    end = d.index(b"\0", nf)
    nm = d[nf:end].decode(errors="replace")
    ordv = struct.unpack_from("<H", d, ords_f + i * 2)[0]
    frva = struct.unpack_from("<I", d, funcs_f + ordv * 4)[0]
    found.append((nm, ordv, frva))
    print("  %-32s ord=%-3d rva=0x%X" % (nm, ordv, frva))

print()
for target in ["DllInitialize", "TdiInitialize"]:
    hit = [x for x in found if x[0] == target]
    print("%-16s exact=%s" % (target, "YES 0x%X" % hit[0][2] if hit else "NO"))
    ci = [x for x in found if x[0].lower() == target.lower()]
    if ci and not hit:
        print("    case-insensitive match:", ci[0][0])