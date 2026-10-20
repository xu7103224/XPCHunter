import os, sys, struct
HERE = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\build\audit'
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..', '..'))
import capstone

EXE = r'E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\samples\PCHunter_2024.09.02\PCHunter64.exe'
IB = 0x140000000
d = open(EXE, 'rb').read()

pe = struct.unpack_from('<I', d, 0x3c)[0]
nsec = struct.unpack_from('<H', d, pe + 6)[0]
opt = struct.unpack_from('<H', d, pe + 20)[0]
sec = pe + 24 + opt
secs = []
for i in range(nsec):
    o = sec + i * 40
    nm = d[o:o + 8].rstrip(b'\x00').decode('latin1')
    vsz, va, rsz, ra = struct.unpack_from('<IIII', d, o + 8)
    secs.append((nm, va, vsz, ra, rsz))


def rva2off(rva):
    for nm, va, vsz, ra, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return ra + (rva - va)
    return None


md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)


def dump(start, end, label):
    print('=' * 70)
    print(label, hex(start), '-', hex(end))
    print('=' * 70)
    off = rva2off(start - IB)
    code = d[off:off + (end - start)]
    for ins in md.disasm(code, start):
        print('  %X  %-8s %s' % (ins.address, ins.mnemonic, ins.op_str))


# sub_14004DD40 的关键片段：密钥派生 + MD5 + 加密 + DeviceIoControl
dump(0x14004DDCF, 0x14004DE50, 'key derivation')
dump(0x14004DE4D, 0x14004DF30, 'md5 + checksum')
dump(0x14004DF21, 0x14004DF90, 'encrypt + ioctl')

print()
print('=' * 70)
print('Destination 全局缓冲（0x14080C0F0）初值')
print('=' * 70)
off = rva2off(0x14080C0F0 - IB)
print('  bytes:', d[off:off + 32].hex())
print('  byte_14080C0F8 (key seed):', d[rva2off(0x14080C0F8 - IB):rva2off(0x14080C0F8 - IB) + 8].hex())