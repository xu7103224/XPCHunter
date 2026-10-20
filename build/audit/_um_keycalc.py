# 复算 PCHunter64 用户态的密钥与 IOCTL 码
# 依据 sub_14004DD40 (0x14004DD40) 的反汇编

def derive(name):
    """name = 设备名去掉 '\\\\.\\' 前缀后的部分"""
    dest = "\\\\.\\" + name              # Destination 缓冲区内容
    n = len(dest)                        # wchar 数

    # 1) 字循环：从 Destination+8 字节（= name[0]）起，走 (n-4) 个 word
    edi = 0x20
    p = dest.encode('utf-16-le')[8:]
    words = [int.from_bytes(p[i:i+2], 'little') for i in range(0, (n-4)*2, 2)]
    for w in words:
        edi = (w ^ ((w + edi) & 0xFFFFFFFF)) & 0xFFFFFFFF

    # 2) ioctl code = 4 * (name[0] | (edi << 14))
    first = dest.encode('utf-16-le')[8]   # name[0] 的低字节
    ioctl = (4 * (first | ((edi << 14) & 0xFFFFFFFF))) & 0xFFFFFFFF

    # 3) key byte：从 Destination+8 字节起走 2*n-8 字节
    key = 0x20
    for c in dest.encode('utf-16-le')[8:2*n]:
        if c:
            key ^= c
        else:
            key = ((key >> 4) + (16 * key)) & 0xFF

    return ioctl, key


for nm in ("View++ByLinxer", "XPCHunterDrv"):
    ioctl, key = derive(nm)
    print("name=%-16s ioctl=0x%08X  keybyte=0x%02X" % (nm, ioctl, key))

print()
print("驱动侧 GT[0x1E0] 实测 = 0x05E00158（GenerateEncryptionKey）")
print("驱动侧 GT[0x1E1] 实测 = 0xCF")