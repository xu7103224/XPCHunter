import struct

given = [5439580, 7536761, 6619252, 5374061, 7274607, 6029428, 7929971, 7602291,
         7143525, 3276851, 6553692, 6881394, 6619254, 7536754, 7602268, 6881380,
         7536686, 7536761]

prefix = "\\" + "SystemRoot" + "\\" + "system32" + "\\" + "drivers" + "\\"
print("prefix bytes:", prefix.encode("utf-16-le").hex())

for name in ["tdi.sys", "ndis.sys", "fwpkclnt.sys", "netbt.sys", "tcpip.sys"]:
    path = prefix + name
    b = path.encode("utf-16-le")
    n = (len(b) + 3) // 4
    b = b + b"\0" * (n * 4 - len(b))
    words = list(struct.unpack("<%dI" % n, b))
    same = words[:len(given)] == given[:len(words)]
    print("%-14s words=%2d match=%s" % (name, n, same))
    if not same:
        print("   want:", words)

print()
print("given:", given)