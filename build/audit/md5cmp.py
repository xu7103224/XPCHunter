# 对比原版 Md5Transform2（按反编译逐句转写）与标准 MD5，找出分叉步。
# 用途：原版驱动的 MD5 与标准不同，需要定位差异点以便 1:1 复刻。
M = 0xFFFFFFFF
def ROL(x, n): x &= M; return ((x << n) | (x >> (32 - n))) & M
def ROR(x, n): x &= M; return ((x >> n) | (x << (32 - n))) & M

import struct

blk = bytes.fromhex('1008242024000000' '60f72f56a2000000' '0000000000000000' 'b0f82f56a2000000'
                    '0000000004000000' '8000000000000000' '0000000000000000' '4001000000000000')
X = list(struct.unpack('<16I', blk))
A0, B0, C0, D0 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
Ks = [0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
      0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
      0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
      0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
      0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
      0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
      0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
      0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391]
Rs = [7,12,17,22]*4 + [5,9,14,20]*4 + [4,11,16,23]*4 + [6,10,15,21]*4

a, b, c, d = A0, B0, C0, D0
std = []
for i in range(64):
    if i < 16:   f = (d ^ (b & (c ^ d))) & M; g = i
    elif i < 32: f = (c ^ (d & (b ^ c))) & M; g = (5*i + 1) % 16
    elif i < 48: f = (b ^ c ^ d) & M;           g = (3*i + 5) % 16
    else:        f = (c ^ (b | (~d & M))) & M;  g = (7*i) % 16
    tmp = d; d = c; c = b
    b = (b + ROL((a + f + X[g] + Ks[i]) & M, Rs[i])) & M
    a = tmp
    std.append(b)

a2 = X
v2 = C0; v4 = a2[5]; v85 = a2[0]; v80 = A0; v83 = D0; v81 = C0; v87 = a2[1]; v82 = B0
v77 = a2[2]; v86 = a2[3]; v79 = a2[4]; v76 = a2[6]; v11 = a2[7]; v12 = a2[8]; v13 = a2[10]
v14 = a2[12]; v15 = a2[13]; v16 = a2[14]; v75 = a2[9]; v78 = a2[11]; X15 = a2[15]

seq = []
v5  = (v82 + ROL(a2[0] + ((v83 ^ (v82 & (v2 ^ v83))) & M) + A0 - 680876936, 7)) & M; seq.append(v5)
v6  = (v5 + ROL(v87 + ((v2 ^ (v5 & (v82 ^ v2))) & M) + v83 - 389564586, 12)) & M; seq.append(v6)
v7  = (v6 + ROR(v77 + ((v82 ^ (v6 & (v5 ^ v82))) & M) + v2 + 606105819, 15)) & M; seq.append(v7)
v8  = (v7 + ROR(v86 + ((v5 ^ (v7 & (v5 ^ v6))) & M) + v82 - 1044525330, 10)) & M; seq.append(v8)
v9  = (v8 + ROL(v79 + ((v6 ^ (v8 & (v7 ^ v6))) & M) + v5 - 176418897, 7)) & M; seq.append(v9)
v10 = (v9 + ROL(v4 + ((v7 ^ (v9 & (v8 ^ v7))) & M) + v6 + 1200080426, 12)) & M; seq.append(v10)
v17 = (v10 + ROR(v76 + ((v8 ^ (v10 & (v9 ^ v8))) & M) + v7 - 1473231341, 15)) & M; seq.append(v17)
v18 = (v17 + ROR(v11 + ((v9 ^ (v17 & (v9 ^ v10))) & M) + v8 - 45705983, 10)) & M; seq.append(v18)
v19 = (v18 + ROL(v12 + ((v10 ^ (v18 & (v17 ^ v10))) & M) + v9 + 1770035416, 7)) & M; seq.append(v19)
v20 = (v19 + ROL(v75 + ((v17 ^ (v19 & (v18 ^ v17))) & M) + v10 - 1958414417, 12)) & M; seq.append(v20)
v21 = (v20 + ROR(v13 + ((v18 ^ (v20 & (v19 ^ v18))) & M) + v17 - 42063, 15)) & M; seq.append(v21)
v22 = (v21 + ROR(v78 + ((v19 ^ (v21 & (v19 ^ v20))) & M) + v18 - 1990404162, 10)) & M; seq.append(v22)
v23 = (v22 + ROL(v14 + ((v20 ^ (v22 & (v21 ^ v20))) & M) + v19 + 1804603682, 7)) & M; seq.append(v23)
v24 = (v23 + ROL(v20 + v15 + ((v21 ^ (v23 & (v22 ^ v21))) & M) - 40341101, 12)) & M; seq.append(v24)
v25 = (v24 + ROR(v16 + ((v22 ^ (v24 & (v23 ^ v22))) & M) + v21 - 1502002290, 15)) & M; seq.append(v25)
v26 = (v25 + ROR(v22 + X15 + ((v23 ^ (v25 & (v23 ^ v24))) & M) + 1236535329, 10)) & M; seq.append(v26)
v27 = (v26 + ROL(v87 + ((v25 ^ (v24 & (v26 ^ v25))) & M) - 165796510 + v23, 5)) & M; seq.append(v27)
v28 = (v27 + ROL(v76 + ((v26 ^ (v25 & (v27 ^ v26))) & M) - 1069501632 + v24, 9)) & M; seq.append(v28)
v29 = (v28 + ROL(v78 + ((v27 ^ (v26 & (v27 ^ v28))) & M) + 643717713 + v25, 14)) & M; seq.append(v29)
v30 = (v29 + ROR(v85 + ((v28 ^ (v27 & (v29 ^ v28))) & M) + v26 - 373897302, 12)) & M; seq.append(v30)
v31 = (v30 + ROL(v4 + ((v29 ^ (v28 & (v30 ^ v29))) & M) + v27 - 701558691, 5)) & M; seq.append(v31)
v32 = (v31 + ROL(v13 + ((v30 ^ (v29 & (v31 ^ v30))) & M) + v28 + 38016083, 9)) & M; seq.append(v32)
v33 = (v32 + ROL(X15 + ((v31 ^ (v30 & (v31 ^ v32))) & M) + v29 - 660478335, 14)) & M; seq.append(v33)
v34 = (v33 + ROR(v79 + ((v32 ^ (v31 & (v33 ^ v32))) & M) + v30 - 405537848, 12)) & M; seq.append(v34)
v35 = (v34 + ROL(v75 + ((v33 ^ (v32 & (v34 ^ v33))) & M) + v31 + 568446438, 5)) & M; seq.append(v35)
v36 = (v35 + ROL(v16 + ((v34 ^ (v33 & (v35 ^ v34))) & M) + v32 - 1019803690, 9)) & M; seq.append(v36)
v37 = (v36 + ROL(v86 + ((v35 ^ (v34 & (v35 ^ v36))) & M) + v33 - 187363961, 14)) & M; seq.append(v37)
v38 = (v37 + ROR(v12 + ((v36 ^ (v35 & (v37 ^ v36))) & M) + v34 + 1163531501, 12)) & M; seq.append(v38)
v39 = (v38 + ROL(v15 + ((v37 ^ (v36 & (v38 ^ v37))) & M) + v35 - 1444681467, 5)) & M; seq.append(v39)
v40 = (v39 + ROL(v77 + ((v38 ^ (v37 & (v39 ^ v38))) & M) + v36 - 51403784, 9)) & M; seq.append(v40)
v41 = (v40 + ROL(v11 + ((v39 ^ (v38 & (v39 ^ v40))) & M) + v37 + 1735328473, 14)) & M; seq.append(v41)
v42 = (v41 + ROR(v14 + ((v40 ^ (v39 & (v41 ^ v40))) & M) + v38 - 1926607734, 12)) & M; seq.append(v42)
v43 = (v42 + ROL(v4 + ((v42 ^ v41 ^ v40) & M) - 378558 + v39, 4)) & M; seq.append(v43)
v44 = (v43 + ROL(v12 + ((v43 ^ v42 ^ v41) & M) - 2022574461 + v40, 11)) & M; seq.append(v44)
v45 = (v44 + ROL(v78 + ((v43 ^ v42 ^ v44) & M) + 1839030562 + v41, 16)) & M; seq.append(v45)
v46 = (v45 + ROR(v16 + ((v43 ^ v45 ^ v44) & M) + v42 - 35309556, 9)) & M; seq.append(v46)
v47 = (v46 + ROL(v87 + ((v46 ^ v45 ^ v44) & M) + v43 - 1530992060, 4)) & M; seq.append(v47)
v48 = (v47 + ROL(v79 + ((v47 ^ v46 ^ v45) & M) + v44 + 1272893353, 11)) & M; seq.append(v48)
v49 = (v48 + ROL(v11 + ((v47 ^ v46 ^ v48) & M) + v45 - 155497632, 16)) & M; seq.append(v49)
v50 = (v49 + ROR(v13 + ((v47 ^ v49 ^ v48) & M) + v46 - 1094730640, 9)) & M; seq.append(v50)
v51 = (v50 + ROL(v15 + ((v50 ^ v49 ^ v48) & M) + v47 + 681279174, 4)) & M; seq.append(v51)
v52 = (v51 + ROL(v85 + ((v51 ^ v50 ^ v49) & M) - 358537222 + v48, 11)) & M; seq.append(v52)
v53 = (v52 + ROL(v86 + ((v51 ^ v50 ^ v52) & M) - 722521979 + v49, 16)) & M; seq.append(v53)
v54 = (v53 + ROR(v76 + ((v51 ^ v53 ^ v52) & M) + v50 + 76029189, 9)) & M; seq.append(v54)
v55 = (v54 + ROL(v51 + v75 + ((v54 ^ v53 ^ v52) & M) - 640364487, 4)) & M; seq.append(v55)
v56 = (v55 + ROL(v14 + ((v55 ^ v54 ^ v53) & M) + v52 - 421815835, 11)) & M; seq.append(v56)
v57 = (v56 + ROL(X15 + ((v55 ^ v54 ^ v56) & M) + v53 + 530742520, 16)) & M; seq.append(v57)
v58 = (v57 + ROR(v77 + ((v55 ^ v57 ^ v56) & M) + v54 - 995338651, 9)) & M; seq.append(v58)
v59 = (v58 + ROL(v85 + ((v57 ^ (v58 | (~v56 & M))) & M) + v55 - 198630844, 6)) & M; seq.append(v59)
v60 = (v59 + ROL(v11 + ((v58 ^ (v59 | (~v57 & M))) & M) + v56 + 1126891415, 10)) & M; seq.append(v60)
v61 = (v60 + ROL(v16 + ((v59 ^ (v60 | (~v58 & M))) & M) + v57 - 1416354905, 15)) & M; seq.append(v61)
v62 = (v61 + ROR(v4 + ((v60 ^ (v61 | (~v59 & M))) & M) + v58 - 57434055, 11)) & M; seq.append(v62)
v63 = (v62 + ROL(v14 + ((v61 ^ (v62 | (~v60 & M))) & M) + v59 + 1700485571, 6)) & M; seq.append(v63)
v64 = (v63 + ROL(v86 + ((v62 ^ (v63 | (~v61 & M))) & M) + v60 - 1894986606, 10)) & M; seq.append(v64)
v65 = (v64 + ROL(v13 + ((v63 ^ (v64 | (~v62 & M))) & M) + v61 - 1051523, 15)) & M; seq.append(v65)
v66 = (v65 + ROR(v87 + ((v64 ^ (v65 | (~v63 & M))) & M) + v62 - 2054922799, 11)) & M; seq.append(v66)
v67 = (v66 + ROL(v63 + v12 + ((v65 ^ (v66 | (~v64 & M))) & M) + 1873313359, 6)) & M; seq.append(v67)
v68 = (v67 + ROL(X15 + ((v66 ^ (v67 | (~v65 & M))) & M) + v64 - 30611744, 10)) & M; seq.append(v68)
v69 = (v68 + ROL(v76 + ((v67 ^ (v68 | (~v66 & M))) & M) + v65 - 1560198380, 15)) & M; seq.append(v69)
v70 = (v69 + ROR(v15 + ((v68 ^ (v69 | (~v67 & M))) & M) + v66 + 1309151649, 11)) & M; seq.append(v70)
v71 = (v70 + ROL(v79 + ((v69 ^ (v70 | (~v68 & M))) & M) + v67 - 145523070, 6)) & M; seq.append(v71)
v72 = (v71 + ROL(v68 + v78 + ((v70 ^ (v71 | (~v69 & M))) & M) - 1120210379, 10)) & M; seq.append(v72)
v73 = (v72 + ROL(v77 + ((v71 ^ (v72 | (~v70 & M))) & M) + 718787259 + v69, 15)) & M; seq.append(v73)
Bf  = (v73 + ROR(v70 + v75 + ((v72 ^ (v73 | (~v71 & M))) & M) - 343485551, 11) + v82) & M; seq.append(Bf)

first = None
for i in range(64):
    if seq[i] != std[i] and first is None:
        first = i
print('64 步中第一个分歧:', ('step %d' % (first + 1)) if first is not None else '无（完全一致）')
if first is not None:
    print('  seq=%08x  std=%08x' % (seq[first], std[first]))
    for k in range(max(0, first - 2), min(64, first + 3)):
        print('   step %2d seq=%08x std=%08x %s' % (k+1, seq[k], std[k],
              'OK' if seq[k] == std[k] else 'DIFF'))
