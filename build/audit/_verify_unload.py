# 验证卸载路径修复：反汇编新产物中的 DriverUnload
import pefile
from capstone import *

SYS = r'build\bin\Release\x64\XPCHunterDrv.sys'
pe = pefile.PE(SYS)
IB = pe.OPTIONAL_HEADER.ImageBase
secs = [(s.VirtualAddress, max(s.Misc_VirtualSize, s.SizeOfRawData), s.PointerToRawData) for s in pe.sections]
def r2o(rva):
    for va, sz, raw in secs:
        if va <= rva < va + sz:
            return raw + (rva - va)
data = open(SYS, 'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

va, size = 0x14000C780, 0x400
off = r2o(va - IB)
insns = list(md.disasm(data[off:off + size], va))
print(f'=== 新产物 DriverUnload @ {va:#x} ===')
loop_jmps = []
for i in insns:
    print(f'  {i.address:#x}: {i.mnemonic} {i.op_str}')
    if i.mnemonic == 'jmp' and i.op_str.startswith('0x'):
        loop_jmps.append(i)
    if i.mnemonic == 'int3':
        break

print()
print('=== 判定 ===')
# 找 KeDelayExecutionThread 调用
delay = [i for i in insns if 'KeDelay' in i.op_str]
print(f'  KeDelayExecutionThread 调用点: {len(delay)} 个')
# 检查是否存在"跳回自身/回跳"的无条件循环
self_loops = []
for j in loop_jmps:
    tgt = int(j.op_str, 16)
    if tgt <= j.address:
        self_loops.append((j.address, tgt))
print(f'  回跳型无条件 jmp: {len(self_loops)} 个 -> {[(hex(a), hex(t)) for a, t in self_loops]}')

if not self_loops:
    print('  >>> 卸载死循环已消除 ✓')
else:
    print('  >>> 仍存在回跳循环，需进一步检查')
