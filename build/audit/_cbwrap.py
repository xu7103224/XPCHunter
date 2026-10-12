import struct
from capstone import *
P='samples/PCHunter_2024.09.02/View++_Driver64.sys'
d=open(P,'rb').read()
pe=struct.unpack_from('<I',d,0x3c)[0]
n=struct.unpack_from('<H',d,pe+6)[0]
sec=pe+24+struct.unpack_from('<H',d,pe+20)[0]
secs=[]
for i in range(n):
    o=sec+i*40
    vsz,va,rsz,ra=struct.unpack_from('<IIII',d,o+8); secs.append((va,vsz,ra,rsz))
def off(va):
    va-=0x140000000
    for sva,vsz,ra,rsz in secs:
        if sva<=va<sva+max(vsz,rsz): return ra+(va-sva)
md=Cs(CS_ARCH_X86,CS_MODE_64)
funcs=[(0x140070070,'ReadCallbackType1'),(0x1400700D0,'ReadCallbackType2'),(0x140070130,'ReadCallbackType3'),
       (0x140070B3C,'CallbackType1Dispatcher'),(0x140070B9C,'CallbackType2Dispatcher'),
       (0x140070BFC,'CallbackType3Dispatcher'),(0x140070C5C,'CallbackType4Dispatcher'),
       (0x140070CBC,'CallbackType5Dispatcher')]
for a,nm in funcs:
    raw=d[off(a):off(a)+0x60]
    gt=None; calls=[]
    for ins in md.disasm(raw,a):
        if ins.mnemonic=='mov' and ins.op_str.startswith('ecx, '):
            try: gt=int(ins.op_str.split(', ')[1],16)
            except: gt=None
        if ins.mnemonic=='call':
            calls.append(ins.op_str)
        if ins.mnemonic=='ret': break
    print(f'{hex(a)} {nm:<26} GT={hex(gt) if gt else "?"} calls={calls}')
