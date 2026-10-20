import json,subprocess,sys
# 生成 kd 命令清单（每行一个 dq 段），由调用方批量执行
base=0xfffff8010cfd1060
n=18432
chunk=0x200   # 512 slots per dq
lines=[]
for off in range(0,n,chunk):
    lines.append('dq 0x%X L%X' % (base+off*8, chunk))
open('build/audit/_gt_cmds.txt','w').write('\n'.join(lines))
print('cmds',len(lines))
