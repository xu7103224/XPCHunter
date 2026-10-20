# 最终状态（RTZ55 实机验证，MISSING/EXTRA 双零）

## 验收门

```
sc create RTZ55 type= kernel binPath= C:\Users\Public\RTZ55.sys  → CREATE_EXIT=0
sc start  RTZ55                                                → START_EXIT=0
sc query  RTZ55                                                → STATE: 4 RUNNING
```

## GT 全表对比（vs `gt_orig_19045.bin`，同版本 18362 原始基线）

`python build/audit/gt_diff_norm.py build/audit/gt_orig_19045.bin build/audit/gt_mine_rtz55.bin`

| 类别 | RTZ51（本轮起点） | RTZ55（当前） |
| --- | --- | --- |
| MISSING（原始非零、我方 0） | 4 | **0** |
| EXTRA（原始 0、我方非零） | 0 | **0** |
| selfptr（归一后相同） | — | 301 |

`python build/audit/gt_diff_layers.py ... <orig_drv_base> <mine_drv_base>`

| 分层 | 数量 | 判定 |
| --- | --- | --- |
| A 自映像指针但 RVA 不同 | **0** | — |
| B 池/其他内核模块指针（每次启动基址不同） | 294 | 不可直接比对，属正常 |
| C 小整数/零不匹配 | 5 | 见下 |
| D nt 内指针但 RVA 不同 | **0** | — |

## 本轮修复（每项都有离线 oracle + 实机证据）

| # | 修复 | 证据 |
| --- | --- | --- |
| 1 | **ScanFileForPeSectionInfo 两处基址**：扫描窗口与候选减法都应用 `GT[0x20]`（PeBase），旧代码用 `GT[3]`；接受条件改为原始的两段式（`jg` 接受 + `cmp/jnb` 退出） | `0x1400151D0 lea rcx,[rdx+r15]`、`0x140015294 sub eax,r15d` |
| 2 | **MiniFilterPostWrite 的 0x40000 支路不减基址**：原始 `mov ebx,[entry+0x78]; add ebx,ecx`，旧代码多减一次 | `0x140014ECC..ED1` |
| 3 | **MiniFilterPreCleanup 整体重写**（本机 build 18362 < 0x4A61 实际走这个，不是 PostWrite）：读指针推进移到解码之后、去掉虚构的 CumulativeSize、0x40000 支路**要减** PeBase、判据顺序 `GT[0x439F]`→`GT[0x41C5]`、描述符数组 72 DWORD | `oracle_precleanup.py` ORIG/MINE 双双写出 `0x1A4=0x14056f3b0`、`0x179=nt+0x56f3b0` |
| 4 | **BuildHookTable 循环上界 0x4472 → 0x447C**：旧式 `GtTotalSize\|GtEprocessField114\|0x400` 恰为 0x4472，少一轮，漏掉 `esi=0x4473` 组 | `0x140003C13 cmp esi,447Ch` |
| 5 | **GenerateEncryptionKey 整体重写**：原始是 `(edi+c)^c` 逐字符累加 + `((edi<<14)\|首字符)<<2`，第二段按 UTF-16 字节流做半字节互换/异或；旧实现是 `i&3` 移位异或，完全不同 | `oracle_genkey.py` 双重 IDENTICAL，且恰为基线真值 `0x5E00158` / `0xCF` |
| 6 | **InitGtKey** 的 `-32` 改为 `+0xE0`、写回 DWORD（原码 `mov eax,[rsp+..]`） | `0x140029F91 add cl,0E0h` |

## 剩余 5 个 C 类差异的性质（已定性，非缺陷）

| 槽 | 原始 | 我方 | 原因 |
| --- | --- | --- | --- |
| 0x81B/0x81C/0x81D/0x81E | 0xC/0x3/0x2A/0x29 | 0x27/0x28/0x1/0x2 | `ValidateObjReferences@0x14001C340` 对 `IoGetCurrentProcess()`、`gs:[188h]`（当前线程）等**运行期对象**调用 `CheckObjectTypeFlagWrapper` 得到的标志字节，随加载时刻的进程/线程对象而变 |
| 0x877 | "Giap" | "Nrij" | `InitGtKey` 的 SHA1 输入是 `DriverObject` / 导入地址和这类**运行期指针**，每次加载必然不同；形态（4 个 a-z）正确 |

## 回归门（全部通过）

```
build\build.bat Release x64      → Build complete（0 error）
oracle_fsn_table_diff.py         → 464 条全同
oracle_precleanup.py             → IDENTICAL
oracle_mpw2.py                   → IDENTICAL
oracle_minifilter3.py            → PreClose 9 / DirEnum 2 / SetInfo 0，PASS
oracle_genkey.py                 → IDENTICAL
```

## 本轮新增工具

| 工具 | 用途 |
| --- | --- |
| `oracle_precleanup.py` | MiniFilterPreCleanup（0x140014EE4）离线差分 |
| `oracle_genkey.py` | GenerateEncryptionKey（真实入口 0x140081314）离线差分 |
| `gt_diff_layers.py` | GT 差异分层甄别（自映像 / 池指针 / 小整数 / nt 内指针） |
| `_find_dyn_plus.py` | 找 `lea ecx,[reg+1/+2]` 形式的动态索引 GtWrite（定位 BuildHookTable 三元组写入） |
| `_find_4474_sites.py` | 按索引立即数搜索 GtRead/GtWrite 引用点 |
| `_gtwrite_dyn.py` | 枚举全部 GtWrite 调用点并判定索引来源 |

## 实机操作要点（本轮踩过的坑）

- `vmrun` 必须在**关闭沙箱**下调用（`dangerouslyDisableSandbox`），且 `.bat` 必须 **CRLF**，否则报"不是内部或外部命令"。
- 加载新驱动前必须在**同一次会话内** `sc stop` 旧服务；仅 `sc delete` 不释放设备对象，
  再次加载报 **183 (STATUS_OBJECT_NAME_COLLISION)**，此时只能 `vm_reboot`。
- `kd` 处于 broken 时 `file_push`/`file_pull`/`vmrun` 全部阻塞，须先 `kd_go`。
- KDNET 独占唯一 e1000e 网卡，attach 期间 SSH 不可用；`vmrun runProgramInGuest` 是唯一可用的提权通道。
- 我方 `g_GlobalTable` RVA = **0xa1060**（从 map 读）；原始 = 0xa84f0。
  dump 地址 = 模块基址 + RVA，注意不要把 `0x45940000 + 0xa1060` 算成 `0x45941060`。