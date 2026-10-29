# Ring3 inline hook 检测：实现与正向验证（2026-10-29）

## 0. 结论

**新增了 Ring3 导出函数的 inline hook 检测，并用真实 hook 验证通过。**

```
hooktest.dll-->Ring3 Inline Hook  fn=hooktest.dll!HookTargetAdd
```

这是原版 `CCodeHookDialog` 对应的能力，此前我方完全缺失
（只有 IAT 越界扫描）。

## 1. 实现

### 1.1 判据

从磁盘上的模块文件读出导出函数的前 16 字节，与目标进程内存里同一
函数的前 16 字节比对，不同则判为 inline hook。

**只检查导出函数**，不做全 `.text` 逐字节比对 —— 后者在没有完整重定位
基线时误报率极高（重定位项、CFG、hotpatch 填充都会造成合法差异）。

### 1.2 防误判措施（逐条踩坑得来）

| 措施 | 防的误判 | 怎么发现的 |
|---|---|---|
| **跳过 PE 重定位项覆盖的字节** | **ASLR 搬移地址，磁盘值与内存值必然不同** | **用户提问后发现实现缺失，见 `重定位与动态内存影响_2026-10-29.md`** |
| 导出必须落在**可执行节** | 数据导出被运行时初始化后必然不同 | `KiUserInvertedFunctionTable` / `LdrSystemDllInitBlock` / `NlsAnsiCodePage` 三个在 `.data`/`.rdata`，报成了 hook |
| 跳过首字节 `0xCC`/`0x90`（内存或磁盘任一侧） | 编译器 hotpatch padding、int3 填充 | 常见于 MSVC 生成的函数 |
| 跳过转发导出（RVA 落在导出目录内） | 转发项没有真实代码 | 标准 PE 语义 |
| 序号越界检查 `pOrds[i] < NumberOfFunctions` | 越界读导致崩溃/卡死 | 实测 notepad 扫描 7 秒无输出 |
| 磁盘 PE 自己的导出目录 | 内存与磁盘 build 不一致时错位 | 早期用内存的 expDir 算磁盘偏移，读到垃圾 |
| 文件名 RVA → 文件偏移换算 | 函数名乱码 | 出现过 `emoveProcessDebug`、`ent` 这类 |

### 1.3 性能优化

初版对每个 thunk 单独 `ReadProcessMemory`，64 描述符 × 512 thunk × 60 模块
≈ 200 万次系统调用，`--hooks-cli` 要几十秒。改成**一描述符一次读 4KB**
（512 个 qword）。

inline 扫描的模块数默认 1（主模块），可用环境变量
`XPCH_INLINE_MODULES=<n>` 放宽到最多 64。

### 1.4 新增诊断

| 环境变量 | 作用 |
|---|---|
| `XPCH_INLINE_MODULES=<n>` | inline 扫描的模块数上限（默认 1，最大 64） |
| `XPCH_INLINE_VERBOSE=1` | 打印每个参与扫描的模块、导出表参数、前 8 个函数的 RVA |

## 2. 正向验证

### 2.1 为什么不用 ntdll 做目标

第一次尝试用 KD 改 explorer 里 ntdll 的 `A_SHAFinal` 首字节（`48`→`41`）。
**结果把 services.exe 打崩了**：

```
*** An Access Violation occurred in C:\Windows\system32\services.exe:
The instruction at 00007FFF817CC460 tried to write to an invalid address, 0000000000000019
```

根因：**ntdll 的代码页是跨进程共享的**。改一个字节会影响所有加载了
wen 同一物理页的进程，而 `41 89 5c 24 18` 被解释成不同的指令就崩了。
（VM 随后失联，需要 hart reset 才恢复。）

**教训：验证 inline hook 必须用私有模块，不能用系统共享 DLL。**

### 2.2 安全方案：自建测试 DLL

写了一个最小的私有 DLL + 宿主：

```c
// hooktest.dll
__declspec(dllexport) int __stdcall HookTargetAdd(int a, int b)
{
    volatile int t = a + b;
    return t;
}

// hooktest_host.exe
h  = LoadLibraryA("hooktest.dll");
fn = GetProcAddress(h, "HookTargetAdd");
p  = (BYTE*)fn;
VirtualProtect(p, 16, PAGE_EXECUTE_READWRITE, &old);
p[0] = p[0] ^ 1;                       // 8D -> 8C
FlushInstructionCache(...);
// 等待外部扫描
p[0] = orig;                           // 恢复
```

这个 DLL 只在本进程加载，改它不影响其他进程。

### 2.3 验证结果

```
pid=3636
dll=0x00007FFEB4200000
fn=0x00007FFEB4201010 orig=8D
HOOKED: 8D -> 8C
--- scanning ---
    [diag] inline-scan hooktest_host.exe (C:\Users\xuq\Desktop\hooktest_host.exe)
    [diag] inline-scan ntdll.dll (C:\Windows\SYSTEM32\ntdll.dll)
    [diag] inline-scan KERNEL32.DLL (C:\Windows\System32\KERNEL32.DLL)
    [diag] inline-scan KERNELBASE.dll (C:\Windows\System32\KERNELBASE.dll)
    [diag] inline-scan hooktest.dll (C:\Users\xuq\Desktop\hooktest.dll)
=== Ring3 Hooks (pid 3636): 1 entries (IAT + inline) ===
    [diag] modules=5, inline-scanned=5
hooktest.dll-->Ring3 Inline Hook  fn=hooktest.dll!HookTargetAdd
```

**检出 1 条，函数名精确到 `HookTargetAdd`，模块 `hooktest.dll`。**

### 2.4 验证过程暴露的一个真实缺陷

第一次跑上面这个用例时**没检出**（0 条），尽管 hook 明明存在。

原因：我加过一个"首字节看起来像函数序言"的白名单来挡数据导出误报，
白名单里**没有 `0x8D`**（`LEA`，完全合法的函数首字节），
于是 `HookTargetAdd` 被这道闸门挡掉了。

修正：删掉首字节白名单，**只保留"可执行节"这一个判据**——
它已经足够挡掉所有数据导出（那些都在 `.data`/`.rdata`），
而且不会漏任何代码函数。

**这个 bug 只有靠正向验证才能发现**：干净系统上它表现为"0 条，
看起来很正常"。

## 3. 当前能力边界

| 项目 | 状态 |
|---|---|
| Ring3 IAT 越界检测 | ✅ 已有 |
| **Ring3 导出函数 inline hook** | ✅ **本轮新增并验证** |
| 扫描模块数 | 默认 1（主模块），`XPCH_INLINE_MODULES` 可调到 64 |
| 非导出函数被 inline patch | ❌ 不检测（缺重定位基线，误报无法控制） |
| 全 `.text` 逐字节比对 | ❌ 不做（同上） |

## 4. 与原版的对比

原版 `CCodeHookDialog` 是独立对话框，我方现在是 Ring3 Hooks 页的一部分。
判据思路一致（按导出名定位、比对磁盘原始字节），差别是：

- 原版有完整的 PE 重定位基线，可以对全 `.text` 做比对；我方只做导出函数
- 原版是模态对话框；我方是列表的一行

## 5. 复现步骤

```batch
:: 1. 部署（DLL + 宿主 + 前端）
copy hooktest.dll       C:\Users\xuq\Desktop\
copy hooktest_host.exe  C:\Users\xuq\Desktop\
copy xpch_frontend.exe  C:\Users\xuq\Desktop\

:: 2. 一键验证（内含：启动 hook、等待 HOOKED、扫描并打印结果）
verify_hook.bat

:: 预期输出末尾：
::   hooktest.dll-->Ring3 Inline Hook  fn=hooktest.dll!HookTargetAdd
```

`verify_hook.bat` 内容：

```batch
@echo off
cd /d C:\Users\xuq\Desktop
set XPCH_INLINE_MODULES=8
del /q ht3.txt st3.txt 2>nul
start "" /min cmd /c "(timeout /t 18 >nul & echo x) | hooktest_host.exe h > ht3.txt 2>&1"
set /a n=0
:wait
timeout /t 1 >nul
set /a n+=1
findstr /C:"HOOKED" ht3.txt >nul 2>&1 && goto scan
if %n% lss 8 goto wait
:scan
type ht3.txt
echo --- scanning ---
for /f "tokens=2 delims==" %%p in ('findstr /C:"pid=" ht3.txt') do set HOSTPID=%%p
xpch_frontend.exe --hooks-cli %HOSTPID% > st3.txt 2>&1
type st3.txt
```

## 6. 踩坑记录

1. **不要在 ntdll/kernel32 上做 inline hook 验证**——共享页，会崩别的进程
2. **GBK 编码的 .c 文件会让 cl 报错误行号**——写成纯 ASCII 就正常
3. `msbuild /t:Rebuild` 只编译不链接，`.sys` 要靠 `build/build.bat` 里的
   `link.exe` 手动链接
4. GUI 子系统程序的 stdout 是缓冲的，重定向到文件必须 `fflush(stdout)`
5. `FindResourceW(hMod, 0xE7, L"KERNEL")` —— 原版 exe 自释放驱动用的资源 ID