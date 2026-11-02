# XPCHunter

PCHunter（View++ 无壳版）的逆向复刻工程。

包含内核驱动 `XPCHunterDrv.sys` 与用户态客户端 `xpch_frontend.exe`，
实现原版的进程/内核/钩子/注册表/文件/服务等 ARK 功能。

---

## 目录结构

```
src/
  driver/     内核驱动（View++_Driver64.sys 的 1:1 复刻）
  app/        用户态客户端（GUI + CLI 工具）
  common/     驱动与客户端共用代码（预留）
  tools/      分析脚本（IDA/GT 审计/哈希取证等）
build/        编译脚本与产物
doc/          文档
  reversing/    活文档：命令清单与接入指南、通信协议、原版功能地图
  archive/      逆向过程文档（已冻结，仅作历史记录）
samples/      原始样本（原版二进制与 IDA 数据库）
```

---

## 编译

需要 VS2019 BuildTools（MSVC v142）+ WDK 10.0.19041.0。

```bat
build\build.bat        :: 驱动 → build\bin\Release\x64\XPCHunterDrv.sys
build\build_um.bat     :: 客户端 → build\bin\Release\um_x64\xpch_frontend.exe
```

编译细节见 [CLAUDE.md](CLAUDE.md) §4.4。

---

## 文档

- **[驱动命令清单与接入指南](doc/reversing/驱动命令清单与接入指南.md)** ——
  283 个命令槽位全清单 + 用户态接入协议（新接入先读这份）
- [用户态内核通信协议](doc/reversing/用户态内核通信协议.md) ——
  0x30 字节请求结构、加解密、校验的逆向结论
- [原版前端功能地图](doc/reversing/原版前端功能地图.md) ——
  从原版 exe 提取的 14 个主 Tab 与功能字符串
- [逆向过程文档归档](doc/archive/reversing/README.md) ——
  逆向前因后果、实测证据与已失效结论清单

---

## 客户端用法

```bat
xpch_frontend.exe                  :: 启动 GUI
xpch_frontend.exe --page 2         :: 直接打开 Ring0 Hooks 页

:: 无界面查询（结果输出到 stdout）
xpch_frontend.exe --proclist-cli
xpch_frontend.exe --kernel-cli
xpch_frontend.exe --checkhook-cli <pid>
```

完整的 `--xxx-cli` 列表见 `src/app/src/CliMain.c`。

---

## 状态

逆向工作已结束，项目处于维护阶段。命令实现覆盖、能力边界与已知限制
见 [驱动命令清单与接入指南](doc/reversing/驱动命令清单与接入指南.md)。