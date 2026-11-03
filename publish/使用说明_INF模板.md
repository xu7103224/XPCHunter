# templates/XPCHunterDrv.inf 使用说明

驱动包的安装描述文件模板。`sign_xpchsdk.ps1` 会读取它、替换占位符、
放进 `driver_pkg` 目录，然后 Inf2Cat 据此生成 CAT。

## 占位符

只有两个，由脚本替换：

| 占位符 | 替换为 | 来源 |
|---|---|---|
| `@DriverVerDate@` | 日期 `MM/dd/yyyy` | 脚本的 `-DriverVerDate`，默认今天 |
| `@DriverVerVersion@` | 版本号 | 脚本的 `-DriverVerVersion`，默认 `1.2.0.0` |

**不要手工替换后再提交**——脚本每次都会重新展开模板，手工改的会丢。

## 各段含义

```ini
[Version]
Signature="$Windows NT$"                必须原样
Class=System                            设备类：系统设备
ClassGuid={4D36E97D-...}                System 类的固定 GUID
Provider=%ProviderName%                 显示在设备管理器里的厂商名
CatalogFile=XPCHunterDrv.cat            CAT 文件名，必须与实际一致
DriverVer=@DriverVerDate@,@DriverVerVersion@
```

`Class` 和 `ClassGuid` 必须配对。`System` 对应
`{4D36E97D-E325-11CE-BFC1-08002BE10318}`，是内核服务驱动的标准归类。

```ini
[SourceDisksNames]
1 = %DiskName%,,,
[SourceDisksFiles]
XPCHunterDrv.sys = 1,,
```

这两段声明「文件从哪个安装介质来」。少任何一段 Inf2Cat 都会报错
（`missing from [SourceDisksFiles]`）。文件名必须与 `driver_pkg` 里的
实际文件名完全一致。

```ini
[DestinationDirs]
DefaultDestDir = 12
DriverCopyFiles = 12
```

`12` = `%SystemRoot%\System32\Drivers`。

**每个 `CopyFiles` 段都必须列在这里**，否则 setupapi 报
`Section 'XXX' is not listed in [DestinationDirs]`（code 1275）。
注意 `DefaultDestDir` 是**单数**，我曾写成 `DefaultDestDirs` 导致失败。

```ini
[DefaultInstall.NTamd64]
CopyFiles = DriverCopyFiles
```

`.NTamd64` 后缀表示只对 x64 生效。`DefaultInstall`（无后缀）是通用的，
两者可以共存，`.NTamd64` 优先。

```ini
[DefaultInstall.NTamd64.Services]
AddService = XPCHDrv,0x00000002,XpchServiceInstall
```

`0x00000002` = 安装时不重启。最后的参数指向服务安装段。

```ini
[XpchServiceInstall]
DisplayName    = %ServiceName%
ServiceType    = 1           1 = 内核驱动
StartType      = 3           3 = 手动启动（DEMAND_START）
ErrorControl   = 1           1 = 普通错误即记录但不阻止启动
ServiceBinary  = %12%\XPCHunterDrv.sys
```

**`StartType = 3` 的影响**：`pnputil /install` 装完后服务是 `STOPPED`，
需要手动 `sc start XPCHDrv`。如果想随系统自动启动，改成 `2`（AUTO_START），
但内核驱动自动启动会在每次开机时加载，调试时不太方便，默认保持手动。

## 改这个模板的场景

**换服务名**

```ini
AddService = <新名字>,0x00000002,XpchServiceInstall
DisplayName = <显示名>          ; 或改 [Strings] 里的 ServiceName
```

注意 `AddService` 的第一项就是服务名（写死，不能用 `%ServiceName%` 引用），
改了要同步改 `[Strings]` 的 `ServiceName` 和 SDK 侧打开设备名的逻辑
（设备名在驱动里定，与本 INF 无关）。

**改驱动文件名**

三处要一起改：
- `[SourceDisksFiles]` 的条目
- `[DriverCopyFiles]` 的条目
- `[XpchServiceInstall]` 的 `ServiceBinary`

`CatalogFile` 也要跟着改，且 `sign_xpchsdk.ps1` 里 Inf2Cat 生成后找的是
`*.cat`，不依赖具体名字，所以改 CAT 名不会破坏脚本。

**加只读/可选文件**

```ini
[SourceDisksFiles]
XPCHunterDrv.sys = 1,,
readme.txt       = 1,,

[DriverCopyFiles]
XPCHunterDrv.sys,,,0x00000004
readme.txt,,,0x00000020      0x20 = 只在目标不存在时才复制
```

新增的 `CopyFiles` 段如果换了名字（不叫 `DriverCopyFiles`），记得在
`[DestinationDirs]` 里也加一行。

## 验证模板没写错

改完先单独跑一次签名脚本，Inf2Cat 会做语法检查：

```powershell
powershell -ExecutionPolicy Bypass -File publish\sign_xpchsdk.ps1 `
    -SysPath build\bin\Release\x64\XPCHunterDrv.sys `
    -PackageDir $env:TEMP\inftest `
    -Mode Local
```

看到 `3/4 生成 CAT` 且没报错，说明 INF 结构正确。

## 为什么是 legacy 而非 PnP

本驱动用 `IoCreateDevice` 自建设备对象（`FILE_DEVICE_UNKNOWN` + 符号链接），
不实现 `AddDevice`、不处理 `IRP_MJ_PNP`。这类驱动走 `sc create` 或
本 INF 的 `DefaultInstall` 段安装，不需要硬件 ID、不需要 PnP 枚举。

`Class=System` 只是让它在驱动库里归类正确，不意味着它绑定某个硬件。