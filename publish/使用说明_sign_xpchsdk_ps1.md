# sign_xpchsdk.ps1 使用说明

只负责签名和生成驱动包目录，不编译、不复制 SDK 文件、不打 CAB。

## 什么时候用

- 编译产物已就绪，只想重新签名（换了证书、CAT 过期等）
- 想单独控制驱动包内容
- 排查签名问题，想看到每一步的详细输出

日常发布用 `publish_xpchsdk.bat` 就够，它会调本脚本。

## 基本用法

```powershell
# 正式发布（EV 证书）
powershell -ExecutionPolicy Bypass -File publish\sign_xpchsdk.ps1 `
    -SysPath build\bin\Release\x64\XPCHunterDrv.sys `
    -PackageDir output\driver_pkg `
    -Mode Release `
    -PfxPath D:\ev.pfx -PfxPassword 口令

# 本地测试（自签名）
powershell -ExecutionPolicy Bypass -File publish\sign_xpchsdk.ps1 `
    -SysPath build\bin\Release\x64\XPCHunterDrv.sys `
    -PackageDir output\driver_pkg `
    -Mode Local `
    -OutCer
```

## 参数

### 必填

| 参数 | 说明 |
|---|---|
| `-SysPath <路径>` | 要签名的 `.sys` 文件 |
| `-PackageDir <路径>` | 产物目录。**已存在会被清空重建** |

### 模式

| 参数 | 说明 |
|---|---|
| `-Mode Release` | 用 EV 证书（默认） |
| `-Mode Local` | 用本机测试证书 |

### Release 模式

| 参数 | 说明 |
|---|---|
| `-PfxPath <路径>` | EV 证书（必需） |
| `-PfxPassword <口令>` | 证书口令 |

### Local 模式

| 参数 | 说明 |
|---|---|
| `-CertName <名称>` | 证书 Subject 匹配串，默认 `XPCSign2` |
| `-OutCer` | 额外导出 `test_cert.cer` |

### 通用

| 参数 | 说明 | 默认 |
|---|---|---|
| `-TimestampUrl <url>` | 时间戳服务；`""` 跳过 | DigiCert |
| `-InfTemplate <路径>` | INF 模板 | `templates\XPCHunterDrv.inf` |
| `-Inf2CatPath <路径>` | Inf2Cat.exe | 自动查找 |
| `-DriverVerDate <MM/dd/yyyy>` | INF 的 DriverVer 日期 | 今天 |
| `-DriverVerVersion <版本>` | INF 的 DriverVer 版本 | `1.2.0.0` |

## 四个步骤

脚本按固定顺序执行，**这个顺序不能改**：

```
1/4  签名 SYS
     把 SYS 复制到 PackageDir，然后签名。

2/4  生成 INF
     展开模板，把 @DriverVerDate@ / @DriverVerVersion@ 替换成实际值。

3/4  Inf2Cat 生成 CAT
     对 PackageDir 内的 INF + SYS 算哈希，生成 .cat。

4/4  签名 CAT
     CAT 是驱动包校验的主体，必须一起签。
```

**为什么必须是这个顺序**：CAT 记录的是目录内文件的哈希。得先有最终版的
SYS（已签名）才能算出正确的 CAT。反过来的话，CAT 里的哈希会与最终文件不符。

（实测结论：Authenticode 签名写在 PE 的证书目录里，而 CAT 的哈希计算
会排除证书目录，所以"先签 SYS 再算 CAT"不会让哈希失效。）

## 产出

```
<PackageDir>\
├── XPCHunterDrv.inf     安装描述，DriverVer 已填
├── XPCHunterDrv.sys     已签名
└── xpchunterdrv.cat     已签名
```

`Local` 模式加 `-OutCer` 时多一个 `test_cert.cer`。

**不出 CAB**。CAB 由你自己打：

```bat
cd <PackageDir>
makecab /d CabinetNameTemplate=XPCHunterDrv.cab ^
        /d DiskDirectoryTemplate=. ^
        XPCHunterDrv.inf XPCHunterDrv.sys xpchunterdrv.cat
```

## 退出码

| 码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 签名/打包失败（含 Inf2Cat 未生成 CAT） |
| 2 | 证书问题（找不到证书、Release 模式没给 -PfxPath） |

## 验证签名

```powershell
Get-AuthenticodeSignature <PackageDir>\XPCHunterDrv.sys
Get-AuthenticodeSignature <PackageDir>\xpchunterdrv.cat
```

测试证书签出来的状态是 `UnknownError`，含义是"签名块完整，但根证书不在
本机信任库"——这是测试证书的正常表现，不是失败。

## 常见问题

**Inf2Cat 报 `Section 'XXX' is not listed in [DestinationDirs]`**

INF 里每个 `CopyFiles` 段都必须在 `[DestinationDirs]` 里列出来。检查
`templates\XPCHunterDrv.inf` 的这两个段是否对应。

**Inf2Cat 报 `missing from [SourceDisksFiles]`**

INF 的 `[SourceDisksFiles]` 里要列出 SYS 文件名，且与实际文件名完全一致
（含大小写）。

**CAT 生成了但安装时校验失败**

CAT 里的哈希和实际 SYS 不匹配，通常是 Inf2Cat 之后又改过 SYS。
重新跑一遍本脚本即可（它会清空目录重建）。

**pnputil 报 0xE0000247**

驱动包签名验证失败。CAT 的证书不受信任。发布场景下要等微软回签；
测试场景下要装 `test_cert.cer` 或开 testsigning。