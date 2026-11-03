# publish_xpchsdk.bat 使用说明

发布入口。一条命令完成：编译驱动和 SDK → 签名驱动 → 生成 driver_pkg 目录。

## 两种模式

### 正式发布（默认）

用 EV 代码签名证书签名，产出待打包提交微软的驱动包。

```bat
publish\publish_xpchsdk.bat -PfxPath D:\ev.pfx -PfxPassword 你的口令
```

必须给 `-PfxPath`。不给会直接报错退出，不会产出半成品。

### 本地测试

用本机自签名测试证书签名，仅供实验机验证功能。

```bat
publish\publish_xpchsdk.bat -TestSign
```

**这个包不可对外分发**——目标机必须开 testsigning 或安装测试证书才能加载。

## 全部参数

| 参数 | 说明 | 默认 |
|---|---|---|
| `-PfxPath <路径>` | EV 证书 `.pfx`（发布模式必需） | 无 |
| `-PfxPassword <口令>` | 证书口令 | 无 |
| `-TestSign` | 改用自签名测试证书 | 关 |
| `-CertName <名称>` | `-TestSign` 时的证书 Subject 匹配串 | `XPCSign2` |
| `-OutCer` | `-TestSign` 时额外导出 `test_cert.cer` | 关 |
| `-NoBuild` | 跳过编译，只处理现有产物 | 关 |
| `-Zip` | 额外生成 `.zip` | 关 |
| `-OutputDir <路径>` | 输出根目录 | `<仓库>\output` |
| `-Config <配置>` | 构建配置 | `Release` |
| `-IncludeProbe` | 把开发用 `XpchInjProbe.exe` 打进 samples | 关 |
| `-TimestampUrl <url>` | 时间戳服务；传 `""` 跳过 | DigiCert |

参数可任意组合，原样透传给 `pack_xpchsdk.ps1`。

## 产出

```
output\XpchSdk-1.2.0\
├── driver_pkg\                     ← 你要的文件在这里
│   ├── XPCHunterDrv.inf            安装描述
│   ├── XPCHunterDrv.sys            驱动本体（已签名）
│   └── xpchunterdrv.cat            目录文件（已签名）
├── SDK\xpch_sdk\                   XpchSdk.h + XpchSdk.lib
├── SDK\samples\                    示例、自检、注入靶 DLL
├── doc\                            接口文档 + 使用教程
├── README.md
├── VERSION.txt                     版本、签名信息、下一步命令
└── SHA256SUMS.txt
```

## 打完包之后

### 发布路径

自己把 `driver_pkg` 打成 CAB：

```bat
cd output\XpchSdk-1.2.0\driver_pkg
makecab /d CabinetNameTemplate=XPCHunterDrv.cab ^
        /d DiskDirectoryTemplate=. ^
        XPCHunterDrv.inf XPCHunterDrv.sys xpchunterdrv.cat
```

然后上传 CAB 到 <https://partner.microsoft.com/dashboard/hardware> 回签。
微软签好后的 CAB 发给用户，用户机器**不需要装证书、不需要开测试签名**。

### 测试路径

不用打 CAB，直接装：

```bat
pnputil /add-driver output\XpchSdk-1.2.0\driver_pkg\XPCHunterDrv.inf /install
sc start XPCHDrv
```

`pnputil` 返回 3010 是成功（包已入驱动库，只是建议重启）。

## 常见用法

```bat
:: 只重新签名，不重新编译（改完证书或想跳过耗时编译时）
publish\publish_xpchsdk.bat -TestSign -NoBuild

:: 出个压缩包方便传给别人
publish\publish_xpchsdk.bat -TestSign -Zip

:: 输出到别的盘
publish\publish_xpchsdk.bat -TestSign -OutputDir D:\dist

:: 换一张测试证书
publish\publish_xpchsdk.bat -TestSign -CertName MyTestCert

:: 连开发探针一起打进去
publish\publish_xpchsdk.bat -TestSign -IncludeProbe
```

## 前置条件

- Visual Studio 2019 BuildTools（`build\*.bat` 里写死的路径）
- Windows 10 SDK（驱动编译 + Inf2Cat + signtool）
- 发布模式：EV 代码签名证书 `.pfx`
- 测试模式：本机证书库有 `CN=XPCSign2`（`build\sign_driver.ps1` 用同一张）

## 出错时

| 现象 | 原因 | 处理 |
|---|---|---|
| `需要 -PfxPath 指定 EV 代码签名证书` | 发布模式没给证书 | 给 `-PfxPath`，或改 `-TestSign` |
| `本机证书库找不到...证书` | 测试证书不在库里 | 看报错列出的可用证书，用 `-CertName` 指定 |
| `找不到 x64 signtool.exe` | 没装 Windows SDK | 装 SDK |
| `找不到 Inf2Cat.exe` | 同上 | 同上 |
| `缺少必需产物` | 编译没成功 | 去掉 `-NoBuild` 重跑，或看编译错误 |