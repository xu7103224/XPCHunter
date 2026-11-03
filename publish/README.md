# publish —— 编译与发布脚本

本仓库有多个可发布产品，每个产品一组独立的发布脚本，互不干扰。

## 命名约定

```
publish/
├── publish_<产品>.bat     入口（双击 / 命令行）
├── pack_<产品>.ps1        该产品的打包逻辑（含驱动签名）
├── sign_<产品>.ps1        驱动签名（可单独调用）
├── templates/             打进包里的模板文件
│   ├── install_driver.bat 驱动安装/卸载脚本
│   └── SIGNING.txt        签名与加载说明（占位符由打包时替换）
└── README.md              本文件
```

`<产品>` 用小写产品标识。新增产品时复制一套脚本改名，不要在 `publish/` 下
出现无产品前缀的通用名（如 `publish.bat`），否则多产品会互相覆盖。

## 当前产品

| 产品 | 入口 | 默认输出 | 说明 |
|---|---|---|---|
| XpchSdk | `publish\publish_xpchsdk.bat` | `output\XpchSdk-<版本>\` | 内核能力 SDK（驱动 + 静态库 + 文档） |

---

# XpchSdk

## 快速使用

```bat
publish\publish_xpchsdk.bat
```

默认行为：编译驱动 + SDK + 示例 → 打包到 `output\XpchSdk-<版本>\`。

## 参数

| 参数 | 说明 |
|---|---|
| （无） | 完整编译并打包到 `output\` |
| `-Zip` | 额外生成 `XpchSdk-<版本>-<时间戳>.zip` |
| `-NoBuild` | 跳过编译，只打包现有产物（快速验证打包逻辑） |
| `-OutputDir <路径>` | 指定输出根目录，默认 `<仓库>\output` |
| `-Config <配置>` | 构建配置，默认 `Release` |
| `-IncludeProbe` | 把开发用的 `XpchInjProbe.exe` 也打进 samples |
| `-NoSign` | 不签名，只打包（产物是未签名驱动） |
| `-SignMode Local\|Pfx` | 签名模式，默认 `Local`（本机证书库） |
| `-CertName <名称>` | Local 模式证书 Subject 匹配串，默认 `XPCSign2` |
| `-PfxPath <路径>` | Pfx 模式证书文件 |
| `-PfxPassword <口令>` | Pfx 模式证书口令 |
| `-TimestampUrl <url>` | 时间戳服务，默认 DigiCert；传 `""` 跳过 |

参数可组合，会原样透传给 `pack_xpchsdk.ps1`。

## 产物结构

```
output/XpchSdk-1.2.0/
├── bin/x64/XPCHunterDrv.sys      内核驱动（已签名）
├── sdk/inc/XpchSdk.h             SDK 头文件
├── sdk/lib/XpchSdk.lib           SDK 静态库（x64）
├── samples/
│   ├── XpchSdkSample.exe         示例程序
│   ├── XpchSdkTest.exe           逐接口自检（51 条断言）
│   └── XpchInjTarget.dll         注入测试靶 DLL
├── doc/
│   ├── XpchSdk接口文档.md        接口参考
│   └── XpchSdk使用教程.md        入门教程
├── xpch.cer                      驱动公钥证书（装进受信任根即可加载）
├── install_driver.bat            驱动安装/启动/停止/卸载
├── SIGNING.txt                   签名信息 + 两种加载方式说明
├── README.md                     使用教程副本（顶层放一份）
├── VERSION.txt                   版本/构建信息 + 快速开始步骤
└── SHA256SUMS.txt                全部文件的 SHA-256
```

交付给别人时整个 `XpchSdk-<版本>` 目录即可，不会再依赖仓库的其他文件。

## 脚本做了什么

`pack_xpchsdk.ps1` 的执行顺序：

1. **编译**（`-NoBuild` 可跳过）—— 依次调 `build.bat`、`build_sdk.bat`、`build_sdk_sample.bat`
2. **校验产物** —— 逐个检查 8 个必需文件，缺任何一个就直接失败，不产出半成品包
3. **准备目录** —— 清空同名旧包，重建子目录
4. **复制** —— 按分类归位，并在顶层放一份 README
5. **检查驱动签名** —— 区分「证书链完整」「自签名测试证书」「未签名」三种情况分别提示
6. **生成 VERSION.txt** —— 版本从 `XpchSdk.h` 的 `XPCHSDK_VERSION_STRING` 读取，单一来源
7. **生成 SHA256SUMS.txt** —— 供接收方校验完整性
8. **可选压缩** —— `-Zip` 时生成带时间戳的 zip

版本号只从 `src/sdk/inc/XpchSdk.h` 读，改版本不需要动脚本。
产品名由脚本内 `$ProductName` 变量控制，打包目录名与 `VERSION.txt` 首行都用它。

## 驱动签名

默认每次打包都会对 `bin/x64/XPCHunterDrv.sys` 签名（带时间戳），产出完整签名包。
签名由 `sign_xpchsdk.ps1` 完成，打包时自动调用。

### 两种签名模式

**Local（默认）** —— 用本机证书库里的证书：

```bat
publish\publish_xpchsdk.bat
publish\publish_xpchsdk.bat -CertName MyTestCert     :: 换证书
```

**Pfx** —— 用证书文件（正式签名场景）：

```bat
publish\publish_xpchsdk.bat -SignMode Pfx -PfxPath D:\cert.pfx -PfxPassword 口令
```

### 单独签名（不打包）

```powershell
powershell -ExecutionPolicy Bypass -File publish\sign_xpchsdk.ps1 ^
    -SysPath buildin\Released\XPCHunterDrv.sys
```

签名脚本会：签名 → 加时间戳 → `signtool verify` 校验 → 导出同名 `.cer`。

### 签名包里有什么

| 文件 | 作用 |
|---|---|
| `xpch.cer` | 驱动公钥证书。目标机装进「受信任的根」后即可加载 |
| `install_driver.bat` | 驱动 install / start / stop / uninstall / status |
| `SIGNING.txt` | 签名信息（签名者、指纹、有效期、时间戳）+ 两种加载方式 |

目标机加载驱动有两条路（`SIGNING.txt` 里也写了）：

```bat
:: 方式 A：开启测试签名（开发环境）
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
shutdown /r /t 0
install_driver.bat install

:: 方式 B：安装本包证书（不改启动配置）
certutil -addstore -f Root xpch.cer
certutil -addstore -f TrustedPublisher xpch.cer
install_driver.bat install
```

加载失败返回 577 时，`install_driver.bat` 会直接打印这两个解决方式。

### 关于签名状态 NotTrusted / UnknownError

自签名测试证书签名后，`Get-AuthenticodeSignature` 通常返回 `UnknownError`，
含义是「签名块完整，但根证书不在本机信任库」。这不是签名失败——
按上面方式 A 或 B 操作后驱动就能加载。`SIGNING.txt` 会根据实际状态
自动写入对应的说明文字。

### 正式发布前

测试证书只适合内部分发。对外正式发布需要：

1. 换用受信任的商业代码签名证书（EV / OV），用 `-SignMode Pfx` 签
2. 驱动走微软 WHQL / Attestation 签名，否则默认配置的 Win10/11 仍拒绝加载

---

## 关于驱动签名（旧版说明，保留供参考）

打包出来的 `XPCHunterDrv.sys` 用的是测试证书 `CN=XPCSign2`。目标机加载前需要满足其一：

- 开启测试签名：`bcdedit /set testsigning on` 后重启
- 或把 XPCSign2 证书装进「受信任的根证书颁发机构」+「受信任的发布者」

`VERSION.txt` 里也写了这两条，接收方不用另外问。

## 需要的前置条件

- Visual Studio 2019 BuildTools（`build\*.bat` 里写死的路径）
- Windows 10 SDK 10.0.19041.0（驱动构建）
- 签名证书 `CN=XPCSign2` 在本机证书库（`build\sign_driver.ps1` 使用）

缺任一条件时脚本会在编译阶段明确报错退出，不会产出不完整的包。

## 输出目录

`output/` 已在 `.gitignore` 中排除，不会误提交。清空重建直接删目录即可，脚本每次都会覆盖同名包。

## 实现注意（改脚本时别踩）

- `publish_<产品>.bat` 必须是**纯 ASCII + CRLF**。cmd 会按 ANSI 解析，
  中文注释会变成乱码命令；LF 换行在部分 cmd 版本上也有问题。
- `pack_<产品>.ps1` 必须带 **UTF-8 BOM**。PowerShell 5.1 对无 BOM 的
  UTF-8 脚本按 ANSI 解析，中文注释会导致语法错误。