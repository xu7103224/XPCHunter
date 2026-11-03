# publish —— 编译与发布脚本

本仓库有多个可发布产品，每个产品一组独立的发布脚本，互不干扰。

## 命名约定

```
publish/
├── publish_<产品>.bat     入口（双击 / 命令行）
├── pack_<产品>.ps1        该产品的打包逻辑
├── sign_<产品>.ps1        驱动签名与 CAT 生成
├── templates/             打进包里的模板文件
│   ├── XPCHunterDrv.inf   驱动包 INF 模板
│   └── install_driver.bat 驱动安装脚本（本地调试用）
└── README.md              本文件
```

新增产品时复制一套脚本改名，不要在 `publish/` 下出现无产品前缀的通用名
（如 `publish.bat`），否则多产品会互相覆盖。

## 当前产品

| 产品 | 入口 | 默认输出 |
|---|---|---|
| XpchSdk | `publish\publish_xpchsdk.bat` | `output\XpchSdk-<版本>\` |

---

# XpchSdk

## 两条流程，别混用

驱动要能被 Windows 加载，签名是硬门槛。本产品有两种打包模式：

### 发布流程（默认）—— 提交微软签名

```bat
publish\publish_xpchsdk.bat -PfxPath D:\ev.pfx -PfxPassword 口令
```

产出 `output\XpchSdk-<版本>\submit\XPCHunterDrv.cab`，用途是**上传微软**：

1. CAB 内的 SYS 和 CAT 先用你的 EV 证书签名（微软要求提交前先签）
2. 登录 <https://partner.microsoft.com/dashboard/hardware>
3. 新建 submission，上传该 CAB
4. 微软回签后下载签名版 CAB，分发给最终用户

**最终用户的机器不需要装任何证书、不需要开测试签名**——微软的签名链
是系统内置信任的。这是唯一适合对外发布的路径。

没有 EV 证书时，脚本会明确报错拒绝打包，不会产出半成品。

### 内部测试流程 —— 自签名

```bat
publish\publish_xpchsdk.bat -TestSign
```

用本机测试证书签名，产出结构相同的 CAB。目标机需要满足其一才能加载：

```bat
:: a) 开测试签名
bcdedit /set testsigning on
shutdown /r /t 0

:: b) 装证书（加 -OutCer 会额外导出 test_cert.cer）
certutil -addstore -f Root test_cert.cer
certutil -addstore -f TrustedPublisher test_cert.cer
```

**这个包不可对外分发**，只用于本机/实验机验证功能。

## 参数

| 参数 | 说明 |
|---|---|
| （无） | 发布流程，需要 `-PfxPath` |
| `-PfxPath <路径>` | EV 代码签名证书（发布流程必需） |
| `-PfxPassword <口令>` | 证书口令 |
| `-TestSign` | 改用自签名测试证书（内部测试） |
| `-CertName <名称>` | `-TestSign` 时的证书 Subject 匹配串，默认 `XPCSign2` |
| `-OutCer` | `-TestSign` 时额外导出 `test_cert.cer` |
| `-NoSign` | 完全不签名，只出未签名 CAB（检查内容用） |
| `-TimestampUrl <url>` | 时间戳服务，默认 DigiCert；传 `""` 跳过 |
| `-NoBuild` | 跳过编译，只打包现有产物 |
| `-Zip` | 额外生成 `.zip` |
| `-OutputDir <路径>` | 输出根目录，默认 `<仓库>\output` |
| `-Config <配置>` | 构建配置，默认 `Release` |
| `-IncludeProbe` | 把开发用 `XpchInjProbe.exe` 打进 samples |

## 产物结构

```
output/XpchSdk-1.2.0/                 ~1 MB
├── submit/
│   └── XPCHunterDrv.cab              驱动包：INF + SYS + CAT
├── SDK/
│   ├── xpch_sdk/
│   │   ├── XpchSdk.h                 SDK 头文件
│   │   └── XpchSdk.lib               SDK 静态库（x64）
│   └── samples/
│       ├── XpchSdkSample.exe         示例程序
│       ├── XpchSdkTest.exe           逐接口自检（51 条断言）
│       └── XpchInjTarget.dll         注入测试靶 DLL
├── doc/
│   ├── XpchSdk接口文档.md
│   └── XpchSdk使用教程.md
├── README.md                         使用教程副本
├── VERSION.txt                       版本、签名信息、安装步骤
└── SHA256SUMS.txt                    全部文件校验和
```

`test_cert.cer` 只在 `-TestSign -OutCer` 时出现，发布包里不会有。

## CAB 里面是什么

```
XPCHunterDrv.cab
├── XPCHunterDrv.inf     安装描述：服务名、启动类型、二进制路径
├── XPCHunterDrv.sys     驱动本体
└── XPCHunterDrv.cat     目录文件，Inf2Cat 生成后签名
```

**为什么需要 CAT**：Windows 安装驱动包时校验的是 CAT，不是单独校验 SYS。
CAT 覆盖了 INF 和 SYS 的哈希。签好的 SYS 若没有配套 CAT，`pnputil`
仍会拒绝安装。

生成顺序（`sign_xpchsdk.ps1` 内完成）：展开 INF 模板 → `Inf2Cat /os:10_X64`
→ 签 SYS → 签 CAT → `makecab` 打包。

## 安装驱动

```bat
:: 解压
expand XPCHunterDrv.cab -F:* C:\temp\xpch

:: 安装（产生驱动库条目 oemNN.inf）
pnputil /add-driver C:\temp\xpch\XPCHunterDrv.inf /install

:: 启动（INF 里 StartType=3，装完是 STOPPED）
sc start XPCHDrv
```

`pnputil` 返回 **3010** 是**成功**（`ERROR_SUCCESS_REBOOT_REQUIRED`），
包已入驱动库、驱动可立即启动，只是系统建议重启。

卸载（连同驱动库条目）：

```bat
pnputil /enum-drivers
pnputil /delete-driver oemNN.inf /uninstall
sc delete XPCHDrv
```

## 脚本做了什么

`pack_xpchsdk.ps1`：

1. 编译驱动 + SDK + 示例（`-NoBuild` 可跳过）
2. 校验 8 个必需产物，缺一个就失败，不产半成品
3. 建目录、分类复制
4. 调 `sign_xpchsdk.ps1` 生成 CAB（按模式选证书）
5. 写 VERSION.txt（含签名信息与对应安装步骤）
6. 写 SHA256SUMS.txt
7. 可选 zip

版本号从 `src/sdk/inc/XpchSdk.h` 的 `XPCHSDK_VERSION_STRING` 读取，单一来源。

## 需要的前置条件

- Visual Studio 2019 BuildTools（`build\*.bat` 里写的路径）
- Windows 10 SDK 10.0.19041.0（驱动构建 + Inf2Cat）
- 发布流程：EV 代码签名证书 `.pfx`
- 测试流程：本机证书库中有 `CN=XPCSign2`（`build\sign_driver.ps1` 用同一张）

## 输出目录

`output/` 已加入 `.gitignore`。每次打包覆盖同名包，删目录即可重建。

## 实现注意（改脚本时别踩）

- `publish_<产品>.bat` 必须**纯 ASCII + CRLF**。cmd 按 ANSI 解析，
  中文注释会变成乱码命令。
- `pack_<产品>.ps1` / `sign_<产品>.ps1` 必须带 **UTF-8 BOM**。
  PowerShell 5.1 对无 BOM 的 UTF-8 按 ANSI 解析，中文注释会导致语法错误。
- 写 Windows 路径时不要用 `"...\bin"` 这种字符串字面量——
  `\b` `\x` 会被 Python 层当转义吃掉。用 `Join-Path` 逐级拼接。
- `Join-Path` 不能直接接管道：`Join-Path $a "x" | Join-Path -ChildPath "y"`
  是错的，要么嵌套括号，要么分两步。