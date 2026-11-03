# pack_xpchsdk.ps1 使用说明

XpchSdk 的打包逻辑本体。通常由 `publish_xpchsdk.bat` 调用，
也可直接调用来做精细控制。

## 直接调用

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File publish\pack_xpchsdk.ps1 `
    -TestSign
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File publish\pack_xpchsdk.ps1 `
    -PfxPath D:\ev.pfx -PfxPassword 口令
```

## 参数

| 参数 | 说明 | 默认 |
|---|---|---|
| `-PfxPath <路径>` | EV 证书 `.pfx`（发布模式必需） | 无 |
| `-PfxPassword <口令>` | 证书口令 | 无 |
| `-TestSign` | 用自签名测试证书 | 关 |
| `-CertName <名称>` | `-TestSign` 的证书匹配串 | `XPCSign2` |
| `-OutCer` | `-TestSign` 时导出 `test_cert.cer` | 关 |
| `-NoBuild` | 跳过编译 | 关 |
| `-Zip` | 额外生成 zip | 关 |
| `-OutputDir <路径>` | 输出根目录 | `<仓库>\output` |
| `-Config <配置>` | 构建配置 | `Release` |
| `-IncludeProbe` | 打进开发探针 | 关 |
| `-TimestampUrl <url>` | 时间戳服务；`""` 跳过 | DigiCert |

## 执行流程

```
1. 编译          调 build.bat / build_sdk.bat / build_sdk_sample.bat
                  （-NoBuild 跳过）
2. 校验产物      逐个检查 8 个必需文件，缺一个就抛异常，不产半成品
3. 建目录        output\XpchSdk-<版本>\ 下的 driver_pkg / SDK / doc
4. 复制          头文件、库、示例、文档分类归位，顶层放 README 副本
5. 签名          调 sign_xpchsdk.ps1，产出 driver_pkg（INF+SYS+CAT）
6. 写 VERSION.txt  版本、签名信息、按模式给不同的下一步命令
7. 写 SHA256SUMS   全部文件校验和
8. zip           可选
```

## 版本号从哪来

脚本不写死版本，从 `src\sdk\inc\XpchSdk.h` 读：

```c
#define XPCHSDK_VERSION_STRING  L"1.2.0"
```

改版本只改这一处，打包目录名、VERSION.txt、INF 的 DriverVer 全部跟着变。

## 签名怎么选证书

```
-TestSign 给了        → 本机证书库找 Subject 含 -CertName 的证书
-TestSign 没给        → 必须给 -PfxPath，否则抛异常
```

这个判断在脚本第 5 步，硬性拦截。宁可报错也不产出没签名或签错证书的包。

## 产物

```
output\XpchSdk-<版本>\
├── driver_pkg\
│   ├── XPCHunterDrv.inf
│   ├── XPCHunterDrv.sys         已签名
│   └── xpchunterdrv.cat         已签名
├── SDK\
│   ├── xpch_sdk\XpchSdk.h
│   ├── xpch_sdk\XpchSdk.lib
│   └── samples\...
├── doc\
├── README.md
├── VERSION.txt
└── SHA256SUMS.txt
```

`test_cert.cer` 只在 `-TestSign -OutCer` 时出现。

## 和 bat 的关系

`publish_xpchsdk.bat` 只是把参数原样转发给本脚本：

```bat
powershell -NoProfile -ExecutionPolicy Bypass -File "...\pack_xpchsdk.ps1" %*
```

功能和直接调用完全一样。差别只在 bat 更方便（双击、参数不用引号转义）。

## 什么时候直接调本脚本

- 需要 PowerShell 层面的精细控制（比如在脚本里套调用）
- 想看完整错误堆栈（bat 会把异常压成一行）
- 需要把输出重定向到文件做 CI

日常直接用 bat 就行。

## 改脚本注意

- 文件必须带 UTF-8 BOM，否则 PowerShell 5.1 按 ANSI 解析中文注释会报语法错
- `Join-Path $a "x" | Join-Path -ChildPath "y"` 是**非法**的，
  要么嵌套括号 `Join-Path (Join-Path $a "x") "y"`，要么分两步赋值
- 路径别写字面量 `"...\bin"`，`\b` `\x` 会被当转义吃掉