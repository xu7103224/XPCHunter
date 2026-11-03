# publish —— 编译与发布脚本

本仓库有多个可发布产品，每个产品一组独立的发布脚本，互不干扰。

## 命名约定

```
publish/
├── publish_<产品>.bat     入口（双击 / 命令行）
├── pack_<产品>.ps1        该产品的打包逻辑
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

## 关于驱动签名

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