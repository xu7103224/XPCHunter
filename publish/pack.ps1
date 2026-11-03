# ============================================================================
# pack.ps1 —— XpchSdk 发布打包
#
# 把编译产物整理成一份可直接交付给第三方的目录结构：
#   output/XpchSdk-<版本>/
#     ├── bin/x64/XPCHunterDrv.sys          内核驱动（已签名）
#     ├── sdk/inc/XpchSdk.h                 头文件
#     ├── sdk/lib/XpchSdk.lib               静态库
#     ├── samples/                          示例与自检程序
#     ├── doc/                              接口文档 + 使用教程
#     ├── VERSION.txt                       版本与构建信息
#     └── SHA256SUMS.txt                    校验清单
#
# 参数：
#   -OutputDir <path>   输出根目录，默认 <仓库>/output
#   -Config <cfg>       构建配置，默认 Release
#   -NoBuild            跳过编译，只打包现有产物
#   -Zip                打包完成后额外生成同名 .zip
#   -IncludeProbe       把开发用的 XpchInjProbe.exe 也打进去（默认不含）
# ============================================================================
[CmdletBinding()]
param(
    [string] $OutputDir = "",
    [string] $Config = "Release",
    [switch] $NoBuild,
    [switch] $Zip,
    [switch] $IncludeProbe
)

$ErrorActionPreference = "Stop"

# ---- 路径 ----
$PublishDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root       = Split-Path -Parent $PublishDir
$BuildDir   = Join-Path $Root "build"
$BinDrv     = Join-Path $Root "build\bin\$Config\x64"
$BinSdk     = Join-Path $Root "build\bin\$Config\sdk_x64"
$DocSdk     = Join-Path $Root "doc\sdk"
$SdkHeader  = Join-Path $Root "src\sdk\inc\XpchSdk.h"

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $Root "output"
}

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "    $msg" -ForegroundColor Yellow }

# ---- 版本号：从 XpchSdk.h 读取，保持单一来源 ----
function Get-SdkVersion {
    if (-not (Test-Path $SdkHeader)) { return "0.0.0" }
    $m = Select-String -Path $SdkHeader -Pattern '#define\s+XPCHSDK_VERSION_STRING\s+L"([^"]+)"'
    if ($m -and $m.Matches.Count -gt 0) { return $m.Matches[0].Groups[1].Value }
    return "0.0.0"
}

$Version    = Get-SdkVersion
$Stamp      = Get-Date -Format "yyyyMMdd-HHmmss"
$PackageName = "XpchSdk-$Version"
$StageDir   = Join-Path $OutputDir $PackageName

Write-Step "XpchSdk 发布打包 $Version"
Write-Ok "仓库根目录 : $Root"
Write-Ok "输出目录   : $OutputDir"
Write-Ok "构建配置   : $Config"

# ---- 1. 编译（可选） ----
if (-not $NoBuild) {
    Write-Step "编译驱动与 SDK"

    foreach ($script in @("build.bat", "build_sdk.bat", "build_sdk_sample.bat")) {
        $path = Join-Path $BuildDir $script
        if (-not (Test-Path $path)) {
            throw "缺少构建脚本: $path"
        }
        Write-Ok "执行 $script"
        # 通过 cmd 调用，保持与手工构建完全一致的路径
        & cmd.exe /c "`"$path`" $Config"
        if ($LASTEXITCODE -ne 0) {
            throw "$script 失败（退出码 $LASTEXITCODE）"
        }
    }
} else {
    Write-Warn2 "跳过编译（-NoBuild）"
}

# ---- 2. 校验产物齐全 ----
Write-Step "校验构建产物"

$required = [ordered]@{
    "驱动"          = Join-Path $BinDrv "XPCHunterDrv.sys"
    "SDK 静态库"    = Join-Path $BinSdk "XpchSdk.lib"
    "SDK 头文件"    = Join-Path $BinSdk "XpchSdk.h"
    "示例程序"      = Join-Path $BinSdk "XpchSdkSample.exe"
    "自检程序"      = Join-Path $BinSdk "XpchSdkTest.exe"
    "注入靶 DLL"    = Join-Path $BinSdk "XpchInjTarget.dll"
    "接口文档"      = Join-Path $DocSdk "XpchSdk接口文档.md"
    "使用教程"      = Join-Path $DocSdk "XpchSdk使用教程.md"
}

$missing = @()
foreach ($k in $required.Keys) {
    $p = $required[$k]
    if (Test-Path $p) {
        $size = (Get-Item $p).Length
        Write-Ok ("{0,-14} {1,10:N0} B  {2}" -f $k, $size, (Split-Path -Leaf $p))
    } else {
        Write-Warn2 ("{0,-14} 缺失: {1}" -f $k, $p)
        $missing += $k
    }
}
if ($missing.Count -gt 0) {
    throw "缺少必需产物: $($missing -join ', ')。先执行编译或去掉 -NoBuild。"
}

# ---- 3. 准备暂存目录 ----
Write-Step "准备打包目录"

if (Test-Path $StageDir) {
    Remove-Item $StageDir -Recurse -Force
}
$dirs = @(
    (Join-Path $StageDir "bin\x64"),
    (Join-Path $StageDir "sdk\inc"),
    (Join-Path $StageDir "sdk\lib"),
    (Join-Path $StageDir "samples"),
    (Join-Path $StageDir "doc")
)
foreach ($d in $dirs) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
Write-Ok "已创建 $($dirs.Count) 个子目录"

# ---- 4. 复制产物 ----
Write-Step "复制文件"

$copies = @(
    @{ Src = (Join-Path $BinDrv "XPCHunterDrv.sys");   Dst = "bin\x64\XPCHunterDrv.sys" },
    @{ Src = (Join-Path $BinSdk "XpchSdk.lib");        Dst = "sdk\lib\XpchSdk.lib" },
    @{ Src = (Join-Path $BinSdk "XpchSdk.h");          Dst = "sdk\inc\XpchSdk.h" },
    @{ Src = (Join-Path $BinSdk "XpchSdkSample.exe");  Dst = "samples\XpchSdkSample.exe" },
    @{ Src = (Join-Path $BinSdk "XpchSdkTest.exe");    Dst = "samples\XpchSdkTest.exe" },
    @{ Src = (Join-Path $BinSdk "XpchInjTarget.dll");  Dst = "samples\XpchInjTarget.dll" },
    @{ Src = (Join-Path $DocSdk "XpchSdk接口文档.md"); Dst = "doc\XpchSdk接口文档.md" },
    @{ Src = (Join-Path $DocSdk "XpchSdk使用教程.md"); Dst = "doc\XpchSdk使用教程.md" }
)

if ($IncludeProbe) {
    $probe = Join-Path $BinSdk "XpchInjProbe.exe"
    if (Test-Path $probe) {
        $copies += @{ Src = $probe; Dst = "samples\XpchInjProbe.exe" }
    }
}

foreach ($c in $copies) {
    $target = Join-Path $StageDir $c.Dst
    Copy-Item $c.Src $target -Force
    Write-Ok $c.Dst
}

# 顶层放一份使用教程，拿到包的人第一眼就能看到
Copy-Item (Join-Path $DocSdk "XpchSdk使用教程.md") (Join-Path $StageDir "README.md") -Force
Write-Ok "README.md（使用教程副本）"

# ---- 5. 驱动签名状态 ----
Write-Step "检查驱动签名"
$sysPath = Join-Path $StageDir "bin\x64\XPCHunterDrv.sys"
$sig = Get-AuthenticodeSignature $sysPath
$subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "<无>" }

if ($sig.Status -eq "Valid") {
    Write-Ok "已签名且证书链完整（$subject）"
} elseif ($sig.Status -eq "NotSigned") {
    Write-Warn2 "未签名 —— 目标机必须开启 testsigning 才能加载"
} elseif ($sig.SignerCertificate) {
    # 测试证书（自签名）的典型状态：签名块完整，但根证书不在本机信任库。
    # 目标机用同一张证书或开启 testsigning 即可加载。
    Write-Warn2 "已签名（$subject），但根证书不受本机信任"
    Write-Warn2 "自签名测试证书属正常；目标机需 testsigning on 或安装该证书"
} else {
    Write-Warn2 "签名状态: $($sig.Status) — $($sig.StatusMessage)"
}

# ---- 6. VERSION.txt ----
Write-Step "生成 VERSION.txt"

$verLines = @(
    "XpchSdk $Version",
    "",
    "构建时间   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
    "构建配置   : $Config",
    "构建架构   : x64",
    "",
    "内容：",
    "  bin/x64/XPCHunterDrv.sys    内核驱动（管理员加载，设备名 \\Device\\View++ByLinxer）",
    "  sdk/inc/XpchSdk.h           SDK 唯一头文件",
    "  sdk/lib/XpchSdk.lib         SDK 静态库（x64）",
    "  samples/                    示例与自检程序",
    "  doc/                        接口文档与使用教程",
    "",
    "快速开始：",
    "  1. 管理员 PowerShell 加载驱动：",
    "       Unblock-File .\bin\x64\XPCHunterDrv.sys",
    "       sc.exe create XPCHDrv type= kernel binPath= <绝对路径>\bin\x64\XPCHunterDrv.sys",
    "       sc.exe start XPCHDrv",
    "  2. 跑自检确认环境：samples\XpchSdkTest.exe  （应输出 PASS 51 / FAIL 0）",
    "  3. 接入自己的项目：见 README.md / doc\XpchSdk使用教程.md",
    "",
    "依赖链接库：advapi32.lib wintrust.lib crypt32.lib psapi.lib",
    "支持平台  ：Windows 10 x64 构建号 18362（其它版本部分接口返回 NOT_SUPPORTED）",
    "",
    "驱动签名：",
    "  本包驱动使用测试证书（CN=XPCSign2）签名。目标机加载前需满足其一：",
    "    a) 开启测试签名：bcdedit /set testsigning on 后重启",
    "    b) 把 XPCSign2 根证书装进 受信任的根证书颁发机构 + 受信任的发布者"
)
Set-Content -Path (Join-Path $StageDir "VERSION.txt") -Value $verLines -Encoding UTF8
Write-Ok "VERSION.txt"

# ---- 7. SHA256SUMS.txt ----
Write-Step "生成 SHA256SUMS.txt"

$sums = @()
$files = Get-ChildItem $StageDir -Recurse -File |
         Where-Object { $_.Name -ne "SHA256SUMS.txt" } |
         Sort-Object FullName
foreach ($f in $files) {
    $h = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()
    $rel = $f.FullName.Substring($StageDir.Length + 1).Replace('\', '/')
    $sums += "$h  $rel"
}
Set-Content -Path (Join-Path $StageDir "SHA256SUMS.txt") -Value $sums -Encoding UTF8
Write-Ok "$($sums.Count) 个文件的校验和"

# ---- 8. 可选 zip ----
if ($Zip) {
    Write-Step "生成压缩包"
    $zipPath = Join-Path $OutputDir "$PackageName-$Stamp.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path $StageDir -DestinationPath $zipPath -CompressionLevel Optimal
    $zsize = (Get-Item $zipPath).Length
    Write-Ok ("{0}  ({1:N0} B)" -f (Split-Path -Leaf $zipPath), $zsize)
}

# ---- 9. 汇总 ----
Write-Step "完成"
$totalSize = (Get-ChildItem $StageDir -Recurse -File | Measure-Object -Property Length -Sum).Sum
Write-Host ""
Write-Host "  包目录 : $StageDir" -ForegroundColor Green
Write-Host ("  总大小 : {0:N0} B" -f $totalSize)
Write-Host "  文件数 : $((Get-ChildItem $StageDir -Recurse -File).Count)"
Write-Host ""
Write-Host "目录结构：" -ForegroundColor Cyan
Get-ChildItem $StageDir -Recurse | Sort-Object FullName | ForEach-Object {
    $rel = $_.FullName.Substring($StageDir.Length + 1)
    if ($_.PSIsContainer) { Write-Host "    $rel\" }
    else { Write-Host ("    {0,-52} {1,10:N0} B" -f $rel, $_.Length) }
}
Write-Host ""