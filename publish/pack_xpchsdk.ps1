# ============================================================================
# pack_xpchsdk.ps1 —— XpchSdk 发布打包
#
# 产品名：XpchSdk（内核能力 SDK）
# 命名约定：publish/pack_<产品>.ps1 + publish/publish_<产品>.bat
#           新增产品时复制本脚本改名，避免入口重名。
#
# 产出目录：
#   output/XpchSdk-<版本>/
#     ├── driver_pkg/                 待打包的驱动文件目录（INF+SYS+CAT）
#     │   ├── XPCHunterDrv.inf
#     │   ├── XPCHunterDrv.sys        已签名
#     │   └── XPCHunterDrv.cat        已签名
#     ├── SDK/xpch_sdk/              SDK 头文件 + 静态库
#     ├── SDK/samples/               示例与自检程序
#     ├── doc/                       接口文档 + 使用教程
#     └── VERSION.txt / SHA256SUMS.txt
#
# 驱动签名有两条完全不同的流程，本脚本用 -TestSign 区分：
#
#   默认（发布流程）
#     产出待提交微软的 CAB。驱动包在本地用 EV 证书签名后，
#     上传到微软硬件开发者中心回签。分发给最终用户的包由微软签名，
#     用户机器无需安装证书、无需开启测试签名。
#     需要 -PfxPath 指定 EV 证书；没有 EV 证书时只能走 -TestSign。
#
#   -TestSign（内部测试）
#     用自签名测试证书签 SYS 和 CAT，产出本地可加载的 CAB。
#     目标机需要 testsigning on 或安装导出证书。产物不可对外分发。
#
# 参数：
#   -OutputDir <path>   输出根目录，默认 <仓库>/output
#   -Config <cfg>       构建配置，默认 Release
#   -NoBuild            跳过编译，只打包现有产物
#   -Zip                额外生成同名 .zip
#   -IncludeProbe       把开发用的 XpchInjProbe.exe 打进 samples
#
#   -PfxPath <path>     发布流程：EV 代码签名证书
#   -PfxPassword <pw>   发布流程：证书口令
#
#   -TestSign           改用自签名测试证书（内部调试）
#   -CertName <name>    -TestSign 时证书 Subject 匹配串，默认 XPCSign2
#   -OutCer             -TestSign 时额外导出公钥证书
#
#   -TimestampUrl <url> 时间戳服务，默认 DigiCert；传 "" 跳过
# ============================================================================
[CmdletBinding()]
param(
    [string] $OutputDir = "",
    [string] $Config = "Release",
    [switch] $NoBuild,
    [switch] $Zip,
    [switch] $IncludeProbe,

    [string] $PfxPath = "",
    [string] $PfxPassword = "",

    [switch] $TestSign,
    [string] $CertName = "XPCSign2",
    [switch] $OutCer,

    [string] $TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"

function J([string]$a, [string]$b, [string]$c = $null) {
    $r = Join-Path $a $b
    if ($c) { $r = Join-Path $r $c }
    return $r
}

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    $m" -ForegroundColor Green }
function Write-Warn2($m){ Write-Host "    $m" -ForegroundColor Yellow }

# ---- 路径 ----
$PublishDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root        = Split-Path -Parent $PublishDir
$BuildDir    = Join-Path $Root "build"
$BinDrv      = J $BuildDir "bin" $Config
$BinDrv      = Join-Path $BinDrv "x64"
$BinSdk      = J $BuildDir "bin" $Config
$BinSdk      = Join-Path $BinSdk "sdk_x64"
$DocSdk      = J $Root "doc" "sdk"
$SdkHeader   = J $Root "src" "sdk"
$SdkHeader   = J $SdkHeader "inc" "XpchSdk.h"
$SignScript  = Join-Path $PublishDir "sign_xpchsdk.ps1"

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $Root "output"
}

# ---- 版本号：从 XpchSdk.h 单一来源读取 ----
function Get-SdkVersion {
    if (-not (Test-Path $SdkHeader)) { return "0.0.0" }
    $m = Select-String -Path $SdkHeader -Pattern '#define\s+XPCHSDK_VERSION_STRING\s+L"([^"]+)"'
    if ($m -and $m.Matches.Count -gt 0) { return $m.Matches[0].Groups[1].Value }
    return "0.0.0"
}

$ProductName = "XpchSdk"
$Version     = Get-SdkVersion
$Stamp       = Get-Date -Format "yyyyMMdd-HHmmss"
$PackageName = "$ProductName-$Version"
$StageDir    = Join-Path $OutputDir $PackageName

Write-Step "$ProductName 发布打包 $Version"
Write-Ok "仓库根目录 : $Root"
Write-Ok "输出目录   : $OutputDir"
Write-Ok "构建配置   : $Config"
if ($TestSign) {
    Write-Ok "签名方式   : 自签名测试证书（内部测试，不可分发）"
} else {
    Write-Ok "签名方式   : EV 证书 → 待打包提交微软"
}

# ---- 1. 编译 ----
if (-not $NoBuild) {
    Write-Step "编译驱动与 SDK"
    foreach ($script in @("build.bat", "build_sdk.bat", "build_sdk_sample.bat")) {
        $path = Join-Path $BuildDir $script
        if (-not (Test-Path $path)) { throw "缺少构建脚本: $path" }
        Write-Ok "执行 $script"
        & cmd.exe /c "`"$path`" $Config"
        if ($LASTEXITCODE -ne 0) { throw "$script 失败（退出码 $LASTEXITCODE）" }
    }
} else {
    Write-Warn2 "跳过编译（-NoBuild）"
}

# ---- 2. 校验产物 ----
Write-Step "校验构建产物"
$required = [ordered]@{
    "驱动"       = Join-Path $BinDrv "XPCHunterDrv.sys"
    "SDK 静态库" = Join-Path $BinSdk "XpchSdk.lib"
    "SDK 头文件" = Join-Path $BinSdk "XpchSdk.h"
    "示例程序"   = Join-Path $BinSdk "XpchSdkSample.exe"
    "自检程序"   = Join-Path $BinSdk "XpchSdkTest.exe"
    "注入靶 DLL" = Join-Path $BinSdk "XpchInjTarget.dll"
    "接口文档"   = Join-Path $DocSdk "XpchSdk接口文档.md"
    "使用教程"   = Join-Path $DocSdk "XpchSdk使用教程.md"
}
$missing = @()
foreach ($k in $required.Keys) {
    $p = $required[$k]
    if (Test-Path $p) {
        Write-Ok ("{0,-12} {1,10:N0} B  {2}" -f $k, (Get-Item $p).Length, (Split-Path -Leaf $p))
    } else {
        Write-Warn2 ("{0,-12} 缺失: {1}" -f $k, $p)
        $missing += $k
    }
}
if ($missing.Count -gt 0) {
    throw "缺少必需产物: $($missing -join ', ')"
}

# ---- 3. 目录 ----
Write-Step "准备打包目录"
if (Test-Path $StageDir) { Remove-Item $StageDir -Recurse -Force }
$dirs = @(
    (Join-Path $StageDir "driver_pkg"),
    (Join-Path $StageDir ("SDK" + [char]92 + "xpch_sdk")),
    (Join-Path $StageDir ("SDK" + [char]92 + "samples")),
    (Join-Path $StageDir "doc")
)
foreach ($d in $dirs) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
Write-Ok "已创建 $($dirs.Count) 个子目录"

# ---- 4. 复制 ----
Write-Step "复制文件"
$sdkInc = Join-Path $StageDir ("SDK" + [char]92 + "xpch_sdk")
$sdkSmp = Join-Path $StageDir ("SDK" + [char]92 + "samples")
$copies = @(
    @{ Src = (Join-Path $BinSdk "XpchSdk.lib");       Dst = (Join-Path $sdkInc "XpchSdk.lib") },
    @{ Src = (Join-Path $BinSdk "XpchSdk.h");         Dst = (Join-Path $sdkInc "XpchSdk.h") },
    @{ Src = (Join-Path $BinSdk "XpchSdkSample.exe"); Dst = (Join-Path $sdkSmp "XpchSdkSample.exe") },
    @{ Src = (Join-Path $BinSdk "XpchSdkTest.exe");   Dst = (Join-Path $sdkSmp "XpchSdkTest.exe") },
    @{ Src = (Join-Path $BinSdk "XpchInjTarget.dll"); Dst = (Join-Path $sdkSmp "XpchInjTarget.dll") },
    @{ Src = (Join-Path $DocSdk "XpchSdk接口文档.md"); Dst = (Join-Path $StageDir ("doc" + [char]92 + "XpchSdk接口文档.md")) },
    @{ Src = (Join-Path $DocSdk "XpchSdk使用教程.md"); Dst = (Join-Path $StageDir ("doc" + [char]92 + "XpchSdk使用教程.md")) }
)
if ($IncludeProbe) {
    $probe = Join-Path $BinSdk "XpchInjProbe.exe"
    if (Test-Path $probe) {
        $copies += @{ Src = $probe; Dst = (Join-Path $sdkSmp "XpchInjProbe.exe") }
    }
}
foreach ($c in $copies) {
    Copy-Item $c.Src $c.Dst -Force
    Write-Ok (Split-Path -Leaf $c.Dst)
}

# 顶层说明
Copy-Item (Join-Path $DocSdk "XpchSdk使用教程.md") (Join-Path $StageDir "README.md") -Force
Write-Ok "README.md（使用教程副本）"

# ---- 5. 驱动包目录 ----
Write-Step "生成驱动包目录"
$sysSrc  = Join-Path $BinDrv "XPCHunterDrv.sys"
$pkgDir  = Join-Path $StageDir "driver_pkg"
$sigInfo = @{ Signer = "<未签名>"; Thumbprint = "-"; NotAfter = "-"; Timestamp = "-"; Status = "NotSigned" }

if (-not (Test-Path $SignScript)) { throw "缺少签名脚本: $SignScript" }

$signArgs = @(
    "-SysPath", $sysSrc,
    "-PackageDir", $pkgDir,
    "-TimestampUrl", $TimestampUrl,
    "-DriverVerVersion", $Version
)

if ($TestSign) {
    $signArgs += @("-Mode", "Local", "-CertName", $CertName)
    if ($OutCer) { $signArgs += @("-OutCer") }
    Write-Ok "签名证书：本机测试证书（$CertName）"
} else {
    if (-not $PfxPath) {
        throw "发布流程需要 -PfxPath 指定 EV 代码签名证书。仅内部测试请加 -TestSign。"
    }
    $signArgs += @("-Mode", "Release", "-PfxPath", $PfxPath)
    if ($PfxPassword) { $signArgs += @("-PfxPassword", $PfxPassword) }
    Write-Ok "签名证书：EV 证书 $PfxPath"
}

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $SignScript @signArgs
if ($LASTEXITCODE -ne 0) { throw "驱动签名失败（退出码 $LASTEXITCODE）" }

# 采集签名信息（从产物目录里的 SYS 读）
$pkgSys = Join-Path $pkgDir "XPCHunterDrv.sys"
if (Test-Path $pkgSys) {
    $sig = Get-AuthenticodeSignature $pkgSys
    if ($sig.SignerCertificate) {
        $sigInfo.Signer     = $sig.SignerCertificate.Subject
        $sigInfo.Thumbprint = $sig.SignerCertificate.Thumbprint
        $sigInfo.NotAfter   = $sig.SignerCertificate.NotAfter.ToString("yyyy-MM-dd")
    }
    if ($sig.TimeStamperCertificate) { $sigInfo.Timestamp = $sig.TimeStamperCertificate.Subject }
    $sigInfo.Status = $sig.Status
}

# 列出目录内容
Get-ChildItem $pkgDir -File | Sort-Object Name | ForEach-Object {
    Write-Ok ("{0,-24} {1,10:N0} B" -f $_.Name, $_.Length)
}

# ---- 6. VERSION.txt ----
Write-Step "生成 VERSION.txt"
$modeText = if ($TestSign) { "自签名测试证书（内部测试，不可分发）" }
            else { "EV 证书已签，待打包提交微软回签" }

$verLines = @(
    "$ProductName $Version",
    "",
    "构建时间   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
    "构建配置   : $Config",
    "签名方式   : $modeText",
    "",
    "目录：",
    "  driver_pkg/                    驱动包文件（自行打成 CAB）",
    "    XPCHunterDrv.inf             安装描述",
    "    XPCHunterDrv.sys             驱动本体（已签名）",
    "    XPCHunterDrv.cat             目录文件（已签名）",
    "  SDK/xpch_sdk/                  XpchSdk.h + XpchSdk.lib",
    "  SDK/samples/                   示例、自检、注入靶 DLL",
    "  doc/                           接口文档 + 使用教程",
    ""
)

if ($TestSign) {
    $verLines += @(
        "本地测试安装：",
        "  本目录的 SYS/CAT 用自签名测试证书签名，目标机需先满足其一：",
        "    a) bcdedit /set testsigning on 后重启",
        "    b) 安装 test_cert.cer 到受信任的根 + 受信任的发布者",
        "  然后：",
        "    pnputil /add-driver driver_pkg\\XPCHunterDrv.inf /install",
        "    sc start XPCHDrv",
        "",
        "  产物仅供内部验证，不可对外分发。"
    )
} else {
    $verLines += @(
        "发布流程：",
        "  1. 把 driver_pkg 目录打成 CAB（示例）：",
        "       cd driver_pkg",
        "       makecab /d CabinetNameTemplate=XPCHunterDrv.cab ^",
        "               /d DiskDirectoryTemplate=. ^",
        "               XPCHunterDrv.inf XPCHunterDrv.sys xpchunterdrv.cat",
        "  2. 上传 CAB 到 https://partner.microsoft.com/dashboard/hardware 回签",
        "  3. 下载微软签名后的 CAB，分发给最终用户",
        "  4. 用户机器安装（无需证书、无需测试签名）：",
        "       expand XPCHunterDrv.cab -F:* C:\\temp\\xpch",
        "       pnputil /add-driver C:\\temp\\xpch\\XPCHunterDrv.inf /install",
        "       sc start XPCHDrv",
        "",
        "  注意：微软回签前的包在默认配置的 Win10/11 上无法加载。"
    )
}
$verLines += @(
    "",
    "驱动签名信息：",
    ("  签名者  : " + $sigInfo.Signer),
    ("  指纹    : " + $sigInfo.Thumbprint),
    ("  有效期  : " + $sigInfo.NotAfter),
    ("  时间戳  : " + $sigInfo.Timestamp),
    ("  状态    : " + $sigInfo.Status),
    "",
    "SDK 接入：",
    "  编译：cl /utf-8 /DUNICODE /D_UNICODE /I SDK\xpch_sdk your.c SDK\xpch_sdk\XpchSdk.lib ^",
    "           advapi32.lib wintrust.lib crypt32.lib psapi.lib",
    "  用法：见 README.md / doc\XpchSdk使用教程.md",
    "",
    "支持平台：Windows 10 x64 构建号 18362（其它版本部分接口返回 NOT_SUPPORTED）"
)
Set-Content -Path (Join-Path $StageDir "VERSION.txt") -Value $verLines -Encoding UTF8
Write-Ok "VERSION.txt"

# ---- 7. SHA256SUMS.txt ----
Write-Step "生成 SHA256SUMS.txt"
$sums = @()
$files = Get-ChildItem $StageDir -Recurse -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | Sort-Object FullName
foreach ($f in $files) {
    $h = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()
    $rel = $f.FullName.Substring($StageDir.Length + 1).Replace([char]92, '/')
    $sums += "$h  $rel"
}
Set-Content -Path (Join-Path $StageDir "SHA256SUMS.txt") -Value $sums -Encoding UTF8
Write-Ok "$($sums.Count) 个文件的校验和"

# ---- 8. zip ----
if ($Zip) {
    Write-Step "生成压缩包"
    $zipPath = Join-Path $OutputDir "$PackageName-$Stamp.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path $StageDir -DestinationPath $zipPath -CompressionLevel Optimal
    Write-Ok ("{0}  ({1:N0} B)" -f (Split-Path -Leaf $zipPath), (Get-Item $zipPath).Length)
}

# ---- 9. 汇总 ----
Write-Step "完成"
$totalSize = (Get-ChildItem $StageDir -Recurse -File | Measure-Object -Property Length -Sum).Sum
Write-Host ""
Write-Host "  包目录 : $StageDir" -ForegroundColor Green
Write-Host ("  总大小 : {0:N0} B" -f $totalSize)
Write-Host ""
Get-ChildItem $StageDir -Recurse | Sort-Object FullName | ForEach-Object {
    $rel = $_.FullName.Substring($StageDir.Length + 1)
    if ($_.PSIsContainer) { Write-Host "    $rel\" }
    else { Write-Host ("    {0,-56} {1,10:N0} B" -f $rel, $_.Length) }
}
Write-Host ""