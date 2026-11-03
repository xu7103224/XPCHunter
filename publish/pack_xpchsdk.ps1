# ============================================================================
# pack_xpchsdk.ps1 —— XpchSdk 发布打包
#
# 产品名：XpchSdk（内核能力 SDK）
# 命名约定：publish/pack_<产品>.ps1 + publish/publish_<产品>.bat
#           新增产品时复制本脚本改名，避免入口重名。
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
#
# 签名（默认签名，产出完整签名包）：
#   -NoSign             不签名，只打包（产物是未签名驱动）
#   -SignMode Local|Pfx 签名模式，默认 Local（本机证书库）
#   -CertName <name>    Local 模式证书 Subject 匹配串，默认 XPCSign2
#   -PfxPath <path>     Pfx 模式证书文件
#   -PfxPassword <pw>   Pfx 模式口令
#   -TimestampUrl <url> 时间戳服务，默认 DigiCert；传 "" 跳过
#
# 签名包在普通包基础上多出：
#   xpch.cer            驱动公钥证书（目标机装进受信任根后即可加载）
#   SIGNING.txt         签名与加载说明
#   install_driver.bat  驱动安装/启动/停止/卸载
# ============================================================================
[CmdletBinding()]
param(
    [string] $OutputDir = "",
    [string] $Config = "Release",
    [switch] $NoBuild,
    [switch] $Zip,
    [switch] $IncludeProbe,
    [switch] $NoSign,
    [ValidateSet("Local", "Pfx")][string] $SignMode = "Local",
    [string] $CertName = "XPCSign2",
    [string] $PfxPath = "",
    [string] $PfxPassword = "",
    [string] $TimestampUrl = "http://timestamp.digicert.com"
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
$SignScript = Join-Path $PublishDir "sign_xpchsdk.ps1"
$TemplateDir = Join-Path $PublishDir "templates"

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

# 产品标识：打包目录名与 VERSION.txt 首行都用它
$ProductName = "XpchSdk"

$Version    = Get-SdkVersion
$Stamp      = Get-Date -Format "yyyyMMdd-HHmmss"
$PackageName = "$ProductName-$Version"
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

# ---- 5. 驱动签名（对暂存副本签名，产出完整签名包） ----
$sysPath = Join-Path $StageDir (Join-Path "bin" "x64")
$sysPath = Join-Path $sysPath "XPCHunterDrv.sys"
$cerPath = Join-Path $StageDir "xpch.cer"
$sigInfo = @{
    Signer     = "<未签名>"
    Thumbprint = "-"
    NotBefore  = "-"
    NotAfter   = "-"
    Timestamp  = "-"
    Status     = "NotSigned"
}

if ($NoSign) {
    Write-Step "驱动签名"
    Write-Warn2 "已跳过签名（-NoSign）—— 目标机必须 testsigning on 才能加载"
} else {
    Write-Step "驱动签名"
    if (-not (Test-Path $SignScript)) {
        throw "缺少签名脚本: $SignScript"
    }

    $signArgs = @(
        "-SysPath", $sysPath,
        "-Mode", $SignMode,
        "-CertName", $CertName,
        "-TimestampUrl", $TimestampUrl,
        "-OutCer", $cerPath
    )
    if ($SignMode -eq "Pfx") {
        $signArgs += @("-PfxPath", $PfxPath)
        if ($PfxPassword) { $signArgs += @("-PfxPassword", $PfxPassword) }
    }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $SignScript @signArgs
    if ($LASTEXITCODE -ne 0) {
        throw "驱动签名失败（sign_xpchsdk.ps1 退出码 $LASTEXITCODE）"
    }

    # 采集签名信息，供 SIGNING.txt 使用
    $sig = Get-AuthenticodeSignature $sysPath
    if ($sig.SignerCertificate) {
        $sigInfo.Signer     = $sig.SignerCertificate.Subject
        $sigInfo.Thumbprint = $sig.SignerCertificate.Thumbprint
        $sigInfo.NotBefore  = $sig.SignerCertificate.NotBefore.ToString("yyyy-MM-dd")
        $sigInfo.NotAfter   = $sig.SignerCertificate.NotAfter.ToString("yyyy-MM-dd")
    }
    if ($sig.TimeStamperCertificate) {
        $sigInfo.Timestamp = $sig.TimeStamperCertificate.Subject
    }
    $sigInfo.Status = $sig.Status
    Write-Ok "签名状态: $($sig.Status)"
}

# ---- 5b. 放入签名包附属文件：证书、安装脚本、签名说明 ----
Write-Step "生成签名包附属文件"

if (-not $NoSign -and (Test-Path $cerPath)) {
    Write-Ok ("xpch.cer（{0} B）" -f (Get-Item $cerPath).Length)
} elseif (-not $NoSign) {
    Write-Warn2 "未生成 xpch.cer（签名脚本未导出证书）"
}

# 安装/卸载脚本
$installTpl = Join-Path $TemplateDir "install_driver.bat"
if (Test-Path $installTpl) {
    Copy-Item $installTpl (Join-Path $StageDir "install_driver.bat") -Force
    Write-Ok "install_driver.bat"
} else {
    Write-Warn2 "缺少模板: $installTpl"
}

# SIGNING.txt（从模板替换占位符）
$signingTpl = Join-Path $TemplateDir "SIGNING.txt"
if (Test-Path $signingTpl) {
    $note = switch ($sigInfo.Status) {
        "Valid"        { "证书链完整，目标机可直接加载（无需改启动配置）。" }
        "NotSigned"    { "驱动未签名。目标机必须开启 testsigning 才能加载。" }
        "UnknownError" { "使用自签名测试证书：签名块完整，但根证书不在本机信任库。`r`n目标机按下面「方式 A」或「方式 B」操作后即可加载。" }
        default        { "签名状态 $($sigInfo.Status)：$((Get-AuthenticodeSignature $sysPath).StatusMessage)" }
    }
    $txt = Get-Content $signingTpl -Raw -Encoding UTF8
    $txt = $txt.Replace("{{SIGNER}}",      $sigInfo.Signer)
    $txt = $txt.Replace("{{THUMBPRINT}}",  $sigInfo.Thumbprint)
    $txt = $txt.Replace("{{NOTBEFORE}}",   $sigInfo.NotBefore)
    $txt = $txt.Replace("{{NOTAFTER}}",    $sigInfo.NotAfter)
    $txt = $txt.Replace("{{TIMESTAMP}}",   $sigInfo.Timestamp)
    $txt = $txt.Replace("{{SIGSTATUS}}",   $sigInfo.Status)
    $txt = $txt.Replace("{{SIGSTATUSNOTE}}", $note)
    Set-Content -Path (Join-Path $StageDir "SIGNING.txt") -Value $txt -Encoding UTF8
    Write-Ok "SIGNING.txt"
} else {
    Write-Warn2 "缺少模板: $signingTpl"
}

# ---- 6. VERSION.txt ----
Write-Step "生成 VERSION.txt"

$verLines = @(
    "$ProductName $Version",
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
    "  xpch.cer                    驱动公钥证书（已签名时提供）",
    "  SIGNING.txt                 签名与加载说明（已签名时提供）",
    "  install_driver.bat          驱动安装脚本",
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
    "签名包内容（除上述常规内容外）：",
    "  xpch.cer                    驱动公钥证书",
    "  SIGNING.txt                 签名信息与加载方式说明",
    "  install_driver.bat          驱动安装/启动/停止/卸载",
    "",
    "快速加载驱动（管理员权限）：",
    "  install_driver.bat install",
    "",
    "  如返回 577（签名无法验证），任选其一后重试：",
    "    a) 开启测试签名：bcdedit /set testsigning on && shutdown /r /t 0",
    "    b) 安装本包证书：",
    "         certutil -addstore -f Root xpch.cer",
    "         certutil -addstore -f TrustedPublisher xpch.cer",
    "",
    "驱动签名信息：",
    ("  签名者  : " + $sigInfo.Signer),
    ("  指纹    : " + $sigInfo.Thumbprint),
    ("  有效期  : " + $sigInfo.NotBefore + " ~ " + $sigInfo.NotAfter),
    ("  时间戳  : " + $sigInfo.Timestamp),
    ("  状态    : " + $sigInfo.Status)
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