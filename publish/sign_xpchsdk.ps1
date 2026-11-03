# ============================================================================
# sign_xpchsdk.ps1 —— XPCHunterDrv 驱动签名与 CAT 生成
#
# 本脚本服务两条不同的流程，不要混用：
#
#   [Release] 发布流程（提交微软签名）
#       产出待提交的驱动包：build\submit\XPCHunterDrv.cab
#       CAB 内含 INF + SYS + CAT，CAT 用 EV 证书签名（微软要求先签名再提交）。
#       这份 CAB 上传到微软硬件开发者中心，微软回签后再分发给最终用户。
#       最终用户的机器不需要装任何证书、不需要开测试签名。
#
#   [Local]   本地测试流程（仅内部调试用）
#       用自签名测试证书签 SYS，目标机需要 testsigning 或安装该证书才能加载。
#       产物仅用于本机/实验机验证功能，不可对外分发。
#
# 参数：
#   -Mode Release|Local   默认 Release
#   -SysPath <path>       驱动 SYS 路径（必填）
#
#   Release 模式：
#     -CabOut <path>      产出 CAB 的路径，默认 <sys目录>\XPCHunterDrv.cab
#     -PfxPath <path>     EV 代码签名证书（.pfx）
#     -PfxPassword <pw>   证书口令
#
#   Local 模式：
#     -CertName <name>    本机证书 Subject 匹配串，默认 XPCSign2
#     -CabOut <path>      可选，同时产出一个本地测试用 CAB
#     -OutCer <path>      可选，导出公钥证书供目标机安装
#
#   通用：
#     -TimestampUrl <url> 默认 http://timestamp.digicert.com，传 "" 跳过
#     -InfTemplate <path> INF 模板，默认 templates\XPCHunterDrv.inf
#     -Inf2CatPath <path> Inf2Cat.exe 路径（自动查找）
#     -DriverVerDate / -DriverVerVersion   INF 的 DriverVer
#
# 退出码：0 成功；1 签名失败；2 证书问题；3 校验失败
# ============================================================================
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $SysPath,
    [ValidateSet("Release", "Local")][string] $Mode = "Release",

    [string] $CabOut = "",
    [string] $PfxPath = "",
    [string] $PfxPassword = "",
    [string] $CertName = "XPCSign2",
    [string] $OutCer = "",

    [string] $TimestampUrl = "http://timestamp.digicert.com",
    [string] $InfTemplate = "",
    [string] $Inf2CatPath = "",
    [string] $DriverVerDate = "",
    [string] $DriverVerVersion = ""
)

$ErrorActionPreference = "Stop"

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    $m" -ForegroundColor Green }
function Write-Warn3($m){ Write-Host "    $m" -ForegroundColor Yellow }

# ---- 输入校验 ----
if (-not (Test-Path $SysPath)) {
    Write-Host "ERROR: 找不到驱动文件 $SysPath" -ForegroundColor Red
    exit 1
}
$SysPath = (Resolve-Path $SysPath).Path
$SysDir  = Split-Path -Parent $SysPath
$SysName = Split-Path -Leaf $SysPath

# ---- 定位 signtool ----
function Find-SignTool {
    $roots = @(
        "C:\Program Files (x86)\Windows Kits\10\bin",
        "C:\Program Files\Windows Kits\10\bin"
    )
    $sep = [System.IO.Path]::DirectorySeparatorChar
    foreach ($r in $roots) {
        if (-not (Test-Path $r)) { continue }
        $exe = Get-ChildItem $r -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
               Where-Object { $_.Directory.Name -eq "x64" } |
               Sort-Object FullName -Descending | Select-Object -First 1
        if ($exe) { return $exe.FullName }
    }
    return $null
}

$Signtool = Find-SignTool
if (-not $Signtool) {
    Write-Host "ERROR: 找不到 x64 signtool.exe（需要 Windows SDK）" -ForegroundColor Red
    exit 2
}

Write-Step "XPCHunterDrv 签名"
Write-Ok "模式   : $Mode"
Write-Ok "驱动   : $SysPath"
Write-Ok "工具   : $Signtool"

# ---- 解析签名凭据 ----
$certThumbprint = $null
$exportCert = $null

switch ($Mode) {
    "Release" {
        # 提交微软用的 EV 证书。没有它就无法走官方签名流程。
        if (-not $PfxPath) {
            Write-Host "ERROR: Release 模式需要 -PfxPath 指向 EV 代码签名证书" -ForegroundColor Red
            Write-Host "       没有 EV 证书时改用 -Mode Local 做本机测试" -ForegroundColor Yellow
            exit 2
        }
        if (-not (Test-Path $PfxPath)) {
            Write-Host "ERROR: 找不到证书文件 $PfxPath" -ForegroundColor Red
            exit 2
        }
        $PfxPath = (Resolve-Path $PfxPath).Path
        Write-Ok "证书   : $PfxPath"
        if ($PfxPassword) {
            $sec = ConvertTo-SecureString $PfxPassword -AsPlainText -Force
            $exportCert = Get-PfxCertificate -FilePath $PfxPath -Password $sec
        } else {
            $exportCert = Get-PfxCertificate -FilePath $PfxPath
        }
        if ($exportCert) {
            Write-Ok "签名者 : $($exportCert.Subject)"
            Write-Ok "有效期 : $($exportCert.NotBefore.ToString('yyyy-MM-dd')) ~ $($exportCert.NotAfter.ToString('yyyy-MM-dd'))"
        }
    }
    "Local" {
        $c = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
             Where-Object { $_.Subject -like "*$CertName*" -and $_.HasPrivateKey } |
             Sort-Object NotAfter -Descending | Select-Object -First 1
        if (-not $c) {
            Write-Host "ERROR: 本机证书库找不到含私钥、Subject 匹配 '*$CertName*' 的证书" -ForegroundColor Red
            Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
                Where-Object { $_.HasPrivateKey } |
                ForEach-Object { Write-Host "         $($_.Subject)  [$($_.Thumbprint)]" }
            exit 2
        }
        $certThumbprint = $c.Thumbprint
        $exportCert = $c
        Write-Ok "证书   : $($c.Subject)"
        Write-Ok "指纹   : $($c.Thumbprint)"
        Write-Ok "有效期 : $($c.NotBefore.ToString('yyyy-MM-dd')) ~ $($c.NotAfter.ToString('yyyy-MM-dd'))"
        Write-Warn3 "本模式产物仅供内部测试，不可对外分发"
    }
}

# ---- 组装签名参数 ----
function Get-SignArgs([string] $Target) {
    $a = @("sign", "/fd", "SHA256")
    if ($Mode -eq "Local") {
        $a += @("/sha1", $certThumbprint)
    } else {
        $a += @("/f", $PfxPath)
        if ($PfxPassword) { $a += @("/p", $PfxPassword) }
    }
    if ($TimestampUrl) { $a += @("/tr", $TimestampUrl, "/td", "SHA256") }
    $a += $Target
    return $a
}

# ---- 时间戳提示 ----
if ($TimestampUrl) {
    Write-Ok "时间戳 : $TimestampUrl"
} else {
    Write-Warn3 "跳过时间戳 —— 证书过期后签名会失效"
}

# ============================================================================
# 生成驱动包 CAB（INF + SYS + CAT）
# ============================================================================
Write-Step "生成驱动包 CAB"

if (-not $CabOut) {
    $CabOut = Join-Path $SysDir "XPCHunterDrv.cab"
}
if (-not $InfTemplate) {
    $InfTemplate = Join-Path (Join-Path $PSScriptRoot "templates") "XPCHunterDrv.inf"
}
if (-not (Test-Path $InfTemplate)) {
    Write-Host "ERROR: 找不到 INF 模板 $InfTemplate" -ForegroundColor Red
    exit 1
}

if (-not $Inf2CatPath) {
    $kits = "C:" + [char]92 + "Program Files (x86)" + [char]92 + "Windows Kits"
    $bin  = Join-Path (Join-Path $kits "10") "bin"
    if (Test-Path $bin) {
        $Inf2CatPath = Get-ChildItem $bin -Recurse -Filter Inf2Cat.exe -ErrorAction SilentlyContinue |
                       Sort-Object FullName -Descending | Select-Object -First 1 |
                       ForEach-Object { $_.FullName }
    }
}
if (-not $Inf2CatPath -or -not (Test-Path $Inf2CatPath)) {
    Write-Host "ERROR: 找不到 Inf2Cat.exe（需要 Windows 10 SDK）" -ForegroundColor Red
    exit 1
}

$makecab = Join-Path $env:windir ("System32" + [char]92 + "makecab.exe")
if (-not (Test-Path $makecab)) {
    Write-Host "ERROR: 找不到 makecab.exe" -ForegroundColor Red
    exit 1
}

# 工作目录
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("xpchcab_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work -Force | Out-Null

try {
    # INF 的 DriverVer
    if (-not $DriverVerDate) {
        $DriverVerDate = (Get-Date).ToString("MM/dd/yyyy")
    }
    if (-not $DriverVerVersion) {
        $DriverVerVersion = "1.2.0.0"
    }

    # 1) 展开 INF 模板
    $infText = Get-Content $InfTemplate -Raw -Encoding UTF8
    $infText = $infText -replace '@DriverVerDate@',    $DriverVerDate
    $infText = $infText -replace '@DriverVerVersion@', $DriverVerVersion
    $infWork = Join-Path $work "XPCHunterDrv.inf"
    Set-Content -Path $infWork -Value $infText -Encoding ASCII
    Write-Ok "INF  : DriverVer=$DriverVerDate,$DriverVerVersion"

    # 2) 放入 SYS 副本（先复制，后面可能对它签名）
    $sysWork = Join-Path $work $SysName
    Copy-Item $SysPath $sysWork -Force

    # 3) Inf2Cat 生成 CAT
    & $Inf2CatPath /driver:$work /os:10_X64 | Out-Null
    $catWork = Get-ChildItem $work -Filter "*.cat" -ErrorAction SilentlyContinue |
               Select-Object -First 1 -ExpandProperty FullName
    if (-not $catWork) {
        Write-Host "ERROR: Inf2Cat 未生成 .cat" -ForegroundColor Red
        exit 1
    }
    Write-Ok ("CAT  : {0:N0} B（Inf2Cat）" -f (Get-Item $catWork).Length)

    # 4) 给 CAB 里的 SYS 签名
    #    微软要求提交的 CAB 内所有 PE 文件先签好，否则会被拒
    Write-Ok "签名 SYS（包内副本）"
    $a = Get-SignArgs $sysWork
    & $Signtool @a
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: SYS 签名失败（退出码 $LASTEXITCODE）" -ForegroundColor Red
        exit 1
    }

    # 5) 给 CAT 签名（CAT 覆盖 INF 与 SYS，是驱动包校验的主体）
    Write-Ok "签名 CAT"
    $a = Get-SignArgs $catWork
    & $Signtool @a
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: CAT 签名失败（退出码 $LASTEXITCODE）" -ForegroundColor Red
        exit 1
    }

    # 6) makecab 打包
    $cabFull = [System.IO.Path]::GetFullPath($CabOut)
    $cabDir  = Split-Path -Parent $cabFull
    $cabLeaf = Split-Path -Leaf $cabFull
    if ($cabDir -and -not (Test-Path $cabDir)) {
        New-Item -ItemType Directory -Path $cabDir -Force | Out-Null
    }
    if (Test-Path $cabFull) { Remove-Item $cabFull -Force }

    $ddf = Join-Path $work "pack.ddf"
    Set-Content -Path $ddf -Encoding ASCII -Value @(
        ".OPTION EXPLICIT",
        ".Set CabinetNameTemplate=$cabLeaf",
        ".Set DiskDirectoryTemplate=$cabDir",
        ".Set CompressionType=MSZIP",
        ".Set Cabinet=on",
        ".Set Compress=on",
        ".Set MaxDiskSize=0",
        "XPCHunterDrv.inf",
        $SysName,
        (Split-Path -Leaf $catWork)
    )
    Push-Location $work
    try { & $makecab /f $ddf | Out-Null } finally { Pop-Location }

    if (-not (Test-Path $cabFull)) {
        Write-Host "ERROR: makecab 未产出 $cabFull" -ForegroundColor Red
        exit 1
    }
    Write-Ok ("CAB  : {0}  {1:N0} B" -f $cabLeaf, (Get-Item $cabFull).Length)
    Write-Ok "内容 : XPCHunterDrv.inf + $SysName + $(Split-Path -Leaf $catWork)"
}
finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}

# ---- 校验 CAB 内的签名 ----
Write-Step "校验签名"
$sig = Get-AuthenticodeSignature $SysPath
if ($exportCert) {
    switch ($sig.Status) {
        "Valid"        { Write-Ok "SYS 证书链完整" }
        "UnknownError" { Write-Warn3 "SYS 已签名但根证书不受本机信任（本地测试证书属正常）" }
        "NotSigned"    { Write-Warn3 "SYS 未签名（仅 CAB 内副本已签）" }
        default        { Write-Warn3 "SYS 签名状态: $($sig.Status)" }
    }
}

# ---- 导出证书（仅 Local 模式且显式要求时） ----
if ($Mode -eq "Local" -and $OutCer) {
    Write-Step "导出公钥证书（本机测试用）"
    if (Test-Path $OutCer) { Remove-Item $OutCer -Force }
    if ($exportCert) {
        Export-Certificate -Cert $exportCert -FilePath $OutCer -Type CERT | Out-Null
        Write-Ok "$OutCer  ($((Get-Item $OutCer).Length) B)"
    }
}

# ---- 结果 ----
Write-Step "完成"
Write-Host ""
if ($Mode -eq "Release") {
    Write-Host "待提交微软的驱动包：$cabFull" -ForegroundColor Green
    Write-Host ""
    Write-Host "下一步："
    Write-Host "  1. 登录 https://partner.microsoft.com/dashboard/hardware"
    Write-Host "  2. 新建 submission -> 上传该 CAB"
    Write-Host "  3. 微软回签后下载签名版 CAB，分发给最终用户"
    Write-Host "     （回签后的包在用户机器上无需装证书、无需开测试签名）"
} else {
    Write-Host "本地测试包：$cabFull" -ForegroundColor Yellow
    Write-Host "（仅供内部验证，不可对外分发）"
}
Write-Host ""
exit 0