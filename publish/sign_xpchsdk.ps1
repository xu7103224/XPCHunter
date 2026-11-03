# ============================================================================
# sign_xpchsdk.ps1 —— XPCHunterDrv 驱动签名与驱动包目录生成
#
# 只产出「待打包的驱动包目录」，不生成 CAB。CAB 由使用者自行打包。
#
# 产出目录内容（可直接用 makecab 或任何工具打包成 CAB）：
#   <PackageDir>/
#     ├── XPCHunterDrv.inf     安装描述（DriverVer 已替换为实际值）
#     ├── XPCHunterDrv.sys     驱动本体（已签名）
#     └── XPCHunterDrv.cat     目录文件（已签名，覆盖 INF + SYS）
#
# 之所以不在这里打 CAB：CAB 里除了这三个文件往往还要放别的（readme、
# 多架构 SYS 等），打包方式和目标环境各家不同，交给使用者决定。
#
# 两种签名模式：
#
#   [Release] 提交微软签名
#       用 EV 证书签 SYS 和 CAT。产出的目录打成 CAB 后上传微软硬件开发者
#       中心回签。最终用户的机器无需安装证书、无需开启测试签名。
#
#   [Local]   本地测试
#       用自签名测试证书签。目标机需要 testsigning 或安装导出证书才能加载。
#       产物仅用于本机/实验机验证功能，不可对外分发。
#
# 参数：
#   -SysPath <path>        驱动 SYS 路径（必填）
#   -PackageDir <path>     产物目录（必填），已存在则清空重建
#   -Mode Release|Local    默认 Release
#
#   Release 模式：
#     -PfxPath <path>      EV 代码签名证书（.pfx），必需
#     -PfxPassword <pw>    证书口令
#
#   Local 模式：
#     -CertName <name>     本机证书 Subject 匹配串，默认 XPCSign2
#     -OutCer              额外导出公钥证书 test_cert.cer 到 PackageDir
#
#   通用：
#     -TimestampUrl <url>  时间戳服务，默认 http://timestamp.digicert.com
#                         传 "" 跳过
#     -InfTemplate <path>  INF 模板，默认 templates\XPCHunterDrv.inf
#     -Inf2CatPath <path>  Inf2Cat.exe（自动查找）
#     -DriverVerDate        INF 的 DriverVer 日期，默认今天 MM/dd/yyyy
#     -DriverVerVersion     INF 的 DriverVer 版本，默认 1.2.0.0
#
# 退出码：0 成功；1 失败；2 证书问题
# ============================================================================
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $SysPath,
    [Parameter(Mandatory = $true)][string] $PackageDir,
    [ValidateSet("Release", "Local")][string] $Mode = "Release",

    [string] $PfxPath = "",
    [string] $PfxPassword = "",
    [string] $CertName = "XPCSign2",
    [switch] $OutCer,

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
$SysName = Split-Path -Leaf $SysPath

# ---- 定位 signtool ----
function Find-SignTool {
    $roots = @(
        "C:\Program Files (x86)\Windows Kits\10\bin",
        "C:\Program Files\Windows Kits\10\bin"
    )
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

# ---- 定位 Inf2Cat ----
if (-not $Inf2CatPath) {
    foreach ($r in @("C:\Program Files (x86)\Windows Kits\10\bin",
                     "C:\Program Files\Windows Kits\10\bin")) {
        if (-not (Test-Path $r)) { continue }
        $exe = Get-ChildItem $r -Recurse -Filter Inf2Cat.exe -ErrorAction SilentlyContinue |
               Sort-Object FullName -Descending | Select-Object -First 1
        if ($exe) { $Inf2CatPath = $exe.FullName; break }
    }
}
if (-not $Inf2CatPath -or -not (Test-Path $Inf2CatPath)) {
    Write-Host "ERROR: 找不到 Inf2Cat.exe（需要 Windows 10 SDK）" -ForegroundColor Red
    exit 1
}

Write-Step "XPCHunterDrv 签名"
Write-Ok "模式     : $Mode"
Write-Ok "驱动     : $SysPath"
Write-Ok "输出目录 : $PackageDir"
Write-Ok "signtool : $Signtool"
Write-Ok "Inf2Cat  : $Inf2CatPath"

# ---- 解析签名凭据 ----
$certThumbprint = $null
$exportCert = $null

switch ($Mode) {
    "Release" {
        if (-not $PfxPath) {
            Write-Host "ERROR: Release 模式需要 -PfxPath 指向 EV 代码签名证书" -ForegroundColor Red
            Write-Host "       仅本机测试请用 -Mode Local" -ForegroundColor Yellow
            exit 2
        }
        if (-not (Test-Path $PfxPath)) {
            Write-Host "ERROR: 找不到证书 $PfxPath" -ForegroundColor Red
            exit 2
        }
        $PfxPath = (Resolve-Path $PfxPath).Path
        if ($PfxPassword) {
            $sec = ConvertTo-SecureString $PfxPassword -AsPlainText -Force
            $exportCert = Get-PfxCertificate -FilePath $PfxPath -Password $sec
        } else {
            $exportCert = Get-PfxCertificate -FilePath $PfxPath
        }
        if ($exportCert) {
            Write-Ok "签名者   : $($exportCert.Subject)"
            Write-Ok "有效期   : $($exportCert.NotBefore.ToString('yyyy-MM-dd')) ~ $($exportCert.NotAfter.ToString('yyyy-MM-dd'))"
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
        Write-Ok "证书     : $($c.Subject)"
        Write-Ok "指纹     : $($c.Thumbprint)"
        Write-Ok "有效期   : $($c.NotBefore.ToString('yyyy-MM-dd')) ~ $($c.NotAfter.ToString('yyyy-MM-dd'))"
        Write-Warn3 "本模式产物仅供内部测试，不可对外分发"
    }
}

if ($TimestampUrl) {
    Write-Ok "时间戳   : $TimestampUrl"
} else {
    Write-Warn3 "跳过时间戳 —— 证书过期后签名会失效"
}

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

# ============================================================================
# 组装驱动包目录
# ============================================================================
$pkgFull = [System.IO.Path]::GetFullPath($PackageDir)
if (Test-Path $pkgFull) {
    Write-Step "清空旧目录"
    Remove-Item $pkgFull -Recurse -Force
    Write-Ok $pkgFull
}
New-Item -ItemType Directory -Path $pkgFull -Force | Out-Null

if (-not $InfTemplate) {
    $InfTemplate = Join-Path (Join-Path $PSScriptRoot "templates") "XPCHunterDrv.inf"
}
if (-not (Test-Path $InfTemplate)) {
    Write-Host "ERROR: 找不到 INF 模板 $InfTemplate" -ForegroundColor Red
    exit 1
}
if (-not $DriverVerDate)    { $DriverVerDate = (Get-Date).ToString("MM/dd/yyyy") }
if (-not $DriverVerVersion) { $DriverVerVersion = "1.2.0.0" }

# ---- 1. SYS（先签名，再做 CAT，这样 CAT 覆盖的是已签名文件） ----
Write-Step "1/4 签名 SYS"
$sysDst = Join-Path $pkgFull $SysName
Copy-Item $SysPath $sysDst -Force
$a = Get-SignArgs $sysDst
& $Signtool @a
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: SYS 签名失败（退出码 $LASTEXITCODE）" -ForegroundColor Red
    exit 1
}
Write-Ok ("$SysName  ({0:N0} B)" -f (Get-Item $sysDst).Length)

# ---- 2. INF（展开模板，DriverVer 填实际值） ----
Write-Step "2/4 生成 INF"
$infText = Get-Content $InfTemplate -Raw -Encoding UTF8
$infText = $infText -replace '@DriverVerDate@',    $DriverVerDate
$infText = $infText -replace '@DriverVerVersion@', $DriverVerVersion
$infDst = Join-Path $pkgFull "XPCHunterDrv.inf"
Set-Content -Path $infDst -Value $infText -Encoding ASCII
Write-Ok ("XPCHunterDrv.inf  DriverVer=$DriverVerDate,$DriverVerVersion  ({0:N0} B)" -f (Get-Item $infDst).Length)

# ---- 3. CAT（Inf2Cat 对目录内 INF+SYS 算哈希生成） ----
Write-Step "3/4 生成 CAT"
& $Inf2CatPath /driver:$pkgFull /os:10_X64 | Out-Null
$catDst = Get-ChildItem $pkgFull -Filter "*.cat" -ErrorAction SilentlyContinue |
          Select-Object -First 1 -ExpandProperty FullName
if (-not $catDst) {
    Write-Host "ERROR: Inf2Cat 未生成 .cat" -ForegroundColor Red
    Write-Host "       常见原因：INF 语法错误、缺 [SourceDisksFiles]、SYS 文件名不匹配" -ForegroundColor Yellow
    exit 1
}
Write-Ok ("{0}  ({1:N0} B)" -f (Split-Path -Leaf $catDst), (Get-Item $catDst).Length)

# ---- 4. 签名 CAT ----
Write-Step "4/4 签名 CAT"
$a = Get-SignArgs $catDst
& $Signtool @a
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: CAT 签名失败（退出码 $LASTEXITCODE）" -ForegroundColor Red
    exit 1
}

# ---- 可选：导出证书（Local 模式） ----
if ($Mode -eq "Local" -and $OutCer) {
    if ($exportCert) {
        $cerOut = Join-Path $pkgFull "test_cert.cer"
        Export-Certificate -Cert $exportCert -FilePath $cerOut -Type CERT | Out-Null
        Write-Ok "test_cert.cer（本机测试用）"
    }
}

# ---- 校验 ----
Write-Step "校验签名"
foreach ($f in @($sysDst, $catDst)) {
    $s = Get-AuthenticodeSignature $f
    $name = Split-Path -Leaf $f
    switch ($s.Status) {
        "Valid"        { Write-Ok ("{0,-22} 证书链完整" -f $name) }
        "UnknownError" { Write-Ok ("{0,-22} 已签名（根证书不在本机信任库，测试证书属正常）" -f $name) }
        "NotSigned"    { Write-Warn3 ("{0,-22} 未签名！" -f $name) }
        default        { Write-Warn3 ("{0,-22} 状态: {1}" -f $name, $s.Status) }
    }
}

# ---- 结果 ----
Write-Step "完成"
Write-Host ""
Write-Host "驱动包目录：$pkgFull" -ForegroundColor Green
Get-ChildItem $pkgFull -File | Sort-Object Name | ForEach-Object {
    Write-Host ("    {0,-24} {1,10:N0} B" -f $_.Name, $_.Length)
}
Write-Host ""
if ($Mode -eq "Release") {
    Write-Host "下一步：" -ForegroundColor Cyan
    Write-Host "  1. 把本目录打成 CAB："
    Write-Host "       makecab /d CabinetNameTemplate=XPCHunterDrv.cab ^"
    Write-Host "               /d DiskDirectoryTemplate=<输出目录> ^"
    Write-Host "               XPCHunterDrv.inf XPCHunterDrv.sys xpchunterdrv.cat"
    Write-Host "     （或用任何能生成 MSZIP cabinet 的工具）"
    Write-Host "  2. 上传 CAB 到 https://partner.microsoft.com/dashboard/hardware"
    Write-Host "  3. 微软回签后下载签名版 CAB 分发给最终用户"
    Write-Host "     用户机器无需装证书、无需开测试签名"
} else {
    Write-Host "本地测试安装：" -ForegroundColor Yellow
    Write-Host "  目标机先满足其一："
    Write-Host "    a) bcdedit /set testsigning on  然后重启"
    Write-Host "    b) 把 test_cert.cer 装进「受信任的根」+「受信任的发布者」"
    Write-Host "  然后：pnputil /add-driver <本目录>\XPCHunterDrv.inf /install"
    Write-Host "       sc start XPCHDrv"
    Write-Host "  （产物仅供内部验证，不可对外分发）"
}
Write-Host ""
exit 0