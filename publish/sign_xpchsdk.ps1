# ============================================================================
# sign_xpchsdk.ps1 —— XPCHunterDrv.sys 驱动签名
#
# 两种签名模式：
#   Local  使用本机证书库里的证书（默认 CN=XPCSign2 测试证书）
#   Pfx    使用 .pfx 文件（正式签名时用，配 -PfxPath/-PfxPassword）
#
# 签名后做三件事：
#   1. 带时间戳（默认 DigiCert，可用 -TimestampUrl 覆盖）
#   2. 用 signtool verify 校验签名块完整性
#   3. 导出公钥证书 .cer，供目标机安装到「受信任的根」后加载驱动
#
# 参数：
#   -SysPath <path>       要签名的 .sys 路径（必填）
#   -Mode Local|Pfx       签名模式，默认 Local
#   -CertName <name>      Local 模式：证书 Subject 匹配串，默认 XPCSign2
#   -PfxPath <path>       Pfx 模式：证书文件
#   -PfxPassword <pw>     Pfx 模式：证书口令
#   -TimestampUrl <url>   时间戳服务，默认 http://timestamp.digicert.com
#                         传空字符串 "" 可跳过时间戳
#   -OutCer <path>        导出的公钥证书路径；不给则放在 sys 同目录同名 .cer
#
# 退出码：0 成功；1 签名失败；2 找不到证书；3 校验失败
# ============================================================================
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $SysPath,
    [ValidateSet("Local", "Pfx")][string] $Mode = "Local",
    [string] $CertName = "XPCSign2",
    [string] $PfxPath = "",
    [string] $PfxPassword = "",
    [string] $TimestampUrl = "http://timestamp.digicert.com",
    [string] $OutCer = ""
)

$ErrorActionPreference = "Stop"

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    $m" -ForegroundColor Green }
function Write-Warn3($m){ Write-Host "    $m" -ForegroundColor Yellow }

# ---- 输入校验 ----
if (-not (Test-Path $SysPath)) {
    Write-Host "ERROR: 找不到待签名文件 $SysPath" -ForegroundColor Red
    exit 1
}
$SysPath = (Resolve-Path $SysPath).Path

# ---- 定位 signtool ----
function Find-SignTool {
    $roots = @(
        "C:\Program Files (x86)\Windows Kits\10\bin",
        "C:\Program Files\Windows Kits\10\bin"
    )
    foreach ($r in $roots) {
        if (-not (Test-Path $r)) { continue }
        $exe = Get-ChildItem $r -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
               Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
               Sort-Object FullName -Descending |
               Select-Object -First 1
        if ($exe) { return $exe.FullName }
    }
    return $null
}

$Signtool = Find-SignTool
if (-not $Signtool) {
    Write-Host "ERROR: 找不到 x64 signtool.exe（需要 Windows SDK）" -ForegroundColor Red
    exit 1
}

Write-Step "驱动签名"
Write-Ok "文件   : $SysPath"
Write-Ok "工具   : $Signtool"
Write-Ok "模式   : $Mode"

# ---- 1. 解析证书并决定签名参数 ----
$signArgs = @("sign", "/fd", "SHA256")

switch ($Mode) {
    "Local" {
        $cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
                Where-Object { $_.Subject -like "*$CertName*" -and $_.HasPrivateKey } |
                Sort-Object NotAfter -Descending |
                Select-Object -First 1
        if (-not $cert) {
            Write-Host "ERROR: 本机证书库中找不到含私钥、Subject 匹配 '*$CertName*' 的证书" -ForegroundColor Red
            Write-Host "       可用证书：" -ForegroundColor Yellow
            Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
                Where-Object { $_.HasPrivateKey } |
                ForEach-Object { Write-Host "         $($_.Subject)  [$($_.Thumbprint)]" }
            exit 2
        }
        Write-Ok "证书   : $($cert.Subject)"
        Write-Ok "指纹   : $($cert.Thumbprint)"
        Write-Ok "有效期 : $($cert.NotBefore.ToString('yyyy-MM-dd')) ~ $($cert.NotAfter.ToString('yyyy-MM-dd'))"
        if ($cert.NotAfter -lt (Get-Date).AddDays(30)) {
            Write-Warn3 "证书将在 30 天内过期，请及时更换"
        }
        $signArgs += @("/sha1", $cert.Thumbprint)
        $exportCert = $cert
    }
    "Pfx" {
        if (-not $PfxPath -or -not (Test-Path $PfxPath)) {
            Write-Host "ERROR: Pfx 模式需要 -PfxPath 指向存在的 .pfx 文件" -ForegroundColor Red
            exit 2
        }
        $PfxPath = (Resolve-Path $PfxPath).Path
        Write-Ok "证书   : $PfxPath"
        $signArgs += @("/f", $PfxPath)
        if ($PfxPassword) { $signArgs += @("/p", $PfxPassword) }
        if ($PfxPassword) {
            $sec = ConvertTo-SecureString $PfxPassword -AsPlainText -Force
            $exportCert = Get-PfxCertificate -FilePath $PfxPath -Password $sec
        } else {
            $exportCert = Get-PfxCertificate -FilePath $PfxPath
        }
    }
}

# ---- 2. 时间戳 ----
if ($TimestampUrl) {
    $signArgs += @("/tr", $TimestampUrl, "/td", "SHA256")
    Write-Ok "时间戳 : $TimestampUrl"
} else {
    Write-Warn3 "跳过时间戳（-TimestampUrl 为空）——证书过期后签名将失效"
}

# ---- 3. 执行签名 ----
$signArgs += $SysPath
Write-Step "执行 signtool sign"
& $Signtool @signArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: signtool sign 失败（退出码 $LASTEXITCODE）" -ForegroundColor Red
    exit 1
}

# ---- 4. 校验 ----
Write-Step "校验签名"
# signtool 对自签名证书会把链错误写 stderr；在 PS 里这会被当成
# NativeCommandError 终止脚本。用临时降级 ErrorActionPreference 捕获退出码。
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $Signtool verify /pa /v $SysPath 2>&1 | Out-Null
$verifyRc = $LASTEXITCODE
$ErrorActionPreference = $prevEAP

$sig = Get-AuthenticodeSignature $SysPath
switch ($sig.Status) {
    "Valid" {
        Write-Ok "签名有效，证书链完整"
    }
    "UnknownError" {
        # 自签名测试证书的典型结果：签名块完整，根证书不在本机信任库
        Write-Warn3 "签名块完整，但根证书不受本机信任（自签名测试证书属正常）"
        Write-Warn3 "目标机需安装本包的 .cer 到「受信任的根」，或开启 testsigning"
    }
    default {
        Write-Host "ERROR: 签名校验失败，状态 $($sig.Status)" -ForegroundColor Red
        Write-Host "       $($sig.StatusMessage)" -ForegroundColor Red
        exit 3
    }
}
Write-Ok "签名者 : $($sig.SignerCertificate.Subject)"
if ($sig.TimeStamperCertificate) {
    Write-Ok "时间戳 : $($sig.TimeStamperCertificate.Subject)"
}

# signtool verify /pa 对自签名证书会返回非 0，这不是失败
if ($verifyRc -ne 0 -and $sig.Status -eq "Valid") {
    Write-Warn3 "signtool verify /pa 返回 $verifyRc（策略校验，非签名块问题）"
}

# ---- 5. 导出公钥证书 ----
if (-not $OutCer) {
    $OutCer = [System.IO.Path]::ChangeExtension($SysPath, ".cer")
}
Write-Step "导出公钥证书"
if (Test-Path $OutCer) { Remove-Item $OutCer -Force }
if ($exportCert) {
    Export-Certificate -Cert $exportCert -FilePath $OutCer -Type CERT | Out-Null
    Write-Ok "$OutCer  ($((Get-Item $OutCer).Length) B)"
} else {
    Write-Warn3 "未能取得证书对象，跳过 .cer 导出"
}

Write-Step "完成"
Write-Host ""
exit 0