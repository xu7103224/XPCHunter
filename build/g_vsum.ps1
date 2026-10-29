$out = 'C:\Users\Public\vsum.txt'
function Parse-AB([string]$path) {
    $res = @{}
    $cur = $null
    foreach ($line in Get-Content $path -Encoding UTF8) {
        if ($line -match '^CMD\s+(0x[0-9A-Fa-f]+)\s+INSZ=(\d+)\s+OUTSZ=(\d+)\s+RES=(\S+)\s+(\S+)\s+ERR=(\S+)\s+HDRLEN=(\d+)') {
            $cur = $matches[1].ToUpper()
            $res[$cur] = @{ Res = $matches[4]; St = $matches[5]; Out = '' }
        } elseif ($line -match '^OUT\s+(\S+)' -and $cur) {
            $v = $matches[1]
            if ($v -ne '-') { $res[$cur].Out = $v }
            $cur = $null
        }
    }
    return $res
}
$o = Parse-AB 'C:\Users\Public\gw_orig.txt'
$m = Parse-AB 'C:\Users\Public\gv_mine.txt'
Add-Content $out "=== Verifier 轮 vs 原版基线 ==="
Add-Content $out "orig=$($o.Count) verifier-mine=$($m.Count)"
$nSame = 0; $nDiff = 0
foreach ($k in ($o.Keys | Sort-Object)) {
    if (-not $m.ContainsKey($k)) { Add-Content $out "$k MISSING"; continue }
    if ($o[$k].Res -ne $m[$k].Res -or $o[$k].St -ne $m[$k].St) { Add-Content $out "$k STATUS-DIFF resO=$($o[$k].Res) resM=$($m[$k].Res)"; continue }
    if ($o[$k].Out -ceq $m[$k].Out) { $nSame++ } else { $nDiff++; Add-Content $out "$k DIFF lenO=$($o[$k].Out.Length/2) lenM=$($m[$k].Out.Length/2)" }
}
Add-Content $out "SAME=$nSame DIFF=$nDiff"
Add-Content $out "=== 0x031 x3 自稳定（首记录节点） ==="
foreach ($f in @('s031_1','s031_2','s031_3')) {
    $p = "C:\Users\Public\$f.txt"
    if (Test-Path $p) {
        $l = (Get-Content $p -Encoding UTF8 | Select-String -Pattern '^\s+0000:').Line
        Add-Content $out "$f $l"
    } else { Add-Content $out "$f MISSING" }
}
Add-Content $out "=== 0x0D4 x2 自稳定（长度+计数+首16B） ==="
foreach ($f in @('s0d4_1','s0d4_2')) {
    $p = "C:\Users\Public\$f.txt"
    if (Test-Path $p) {
        $l = (Get-Content $p -Encoding UTF8 | Select-String -Pattern '^\s+0000:').Line
        Add-Content $out "$f size=$((Get-Item $p).Length) $l"
    } else { Add-Content $out "$f MISSING" }
}
Add-Content $out "=== Verifier 统计（boot vs after 差异行） ==="
$boot = Get-Content 'C:\Users\Public\vq_boot.txt' -Encoding UTF8
$aft = Get-Content 'C:\Users\Public\vq_after.txt' -Encoding UTF8
Add-Content $out "boot 行数=$($boot.Count) after 行数=$($aft.Count)"
# 抽取 VerifyRoot 与统计段
$idx = ($aft | Select-String -Pattern 'XPCHunterDrv').LineNumber
if ($idx) { Add-Content $out ("after 含 XPCHunterDrv 行: {0}" -f ($aft | Where-Object { $_ -match 'XPCHunterDrv' } | Select-Object -First 4)) }
Add-Content $out 'END'