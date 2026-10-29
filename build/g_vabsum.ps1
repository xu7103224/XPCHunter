$out = 'C:\Users\Public\vabsum.txt'
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
$o = Parse-AB 'C:\Users\Public\gv_orig2.txt'
$m = Parse-AB 'C:\Users\Public\gv_mine2.txt'
Add-Content $out "=== 同 boot（Verifier 会话）A/B ==="
Add-Content $out "orig=$($o.Count) mine=$($m.Count)"
$nSame = 0; $nDiff = 0
foreach ($k in ($o.Keys | Sort-Object)) {
    if (-not $m.ContainsKey($k)) { Add-Content $out "$k MISSING"; continue }
    if ($o[$k].Res -ne $m[$k].Res -or $o[$k].St -ne $m[$k].St) { Add-Content $out "$k STATUS-DIFF resO=$($o[$k].Res) resM=$($m[$k].Res)"; continue }
    if ($o[$k].Out -ceq $m[$k].Out) { $nSame++ } else { $nDiff++; Add-Content $out "$k DIFF lenO=$($o[$k].Out.Length/2) lenM=$($m[$k].Out.Length/2)" }
}
Add-Content $out "SAME=$nSame DIFF=$nDiff"
Add-Content $out "=== vrun 摘要（verifier 首轮） ==="
if (Test-Path 'C:\Users\Public\vrun.txt') { Get-Content 'C:\Users\Public\vrun.txt' -Encoding UTF8 | Select-String -Pattern 'START_EXIT|SWEEP_EXIT|STATE|BEGIN' | ForEach-Object { Add-Content $out $_.Line } }
Add-Content $out 'END'