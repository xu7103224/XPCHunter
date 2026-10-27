$out = 'C:\Users\Public\goal_cmp.txt'
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
$a = Parse-AB 'C:\Users\Public\gw_orig.txt'
$b = Parse-AB 'C:\Users\Public\gw_mine.txt'
Add-Content $out "orig=$($a.Count) mine=$($b.Count)"
$nSame = 0; $nDiff = 0
foreach ($k in ($a.Keys | Sort-Object)) {
    if (-not $b.ContainsKey($k)) { Add-Content $out "$k MISSING-IN-MINE"; continue }
    $la = [int]($a[$k].Out.Length / 2)
    $lb = [int]($b[$k].Out.Length / 2)
    $v = ''
    if ($a[$k].Res -ne $b[$k].Res -or $a[$k].St -ne $b[$k].St) { $v = 'STATUS-DIFF' }
    elseif ($a[$k].Out -ceq $b[$k].Out) { $v = 'same'; $nSame++ }
    else { $v = 'DIFF'; $nDiff++ }
    if ($v -ne 'same') {
        Add-Content $out ("{0} resO={1} resM={2} lenO={3} lenM={4} {5}" -f $k, $a[$k].Res, $b[$k].Res, $la, $lb, $v)
    }
}
Add-Content $out "SUMMARY same=$nSame diff=$nDiff"
Add-Content $out '--- 0x0D4/0x031/0x11B 详情 ---'
foreach ($k in @('0X0D4','0X031','0X11B')) {
    if ($a.ContainsKey($k) -and $b.ContainsKey($k)) {
        $ao = $a[$k].Out; $bo = $b[$k].Out
        Add-Content $out ("{0}: orig len={1} first16={2}" -f $k, ($ao.Length/2), $ao.Substring(0,[Math]::Min(32,$ao.Length)))
        Add-Content $out ("{0}: mine len={1} first16={2}" -f $k, ($bo.Length/2), $bo.Substring(0,[Math]::Min(32,$bo.Length)))
    }
}
Add-Content $out 'END'