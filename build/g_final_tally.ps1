$out = 'C:\Users\Public\final_tally.txt'
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
$m = Parse-AB 'C:\Users\Public\gw_mine.txt'
Add-Content $out "orig=$($o.Count) mine=$($m.Count)"
$same = @(); $diffs = @()
foreach ($k in ($o.Keys | Sort-Object)) {
    if (-not $m.ContainsKey($k)) { $diffs += "$k MISSING-IN-MINE"; continue }
    if ($o[$k].Res -ne $m[$k].Res -or $o[$k].St -ne $m[$k].St) { $diffs += "$k STATUS resO=$($o[$k].Res)/$($o[$k].St) resM=$($m[$k].Res)/$($m[$k].St) lenO=$($o[$k].Out.Length/2) lenM=$($m[$k].Out.Length/2)"; continue }
    if ($o[$k].Out -ceq $m[$k].Out) { $same += $k } else { $diffs += "$k BYTE-DIFF lenO=$($o[$k].Out.Length/2) lenM=$($m[$k].Out.Length/2)" }
}
Add-Content $out "SAME=$($same.Count)"
foreach ($d in $diffs) { Add-Content $out "  $d" }
# 对每条 BYTE-DIFF 做字节级差异位分析
function Parse-OutHex([string]$hex) {
    $bytes = New-Object byte[] ($hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i*2,2), 16) }
    return $bytes
}
foreach ($d in $diffs) {
    if ($d -notmatch 'BYTE-DIFF') { continue }
    $k = ($d -split ' ')[0]
    $a = Parse-OutHex $o[$k].Out
    $b = Parse-OutHex $m[$k].Out
    $n = [Math]::Min($a.Length, $b.Length)
    $diffs2 = @()
    for ($i = 0; $i -lt $n; $i++) { if ($a[$i] -ne $b[$i]) { $diffs2 += $i } }
    $extra = [Math]::Abs($a.Length - $b.Length)
    $runs = @(); $s = -1; $p = -1
    foreach ($i in $diffs2) {
        if ($s -lt 0) { $s = $i; $p = $i }
        elseif ($i -eq $p + 1) { $p = $i }
        else { $runs += "0x{0:X}(0x{1:X})" -f $s, ($p - $s + 1); $s = $i; $p = $i }
    }
    if ($s -ge 0) { $runs += "0x{0:X}(0x{1:X})" -f $s, ($p - $s + 1) }
    Add-Content $out ("  {0} 字节差异位: {1}" -f $k, ($runs -join ', '))
}
Add-Content $out 'END'