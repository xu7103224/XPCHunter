$out = 'C:\Users\Public\detail.txt'
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
$o = Parse-AB 'C:\Users\Public\sw_oA.txt'
$m = Parse-AB 'C:\Users\Public\sw_mine.txt'
foreach ($cmd in @('0X020','0X031','0X04D','0X0D4','0X11B','0X13A')) {
    Add-Content $out "===== $cmd ====="
    Add-Content $out ("orig res={0} st={1} len={2}" -f $o[$cmd].Res, $o[$cmd].St, ($o[$cmd].Out.Length/2))
    Add-Content $out ("mine res={0} st={1} len={2}" -f $m[$cmd].Res, $m[$cmd].St, ($m[$cmd].Out.Length/2))
    $a = $o[$cmd].Out; $b = $m[$cmd].Out
    $n = [Math]::Min($a.Length, $b.Length)
    $d = 0; $first = -1; $last = -1
    for ($i = 0; $i -lt $n; $i += 2) {
        if ($a.Substring($i,2) -ne $b.Substring($i,2)) { $d++; if ($first -lt 0) { $first = $i/2 }; $last = $i/2 }
    }
    Add-Content $out ("diffbytes=$d firstoffset=0x{0:X} lastoffset=0x{1:X}" -f $first, $last)
    if ($a.Length -gt 0) { Add-Content $out ("orig[0..63]=" + $a.Substring(0, [Math]::Min(128,$a.Length))) }
    if ($b.Length -gt 0) { Add-Content $out ("mine[0..63]=" + $b.Substring(0, [Math]::Min(128,$b.Length))) }
}
Add-Content $out 'END'