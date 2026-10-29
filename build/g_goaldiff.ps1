$out = 'C:\Users\Public\goaldiff.txt'
function Parse-Dump([string]$path, [string]$cmd) {
    $bytes = $null
    $cur = $null
    foreach ($line in Get-Content $path -Encoding UTF8) {
        if ($line -match '^CMD\s+(0x[0-9A-Fa-f]+)') { $cur = $matches[1].ToUpper(); continue }
        if ($cur -ne $cmd) { continue }
        if ($line -match '^\s*OUT\s+([0-9A-Fa-f]+)') {
            $hex = $matches[1]
            $bytes = New-Object byte[] ($hex.Length / 2)
            for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i*2,2), 16) }
            break
        }
    }
    return $bytes
}
$a = Parse-Dump 'C:\Users\Public\gw_orig.txt' '0X0D4'
$b = Parse-Dump 'C:\Users\Public\gw_mine.txt' '0X0D4'
$n = [Math]::Min($a.Length, $b.Length)
$diffs = @()
for ($i = 0; $i -lt $n; $i++) { if ($a[$i] -ne $b[$i]) { $diffs += $i } }
Add-Content $out ("0x0D4: lenO={0} lenM={1} diffbytes={2}" -f $a.Length, $b.Length, $diffs.Count)
if ($diffs.Count -gt 0) {
    Add-Content $out ("  范围: 0x{0:X}..0x{1:X}" -f $diffs[0], $diffs[$diffs.Count-1])
    $runs = @(); $s = $diffs[0]; $p = $diffs[0]
    for ($i = 1; $i -lt $diffs.Count; $i++) { if ($diffs[$i] -ne $p+1) { $runs += "$s..$p"; $s = $diffs[$i] }; $p = $diffs[$i] }
    $runs += "$s..$p"
    Add-Content $out ("  连续段: {0}" -f ($runs -join ', '))
}
$a2 = Parse-Dump 'C:\Users\Public\gw_orig.txt' '0X11B'
$b2 = Parse-Dump 'C:\Users\Public\gw_mine.txt' '0X11B'
$n2 = [Math]::Min($a2.Length, $b2.Length)
$d2 = @()
for ($i = 0; $i -lt $n2; $i++) { if ($a2[$i] -ne $b2[$i]) { $d2 += $i } }
Add-Content $out ("0x11B: lenO={0} lenM={1} diffbytes={2}" -f $a2.Length, $b2.Length, $d2.Count)
if ($d2.Count -gt 0) {
    $runs2 = @(); $s = $d2[0]; $p = $d2[0]
    for ($i = 1; $i -lt $d2.Count; $i++) { if ($d2[$i] -ne $p+1) { $runs2 += "$s..$p"; $s = $d2[$i] }; $p = $d2[$i] }
    $runs2 += "$s..$p"
    Add-Content $out ("  连续段: {0}" -f ($runs2 -join ', '))
}
Add-Content $out 'END'