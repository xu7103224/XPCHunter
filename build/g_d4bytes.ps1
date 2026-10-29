$out = 'C:\Users\Public\d4bytes.txt'
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
function HexAt($arr, $off, $len) {
    $s = ''
    for ($i = $off; $i -lt $off + $len; $i++) { $s += $arr[$i].ToString('X2') + ' ' }
    return $s
}
foreach ($e in @(12, 13, 14, 16, 17, 18)) {
    $off = 8 + $e * 0x20
    Add-Content $out ("条目{0} @0x{1:X}:" -f $e, $off)
    Add-Content $out ("  orig: {0}" -f (HexAt $a $off 0x20))
    Add-Content $out ("  mine: {0}" -f (HexAt $b $off 0x20))
}
Add-Content $out 'END'