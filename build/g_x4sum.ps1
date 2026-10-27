$out = 'C:\Users\Public\x4.txt'
function Parse-Hex([string]$path) {
    $bytes = New-Object System.Collections.Generic.List[byte]
    foreach ($line in Get-Content $path -Encoding UTF8) {
        if ($line -match '^\s*([0-9A-Fa-f]{4}):\s+((?:[0-9A-Fa-f]{2}\s+)+)') {
            $off = [Convert]::ToInt32($matches[1], 16)
            $hex = $matches[2].Trim() -split '\s+'
            foreach ($h in $hex) {
                $v = [Convert]::ToByte($h, 16)
                while ($bytes.Count -lt $off) { $bytes.Add(0) }
                if ($bytes.Count -eq $off) { $bytes.Add($v) } else { $bytes[$off] = $v }
                $off++
            }
        }
    }
    return ,$bytes.ToArray()
}
function Q($arr, $off) {
    $v = [UInt64]0
    for ($i = 7; $i -ge 0; $i--) { $v = $v * 256 + $arr[$off + $i] }
    return "0x{0:X16}" -f $v
}
$files = @('x_d4_1','x_d4_2','x_d4_3','x_d4_4')
$data = @{}
foreach ($f in $files) { $data[$f] = Parse-Hex "C:\Users\Public\$f.txt" }
# 找出四轮中任一差异的条目，打印其 +8
Add-Content $out ("长度: " + (($files | ForEach-Object { $data[$_].Length }) -join ','))
$base = $data['x_d4_1']
$nE = [int](($base.Length - 8) / 0x20)
for ($e = 0; $e -lt $nE; $e++) {
    $off = 8 + $e * 0x20
    if ($off + 16 -gt $base.Length) { break }
    $vals = @()
    $vary = $false
    foreach ($f in $files) { $vals += (Q $data[$f] ($off + 8)) }
    $u = $vals | Select-Object -Unique
    if ($u.Count -gt 1) { $vary = $true }
    if ($vary) {
        $line = "条目{0} E={1} +8漂移: " -f $e, (Q $base $off)
        for ($i = 0; $i -lt 4; $i++) { $line += "r$($i+1)=$($vals[$i]) " }
        Add-Content $out $line
    }
}
Add-Content $out 'END'