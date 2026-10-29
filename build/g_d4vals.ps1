$out = 'C:\Users\Public\d4vals.txt'
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
$files = @('m_d4_1','m_d4_2','o_d4_1','o_d4_2')
$data = @{}
foreach ($f in $files) { $data[$f] = Parse-Hex "C:\Users\Public\$f.txt" }
for ($e = 12; $e -le 21; $e++) {
    $off = 8 + $e * 0x20
    if ($off + 24 -gt $data['m_d4_1'].Length) { break }
    $line = "条目{0}: " -f $e
    foreach ($f in $files) {
        $ep = Q $data[$f] $off
        $p8 = Q $data[$f] ($off + 8)
        $line += "[$f E=$ep +8=$p8] "
    }
    Add-Content $out $line
}
Add-Content $out 'END'