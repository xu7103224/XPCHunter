$out = 'C:\Users\Public\d4d22.txt'
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
function CmpH([string]$fa, [string]$fb, [string]$tag) {
    $a = Parse-Hex "C:\Users\Public\$fa"
    $b = Parse-Hex "C:\Users\Public\$fb"
    if ($null -eq $a -or $null -eq $b) { Add-Content $out "$tag MISSING"; return }
    $n = [Math]::Min($a.Length, $b.Length)
    $d = @()
    for ($i = 0; $i -lt $n; $i++) { if ($a[$i] -ne $b[$i]) { $d += $i } }
    Add-Content $out ("{0}: lenA={1} lenB={2} diff={3}" -f $tag, $a.Length, $b.Length, $d.Count)
    if ($d.Count -gt 0) {
        $runs = @(); $s = $d[0]; $p = $d[0]
        for ($i = 1; $i -lt $d.Count; $i++) { if ($d[$i] -ne $p+1) { $runs += "0x{0:X}" -f $s; $s = $d[$i] }; $p = $d[$i] }
        $runs += "0x{0:X}" -f $s
        Add-Content $out ("   差异位: {0}" -f ($runs -join ', '))
    }
}
CmpH 'o4d_1.txt' 'o4d_2.txt' 'A.原版自比'
CmpH 'm4d_1.txt' 'm4d_2.txt' 'B.我方自比'
CmpH 'o4d_1.txt' 'm4d_1.txt' 'C.交叉1'
CmpH 'o4d_2.txt' 'm4d_2.txt' 'D.交叉2'
# 0x2C 字段四份对比
foreach ($f in @('o4d_1','o4d_2','m4d_1','m4d_2')) {
    $b = Parse-Hex "C:\Users\Public\$f.txt"
    if ($null -ne $b -and $b.Length -gt 0x38) {
        $s = ''
        for ($i = 0x28; $i -lt 0x38; $i++) { $s += $b[$i].ToString('X2') }
        Add-Content $out "$f 0x28..0x37 = $s"
    }
}
Add-Content $out 'END'