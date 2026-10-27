$out = 'C:\Users\Public\r031sum.txt'
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
    $d = 0
    for ($i = 0; $i -lt $n; $i++) { if ($a[$i] -ne $b[$i]) { $d++ } }
    $d = $d + [Math]::Abs($a.Length - $b.Length)
    Add-Content $out ("{0}: lenA={1} lenB={2} diff={3}" -f $tag, $a.Length, $b.Length, $d)
}
function Head([string]$path, $n) {
    $b = Parse-Hex "C:\Users\Public\$path"
    if ($null -eq $b -or $b.Length -lt 16) { return '(none)' }
    $s = ''
    for ($i = 0; $i -lt 16; $i++) { $s += $b[$i].ToString('X2') }
    return $s
}
foreach ($f in @('r031_m1','r031_o1','r031_m2','r031_o2')) {
    Add-Content $out ("{0}: 头16B={1}" -f $f, (Head "$f.txt" 16))
}
Add-Content $out '--- 两两比对 ---'
CmpH 'r031_m1.txt' 'r031_m2.txt' 'A.我方两次(相隔~3分钟)'
CmpH 'r031_o1.txt' 'r031_o2.txt' 'B.原版两次(相隔~3分钟)'
CmpH 'r031_o1.txt' 'r031_m1.txt' 'C.交叉(o1 vs m1)'
CmpH 'r031_o2.txt' 'r031_m2.txt' 'D.交叉(o2 vs m2)'
CmpH 'r031_o1.txt' 'r031_m2.txt' 'E.交叉(o1 vs m2, 时序最近)'
Add-Content $out 'END'