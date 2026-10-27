$out = 'C:\Users\Public\churn.txt'
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
function Head16([string]$path) {
    $b = Parse-Hex $path
    if ($null -eq $b -or $b.Length -lt 16) { return '(none)' }
    $s = ''
    for ($i = 0; $i -lt 16; $i++) { $s += $b[$i].ToString('X2') }
    return $s
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
foreach ($f in @('gv_orig2','gv_mine2','t031_1','t031_2')) {
    Add-Content $out ("{0}: 031头16B={1}" -f $f, (Head16 "C:\Users\Public\$f.txt"))
}
CmpH 't031_1.txt' 't031_2.txt' 'A.mine 031 自比'
CmpH 'gv_orig2.txt' 'gv_mine2.txt' 'B.之前交叉 031'
CmpH 'gv_mine2.txt' 't031_1.txt' 'C.mine2 vs 现在1'
foreach ($f in @('t0d4_1','t0d4_2')) {
    $p = "C:\Users\Public\$f.txt"
    if (Test-Path $p) {
        $l = (Get-Content $p -Encoding UTF8 | Select-String -Pattern '^\s+0000:').Line
        Add-Content $out "$f size=$((Get-Item $p).Length) $l"
    }
}
CmpH 't0d4_1.txt' 't0d4_2.txt' 'D.mine 0D4 自比'
Add-Content $out 'END'