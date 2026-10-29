$out = 'C:\Users\Public\d4x2.txt'
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
function CmpPair([string]$fa, [string]$fb, [string]$tag) {
    $a = Parse-Hex "C:\Users\Public\$fa"
    $b = Parse-Hex "C:\Users\Public\$fb"
    if ($null -eq $a -or $null -eq $b) { Add-Content $out "$tag MISSING"; return }
    $n = [Math]::Min($a.Length, $b.Length)
    $diffs = @()
    for ($i = 0; $i -lt $n; $i++) { if ($a[$i] -ne $b[$i]) { $diffs += $i } }
    Add-Content $out ("{0}: lenA={1} lenB={2} diffbytes={3}" -f $tag, $a.Length, $b.Length, $diffs.Count)
    if ($diffs.Count -gt 0 -and $diffs.Count -le 40) {
        $runs = @(); $s = $diffs[0]; $p = $diffs[0]
        for ($i = 1; $i -lt $diffs.Count; $i++) { if ($diffs[$i] -ne $p+1) { $runs += "0x{0:X}" -f $s; $s = $diffs[$i] }; $p = $diffs[$i] }
        $runs += "0x{0:X}" -f $s
        Add-Content $out ("   差异位: {0}" -f ($runs -join ', '))
    }
}
CmpPair 'm_d4_1.txt' 'm_d4_2.txt' 'A.我方自比'
CmpPair 'o_d4_1.txt' 'o_d4_2.txt' 'B.原版自比'
CmpPair 'o_d4_1.txt' 'm_d4_1.txt' 'C.交叉1'
CmpPair 'o_d4_2.txt' 'm_d4_2.txt' 'D.交叉2'
Add-Content $out 'END'