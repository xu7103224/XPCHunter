$out = 'C:\Users\Public\d4x2.txt'
function Parse-Dump([string]$path) {
    foreach ($line in Get-Content $path -Encoding UTF8) {
        if ($line -match '^\s*OUT\s+([0-9A-Fa-f]+)') {
            $hex = $matches[1]
            $bytes = New-Object byte[] ($hex.Length / 2)
            for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i*2,2), 16) }
            return ,$bytes
        }
    }
    return $null
}
function CmpPair([string]$fa, [string]$fb, [string]$tag) {
    $a = Parse-Dump "C:\Users\Public\$fa"
    $b = Parse-Dump "C:\Users\Public\$fb"
    if ($null -eq $a -or $null -eq $b) { Add-Content $out "$tag MISSING"; return }
    $n = [Math]::Min($a.Length, $b.Length)
    $diffs = @()
    for ($i = 0; $i -lt $n; $i++) { if ($a[$i] -ne $b[$i]) { $diffs += $i } }
    Add-Content $out ("{0}: lenA={1} lenB={2} diffbytes={3}" -f $tag, $a.Length, $b.Length, $diffs.Count)
    if ($diffs.Count -gt 0 -and $diffs.Count -le 24) {
        $runs = @(); $s = $diffs[0]; $p = $diffs[0]
        for ($i = 1; $i -lt $diffs.Count; $i++) { if ($diffs[$i] -ne $p+1) { $runs += "0x{0:X}" -f $s; $s = $diffs[$i] }; $p = $diffs[$i] }
        $runs += "0x{0:X}" -f $s
        Add-Content $out ("   差异位: {0}" -f ($runs -join ', '))
    }
}
CmpPair 'm_d4_1.txt' 'm_d4_2.txt' '我方自比(1 vs 2)'
CmpPair 'o_d4_1.txt' 'o_d4_2.txt' '原版自比(1 vs 2)'
CmpPair 'o_d4_1.txt' 'm_d4_1.txt' '交叉(orig1 vs mine1)'
CmpPair 'o_d4_2.txt' 'm_d4_2.txt' '交叉(orig2 vs mine2)'
Add-Content $out 'END'