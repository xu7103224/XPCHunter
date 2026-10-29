$out = 'C:\Users\Public\fr_sum.txt'
function Parse-Dump([string]$path) {
    $bytes = New-Object System.Collections.Generic.List[byte]
    foreach ($line in Get-Content $path -Encoding UTF8) {
        if ($line -match '^\s*([0-9A-Fa-f]{4}):\s+((?:[0-9A-Fa-f]{2}\s+)+)') {
            $off = [Convert]::ToInt32($matches[1], 16)
            $hex = $matches[2].Trim() -split '\s+'
            foreach ($h in $hex) {
                $v = [Convert]::ToByte($h, 16)
                if ($bytes.Count -lt $off) { while ($bytes.Count -lt $off) { $bytes.Add(0) } }
                if ($bytes.Count -eq $off) { $bytes.Add($v) } else { $bytes[$off] = $v }
                $off++
            }
        }
    }
    return ,$bytes.ToArray()
}
$files = @('fr_orig1','fr_orig2','fr_mine1','fr_mine2')
$data = @{}
foreach ($k in $files) {
    $p = "C:\Users\Public\$k.txt"
    if (Test-Path $p) {
        $b = Parse-Dump $p
        $cnt = if ($b.Length -ge 8) { [BitConverter]::ToUInt32($b, 4) } else { -1 }
        $data[$k] = $b
        Add-Content $out "$k len=$($b.Length) count=$cnt"
    } else { Add-Content $out "$k MISSING" }
}
Add-Content $out '--- pairs ---'
foreach ($pair in @(@('fr_orig1','fr_mine1'), @('fr_orig2','fr_mine2'), @('fr_orig1','fr_orig2'), @('fr_mine1','fr_mine2'))) {
    $a = $data[$pair[0]]; $b = $data[$pair[1]]
    if ($null -eq $a -or $null -eq $b) { Add-Content $out "$($pair[0]) vs $($pair[1]): MISSING"; continue }
    $n = [Math]::Min($a.Length, $b.Length)
    $d = 0; $first = -1
    for ($i = 0; $i -lt $n; $i++) { if ($a[$i] -ne $b[$i]) { $d++; if ($first -lt 0) { $first = $i } } }
    $d += [Math]::Abs($a.Length - $b.Length)
    Add-Content $out ("{0} vs {1}: diffbytes={2} firstdiff={3}" -f $pair[0], $pair[1], $d, $first)
}
Add-Content $out 'END'