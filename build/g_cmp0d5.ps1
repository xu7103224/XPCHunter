$out = 'C:\Users\Public\cmp0d5.txt'
function Parse-Dump([string]$path) {
    $bytes = New-Object System.Collections.Generic.List[byte]
    foreach ($line in Get-Content $path -Encoding UTF8) {
        if ($line -match '^\s*([0-9A-Fa-f]{4}):\s+((?:[0-9A-Fa-f]{2}\s+)+)') {
            $off = [Convert]::ToInt32($matches[1], 16)
            $hex = $matches[2].Trim() -split '\s+'
            while ($bytes.Count -lt $off) { $bytes.Add(0) }
            foreach ($h in $hex) {
                $v = [Convert]::ToByte($h, 16)
                if ($bytes.Count -eq $off) { $bytes.Add($v); $off++ }
                elseif ($bytes.Count -gt $off) { $bytes[$off] = $v; $off++ }
                else { $off++ }
            }
        }
    }
    return ,$bytes.ToArray()
}
$files = @{ 'orig1'='out_0d5_orig.txt'; 'orig2'='out_0d5_orig2.txt'; 'mine1'='out_0d5_mine.txt'; 'mine2'='out_0d5_mine2.txt'; 'mine3'='out_0d5_mine3.txt' }
$data = @{}
foreach ($k in $files.Keys) {
    $p = "C:\Users\Public\$($files[$k])"
    if (Test-Path $p) {
        $b = Parse-Dump $p
        $cnt = if ($b.Length -ge 8) { [BitConverter]::ToUInt32($b, 4) } else { -1 }
        $data[$k] = $b
        Add-Content $out "$k len=$($b.Length) count=$cnt"
    } else { Add-Content $out "$k MISSING" }
}
Add-Content $out '--- pairs ---'
foreach ($pair in @(@('orig2','mine1'), @('mine1','mine2'), @('mine1','mine3'), @('orig2','mine2'))) {
    $a = $data[$pair[0]]; $b = $data[$pair[1]]
    if ($null -eq $a -or $null -eq $b) { Add-Content $out "$($pair[0]) vs $($pair[1]): MISSING"; continue }
    $n = [Math]::Min($a.Length, $b.Length)
    $d = 0; $first = -1
    for ($i = 0; $i -lt $n; $i++) { if ($a[$i] -ne $b[$i]) { $d++; if ($first -lt 0) { $first = $i } } }
    $d += [Math]::Abs($a.Length - $b.Length)
    Add-Content $out ("{0} vs {1}: diffbytes={2} firstdiff={3}" -f $pair[0], $pair[1], $d, $first)
}
Add-Content $out 'END'