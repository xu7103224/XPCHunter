$out = 'C:\Users\Public\final_cmp.txt'
function Parse-Dump([string]$path) {
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
function Cmp-Bytes($a, $b) {
    if ($null -eq $a -or $null -eq $b) { return 'MISSING' }
    $n = [Math]::Min($a.Length, $b.Length)
    $d = 0; $first = -1
    for ($i = 0; $i -lt $n; $i++) { if ($a[$i] -ne $b[$i]) { $d++; if ($first -lt 0) { $first = $i } } }
    $d += [Math]::Abs($a.Length - $b.Length)
    return "diffbytes=$d firstdiff=$first"
}
foreach ($cmd in @('047','0d5')) {
    $po = "C:\Users\Public\f_${cmd}_orig.txt"
    $pm = "C:\Users\Public\f_${cmd}_mine.txt"
    if (-not (Test-Path $po)) { Add-Content $out "0x$cmd ORIG MISSING"; continue }
    if (-not (Test-Path $pm)) { Add-Content $out "0x$cmd MINE MISSING"; continue }
    $a = Parse-Dump $po
    $b = Parse-Dump $pm
    Add-Content $out ("0x{0}: orig len={1} mine len={2}  {3}" -f $cmd, $a.Length, $b.Length, (Cmp-Bytes $a $b))
    if ($a.Length -ge 8) { Add-Content $out ("      orig hdr04={0} mine hdr04={1}" -f [BitConverter]::ToUInt32($a,4), [BitConverter]::ToUInt32($b,4)) }
}
Add-Content $out 'END'