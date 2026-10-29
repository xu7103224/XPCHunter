$out = 'C:\Users\Public\mv_cmp.txt'
function Parse-Dump([string]$path) {
    $bytes = New-Object System.Collections.Generic.List[byte]
    if (-not (Test-Path $path)) { return $null }
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
function CmpOne([string]$newf, [string]$basef, [string]$tag) {
    $a = Parse-Dump "C:\Users\Public\$newf"
    $b = Parse-Dump "C:\Users\Public\$basef"
    if ($null -eq $a) { Add-Content $out "$tag new-missing"; return }
    if ($null -eq $b) { Add-Content $out "$tag base-missing"; return }
    $n = [Math]::Min($a.Length, $b.Length)
    $d = 0
    for ($i = 0; $i -lt $n; $i++) { if ($a[$i] -ne $b[$i]) { $d++ } }
    $d = $d + [Math]::Abs($a.Length - $b.Length)
    Add-Content $out "$tag mine=$($a.Length) orig=$($b.Length) diffbytes=$d"
}
CmpOne 'v047.txt' 'f_047_orig.txt' '0x047'
CmpOne 'v0d5.txt' 'f_0d5_orig.txt' '0x0D5'
CmpOne 'v0d4.txt' 'f_047_orig.txt' '0x0D4(仅长度参考)'
Add-Content $out 'END'