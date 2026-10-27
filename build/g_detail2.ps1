$out = 'C:\Users\Public\detail2.txt'
function Parse-AB([string]$path) {
    $res = @{}
    $cur = $null
    foreach ($line in Get-Content $path -Encoding UTF8) {
        if ($line -match '^CMD\s+(0x[0-9A-Fa-f]+)\s+INSZ=(\d+)\s+OUTSZ=(\d+)\s+RES=(\S+)\s+(\S+)\s+ERR=(\S+)\s+HDRLEN=(\d+)') {
            $cur = $matches[1].ToUpper()
            $res[$cur] = @{ Out = '' }
        } elseif ($line -match '^OUT\s+(\S+)' -and $cur) {
            $v = $matches[1]; if ($v -ne '-') { $res[$cur].Out = $v }; $cur = $null
        }
    }
    return $res
}
$o = Parse-AB 'C:\Users\Public\sw_oA.txt'
$m = Parse-AB 'C:\Users\Public\sw_mine.txt'
Add-Content $out '===== 0X031 full (orig) ====='
Add-Content $out $o['0X031'].Out
Add-Content $out '===== 0X031 full (mine) ====='
Add-Content $out $m['0X031'].Out
Add-Content $out '===== 0X11B window 0x40..0x100 (orig) ====='
Add-Content $out $o['0X11B'].Out.Substring(0x40*2, (0x100-0x40)*2)
Add-Content $out '===== 0X11B window 0x40..0x100 (mine) ====='
Add-Content $out $m['0X11B'].Out.Substring(0x40*2, (0x100-0x40)*2)
Add-Content $out 'END'