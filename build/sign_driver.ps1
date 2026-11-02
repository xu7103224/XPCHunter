param([Parameter(Mandatory=$true)][string]$SysPath)

$V92 = [char]92
$Signtool = Get-ChildItem ("C:" + $V92 + "Program Files (x86)" + $V92 + "Windows Kits" + $V92 + "10" + $V92 + "bin") -Recurse -Filter signtool.exe |
    Where-Object { $_.DirectoryName.EndsWith($V92 + "x64") } |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $Signtool) { Write-Error "signtool.exe (x64) not found under Windows Kits"; exit 1 }

Write-Output ("Tool  : " + $Signtool.FullName)
Write-Output ("Target: " + $SysPath)
& $Signtool.FullName sign /fd SHA256 /n XPCSign2 $SysPath
if ($LASTEXITCODE -ne 0) { Write-Error ("signtool failed: " + $LASTEXITCODE); exit 1 }
Write-Output ("Signed OK: " + $SysPath)
exit 0
