"OK $(Get-Date)" | Out-File -Encoding utf8 C:\kd_tmp\_t.txt
whoami | Out-File -Append -Encoding utf8 C:\kd_tmp\_t.txt
