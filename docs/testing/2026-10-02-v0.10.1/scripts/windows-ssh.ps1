# windows-11: OpenSSH Server for the tester, key only (run in an elevated PowerShell). Owner approved port forwarding 40023 -> 22.
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service sshd -StartupType Automatic; Start-Service sshd
Set-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPNBCd8G/R13P5BjvBejAPL9Lh6AefaRzWlWuLzPALAo blackbox-tester@claude-code' -Encoding ascii
icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"
(Get-Content C:\ProgramData\ssh\sshd_config) -replace '^#?PasswordAuthentication .*','PasswordAuthentication no' | Set-Content C:\ProgramData\ssh\sshd_config
New-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell -Value C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -PropertyType String -Force
Restart-Service sshd
Get-NetFirewallRule -Name *OpenSSH* | Format-Table Name,Enabled,Profile
