# Generate certificate (run in admin powershell)

Write-Output New-SelfSignedCertificate
$cert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(5)

Write-Output ConvertTo-SecureString
$pwd = ConvertTo-SecureString -String "password" -Force -AsPlainText

Write-Output Export-PfxCertificate
Export-PfxCertificate -Cert $cert -FilePath "server.pfx" -Password $pwd
