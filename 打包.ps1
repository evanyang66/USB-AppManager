[CmdletBinding()]
param([string]$Destination='')
$ErrorActionPreference='Stop'
if(-not $Destination){$Destination=Join-Path $PSScriptRoot 'dist\U盘应用管理-v0.3.7-全部应用版-便携包.zip'}
$stage=Join-Path $PSScriptRoot ('artifacts\发布-'+[guid]::NewGuid().ToString('N'))
$folder=Join-Path $stage 'U盘应用管理-全部应用版'
New-Item -ItemType Directory -Path $folder -Force|Out-Null
foreach($file in @('启动.bat','演示界面.bat','WinBatch.ps1','使用说明.txt')){Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination $folder}
foreach($dir in @('src','config')){Copy-Item -LiteralPath (Join-Path $PSScriptRoot $dir) -Destination (Join-Path $folder $dir) -Recurse}
$destinationFull=[IO.Path]::GetFullPath($Destination)
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destinationFull))|Out-Null
Compress-Archive -LiteralPath $folder -DestinationPath $destinationFull -Force
$hash=(Get-FileHash -LiteralPath $destinationFull -Algorithm SHA256).Hash
[IO.File]::WriteAllText(($destinationFull+'.SHA256.txt'),($hash+'  '+[IO.Path]::GetFileName($destinationFull)+[Environment]::NewLine),[Text.UTF8Encoding]::new($true))
[pscustomobject]@{Path=$destinationFull;Bytes=(Get-Item -LiteralPath $destinationFull).Length;SHA256=$hash;Files=@(Get-ChildItem -LiteralPath $folder -Recurse -File).Count}
