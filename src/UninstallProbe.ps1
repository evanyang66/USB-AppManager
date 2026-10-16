param([Parameter(Mandatory=$true)][string]$RequestPath,[Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference='Stop'
try{
    Import-Module (Join-Path $PSScriptRoot 'WinBatch.System.psm1') -Force -DisableNameChecking
    $request=Get-Content -LiteralPath $RequestPath -Raw -Encoding UTF8|ConvertFrom-Json
    $module=Get-Module WinBatch.System
    $result=& $module {
        param($r)
        if($r.Operation -eq 'Removal'){Get-WBUninstallRemovalState -Target $r.Target}
        elseif($r.Operation -eq 'Runtime'){Get-WBUninstallRuntimeApproval -Target $r.Target -State $r.State -AllowNonzeroExit}
        else{throw 'Unknown read-only probe operation'}
    } $request
    Write-WBJson $OutputPath $result
    exit 0
}catch{exit 1}
