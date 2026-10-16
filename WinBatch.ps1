[CmdletBinding()]
param(
    [ValidateSet('Gui','Scan','Run','Recover')][string]$Mode='Gui',
    [switch]$Demo,
    [string]$OutputPath='',
    [string]$RequestPath='',
    [string]$SmokeTestPath=''
)
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
try {
    if($PSVersionTable.PSVersion.Major -lt 5){throw '需要 Windows PowerShell 5.1 或更高版本。'}
    Import-Module (Join-Path $root 'src\WinBatch.System.psm1') -Force -DisableNameChecking
    switch($Mode){
        'Scan' {
            $snapshot=Get-WBSnapshot -Root $root -Demo:$Demo
            if($OutputPath){Write-WBJson -Path $OutputPath -Value $snapshot}else{$snapshot|ConvertTo-Json -Depth 20}
        }
        'Run' {
            if($Demo){throw '演示模式禁止执行。'}
            if(-not $RequestPath -or -not $OutputPath){throw '请从界面确认执行，不支持缺少请求文件的执行。'}
            Invoke-WBBatch -Root $root -RequestPath $RequestPath -OutputPath $OutputPath|Out-Null
        }
        'Recover' {
            if($Demo){throw '演示模式禁止恢复执行状态。'}
            if(-not $OutputPath){throw '缺少恢复报告路径。'}
            $result=Repair-WBExecutionState -Root $root
            Write-WBJson -Path $OutputPath -Value $result
            if($result.State -eq 'Failed'){exit 1}
        }
        'Gui' {
            Import-Module (Join-Path $root 'src\WinBatch.UI.psm1') -Force -DisableNameChecking
            Show-WBWindow -Root $root -Demo:$Demo -SmokeTestPath $SmokeTestPath
        }
    }
    exit 0
} catch {
    $message=$_.Exception.Message
    if($OutputPath){
        try {
            $existing=$null
            if(Test-Path -LiteralPath $OutputPath){$existing=Get-Content -LiteralPath $OutputPath -Raw -Encoding UTF8|ConvertFrom-Json}
            if(-not $existing -or $existing.State -notin @('Failed','Cancelled')){Write-WBJson -Path $OutputPath -Value ([pscustomobject]@{State='Failed';Message=$message;Percent=0;Results=@();ReportPath='';Error=$message})}
        } catch {Write-Error ('错误报告无法写入：'+$_.Exception.Message) -ErrorAction Continue}
    }
    if($Mode -eq 'Gui'){
        Add-Type -AssemblyName System.Windows.Forms
        [Windows.Forms.MessageBox]::Show($message,'USB-WinBatch 启动失败',[Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Error)|Out-Null
    }
    Write-Error $message -ErrorAction Continue
    exit 1
}
