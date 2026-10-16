function Resolve-WBWinGetExecutable {
    $packages=@(Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue)
    if(-not $packages.Count -and (Test-WBAdmin)){$packages=@(Get-AppxPackage -AllUsers -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue)}
    foreach($package in @($packages|Sort-Object Version -Descending)){
        $path=Join-Path $package.InstallLocation 'winget.exe'
        if(-not (Test-Path -LiteralPath $path -PathType Leaf)){continue}
        $sig=Get-AuthenticodeSignature -LiteralPath $path
        if($sig.Status -eq 'Valid' -and (Test-WBMicrosoftPublisher $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false))){return $path}
    }
    throw '本机未找到可用的 Windows 程序包管理器，无法处理此卸载入口'
}

function Find-WBAdjacentUninstaller([string]$MainPath) {
    if(-not $MainPath -or $MainPath -notmatch '^[A-Za-z]:\\' -or [IO.Path]::GetExtension($MainPath) -ine '.exe' -or -not (Test-Path -LiteralPath $MainPath -PathType Leaf)){return $null}
    $folder=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($MainPath))
    $candidates=@(Get-ChildItem -LiteralPath $folder -File -Filter '*.exe' -ErrorAction SilentlyContinue|Where-Object{$_.Name -imatch '^(?:unins\d*|uninst|uninstall(?:[ _-].*)?)\.exe$' -and $_.FullName -ine $MainPath})
    if($candidates.Count -ne 1 -or -not (Test-WBProductPath $candidates[0].FullName $folder)){return $null}
    return $candidates[0].FullName
}

function Get-WBRegisteredUninstallCommand([string]$Text,$Record) {
    if([string]::IsNullOrWhiteSpace($Text) -or $Text -match '[\x00-\x1f]'){throw '未登记有效的卸载命令'}
    $Text=$Text.Trim()
    if($Text -imatch '^"?winget(?:\.exe)?"?\s+'){
        $m=[regex]::Match($Text,'^"?winget(?:\.exe)?"?\s+uninstall\s+--product-code\s+"?(?<id>[A-Za-z0-9._{}-]+)"?$','IgnoreCase')
        if(-not $m.Success){throw '不支持此程序包管理命令；仅允许卸载当前登记的精确产品'}
        $id=$m.Groups['id'].Value;$key=([string]$Record.Identity).Split('\')[-1]
        if($id -cne $key){throw '卸载命令指向了其他登记产品'}
        $path=Resolve-WBWinGetExecutable
        $scope=if([string]$Record.Identity -like 'CurrentUser|*'){'user'}else{'machine'}
        return [pscustomobject]@{FilePath=$path;Arguments=('uninstall --product-code "'+$id+'" --exact --silent --disable-interactivity --source winget --scope '+$scope);IsMsi=$false;Backend='WinGet';PayloadPaths=@()}
    }
    $r=[regex]::Match($Text,'^"?(?<exe>(?:[A-Za-z]:\\|%[^%]+%\\)[^"\r\n]*?\\rundll32\.exe|rundll32(?:\.exe)?)"?\s+(?<args>.*)$','IgnoreCase')
    if($r.Success){
        $exe=[Environment]::ExpandEnvironmentVariables($r.Groups['exe'].Value)
        $allowed=@((Join-Path $env:windir 'System32\rundll32.exe'),(Join-Path $env:windir 'SysWOW64\rundll32.exe'))
        if($exe -notmatch '^[A-Za-z]:\\'){$exe=$allowed[0]}
        if($exe -inotmatch '^.+\\rundll32\.exe$' -or $exe -notin $allowed){throw 'DLL 卸载必须使用 Windows 自带的执行器'}
        $tail=$r.Groups['args'].Value;Assert-WBAllAppsArguments $tail
        $tokens=@([USBAppManager.ArgumentReader]::Parse('"'+$exe+'" '+$tail)|Select-Object -Skip 1)
        if($tokens.Count -lt 1){throw 'DLL 卸载入口缺失'}
        $entry=[regex]::Match($tokens[0],'^(?<dll>[A-Za-z]:\\[^"\x00-\x1f]+?\.dll),(?<export>[A-Za-z_][A-Za-z0-9_@]{0,127})$','IgnoreCase')
        if(-not $entry.Success){throw '不支持此 DLL 卸载入口格式'}
        $dll=[IO.Path]::GetFullPath($entry.Groups['dll'].Value)
        return [pscustomobject]@{FilePath=$exe;Arguments=$tail;IsMsi=$false;Backend='Rundll';PayloadPaths=@($dll)}
    }
    if($Text -imatch '^msiexec(?:\.exe)?\s+'){$Text='"'+(Join-Path $env:windir 'System32\msiexec.exe')+'" '+($Text -replace '^msiexec(?:\.exe)?\s+','')}
    $spec=ConvertFrom-WBCommand $Text
    Assert-WBAllAppsArguments $spec.Arguments
    $spec|Add-Member -NotePropertyName Backend -NotePropertyValue 'Native'
    $spec|Add-Member -NotePropertyName PayloadPaths -NotePropertyValue @()
    return $spec
}

function Get-WBCommandFileHash($Command) {
    $payloads=@(Get-WBValue $Command 'PayloadPaths' @())
    if($payloads.Count -eq 0){return (Get-FileHash -LiteralPath $Command.FilePath -Algorithm SHA256 -ErrorAction Stop).Hash}
    $values=@(foreach($path in @(@($Command.FilePath)+$payloads|Sort-Object -Unique)){
        if(-not (Test-Path -LiteralPath $path -PathType Leaf)){throw ('卸载入口文件不存在：'+$path)}
        [pscustomobject]@{Path=$path;Hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash}
    })
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($values|ConvertTo-Json -Compress))))).Replace('-','')}finally{$sha.Dispose()}
}

function Get-WBUninstallInvocationFingerprint($Command) {
    if($null -eq $Command){return ''}
    $value=[ordered]@{FilePath=[string]$Command.FilePath;Arguments=[string]$Command.Arguments;Backend=[string](Get-WBValue $Command 'Backend');PayloadPaths=@(Get-WBValue $Command 'PayloadPaths' @())}
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Compress))))).Replace('-','')}finally{$sha.Dispose()}
}

function Test-WBUninstallTargetAbsent($Target) {
    if($Target.Source -eq 'Shortcut'){
        $path=[string](Get-WBValue $Target.Record 'TargetPath')
        return ($path -match '^[A-Za-z]:\\' -and [IO.Path]::GetExtension($path) -ieq '.exe' -and -not (Test-Path -LiteralPath $path -ErrorAction Stop))
    }
    if($Target.Source -ne 'Registry'){return $false}
    $ids=@(Get-WBValue $Target 'RelatedIdentities' @($Target.Identity))
    if(-not $ids.Count){return $false}
    foreach($identity in $ids){
        if($identity -notmatch '^(LocalMachine|CurrentUser)\|(Registry32|Registry64)\|(SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+)$'){return $false}
        $base=$null;$key=$null
        try{
            $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::$($matches[1]),[Microsoft.Win32.RegistryView]::$($matches[2]))
            $key=$base.OpenSubKey($matches[3])
            if($null -ne $key){return $false}
        }finally{if($null -ne $key){$key.Dispose()};if($null -ne $base){$base.Dispose()}}
    }
    return $true
}

function Get-WBUninstallRemovalState($Target,$Snapshot=$null) {
    try{
        if($null -eq $Snapshot){$absent=Test-WBUninstallTargetAbsent $Target}
        else{
            Assert-WBSnapshotReady $Snapshot
            if($Target.Source -eq 'Registry'){
                $related=@(Get-WBValue $Target 'RelatedIdentities' @($Target.Identity))
                $absent=$related.Count -gt 0 -and @($Snapshot.Inventory|Where-Object{$_.Source -eq 'Registry' -and $related -ccontains $_.Identity}).Count -eq 0
            }else{$absent=Test-WBUninstallTargetAbsent $Target}
        }
        return [pscustomobject]@{Complete=$true;Absent=[bool]$absent}
    }catch{return [pscustomobject]@{Complete=$false;Absent=$false}}
}

function Invoke-WBBoundedUninstallProbe([string]$Root,$Target,$State,[datetime]$Deadline,[string]$CancelPath,[string]$Session,[ValidateSet('Runtime','Removal')][string]$Operation='Runtime') {
    $pending=[pscustomobject]@{Complete=$false;ApprovedProcessIds=@()}
    if([datetime]::UtcNow -ge $Deadline -or (Test-Path -LiteralPath $CancelPath)){return $pending}
    $requestPath=Join-Path $Session ('probe-'+[guid]::NewGuid().ToString('N')+'.json')
    $outputPath=$requestPath+'.result';$process=$null
    try{
        Write-WBJson $requestPath ([pscustomobject]@{Target=$Target;State=$State;Operation=$Operation})
        $info=New-Object Diagnostics.ProcessStartInfo
        $info.FileName=Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $info.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $Root 'src\UninstallProbe.ps1')+'" -RequestPath "'+$requestPath+'" -OutputPath "'+$outputPath+'"'
        $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
        $process=[Diagnostics.Process]::Start($info)
        $limit=[datetime]::UtcNow.AddSeconds(20);if($Deadline -lt $limit){$limit=$Deadline}
        while(-not $process.WaitForExit(50)){
            if([datetime]::UtcNow -ge $limit -or (Test-Path -LiteralPath $CancelPath)){return $pending}
        }
        if([datetime]::UtcNow -ge $Deadline -or (Test-Path -LiteralPath $CancelPath) -or $process.ExitCode -ne 0){return $pending}
        return (Get-Content -LiteralPath $outputPath -Raw -Encoding UTF8 -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop)
    }catch{return $pending}
    finally{
        # Only this tool's read-only helper is terminated. The retained Process
        # handle identifies our own child; no vendor PID/name is ever stopped.
        if($null -ne $process){try{if(-not $process.HasExited){$process.Kill();[void]$process.WaitForExit(1000)}}finally{$process.Dispose()}}
        foreach($path in @($requestPath,$outputPath)){if([IO.File]::Exists($path)){[IO.File]::Delete($path)}}
    }
}

function Test-WBSogouResidualIdentity($Target,[string]$Path,[string]$CommandLine) {
    # This is a reason to STOP and request restart, never permission to release
    # a live job, kill a process, or report complete removal. Bind the exception
    # to the exact supplied 8.0 uninstaller and observed runtime paths/argv.
    try {
        if($Target.Source -cne 'Registry' -or $Target.FileHash -cne '648F801EA7C463CBF732BC3FEAB7C69CFC38120A28E9CD0C5404F7BF1917EBA5'){return $false}
        if($Target.Identity -cnotmatch '^LocalMachine\|Registry(?:32|64)\|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sogou Input$'){return $false}
        $command=$Target.Command
        if($command.FilePath -ine 'C:\Program Files (x86)\SogouInput\8.0.0.8026\Uninstall.exe' -or $command.Arguments -cne '/S'){return $false}
        Initialize-WBProcessNative
        $args=@([USBWinBatch.RecoveryProcess]::ParseArguments($CommandLine))
        if(-not $args.Count -or $args[0] -ine $Path){return $false}
        if($Path -ieq (Join-Path $env:windir 'SysWOW64\IME\SogouPY\SogouImeLoader.exe')){return $args.Count -eq 1}
        if($Path -ieq 'C:\Program Files (x86)\SogouInput\8.0.0.8026\SogouCloud.exe'){return ($args.Count -eq 2 -and $args[1] -ceq '-daemon')}
        return $false
    }catch{return $false}
}

function Test-WBSogouResidualProcess($Target,$ProcessCimRecord) {
    $current=$null
    try {
        if(-not (Test-WBSogouResidualIdentity $Target $ProcessCimRecord.ExecutablePath $ProcessCimRecord.CommandLine)){return $false}
        $current=Get-WBRecoveryProcess ([uint32]$ProcessCimRecord.ProcessId)
        if($null -eq $current){return $false}
        $time=([datetime]$ProcessCimRecord.CreationDate).ToUniversalTime().ToFileTimeUtc()
        if([decimal]::Truncate(([decimal]$time/10)) -ne [decimal]::Truncate(([decimal]$current.CreationTime/10)) -or
           $ProcessCimRecord.ExecutablePath -ine $current.Path -or $ProcessCimRecord.CommandLine -cne $current.CommandLine){return $false}
        return (Test-WBSogouResidualIdentity $Target $current.Path $current.CommandLine)
    }catch{return $false}finally{if($null -ne $current){$current.Handle.Dispose()}}
}

function Get-WBUninstallRuntimeApproval([string]$Root,$Target,$State,$Snapshot=$null,$Processes=$null,[switch]$AllowNonzeroExit) {
    $pending=[pscustomobject]@{Complete=$false;ApprovedProcessIds=@()}
    $successCodes=@(0)
    if((Get-WBValue (Get-WBValue $Target 'Command' $null) 'Rule') -ceq 'Chrome'){$successCodes+=19}
    if(-not $State.RootExited -or $null -eq $State.ExitCode -or (-not $AllowNonzeroExit -and $State.ExitCode -notin $successCodes) -or @($State.ActiveProcessIds).Count -eq 0){return $pending}
    try{
        if($Target.Source -notin @('Registry','Shortcut')){return $pending}
        if($null -eq $Snapshot){
            if(-not (Test-WBUninstallTargetAbsent $Target)){return $pending}
        }elseif($Target.Source -eq 'Registry'){
            Assert-WBSnapshotReady $Snapshot
            $related=@(Get-WBValue $Target 'RelatedIdentities' @($Target.Identity))
            if($related.Count -eq 0 -or @($Snapshot.Inventory|Where-Object{$_.Source -eq 'Registry' -and $related -ccontains $_.Identity}).Count){return $pending}
        }else{
            Assert-WBSnapshotReady $Snapshot
            $main=[string](Get-WBValue $Target.Record 'TargetPath')
            if(-not $main -or (Test-Path -LiteralPath $main -ErrorAction Stop)){return $pending}
        }
        $approved=New-Object 'System.Collections.Generic.List[uint32]'
        $residual=New-Object 'System.Collections.Generic.List[uint32]'
        foreach($processId in @($State.ActiveProcessIds)){
            $found=@(if($null -eq $Processes){Get-CimInstance Win32_Process -Filter ('ProcessId='+[uint32]$processId) -ErrorAction Stop}else{$Processes|Where-Object ProcessId -eq $processId})
            if($found.Count -ne 1){return $pending}
            if(Test-WBSogouResidualProcess $Target $found[0]){$residual.Add([uint32]$processId);continue}
            if(-not (Test-WBRecoverableBrowserProcess $found[0])){return $pending}
            $approved.Add([uint32]$processId)
        }
        if($residual.Count){
            return [pscustomobject]@{Complete=$false;RestartRequired=$true;PendingProcessIds=@($approved.ToArray())+@($residual.ToArray());ApprovedProcessIds=@()}
        }
        return [pscustomobject]@{Complete=$true;ApprovedProcessIds=$approved.ToArray()}
    }catch{return $pending}
}
