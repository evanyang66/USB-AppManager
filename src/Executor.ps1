function Write-WBJson([string]$Path,$Value) {
    $full=[IO.Path]::GetFullPath($Path);$parent=[IO.Path]::GetDirectoryName($full);[IO.Directory]::CreateDirectory($parent)|Out-Null
    $temp=$full+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
    try{
        [IO.File]::WriteAllText($temp,($Value|ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))
        for($attempt=0;$attempt -lt 10;$attempt++){
            try{if([IO.File]::Exists($full)){[IO.File]::Replace($temp,$full,[System.Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($temp,$full)};return}catch{if($attempt -eq 9){throw};Start-Sleep -Milliseconds 30}
        }
    }finally{if([IO.File]::Exists($temp)){[IO.File]::Delete($temp)}}
}

function ConvertTo-WBCsvCell($Value) {
    $text=[string]$Value
    if($text -match '^\s*[=+@-]'){return "'"+$text};return $text
}

function Write-WBReport([string]$Path,[object[]]$Results) {
    $safe=@($Results|ForEach-Object{[pscustomobject]@{Time=(ConvertTo-WBCsvCell $_.Time);Product=(ConvertTo-WBCsvCell $_.Product);Action=(ConvertTo-WBCsvCell $_.Action);State=(ConvertTo-WBCsvCell $_.State);ExitCode=(ConvertTo-WBCsvCell $_.ExitCode);Details=(ConvertTo-WBCsvCell $_.Details)}})
    if($safe.Count){$safe|Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8 -Force}
    else{[IO.File]::WriteAllText($Path,'"Time","Product","Action","State","ExitCode","Details"'+[Environment]::NewLine,[Text.UTF8Encoding]::new($true))}
}

function Invoke-WBBatch([string]$Root,[string]$RequestPath,[string]$OutputPath) {
    $mutex=New-Object Threading.Mutex($false,'Global\USBWinBatchV1.Batch')
    $owned=$false
    try{
        try{$owned=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$owned=$true}
        if(-not $owned){throw '本机已有一个执行批次，不能从另一个窗口重复启动。'}
        return Invoke-WBBatchInternal -Root $Root -RequestPath $RequestPath -OutputPath $OutputPath
    }finally{if($owned){$mutex.ReleaseMutex()};$mutex.Dispose()}
}

function Invoke-WBBatchInternal([string]$Root,[string]$RequestPath,[string]$OutputPath) {
    $request=Get-Content -LiteralPath $RequestPath -Raw -Encoding UTF8 -ErrorAction Stop|ConvertFrom-Json
    $silentOnly=Get-WBValue $request 'SilentOnly' $false
    if($silentOnly -isnot [bool]){throw '静默模式设置无效，请重新确认'}
    $snapshotPath=[string](Get-WBValue $request 'SnapshotPath')
    if(-not $snapshotPath -or -not (Test-Path -LiteralPath $snapshotPath)){throw '原始扫描文件不存在，请重新扫描。'}
    $original=Get-Content -LiteralPath $snapshotPath -Raw -Encoding UTF8|ConvertFrom-Json
    if((Get-WBValue $original 'Demo' $false)){throw '演示数据禁止执行。'}
    if((Get-WBValue $original 'SelectionMode') -cne 'AllApps'){throw '预览不是全部应用版，请重新扫描。'}
    Assert-WBSnapshotReady $original
    Assert-WBMachineBinding $original $request (Get-WBMachineIdentity)
    if($original.Computer -cne $env:COMPUTERNAME -or $original.UserSid -cne (Get-WBUserSid)){throw '原始扫描不属于当前机器或用户。'}
    if((Get-Date)-[datetime]::ParseExact($original.ScanTime,'yyyy-MM-dd HH:mm:ss',[Globalization.CultureInfo]::InvariantCulture) -gt [TimeSpan]::FromHours(2)){throw '预览超过两小时，请重新扫描。'}
    if(-not (Test-WBAdmin)){throw '执行需要管理员权限；请通过界面确认后提权。'}
    Assert-WBNoActiveInstaller
    $cfg=Read-WBConfig $Root;$fresh=Get-WBSnapshot $Root
    Assert-WBSnapshotReady $fresh
    Assert-WBInstallSelectionReady -Snapshot $fresh -InstallIds $request.InstallIds
    Assert-WBRequest -Request $request -Computer $env:COMPUTERNAME -UserSid (Get-WBUserSid) -Targets $fresh.Targets -InstallIds @($cfg.Install.Id)
    $selected=New-Object 'System.Collections.Generic.List[object]'
    foreach($id in @($request.TargetIds)){
        $old=@($original.Targets|Where-Object Id -ceq $id);$now=@($fresh.Targets|Where-Object Id -ceq $id)
        if($old.Count -ne 1 -or $now.Count -ne 1 -or $old[0].Fingerprint -cne $now[0].Fingerprint -or $old[0].FileHash -cne $now[0].FileHash -or (Get-WBValue $old[0] 'InvocationFingerprint') -cne (Get-WBValue $now[0] 'InvocationFingerprint')){throw '产品或卸载器自扫描后已变化，请重新扫描。'}
        $selected.Add($now[0])
    }
    Assert-WBAllAppsSelection -Targets $selected.ToArray() -InstallIds $request.InstallIds -Config $cfg
    foreach($target in $selected){if($target.Action -eq 'AppxUninstall'){Assert-WBAppxRemovalReady $target $fresh}}
    $session=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($OutputPath));[IO.Directory]::CreateDirectory($session)|Out-Null
    $cancelPath=Join-Path $session 'cancel.flag';$logPath=Join-Path $session 'activity.log';$report=Join-Path $session ('结果-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.csv')
    $results=New-Object 'System.Collections.Generic.List[object]';$percent=0;$packages=@{};$installPlans=@{};$needsRestart=$false
    foreach($target in $selected){$results.Add([pscustomobject]@{Time=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss');Product=$target.Name;Action=$(if($target.Action -eq 'Shortcut'){'移除快捷方式'}elseif($target.Action -eq 'PortableRemove'){'移除程序文件'}else{'卸载'});State='未开始';ExitCode='';Details='等待前序步骤'})}
    foreach($id in @($request.InstallIds)){$product=@($cfg.Install|Where-Object Id -ceq $id)[0];$results.Add([pscustomobject]@{Time=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss');Product=$product.Name;Action='安装';State='未开始';ExitCode='';Details='等待安装包准备及前序步骤'})}
    $status=[pscustomobject]@{State='Running';Message='重新验证清单通过，正在准备安装包';Percent=0;Results=@();ReportPath=$report;Error=''}
    function Publish-WBStatus([string]$Message) {
        $status.Message=$Message;$status.Percent=$percent;$status.Results=@($results.ToArray())
        Write-WBReport $report $status.Results;Write-WBJson $OutputPath $status
        Add-Content -LiteralPath $logPath -Value ((Get-Date -Format 'HH:mm:ss')+' '+$Message) -Encoding UTF8
    }
    function Add-WBResult([string]$Product,[string]$Action,[string]$State,[string]$Details,$ExitCode='') {
        $pending=@($results|Where-Object{$_.Product -ceq $Product -and $_.Action -ceq $Action -and $_.State -in @('未开始','进行中')}|Select-Object -First 1)
        if($pending.Count){$row=$pending[0];$row.Time=Get-Date -Format 'yyyy-MM-dd HH:mm:ss';$row.State=$State;$row.ExitCode=$ExitCode;$row.Details=$Details}
        else{$results.Add([pscustomobject]@{Time=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss');Product=$Product;Action=$Action;State=$State;ExitCode=$ExitCode;Details=$Details})}
        Publish-WBStatus ($Product+'：'+$State+'；'+$Details)
    }
    try{
        Publish-WBStatus '清单验证完成，未开始卸载。安装包将全部准备完成后再继续。'
        foreach($id in @($request.InstallIds)){
            if(Test-Path -LiteralPath $cancelPath){throw '用户已取消；未继续后续操作。'}
            $product=@($cfg.Install|Where-Object Id -ceq $id)[0]
            $existing=@($fresh.Installations|Where-Object { $_.Id -ceq $id -and $_.State -eq 'Present' })
            if($existing.Count){Add-WBResult $product.Name '安装' '已跳过' '检测到已有安装；第一版不自动升级。';continue}
            Publish-WBStatus ('准备 '+$product.Name+' 官方安装包；联网或签名检查可能需要等待。')
            $local=[string](Get-WBValue (Get-WBValue $request 'PackagePaths' $null) $id)
            $packages[$id]=Get-WBPackage -Root $Root -Product $product -LocalPath $local -CancelPath $cancelPath
            $installPlans[$id]=Get-WBInstallInvocation -Product $product -Package $packages[$id]
            $percent=[int](10*$packages.Count/[Math]::Max(1,@($request.InstallIds).Count))
            Add-WBResult $product.Name '准备安装包' '校验通过' ('签名：'+$packages[$id].Signer+'；文件版本：'+$packages[$id].Version+'；文件：'+$packages[$id].Path)
        }
        $step=0;$total=$selected.Count+$packages.Count
        foreach($target in $selected){
            if(Test-Path -LiteralPath $cancelPath){throw '用户已取消；未继续后续操作。'}
            if($silentOnly -and $target.Action -eq 'ManualUninstall'){
                Add-WBResult $target.Name '卸载' '不支持静默' '已跳过，未弹出卸载窗口；可取消“仅静默卸载”后重新选择此项。'
                $step++;$percent=[int](100*$step/[Math]::Max(1,$total));Publish-WBStatus ('已处理 '+$step+'/'+$total)
                continue
            }
            $current=Get-WBSnapshot $Root;Assert-WBSnapshotReady $current
            if($target.Action -eq 'AppxUninstall' -and -not $current.CompleteAppx){throw '商店应用复查不完整，不能判定目标已移除'}
            $same=Get-WBCurrentTarget $target $current
            if($null -eq $same){Add-WBResult $target.Name $(if($target.Action -eq 'Shortcut'){'移除快捷方式'}elseif($target.Action -eq 'PortableRemove'){'移除程序文件'}else{'卸载'}) '未发现' '完整复查未发现原产品，不运行卸载器。';continue}
            $pending=@($results|Where-Object{$_.Product -ceq $target.Name -and $_.State -eq '未开始'}|Select-Object -First 1);if($pending.Count){$pending[0].State='进行中';$pending[0].Details='动作开始，等待复查结果'}
            Publish-WBStatus ('处理 '+$target.Name+$(if($target.Action -eq 'ManualUninstall'){'；请在厂商窗口完成卸载'}else{'；正在静默卸载并等待复查'}))
            if($target.Action -eq 'PortableRemove'){
                Publish-WBStatus ('移除 '+$target.Name+' 程序文件；保留配置并保存恢复备份')
                $backup=Invoke-WBPortableRemoval -Target $same -Snapshot $current -Session $session -CancelPath $cancelPath
                Add-WBResult $target.Name '移除程序文件' '成功' ('已移除主程序及对应快捷方式；配置和其他文件保留。备份：'+$backup)
            }elseif($target.Action -eq 'Shortcut'){
                $link=[string]$target.Record.Path
                if([IO.Path]::GetExtension($link) -ine '.url'){throw '快捷方式类型已变化。'}
                # Remove exactly the previously previewed file, never its target or containing directory.
                Remove-Item -LiteralPath $link -ErrorAction Stop
                if(Test-Path -LiteralPath $link){Add-WBResult $target.Name '移除快捷方式' '失败' '文件仍存在。'}else{Add-WBResult $target.Name '移除快捷方式' '成功' '仅移除了网页快捷方式，没有卸载程序或删除用户数据。'}
            }elseif($target.Action -eq 'AppxUninstall'){
                Invoke-WBAppxRemoval $same $current
                $after=Get-WBSnapshot $Root;Assert-WBSnapshotReady $after
                if(-not $after.CompleteAppx){throw '卸载后的商店应用扫描不完整，无法确认结果'}
                $remains=@($after.Inventory|Where-Object{$_.Source -eq 'Appx' -and $_.Identity -ceq $target.Identity})
                if($remains.Count -eq 0){Add-WBResult $target.Name '卸载' '成功' '当前用户的原应用包已移除；未更改其他账户或系统预装映像。'}
                else{Add-WBResult $target.Name '卸载' '需人工' '当前用户仍登记此应用包，请在系统列表核对。'}
            }else{
                $command=Get-WBAllAppsUninstallSpec $same.Record
                if((Get-WBCommandFileHash $command) -cne $target.FileHash){throw '卸载器文件已变化，停止执行。'}
                $waitMinutes=if($target.Action -eq 'AutoUninstall'){5}else{30}
                $successCodes=@(0);$restartCodes=@(3010,1641)
                if($command.Rule -ceq 'Chrome'){$successCodes+=19;$restartCodes+=29}
                $probeDeadline=[datetime]::UtcNow.AddMinutes($waitMinutes)
                $completionProbe={param($state) Invoke-WBBoundedUninstallProbe -Root $Root -Target $target -State $state -Deadline $probeDeadline -CancelPath $cancelPath -Session $session}
                $proc=Invoke-WBProcess -FilePath $command.FilePath -Arguments $command.Arguments -CancelPath $cancelPath -TimeoutMinutes $waitMinutes -CompletionProbe $completionProbe -CompletionSuccessCodes $successCodes -InspectNonzeroExit
                if($proc.TimedOut){Add-WBResult $target.Name '卸载' '需人工' '等待超时，已停止后续操作。可点击“恢复执行状态”查看仍在运行的进程。';throw '卸载等待超时。请点击“恢复执行状态”，按诊断结果处理后重新扫描。'}
                if($proc.Cancelled -or (Test-Path -LiteralPath $cancelPath)){throw '用户已取消，停止后续操作；请重新扫描确认当前软件状态。'}
                if(Get-WBValue $proc 'RestartRequired' $false){
                    Add-WBResult $target.Name '卸载' '待重启复查' '原卸载器已退出，卸载登记已移除，但输入法后台仍运行。已停止等待及后续操作，请重启电脑后重新扫描；未强杀进程。' $proc.ExitCode
                    throw '输入法后台仍在运行，需要重启电脑后重新扫描；未自动重启。'
                }
                Publish-WBStatus ('复查 '+$target.Name+'；最多等待二十秒')
                $verification=Invoke-WBBoundedUninstallProbe -Root $Root -Target $target -State $null -Deadline ([datetime]::UtcNow.AddSeconds(20)) -CancelPath $cancelPath -Session $session -Operation Removal
                if(-not $verification.Complete){throw '卸载后复查超时、被取消或无法读取，未判定卸载成功。请重新扫描。'}
                $remains=@(if(-not $verification.Absent){1})
                if($proc.ExitCode -in $restartCodes){$needsRestart=$true;Add-WBResult $target.Name '卸载' '待重启复查' '厂商要求重启；未自动重启。' $proc.ExitCode}
                elseif($remains.Count -eq 0 -and $proc.ExitCode -in $successCodes){Add-WBResult $target.Name '卸载' '成功' $(if($target.Source -eq 'Shortcut'){'原程序文件已移除；未自动清理其他残留。'}else{'复查未发现原产品登记；不自动清理其他残留。'}) $proc.ExitCode}
                elseif($remains.Count -eq 0){Add-WBResult $target.Name '卸载' '登记已移除' ('卸载记录已移除；卸载器退出码 '+$proc.ExitCode+'（非标准成功状态）。请重新扫描核对，未认定完整卸载成功。') $proc.ExitCode}
                else{Add-WBResult $target.Name '卸载' '需人工' ('卸载器退出码 '+$proc.ExitCode+'；原产品登记仍存在，未确认卸载成功。'+$(if($target.Action -eq 'AutoUninstall'){'本次静默方式可能未生效。'}else{'可能取消、失败或需要重启。'})) $proc.ExitCode}
                if($proc.TrackingWarning){Add-WBResult $target.Name '进程跟踪' '需人工' '无法完整跟踪派生进程；停止后续动作，避免重叠执行。';throw '无法确认厂商程序是否完全结束。'}
                if($proc.Cancelled){throw '用户已取消；当前厂商窗口已结束，停止后续操作。'}
                if($needsRestart){throw '需要先重启再重新扫描；未继续后续操作。'}
            }
            $step++;$percent=[int](100*$step/[Math]::Max(1,$total));Publish-WBStatus ('已处理 '+$step+'/'+$total)
        }
        foreach($id in @($request.InstallIds)){
            if(-not $packages.ContainsKey($id)){continue}
            if(Test-Path -LiteralPath $cancelPath){throw '用户已取消；未继续后续操作。'}
            $product=@($cfg.Install|Where-Object Id -ceq $id)[0];$package=$packages[$id]
            $check=Test-WBInstaller $package.Path $product
            if($check.Sha256 -cne $package.Sha256){throw '安装包自准备后发生变化。'}
            $latest=Get-WBSnapshot $Root
            Assert-WBSnapshotReady $latest
            Assert-WBInstallSelectionReady -Snapshot $latest -InstallIds @($id)
            if(@($latest.Installations|Where-Object{$_.Id -ceq $id -and $_.State -eq 'Present'}).Count){Add-WBResult $product.Name '安装' '已跳过' '安装前复查发现该软件已存在。';continue}
            $invocation=$installPlans[$id]
            if($invocation.Mode -eq 'Silent'){Publish-WBStatus ('正在自动安装 '+$product.Name+'，完成后自动复查；无需点击安装窗口。')}
            else{Publish-WBStatus ('打开 '+$product.Name+' 官方安装窗口；请取消附加软件、首页及默认浏览器修改选项。')}
            $pending=@($results|Where-Object{$_.Product -ceq $product.Name -and $_.Action -eq '安装' -and $_.State -eq '未开始'}|Select-Object -First 1);if($pending.Count){$pending[0].State='进行中';$pending[0].Details='安装器已准备启动，等待复查结果'}
            $completionProbe=$null
            if($invocation.Mode -eq 'Silent'){$completionProbe={param($state) Get-WBInstallRuntimeApproval -Root $Root -Product $product -Package $package -State $state}}
            $proc=Invoke-WBProcess -FilePath $package.Path -Arguments $invocation.Arguments -CancelPath $cancelPath -TimeoutMinutes $invocation.TimeoutMinutes -CompletionProbe $completionProbe
            if($proc.TimedOut){Add-WBResult $product.Name '安装' '需人工' '等待超时，未强杀厂商进程；整批停止。';throw '安装器仍可能运行。'}
            $after=Get-WBSnapshot $Root;Assert-WBSnapshotReady $after;$installed=@($after.Installations|Where-Object{$_.Id -ceq $id -and $_.State -eq 'Present'})
            if($invocation.Mode -eq 'Silent' -and -not (Get-WBInstalledProductRuntime -Product $product -Package $package -Snapshot $after)){$installed=@()}
            if($proc.ExitCode -in @(3010,1641)){$needsRestart=$true;Add-WBResult $product.Name '安装' '待重启复查' '厂商要求重启，未自动重启。' $proc.ExitCode}
            elseif($installed.Count -and $proc.ExitCode -eq 0){Add-WBResult $product.Name '安装' '已检测到安装' ('检测版本：'+$installed[0].Version+'；安装登记和程序文件已复查。') $proc.ExitCode}
            else{Add-WBResult $product.Name '安装' '需人工' '复查未发现安装登记；可能取消或引导器未完成，不视为成功。' $proc.ExitCode}
            if($proc.TrackingWarning){throw '无法完整跟踪安装器派生进程，已停止后续动作。'}
            if($proc.Cancelled){throw '用户已取消，停止后续操作。'}
            if($needsRestart){throw '需要重启再重新扫描，后续动作未执行。'}
            $step++;$percent=[int](100*$step/[Math]::Max(1,$total));Publish-WBStatus ('已处理 '+$step+'/'+$total)
        }
        $percent=100;$status.State='Completed'
        $unresolved=@($results|Where-Object State -in @('需人工','失败','待重启复查','不支持静默','登记已移除')).Count
        Publish-WBStatus ('本批已结束；待处理项 '+$unresolved+'。请以逐项结果为准，未自动重启。')
        return $status
    }catch{
        $cancelled=Test-Path -LiteralPath $cancelPath
        $status.State=if($cancelled){'Cancelled'}else{'Failed'};$status.Error=$_.Exception.Message
        Complete-WBPendingResults -Results $results.ToArray() -Reason $status.Error -Cancelled $cancelled|Out-Null
        Publish-WBStatus ('已停止：'+$status.Error+'；后续动作未执行。')
        throw
    }
}
