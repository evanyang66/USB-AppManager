function Get-WBUserSid { return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
function Test-WBAdmin {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WBInventory($Config,[System.Collections.Generic.List[string]]$Warnings) {
    $script:WBRegistryComplete=$true
    $script:WBAppxComplete=$true
    $records=New-Object 'System.Collections.Generic.List[object]';$seen=@{}
    $subpath='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    foreach($hiveName in @('LocalMachine','CurrentUser')){
        foreach($viewName in @('Registry64','Registry32')){
            $base=$null;$key=$null
            try {
                $hive=[Microsoft.Win32.RegistryHive]::$hiveName;$view=[Microsoft.Win32.RegistryView]::$viewName
                $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,$view);$key=$base.OpenSubKey($subpath)
                if($null -eq $key){continue}
                foreach($childName in $key.GetSubKeyNames()){
                    $child=$null
                    try{
                        $child=$key.OpenSubKey($childName);if($null -eq $child){continue}
                        $name=[string]$child.GetValue('DisplayName','');if(-not $name){continue}
                        $command=[string]$child.GetValue('UninstallString','');$location=[string]$child.GetValue('InstallLocation','')
                        $dedup=$hiveName+'|'+$viewName+'|'+$childName
                        if($seen.ContainsKey($dedup)){continue};$seen[$dedup]=$true
                        $records.Add([pscustomobject]@{Name=$name;Version=[string]$child.GetValue('DisplayVersion','');Publisher=[string]$child.GetValue('Publisher','');Source='Registry';Identity=($hiveName+'|'+$viewName+'|'+$subpath+'\'+$childName);InstallLocation=$location;UninstallString=$command;QuietUninstallString=[string]$child.GetValue('QuietUninstallString','');WindowsInstaller=$child.GetValue('WindowsInstaller',0);PackageName='';Path='';TargetPath='';Arguments=''})
                    }catch{$script:WBRegistryComplete=$false;$Warnings.Add('无法读取卸载记录：'+$childName+'；'+$_.Exception.Message)}finally{if($child){$child.Dispose()}}
                }
            }catch{$script:WBRegistryComplete=$false;$Warnings.Add('扫描注册表失败：'+$hiveName+'/'+$viewName+'；'+$_.Exception.Message)}finally{if($key){$key.Dispose()};if($base){$base.Dispose()}}
        }
    }
    $appNames=@{}
    try{foreach($entry in @(Get-StartApps -ErrorAction Stop)){$family=([string]$entry.AppID).Split('!')[0];if(-not $appNames.ContainsKey($family)){$appNames[$family]=[string]$entry.Name}}}catch{}
    try{
        foreach($app in @(Get-AppxPackage -ErrorAction Stop)){
            $display=if($appNames.ContainsKey([string]$app.PackageFamilyName)){$appNames[[string]$app.PackageFamilyName]}else{[string]$app.Name}
            $records.Add([pscustomobject]@{Name=$app.Name;DisplayName=$display;Version=[string]$app.Version;Publisher=$app.Publisher;Source='Appx';Identity=$app.PackageFullName;InstallLocation=$app.InstallLocation;UninstallString='';QuietUninstallString='';WindowsInstaller=0;PackageName=$app.Name;Path='';TargetPath='';Arguments='';NonRemovable=(Get-WBValue $app 'NonRemovable' $null);IsFramework=(Get-WBValue $app 'IsFramework' $null);IsResourcePackage=(Get-WBValue $app 'IsResourcePackage' $null)})
        }
    }catch{$script:WBAppxComplete=$false;$Warnings.Add('商店应用扫描不完整，商店应用卸载暂停：'+$_.Exception.Message)}
    $folders=@([Environment]::GetFolderPath('Desktop'),[Environment]::GetFolderPath('CommonDesktopDirectory'),[Environment]::GetFolderPath('StartMenu'),[Environment]::GetFolderPath('CommonStartMenu'))|Select-Object -Unique
    $shell=$null
    try{
        $shell=New-Object -ComObject WScript.Shell
        foreach($folder in $folders){
            if(-not $folder -or -not (Test-Path -LiteralPath $folder)){continue}
            foreach($file in @(Get-ChildItem -LiteralPath $folder -File -Recurse -ErrorAction SilentlyContinue | Where-Object Extension -in @('.url','.lnk'))){
                $name=$file.BaseName
                try{
                    $target='';$args='';$publisher=''
                    if($file.Extension -ieq '.url'){
                        $urlLine=@(Get-Content -LiteralPath $file.FullName -ErrorAction Stop | Where-Object {$_ -match '^URL='})
                        if($urlLine.Count){$target=$urlLine[0].Substring(4).Trim()}
                    }else{
                        $shortcut=$shell.CreateShortcut($file.FullName);$target=$shortcut.TargetPath;$args=$shortcut.Arguments
                        if([IO.Path]::GetExtension($target) -ieq '.exe' -and $target -match '^[A-Za-z]:\\' -and (Test-Path -LiteralPath $target -PathType Leaf)){
                            try{$publisher=[string]([Diagnostics.FileVersionInfo]::GetVersionInfo($target).CompanyName)}catch{}
                        }
                    }
                    $records.Add([pscustomobject]@{Name=$name;Version='';Publisher=$publisher;Source='Shortcut';Identity=$file.FullName;InstallLocation='';UninstallString='';QuietUninstallString='';WindowsInstaller=0;PackageName='';Path=$file.FullName;TargetPath=$target;Arguments=$args})
                }catch{$Warnings.Add('快捷方式读取失败：'+$file.Name)}
            }
        }
    }catch{$Warnings.Add('快捷方式识别不可用：'+$_.Exception.Message)}finally{if($shell){[Runtime.InteropServices.Marshal]::ReleaseComObject($shell)|Out-Null}}
    return $records.ToArray()
}

function Get-WBDemoInventory {
    $names=@('360安全浏览器','360安全卫士','Google Chrome','加速浏览器-2345','安全组件-2345','老毛桃U盘启动装机工具','Windows系统工具','驱动人生','超级兔子数据恢复','电脑管家','电影和电视','截图和草图','WPS Office','AMD Software')
    $items=New-Object 'System.Collections.Generic.List[object]';$number=0
    foreach($name in $names){
        $number++;$location='C:\Program Files\DemoProduct'+$number;$publisher='身份待核实（演示）'
        switch($name){
            '360安全浏览器'{$location='C:\Program Files\360\360se6';$publisher='360安全中心'}
            '360安全卫士'{$location='C:\Program Files\360\360Safe';$publisher='360安全中心'}
            'Google Chrome'{$location='C:\Program Files\Google\Chrome\Bin';$publisher='Google LLC'}
            '加速浏览器-2345'{$location='C:\Program Files\2345Explorer';$publisher='上海二三四五网络科技有限公司'}
            '安全组件-2345'{$location='C:\Program Files\2345Safe';$publisher='上海二三四五网络科技有限公司'}
            '驱动人生'{$location='C:\Program Files\DTLSoft\DriveTheLife8';$publisher='深圳市驱动人生科技股份有限公司'}
        }
        $items.Add([pscustomobject]@{Name=$name;Version='1.0（演示）';Publisher=$publisher;Source='Registry';Identity=('DEMO|Registry64|Product'+$number);InstallLocation=$location;UninstallString=('"'+$location+'\uninstall.exe"');QuietUninstallString='';WindowsInstaller=0;PackageName='';Path='';TargetPath='';Arguments=''})
    }
    $items.Add([pscustomobject]@{Name='淘宝';Version='';Publisher='';Source='Shortcut';Identity='C:\Users\Public\Desktop\淘宝.url';InstallLocation='';UninstallString='';QuietUninstallString='';WindowsInstaller=0;PackageName='';Path='C:\Users\Public\Desktop\淘宝.url';TargetPath='https://www.taobao.com/';Arguments=''})
    return $items.ToArray()
}

function Get-WBQQDriveProbes([string[]]$Roots) {
    foreach($root in $Roots){
        foreach($relative in @('Program Files\Tencent\QQNT\QQ.exe','Program Files (x86)\Tencent\QQNT\QQ.exe','Program Files\Tencent\QQ\Bin\QQ.exe','Program Files (x86)\Tencent\QQ\Bin\QQ.exe','Tencent\QQNT\QQ.exe')){
            [IO.Path]::Combine($root,$relative)
        }
    }
}

function Get-WBQQCandidates($Inventory,[System.Collections.Generic.List[string]]$Warnings) {
    $candidates=New-Object 'System.Collections.Generic.List[object]';$seen=@{}
    function Add-WBQQCandidate([string]$Path,[string]$Source){
        if(-not $Path){return}
        $Path=[Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
        if(-not [IO.Path]::IsPathRooted($Path) -or [IO.Path]::GetFileName($Path) -ine 'QQ.exe'){return}
        $Path=[IO.Path]::GetFullPath($Path)
        if($seen.ContainsKey($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)){return}
        $seen[$Path]=$true;$candidates.Add([pscustomobject]@{Path=$Path;DetectionSource=$Source})
    }
    foreach($record in @($Inventory|Where-Object{(Get-WBValue $_ 'Source') -eq 'Shortcut'})){
        Add-WBQQCandidate ([string](Get-WBValue $record 'TargetPath')) '软件快捷方式'
    }
    try{
        $sid=Get-WBUserSid
        foreach($process in @(Get-CimInstance Win32_Process -Filter "Name='QQ.exe'" -ErrorAction Stop)){
            $path=[string]$process.ExecutablePath
            if($path -and $seen.ContainsKey($path)){continue}
            try{
                $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
                if($owner.ReturnValue -eq 0 -and $owner.Sid -eq $sid){Add-WBQQCandidate $path '当前用户正在运行的 QQ'}
            }catch{$Warnings.Add('无法核对 QQ 进程所属用户；继续检查其他已知位置。')}
        }
    }catch{$Warnings.Add('QQ 进程只读识别不可用；继续检查其他已知位置。')}
    foreach($hiveName in @('LocalMachine','CurrentUser')){
        foreach($viewName in @('Registry64','Registry32')){
            $base=$null;$key=$null
            try{
                $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::$hiveName,[Microsoft.Win32.RegistryView]::$viewName)
                $key=$base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\QQ.exe')
                if($key){Add-WBQQCandidate ([string]$key.GetValue('','')) '注册表应用路径'}
            }catch{$Warnings.Add('无法读取 QQ 应用路径；继续检查其他已知位置。')}finally{if($key){$key.Dispose()};if($base){$base.Dispose()}}
        }
    }
    $roots=@([IO.DriveInfo]::GetDrives()|Where-Object{$_.DriveType -eq [IO.DriveType]::Fixed -and $_.IsReady}|ForEach-Object{$_.RootDirectory.FullName})
    foreach($path in @(Get-WBQQDriveProbes $roots)){Add-WBQQCandidate $path '固定磁盘常见 QQ 目录'}
    $local=[Environment]::GetFolderPath('LocalApplicationData')
    foreach($relative in @('Tencent\QQNT\QQ.exe','Programs\Tencent\QQNT\QQ.exe')){if($local){Add-WBQQCandidate (Join-Path $local $relative) '当前用户常见 QQ 目录'}}
    return $candidates.ToArray()
}

function Get-WBInstalledQQEvidence($Product,[string]$Path,[string]$DetectionSource) {
    if($Product.Id -cne 'qq' -or [IO.Path]::GetFileName($Path) -ine 'QQ.exe'){throw '不是 QQ 主程序候选文件。'}
    $evidence=Test-WBInstaller -Path $Path -Product $Product
    [pscustomobject]@{ProductId='qq';Path=$evidence.Path;Version=$evidence.Version;DetectionSource=$DetectionSource;Verified=$true}
}

function Get-WBInstallationStatus($Product,$Inventory,[bool]$CompleteRegistry,[object[]]$ExecutableEvidence=@(),[bool]$UnverifiedCandidate=$false) {
    $found=@($Inventory|Where-Object{(Get-WBValue $_ 'Source') -eq 'Registry' -and (Test-WBAlias ([string](Get-WBValue $_ 'Name')) $Product.Aliases)})
    $verified=@($ExecutableEvidence|Where-Object{(Get-WBValue $_ 'ProductId') -ceq $Product.Id -and (Get-WBValue $_ 'Verified' $false) -eq $true})
    $state='Unknown';$version='';$path='';$source='';$reason='扫描或程序文件身份未能核实，请人工核对后再安装'
    if($found.Count){$state='Present';$version=[string]$found[0].Version;$source='软件卸载登记';$reason='已安装，默认跳过；未核实是否最新版'}
    elseif($verified.Count){$state='Present';$version=[string]$verified[0].Version;$path=[string]$verified[0].Path;$source=[string]$verified[0].DetectionSource;$reason='已校验现有程序的签名与产品身份，默认跳过；未发现卸载登记'}
    elseif($CompleteRegistry -and -not $UnverifiedCandidate){$state='Missing';$reason='未发现软件登记或可验证的现有主程序'}
    [pscustomobject]@{Id=$Product.Id;Name=$Product.Name;State=$state;Version=$version;OfficialPage=$Product.OfficialPage;Reason=$reason;DetectionSource=$source;ExecutablePath=$path;InstallMode=[string](Get-WBValue $Product 'InstallMode' 'Interactive')}
}

function Assert-WBInstallSelectionReady($Snapshot,[string[]]$InstallIds) {
    foreach($id in $InstallIds){
        $state=@($Snapshot.Installations|Where-Object Id -ceq $id)
        if($state.Count -ne 1 -or $state[0].State -notin @('Present','Missing')){throw ('安装状态未核实，停止本批处理以避免重复安装：'+$id)}
    }
}

function Get-WBSnapshot([string]$Root,[switch]$Demo) {
    $cfg=Read-WBConfig $Root;$warnings=New-Object 'System.Collections.Generic.List[string]'
    $inventory=if($Demo){@(Get-WBDemoInventory)}else{@(Get-WBInventory $cfg $warnings)}
    $completeRegistry=if($Demo){$true}else{$script:WBRegistryComplete}
    $plan=Get-WBAllAppsPlan $inventory $cfg -Demo:$Demo
    foreach($item in $plan.Targets){
        $hash=''
        if(-not $Demo -and $item.Action -in @('AutoUninstall','ManualUninstall','PortableRemove')){
            try{if(-not (Test-Path -LiteralPath $item.Command.FilePath -PathType Leaf)){throw '文件不存在'};$hash=Get-WBCommandFileHash $item.Command}
            catch{$item.Action='Review';$item.SelectedDefault=$false;$item.Reason='卸载器不存在或不可读取，需要人工核实'}
        }
        if(-not $Demo -and $item.Action -eq 'Shortcut'){
            try{$hash=(Get-FileHash -LiteralPath $item.Record.Path -Algorithm SHA256 -ErrorAction Stop).Hash}catch{$item.Action='Review';$item.SelectedDefault=$false;$item.Reason='快捷方式已变化或无法读取'}
        }
        $item|Add-Member -NotePropertyName FileHash -NotePropertyValue $hash
    }
    $installs=New-Object 'System.Collections.Generic.List[object]'
    $installRules=@($cfg.Install)
    if($installRules.Count -eq 0){throw '安装配置尚未准备完成，停止扫描。'}
    foreach($product in $installRules){
        $status=Get-WBInstallationStatus -Product $product -Inventory $inventory -CompleteRegistry $completeRegistry
        if(-not $Demo -and $product.Id -ceq 'qq' -and $status.State -ne 'Present'){
            $evidence=New-Object 'System.Collections.Generic.List[object]';$uncertain=$false
            foreach($candidate in @(Get-WBQQCandidates -Inventory $inventory -Warnings $warnings)){
                try{$evidence.Add((Get-WBInstalledQQEvidence -Product $product -Path $candidate.Path -DetectionSource $candidate.DetectionSource))}
                catch{$uncertain=$true;$warnings.Add('发现 QQ 候选文件但未通过身份校验：'+$candidate.Path+'；'+$_.Exception.Message)}
            }
            $status=Get-WBInstallationStatus -Product $product -Inventory $inventory -CompleteRegistry $completeRegistry -ExecutableEvidence $evidence.ToArray() -UnverifiedCandidate $uncertain
        }
        $installs.Add($status)
    }
    if(-not $Demo){$warnings.Add('扫描范围：当前用户及系统级已登记软件、商店应用和常见快捷方式；不扫描其他账户或全盘便携文件。')}
    if(-not $completeRegistry){$warnings.Add('软件登记扫描不完整：执行将被拦截，不能将未检测到当作已卸载。')}
    [pscustomobject]@{SchemaVersion=1;SelectionMode='AllApps';Computer=$env:COMPUTERNAME;MachineId=(Get-WBMachineIdentity);CompleteRegistry=[bool]$completeRegistry;CompleteAppx=$(if($Demo){$true}else{[bool]$script:WBAppxComplete});UserSid=(Get-WBUserSid);User=[Security.Principal.WindowsIdentity]::GetCurrent().Name;ScanTime=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss');Demo=[bool]$Demo;Targets=@($plan.Targets);Protected=@($plan.Protected);Installations=@($installs.ToArray());Warnings=@($warnings.ToArray());Inventory=@($inventory)}
}

function Get-WBMachineIdentity {
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $key=$null
    try{$key=$base.OpenSubKey('SOFTWARE\Microsoft\Cryptography');$guid=[string]$key.GetValue('MachineGuid','')}finally{if($key){$key.Dispose()};$base.Dispose()}
    if(-not $guid){throw '无法读取机器身份，不能生成可执行预览。'}
    $hardware=''
    try{$hardware=[string](Get-CimInstance Win32_ComputerSystemProduct -Property UUID -ErrorAction Stop).UUID}catch{}
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($guid+'|'+$hardware)))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
}
