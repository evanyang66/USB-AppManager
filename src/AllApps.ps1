function Get-WBAllAppsId([string]$Source,[string]$Identity) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return 'A-'+([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Source+'|'+$Identity)))).Replace('-','').Substring(0,24).ToLowerInvariant()}finally{$sha.Dispose()}
}

function Test-WBMicrosoftPublisher([string]$Publisher) {
    $company=$Publisher.Trim()
    if(-not $company){return $false}
    if($company -match '^(?:CN|O|OU|C|L|S)\s*='){
        try{
            $dn=New-Object Security.Cryptography.X509Certificates.X500DistinguishedName($company)
            $organization='';$commonName=''
            foreach($line in $dn.Decode([Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseNewLines).Split([char]10)){
                if($line.Trim() -match '^(O|CN)\s*=\s*(.+)$'){
                    $value=$matches[2].Trim().Trim('"')
                    if($matches[1] -ieq 'O'){$organization=$value}else{$commonName=$value}
                }
            }
            $company=if($organization){$organization}else{$commonName}
        }catch{return $false}
    }
    $company=($company -replace '\s+',' ').Trim()
    return ($company -imatch '^(?:Microsoft(?: Corporation| Corp\.?| Windows)?|Microsoft \(China\) Co\.,? Ltd\.?|微软(?:公司)?|微软[（(]中国[)）](?:有限公司)?)$')
}

function Assert-WBAllAppsArguments([string]$Arguments) {
    if(-not ('USBAppManager.ArgumentReader' -as [type])){
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace USBAppManager {
 public static class ArgumentReader {
  [DllImport("shell32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern IntPtr CommandLineToArgvW(string text, out int count);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr ptr);
  public static string[] Parse(string text) {
   int count; IntPtr ptr=CommandLineToArgvW(text,out count);
   if(ptr==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
   try {
    if(count<1 || count>256) throw new ArgumentException("Unsupported argument count.");
    string[] result=new string[count];
    for(int i=0;i<count;i++) result[i]=Marshal.PtrToStringUni(Marshal.ReadIntPtr(ptr,i*IntPtr.Size));
    return result;
   } finally {LocalFree(ptr);}
  }
 }
}
'@ -ErrorAction Stop
    }
    if($Arguments.Length -gt 32700 -or $Arguments -match '[\x00-\x1f]'){throw '卸载参数异常，请人工核对'}
    $tokens=@([USBAppManager.ArgumentReader]::Parse('"C:\AppManagerArgCheck.exe" '+$Arguments)|Select-Object -Skip 1)
    $normalized=$tokens -join ' '
    if($normalized -imatch '(delete|remove)[-_ ]?(profile|userdata|user-data)|/purge|--purge'){throw '卸载参数包含个人数据删除选项，需人工处理'}
}

function Get-WBAllAppsUninstallSpec($Record) {
    # Only the registered native entry is used; shortcut targets never become uninstallers.
    $copy=$Record|Select-Object *
    if(Get-WBValue $copy 'InstallLocation'){$copy.InstallLocation=[Environment]::ExpandEnvironmentVariables(([string]$copy.InstallLocation).Trim().Trim('"'))}
    $normal=[string](Get-WBValue $copy 'UninstallString')
    $quiet=[string](Get-WBValue $copy 'QuietUninstallString')
    if(-not $normal -and -not $quiet -and (Get-WBValue $copy 'Source') -eq 'Shortcut'){
        $adjacent=Find-WBAdjacentUninstaller ([string](Get-WBValue $copy 'TargetPath'))
        if(-not $adjacent){throw '未找到可用卸载程序'}
        $normal='"'+$adjacent+'"'
        $copy|Add-Member -NotePropertyName UninstallString -NotePropertyValue $normal -Force
    }
    if(-not $normal -and -not $quiet){throw '未登记卸载入口'}
    # Registered publisher/location are display evidence, not authorization gates.
    # Select the exact registered entry; never interpret it through a shell.
    $chosen=if($quiet){$quiet}else{$normal}
    $spec=Get-WBRegisteredUninstallCommand $chosen $copy
    $action=if($quiet -or $spec.Backend -eq 'WinGet'){'AutoUninstall'}else{'ManualUninstall'}
    if($spec.IsMsi){
        $validated=Get-WBUninstallSpec $copy ([pscustomobject]@{ForceInteractive=$false})
        $spec.Arguments=$validated.Arguments;$action='AutoUninstall'
    }
    $spec|Add-Member -NotePropertyName Action -NotePropertyValue $action
    $spec|Add-Member -NotePropertyName Rule -NotePropertyValue $(if($spec.IsMsi){'MSI'}elseif($quiet){'RegisteredQuiet'}else{$spec.Backend})
    $interactiveReason=Get-WBInteractiveUninstallReason -Path $spec.FilePath -Record $copy
    if($interactiveReason){
        # A known no-op quiet entry must not win over the normal registered entry.
        if(-not $normal){throw '此卸载器静默入口无效，且未登记普通卸载入口。'}
        $spec=Get-WBRegisteredUninstallCommand $normal $copy
        $spec|Add-Member -NotePropertyName Action -NotePropertyValue 'ManualUninstall'
        $spec|Add-Member -NotePropertyName Rule -NotePropertyValue $(if($interactiveReason -match '360'){'360Manual'}else{'2345CustomPage'})
        $spec|Add-Member -NotePropertyName Reason -NotePropertyValue $interactiveReason
        if($spec.Rule -ceq '360Manual'){
            $parsed=Get-WBSilentArgumentTokens $spec.Arguments
            if($null -eq $parsed){throw '360普通卸载参数无法读取，请在系统应用列表卸载。'}
            if(@($parsed.Tokens|Where-Object {$_ -cin @('/S','/NOREBOOT=1','--force-uninstall')}).Count){
                if(@($parsed.Tokens|Where-Object {$_ -cnotin @('/S','/NOREBOOT=1','--force-uninstall','--uninstall','--system-level','--verbose-logging')}).Count){throw '360卸载参数混有未知模式，请在系统应用列表卸载。'}
                $spec.Arguments=(@($parsed.Tokens|Where-Object {$_ -cnotin @('/S','/NOREBOOT=1','--force-uninstall')}) -join ' ')
            }
        }
        Assert-WBAllAppsArguments $spec.Arguments
        return $spec
    }
    $automation=Get-Command Get-WBUninstallAutomation -ErrorAction SilentlyContinue
    if($automation -and $spec.Backend -in @('Native','Rundll') -and -not $spec.IsMsi){
        $profile=Get-WBUninstallAutomation -Record $copy -Command $spec
        if($null -ne $profile){
            $spec.Arguments=$profile.Arguments;$spec.Action='AutoUninstall';$spec.Rule=$profile.Rule
            if($profile.PSObject.Properties['PayloadPaths']){$spec.PayloadPaths=@($profile.PayloadPaths)}
        }
    }
    Assert-WBAllAppsArguments $spec.Arguments
    return $spec
}

function Test-WBAppxRemovalMetadata($Record) {
    $value=Get-WBValue $Record 'NonRemovable' $null
    if($value -isnot [bool] -or $value){return $false}
    $name=[string](Get-WBValue $Record 'PackageName');$identity=[string](Get-WBValue $Record 'Identity')
    return ($name -match '^[A-Za-z0-9][A-Za-z0-9.-]+$' -and $identity -cmatch ('^'+[regex]::Escape($name)+'_[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+_(?:x64|x86|arm64|arm|neutral)_[A-Za-z0-9.-]*_[A-Za-z0-9]+$'))
}

function Merge-WBRegistryMirrors([object[]]$Inventory) {
    $groups=@{};$others=New-Object 'System.Collections.Generic.List[object]'
    foreach($record in $Inventory){
        if((Get-WBValue $record 'Source') -cne 'Registry'){$others.Add($record);continue}
        $keyRecord=$record|Select-Object *
        $keyRecord.Identity=([string]$record.Identity) -replace '\|Registry(?:32|64)\|','|RegistryShared|'
        $keyRecord|Add-Member -NotePropertyName RegistryMirrorIdentities -NotePropertyValue '' -Force
        $key=Get-WBFingerprint $keyRecord
        if(-not $groups.ContainsKey($key)){$groups[$key]=New-Object 'System.Collections.Generic.List[object]'}
        $groups[$key].Add($record)
    }
    foreach($group in $groups.Values){
        # Merge only identical data in the two views of the same hive and subkey.
        $representative=@($group|Sort-Object @{Expression={$_.Identity -match '\|Registry64\|'};Descending=$true},Identity)[0]|Select-Object *
        $ids=@($group|ForEach-Object{[string]$_.Identity}|Sort-Object -Unique)
        $representative|Add-Member -NotePropertyName RegistryMirrorIdentities -NotePropertyValue ($ids -join "`n") -Force
        $others.Add($representative)
    }
    return $others.ToArray()
}

function Get-WBAllAppsPlan([object[]]$Inventory,$Config,[switch]$Demo) {
    $targets=New-Object 'System.Collections.Generic.List[object]';$seen=@{};$shortcutSeen=@{}
    $primary=@(Merge-WBRegistryMirrors $Inventory|Where-Object{(Get-WBValue $_ 'Source') -in @('Registry','Appx')})
    foreach($record in @($primary)+@($Inventory|Where-Object{(Get-WBValue $_ 'Source') -eq 'Shortcut'})){
        $source=[string](Get-WBValue $record 'Source');$identity=[string](Get-WBValue $record 'Identity');$name=[string](Get-WBValue $record 'Name')
        if(-not $identity -or -not $name -or $source -notin @('Registry','Appx','Shortcut')){continue}
        if(Test-WBMicrosoftPublisher ([string](Get-WBValue $record 'Publisher'))){continue}
        $dedup=$source+'|'+$identity;if($seen.ContainsKey($dedup)){continue};$seen[$dedup]=$true
        if($source -eq 'Shortcut'){
            $dest=[string](Get-WBValue $record 'TargetPath');if(-not $dest){continue}
            if([IO.Path]::GetExtension($dest) -ine '.exe' -or -not [IO.Path]::IsPathRooted($dest)){continue}
            $windowsRoot=$env:windir.TrimEnd('\')+'\'
            if($dest.StartsWith($windowsRoot,[StringComparison]::OrdinalIgnoreCase)){continue}
            $matched=$false
            foreach($installed in $primary){
                $loc=[string](Get-WBValue $installed 'InstallLocation')
                if($loc){$loc=[Environment]::ExpandEnvironmentVariables($loc.Trim().Trim('"'))}
                if(-not $loc -and (Get-WBValue $installed 'Source') -eq 'Registry'){
                    try{$entry=Get-WBAllAppsUninstallSpec $installed;if([IO.Path]::GetFileName($entry.FilePath) -ine 'msiexec.exe'){$loc=[IO.Path]::GetDirectoryName($entry.FilePath)}}catch{}
                }
                if($loc -and $dest.StartsWith($loc.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){$matched=$true;break}
            }
            if($matched -or $shortcutSeen.ContainsKey($dest)){continue};$shortcutSeen[$dest]=$true
        }
        $display=[string](Get-WBValue $record 'DisplayName');if($source -eq 'Appx' -and $display){$name=$display}
        $action='Review';$reason='未登记卸载入口';$command=$null;$risk=''
        $preserved=$false
        foreach($rule in $Config.Protect){
            if((Test-WBAlias $name $rule.Aliases) -or (Test-WBAlias ([string](Get-WBValue $record 'Name')) $rule.Aliases) -or ([string](Get-WBValue $record 'PackageName') -in @($rule.PackageNames))){$preserved=$true;break}
        }
        if($preserved){$reason='按原要求保留'}
        elseif($source -in @('Registry','Shortcut')){
            try{
                $command=Get-WBPortableRemovalSpec $record $Inventory
                if($null -eq $command){$command=Get-WBAllAppsUninstallSpec $record}
                if(-not $Demo -and -not (Test-Path -LiteralPath $command.FilePath -PathType Leaf)){throw '卸载器不存在或不可读取'}
                $action=$command.Action;$reason=if($action -eq 'AutoUninstall'){'静默卸载：'+$command.Rule}elseif(Get-WBValue $command 'Reason'){[string]$command.Reason}else{'暂未适配静默卸载'}
                if($command.Rule -eq '360SafeQuiet'){$reason='尝试静默卸载；360自保护可能需确认'}
            }catch{$reason=$_.Exception.Message;$command=$null}
        }elseif($source -eq 'Appx'){
            if(Test-WBAppxRemovalMetadata $record){$action='AppxUninstall';$reason='移除当前用户的商店应用'}
            else{$reason='Windows 禁止移除此应用，或未提供可用移除状态'}
        }else{$reason='仅发现快捷方式，未找到卸载登记；可在系统卸载列表核对'}
        if($action -ne 'PortableRemove' -and (($Config.SharedPattern -and $name -imatch $Config.SharedPattern) -or $name -imatch '(?i)(driver|驱动|redistributable|runtime|运行库|\.NET|DirectX|WebView|Windows.*Update|更新.*Windows)')){
            $risk='可能被其他软件或硬件依赖，卸载会影响其运行'
            if($action -ne 'Review'){$reason+='；'+$risk}
        }
        if($source -eq 'Appx' -and (Get-WBValue $record 'IsFramework' $false) -eq $true){$risk='共享组件，Windows 将检查其他应用依赖后决定是否移除'}
        $id=Get-WBAllAppsId $source $identity
        $scope=if($source -eq 'Appx' -or $identity -like 'CurrentUser|*'){'当前用户'}elseif($source -eq 'Registry'){'系统级'}else{'快捷方式'}
        $related=if($source -eq 'Registry'){@(([string]$record.RegistryMirrorIdentities).Split([char]10))}else{@($identity)}
        $targets.Add([pscustomobject]@{Id=$id;ProductId=$id;Name=$name;Version=[string](Get-WBValue $record 'Version');Publisher=[string](Get-WBValue $record 'Publisher');Source=$source;Scope=$scope;Identity=$identity;RelatedIdentities=@($related);InstallLocation=[string](Get-WBValue $record 'InstallLocation');Action=$action;Reason=$reason;Risk=$risk;Fingerprint=(Get-WBFingerprint $record);InvocationFingerprint=(Get-WBUninstallInvocationFingerprint $command);SelectedDefault=$false;Record=$record;Command=$command})
    }
    [pscustomobject]@{Targets=@($targets.ToArray()|Sort-Object Name,Source,Identity);Protected=@()}
}

function Assert-WBAllAppsSelection([object[]]$Targets,[string[]]$InstallIds,$Config) {
    foreach($id in $InstallIds){
        $product=@($Config.Install|Where-Object Id -ceq $id)
        if($product.Count -ne 1){throw '安装产品不存在'}
        foreach($target in $Targets){
            if((Test-WBAlias $target.Name $product[0].Aliases) -or (Test-WBAlias ([string](Get-WBValue $target.Record 'Name')) $product[0].Aliases)){throw ('同一软件不能同时卸载和安装：'+$product[0].Name)}
        }
    }
}

function Assert-WBAppxRemovalReady($Target,$Snapshot) {
    if((Get-WBValue $Snapshot 'CompleteAppx' $false) -ne $true -or $Target.Source -cne 'Appx' -or $Target.Action -cne 'AppxUninstall' -or -not (Test-WBAppxRemovalMetadata $Target.Record)){throw '商店应用扫描不完整或目标不可移除，请重新扫描'}
    if($Target.Identity -cne $Target.Record.Identity){throw '商店应用身份不一致'}
}

function Invoke-WBAppxRemoval($Target,$Snapshot) {
    Assert-WBAppxRemovalReady $Target $Snapshot
    # Exact current-user package only: no wildcards, AllUsers, or provisioned-image edits.
    Remove-AppxPackage -Package ([string]$Target.Identity) -ErrorAction Stop
}
