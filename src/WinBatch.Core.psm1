Set-StrictMode -Version 2.0

function Get-WBValue($Object, [string]$Name, $Default = '') {
    if ($null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name]) { return $Object.$Name }
    return $Default
}

function Read-WBConfig([string]$Root) {
    $u = Get-Content -LiteralPath (Join-Path $Root 'config\uninstall.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $p = Get-Content -LiteralPath (Join-Path $Root 'config\protect.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($u.SchemaVersion -ne 1 -or $p.SchemaVersion -ne 1) { throw '不支持的配置版本。' }
    if (@($u.Products).Count -ne 10 -or @($u.Products.Id | Select-Object -Unique).Count -ne 10) { throw '卸载配置必须包含且仅包含 10 类指定产品。' }
    foreach ($product in $u.Products) {
        if ($product.Id -notmatch '^U-(0[1-9]|10)$' -or @($product.Aliases).Count -eq 0) { throw '无效的卸载产品配置。' }
        foreach ($alias in $product.Aliases) { if ([string]::IsNullOrWhiteSpace($alias) -or $alias -match '[*?\[\]]') { throw '执行配置不允许通配符或空名称。' } }
    }
    foreach ($id in @('pcmanager','movies','snip')) { if (@($p.Products | Where-Object Id -eq $id).Count -ne 1) { throw '三个保留应用的保护配置缺失。' } }
    $installs = @()
    $installPath = Join-Path $Root 'config\install.json'
    if (Test-Path -LiteralPath $installPath) {
        $i = Get-Content -LiteralPath $installPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($i.SchemaVersion -ne 1 -or @($i.Products).Count -ne 3) { throw '安装配置应当仅包含 QQ、微信、搜狗高速浏览器。' }
        foreach ($id in @('qq','wechat','sogou')) { if (@($i.Products | Where-Object Id -eq $id).Count -ne 1) { throw '安装产品身份缺失或重复。' } }
        $installs = @($i.Products)
    }
    [pscustomobject]@{ Uninstall=@($u.Products); Protect=@($p.Products); SharedPattern=$p.SharedComponentPattern; Install=$installs }
}

function Test-WBAlias([string]$Name, [object[]]$Aliases) {
    foreach ($alias in $Aliases) {
        if ($Name.Trim() -ieq ([string]$alias).Trim()) { return $true }
        $pattern = '^(?:' + [regex]::Escape(([string]$alias).Trim()) + ')\s+(?:v(?:ersion)?\s*)?\d+(?:\.\d+){1,4}(?:\s*\([^\r\n]+\))?$'
        if ($Name.Trim() -imatch $pattern) { return $true }
    }
    return $false
}

function Get-WBFingerprint($Record) {
    $parts = [ordered]@{}
    foreach ($key in @('Name','Version','Publisher','Source','Identity','InstallLocation','UninstallString','QuietUninstallString','WindowsInstaller','PackageName','Path','TargetPath','Arguments','NonRemovable','IsFramework','IsResourcePackage','RegistryMirrorIdentities')) {
        $parts[$key] = [string](Get-WBValue $Record $key)
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($parts | ConvertTo-Json -Compress))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
}

function ConvertFrom-WBCommand([string]$Command) {
    if ([string]::IsNullOrWhiteSpace($Command) -or $Command -match '[\x00-\x1f]') { throw '卸载命令为空或含控制字符。' }
    $Command = $Command.Trim()
    $match = [regex]::Match($Command, '^"(?<exe>[^"\r\n]+\.exe)"(?:\s+(?<args>.*))?$','IgnoreCase')
    if (-not $match.Success) { $match = [regex]::Match($Command, '^(?<exe>(?:[A-Za-z]:\\|%[^%]+%\\)[^"\r\n]*?\.exe)(?:\s+(?<args>.*))?$','IgnoreCase') }
    if (-not $match.Success) { throw '无法安全解析卸载入口；不通过命令行解释器执行。' }
    $exe = [Environment]::ExpandEnvironmentVariables($match.Groups['exe'].Value)
    if ($exe -notmatch '^[A-Za-z]:\\' -or $exe -match '%' -or $exe -match '[\x00-\x1f]') { throw '卸载入口必须是本地绝对路径。' }
    $exe = [IO.Path]::GetFullPath($exe)
    if ([IO.Path]::GetFileName($exe) -imatch '^(cmd|powershell|pwsh|wscript|cscript|rundll32|regsvr32|mshta|reg|schtasks)\.exe$') { throw '不允许通过脚本解释器或系统间接执行器卸载。' }
    [pscustomobject]@{ FilePath=$exe; Arguments=$match.Groups['args'].Value; IsMsi=([IO.Path]::GetFileName($exe) -ieq 'msiexec.exe') }
}

function Test-WBProductPath([string]$Exe, [string]$Location) {
    if ([string]::IsNullOrWhiteSpace($Location) -or $Location -notmatch '^[A-Za-z]:\\') { return $false }
    try { $locationFull=[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Location)).TrimEnd('\'); $exeFull=[IO.Path]::GetFullPath($Exe) } catch { return $false }
    $windowsDir = if ($env:windir) { $env:windir } else { 'C:\Windows' }
    if ($locationFull.Length -le 3 -or $locationFull -ieq $windowsDir -or $locationFull.StartsWith($windowsDir.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { return $false }
    $usersRoot=if($env:PUBLIC){[IO.Path]::GetDirectoryName($env:PUBLIC)}else{'C:\Users'}
    foreach ($broad in @($env:ProgramFiles,${env:ProgramFiles(x86)},$env:ProgramData,$env:USERPROFILE,$env:LOCALAPPDATA,$env:APPDATA,$usersRoot,$env:PUBLIC,$env:CommonProgramFiles,${env:CommonProgramFiles(x86)},'C:\Users\Public','C:\Program Files\Common Files','C:\Program Files (x86)\Common Files')) {
        if ($broad -and $locationFull -ieq $broad.TrimEnd('\')) { return $false }
    }
    $ancestor=$exeFull
    while($ancestor){
        if(Test-Path -LiteralPath $ancestor){
            try{if(((Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){return $false}}catch{return $false}
        }
        $parent=[IO.Path]::GetDirectoryName($ancestor)
        if($parent -eq $ancestor){break};$ancestor=$parent
    }
    return $exeFull.StartsWith($locationFull+'\',[StringComparison]::OrdinalIgnoreCase)
}

function Get-WBUninstallSpec($Record, $Product) {
    $quiet = [string](Get-WBValue $Record 'QuietUninstallString')
    $normal = [string](Get-WBValue $Record 'UninstallString')
    $interactive = [bool](Get-WBValue $Product 'ForceInteractive' $true)
    $command = if (-not $interactive -and $quiet) { $quiet } else { $normal }
    if (-not $command) { throw '没有可验证的卸载入口，需要人工定位。' }
    # A bare msiexec is accepted only for a registered MSI identity, and replaced by the OS path.
    if ($command -imatch '^msiexec(?:\.exe)?\s+') { $command = '"'+(Join-Path $env:windir 'System32\msiexec.exe')+'" '+($command -replace '^msiexec(?:\.exe)?\s+','') }
    $spec = ConvertFrom-WBCommand $command
    if ($spec.IsMsi) {
        $guid = [regex]::Match([string](Get-WBValue $Record 'Identity'), '\{[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}\}$').Value
        $osMsi = Join-Path $env:windir 'System32\msiexec.exe'
        $operations=@([regex]::Matches($spec.Arguments,'(?i)(?:^|\s)/[ix]\s*"?(?<guid>\{[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}\})"?(?=\s|$)'))
        if ((Get-WBValue $Record 'WindowsInstaller' 0) -ne 1 -or -not $guid -or $spec.FilePath -ine $osMsi -or $operations.Count -ne 1 -or $operations[0].Groups['guid'].Value -ine $guid) { throw 'MSI 产品身份与实际操作的产品 GUID 不一致。' }
        $spec.Arguments = '/x '+$guid+' /norestart'
        if (-not $interactive) { $spec.Arguments += ' /qn' }
    } elseif (-not (Test-WBProductPath $spec.FilePath ([string](Get-WBValue $Record 'InstallLocation')))) {
        throw '卸载入口不在明确的产品专用目录内，需核实。'
    }
    if ($spec.Arguments -imatch '(delete|remove)[-_ ]?(profile|userdata|user-data)|/purge|--purge') { throw '卸载参数包含个人数据删除选项，需人工处理。' }
    $action = if (-not $interactive -and ($quiet -or $spec.IsMsi)) { 'AutoUninstall' } else { 'ManualUninstall' }
    [pscustomobject]@{FilePath=$spec.FilePath;Arguments=$spec.Arguments;Action=$action}
}

function Get-WBPlan([object[]]$Inventory, $Config) {
    $targets = New-Object 'System.Collections.Generic.List[object]'
    $protected = New-Object 'System.Collections.Generic.List[object]'
    foreach ($rule in $Config.Protect) {
        $found = @($Inventory | Where-Object { (Test-WBAlias ([string](Get-WBValue $_ 'Name')) $rule.Aliases) -or ([string](Get-WBValue $_ 'PackageName') -in @($rule.PackageNames)) })
        $protected.Add([pscustomobject]@{Id=$rule.Id;Name=$rule.Name;State=$(if($found.Count){'Present'}else{'NotDetected'});Reason=$(if($found.Count){'明确保留，不参与卸载'}else{'未检测到；保护规则仍然生效'})})
    }
    $seen = @{}
    foreach ($record in $Inventory) {
        $name = [string](Get-WBValue $record 'Name')
        $isProtected = $false
        foreach($rule in $Config.Protect){if((Test-WBAlias $name $rule.Aliases) -or ([string](Get-WBValue $record 'PackageName') -in @($rule.PackageNames))){$isProtected=$true;break}}
        if($isProtected -or ($Config.SharedPattern -and $name -imatch $Config.SharedPattern)){continue}
        $products = @($Config.Uninstall | Where-Object { Test-WBAlias $name $_.Aliases })
        if($products.Count -eq 0){continue}
        $product=$products[0]
        $identity=[string](Get-WBValue $record 'Identity')
        if(-not $identity){$identity=Get-WBFingerprint $record}
        $dedup=[string](Get-WBValue $record 'Source')+'|'+$identity
        if($seen.ContainsKey($dedup)){continue};$seen[$dedup]=$true
        $action='Review';$reason='产品身份待核实';$spec=$null
        $source=[string](Get-WBValue $record 'Source')
        if($products.Count -gt 1){$reason='多个产品规则冲突，禁止执行'}
        elseif($source -eq 'Registry') {
            try {
                $publisherPattern=[string](Get-WBValue $product 'PublisherPattern');$directoryPattern=[string](Get-WBValue $product 'DirectoryPattern')
                if(-not $publisherPattern -or -not $directoryPattern -or ([string](Get-WBValue $record 'Publisher')) -notmatch $publisherPattern -or ([string](Get-WBValue $record 'InstallLocation')) -notmatch $directoryPattern){throw '已列为卸载目标；发布者与产品目录身份尚未核实，请打开系统卸载列表人工处理。'}
                $spec=Get-WBUninstallSpec $record $product;$action=$spec.Action;$reason=if($action -eq 'AutoUninstall'){'产品发布者、目录及登记的静默入口符合规则；执行前再次核实'}else{'产品发布者与目录符合规则；打开卸载窗口，人工完成并保留个人数据'}
            } catch {$reason=$_.Exception.Message}
        } elseif($source -eq 'Shortcut') {
            $path=[string](Get-WBValue $record 'Path');$dest=[string](Get-WBValue $record 'TargetPath')
            $registered=@($Inventory | Where-Object {(Get-WBValue $_ 'Source') -eq 'Registry' -and (Test-WBAlias ([string](Get-WBValue $_ 'Name')) $product.Aliases)})
            if($registered.Count){continue}
            if([IO.Path]::GetExtension($path) -ieq '.url' -and $dest -imatch '^https?://'){$action='Shortcut';$reason='仅移除已预览的网页快捷方式，不代表卸载程序'}
            else{$reason='仅发现快捷方式或便携工具，无已验证卸载入口；需人工处理'}
        }
        $fp=Get-WBFingerprint $record
        $targets.Add([pscustomobject]@{Id=($product.Id+'-'+$fp.Substring(0,16));ProductId=$product.Id;Name=$name;Version=[string](Get-WBValue $record 'Version');Publisher=[string](Get-WBValue $record 'Publisher');Source=$source;Identity=$identity;InstallLocation=[string](Get-WBValue $record 'InstallLocation');Action=$action;Reason=$reason;Fingerprint=$fp;SelectedDefault=($action -ne 'Review');Record=$record;Command=$spec})
    }
    [pscustomobject]@{Targets=@($targets.ToArray());Protected=@($protected.ToArray())}
}

function Assert-WBRequest($Request,[string]$Computer,[string]$UserSid,[object[]]$Targets,[string[]]$InstallIds) {
    $confirmation=Get-WBValue $Request 'Confirmed' $false
    if($confirmation -isnot [bool] -or -not $confirmation){throw '缺少用户确认，拒绝执行。'}
    if((Get-WBValue $Request 'Computer') -cne $Computer -or (Get-WBValue $Request 'UserSid') -cne $UserSid){throw '机器或用户已变化；请回原用户重新扫描。'}
    $targetIds=@(Get-WBValue $Request 'TargetIds' @());$requestedInstalls=@(Get-WBValue $Request 'InstallIds' @())
    if($targetIds.Count -ne @($targetIds|Select-Object -Unique).Count -or $requestedInstalls.Count -ne @($requestedInstalls|Select-Object -Unique).Count){throw '请求存在重复动作。'}
    foreach($id in $targetIds){$matches=@($Targets|Where-Object Id -ceq $id);if($matches.Count -ne 1 -or $matches[0].Action -eq 'Review'){throw '产品已变化、身份待核实或不在执行清单中。'}}
    foreach($id in $requestedInstalls){if($id -cnotin $InstallIds){throw '安装请求含未授权产品。'}}
}

function Test-WBAllowedUri([string]$Uri,[string[]]$Hosts) {
    $parsed=$null
    if(-not [Uri]::TryCreate($Uri,[UriKind]::Absolute,[ref]$parsed) -or $parsed.Scheme -cne 'https' -or $parsed.UserInfo -or -not $parsed.IsDefaultPort){return $false}
    foreach($hostName in $Hosts){if($parsed.DnsSafeHost -ieq $hostName){return $true}}
    return $false
}

function Get-WBDownloadCapture([string]$Text,[string]$Pattern) {
    $regex=New-Object Text.RegularExpressions.Regex($Pattern,[Text.RegularExpressions.RegexOptions]::IgnoreCase,[TimeSpan]::FromSeconds(5))
    $urls=@($regex.Matches($Text)|ForEach-Object{if($_.Groups['url'].Success){$_.Groups['url'].Value}}|Where-Object{$_}|Select-Object -Unique)
    if($urls.Count -ne 1){throw '官网安装包地址缺失或存在歧义，停止解析；可选择本地官方安装包。'}
    return [string]$urls[0]
}

function Get-WBQQAuthorizedUrl([string]$OriginalUrl,$Response) {
    if(-not (Test-WBAllowedUri $OriginalUrl @('qqdl.gtimg.cn')) -or (Get-WBValue $Response 'retcode' -1) -ne 0){throw 'QQ 官网下载授权失败。'}
    $url=[string](Get-WBValue (Get-WBValue $Response 'data' $null) 'url')
    if(-not (Test-WBAllowedUri $url @('qqdl.gtimg.cn'))){throw 'QQ 官网授权地址来源异常。'}
    $before=[Uri]$OriginalUrl;$after=[Uri]$url
    if($before.AbsolutePath -cne $after.AbsolutePath -or $after.Query -notmatch '(?:[?&])sign=[^&]+' -or $after.Query -notmatch '(?:[?&])t=[^&]+'){throw 'QQ 官网授权响应替换了产品路径或缺少授权参数。'}
    return $url
}

function Assert-WBSnapshotReady($Snapshot) {
    $complete=Get-WBValue $Snapshot 'CompleteRegistry' $false
    if($complete -isnot [bool] -or -not $complete){throw '软件登记扫描不完整，不能据此判断未安装或卸载成功；请排查报告后重新扫描。'}
}

function Assert-WBMachineBinding($Original,$Request,[string]$MachineId) {
    if(-not $MachineId -or (Get-WBValue $Original 'MachineId') -cne $MachineId -or (Get-WBValue $Request 'MachineId') -cne $MachineId){throw '机器身份与预览不一致，请在本机重新扫描。'}
}

function Get-WBCurrentTarget($Target,$Snapshot) {
    $same=@($Snapshot.Targets|Where-Object Id -ceq $Target.Id)
    if($same.Count -eq 0){
        $related=@(Get-WBValue $Target 'RelatedIdentities' @($Target.Identity))
        $identityStillPresent=@($Snapshot.Inventory|Where-Object{$_.Source -ceq $Target.Source -and $related -ccontains $_.Identity})
        $productStillPresent=@($Snapshot.Targets|Where-Object{$_.ProductId -ceq $Target.ProductId -and $_.InstallLocation -ceq $Target.InstallLocation})
        if($identityStillPresent.Count -or $productStillPresent.Count){throw '软件登记或卸载器自预览后已变化，需重新扫描确认；不能记为已移除。'}
        return $null
    }
    if($same.Count -ne 1 -or $same[0].Fingerprint -cne $Target.Fingerprint -or $same[0].FileHash -cne $Target.FileHash -or (Get-WBValue $same[0] 'InvocationFingerprint') -cne (Get-WBValue $Target 'InvocationFingerprint') -or $same[0].Action -eq 'Review'){throw '目标身份或卸载器已变化，请重新扫描。'}
    return $same[0]
}

function Assert-WBPlatform([bool]$Is64OS=[Environment]::Is64BitOperatingSystem,[string]$Architecture=$env:PROCESSOR_ARCHITECTURE) {
    if(-not $Is64OS -or $Architecture -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64'){throw '第一版安装流程仅验证 Windows x64；此机器架构暂不支持，未开始卸载。'}
}

function Complete-WBPendingResults([object[]]$Results,[string]$Reason,[bool]$Cancelled) {
    foreach($row in $Results){
        if($row.State -eq '进行中'){$row.State='需人工';$row.Details='动作已开始但结果未确认；'+$Reason}
        elseif($row.State -eq '未开始'){$row.State=if($Cancelled){'已取消'}else{'未执行'};$row.Details=$Reason}
    }
    return $Results
}

Export-ModuleMember -Function Get-WBValue,Read-WBConfig,Test-WBAlias,Get-WBFingerprint,ConvertFrom-WBCommand,Test-WBProductPath,Get-WBUninstallSpec,Get-WBPlan,Assert-WBRequest,Test-WBAllowedUri,Get-WBDownloadCapture,Get-WBQQAuthorizedUrl,Assert-WBSnapshotReady,Assert-WBMachineBinding,Get-WBCurrentTarget,Assert-WBPlatform,Complete-WBPendingResults
