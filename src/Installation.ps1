# Profiles describe specific signed installer bytes inspected during development.
# Never transfer silent switches to a new version merely because its name matches.
function Get-WBInstallInvocation($Product,$Package) {
    $mode=[string](Get-WBValue $Product 'InstallMode' 'Interactive')
    if($mode -eq 'Interactive'){return [pscustomobject]@{Mode='Interactive';Arguments='';TimeoutMinutes=30}}
    if($mode -cne 'Silent'){throw '该产品没有经过核实的自动安装规则。'}
    if($Product.Id -ceq 'qq'){
        if($Package.Sha256 -ine '63255C70C7FF523E7EED7D52D9708ED7A77EA346ECE6474C65DDED406EDB3155' -or $Package.Version -cne '9.9.36.53644-aff854e8' -or $Product.SilentArgs -cne '/s'){throw 'QQ 安装包与已核实的 Hummer 静默安装规则不一致，停止在卸载之前。'}
        return [pscustomobject]@{Mode='Silent';Arguments='/s';TimeoutMinutes=5}
    }
    if($Product.Id -ceq 'wechat'){
        if($Package.Sha256 -ine 'AA727E6CC74CD7C4E101C350D125508B0230A8A19C1F5304BF6F33DDE2E758C5' -or $Package.Version -cne '4.1.15.0' -or $Product.SilentArgs -cne '/S'){throw '微信安装包与已核实的 NSIS 静默安装规则不一致，停止在卸载之前。'}
        return [pscustomobject]@{Mode='Silent';Arguments='/S';TimeoutMinutes=5}
    }
    if($Product.Id -cne 'sogou'){throw '该产品没有经过核实的自动安装规则。'}
    $arguments='/S /isrunbrowser=0 /setdefbrowser=0 /createdaohang1=0 /installservice=0 /installdriver=0 /disableyybguide'
    if($Package.Sha256 -ine '466A858786F8EFA5384D363250E0C8D014B349A506EA240489D86692894A6DAC' -or $Package.Version -cne '13.9.6121.400' -or $Product.SilentArgs -cne $arguments){throw '安装包版本或规则与已核实的搜狗静默安装规则不一致，停止在卸载之前；需要核实新版安装包。'}
    [pscustomobject]@{Mode='Silent';Arguments=$arguments;TimeoutMinutes=5}
}

function Test-WBProductRuntimeFile($Product,[string]$Path) {
    $leaf=[IO.Path]::GetFileName($Path)
    switch(($Product.Id+':'+$leaf).ToLowerInvariant()){
        'sogou:sogouexplorer.exe'{$rule=[pscustomobject]@{Name='搜狗浏览器主程序';AllowedSignerNames=@('Beijing Sogou Technology Development Co., Ltd.');ProductNames=@('SogouExplorer')}}
        'sogou:crashpad_handler.exe'{$rule=[pscustomobject]@{Name='搜狗附带的崩溃报告进程';AllowedSignerNames=@('Tencent Technology (Shenzhen) Company Limited');ProductNames=@('Bugly-Windows')}}
        'wechat:weixin.exe'{$rule=[pscustomobject]@{Name='微信主程序';AllowedSignerNames=@('Tencent Technology (Shenzhen) Company Limited');ProductNames=@('Weixin')}}
        'qq:qq.exe'{$rule=[pscustomobject]@{Name='QQ 主程序';AllowedSignerNames=@('Tencent Technology (Shenzhen) Company Limited');ProductNames=@('QQ')}}
        default{throw '不是已核实的浏览器运行文件。'}
    }
    Test-WBInstaller -Path $Path -Product $rule
}

function Test-WBNormalRuntimeCommandLine([string]$Path,[string]$CommandLine) {
    if(-not $CommandLine -or $CommandLine.Length -gt 32767 -or $CommandLine -match '[\x00-\x1f]'){return $false}
    if(-not ('USBWinBatch.RuntimeCommandLine' -as [type])){
        Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace USBWinBatch {
    public static class RuntimeCommandLine {
        [DllImport("shell32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern IntPtr CommandLineToArgvW(string line, out int count);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
        public static string[] Parse(string line) {
            int count; IntPtr memory=CommandLineToArgvW(line,out count);
            if(memory==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                if(count<1 || count>256) throw new ArgumentException("Unsupported runtime argument count.");
                string[] result=new string[count];
                for(int i=0;i<count;i++) result[i]=Marshal.PtrToStringUni(Marshal.ReadIntPtr(memory,i*IntPtr.Size));
                return result;
            } finally { LocalFree(memory); }
        }
    }
}
"@ -ErrorAction Stop
    }
    try{$arguments=@([USBWinBatch.RuntimeCommandLine]::Parse($CommandLine));if([IO.Path]::GetFullPath($arguments[0]) -ine [IO.Path]::GetFullPath($Path)){return $false}}catch{return $false}
    $flags=@('--no-sandbox','--disable-gpu-sandbox','--disable-gpu','--disable-gpu-compositing','--disable-software-rasterizer','--enable-logging','--no-error-dialogs','--no-first-run','--from-installer','--force-first-run','--start-minimized','--monitor-self','--no-rate-limit','--no-server-upload')
    foreach($argument in @($arguments|Select-Object -Skip 1)){
        if($argument -in $flags){continue}
        if($argument -match '^--type=(renderer|utility|gpu-process|crashpad-handler|ppapi|ppapi-broker)$'){continue}
        if($argument -match '^--(lang|user-data-dir|crashpad-handler-pid|enable-features|disable-features|field-trial-handle|variations-seed-version|metrics-shmem-handle|mojo-platform-channel-handle|renderer-client-id|time-ticks-at-unix-epoch|launch-time-ticks|shared-files|gpu-preferences|utility-sub-type|service-sandbox-type|log-file|log-level|database|metrics-dir|url|annotation|initial-client-data|monitor-self-annotation)=.+$'){continue}
        if($argument -match '^/prefetch:[1-8]$' -or $argument -eq '-fixlaunch=0' -or $argument -match '^-sc=(startmenushortcut|desktopshortcut|taskbarshortcut|installer)$'){continue}
        $uri=$null
        if([Uri]::TryCreate($argument,[UriKind]::Absolute,[ref]$uri) -and $uri.Scheme -in @('http','https')){continue}
        return $false
    }
    return $true
}

function Get-WBInstalledProductRuntime($Product,$Package,$Snapshot) {
    $mainName=switch($Product.Id){'sogou'{'SogouExplorer.exe'} 'wechat'{'Weixin.exe'} 'qq'{'QQ.exe'} default{return $null}}
    $installed=@($Snapshot.Installations|Where-Object{$_.Id -ceq $Product.Id -and $_.State -eq 'Present'})
    if($installed.Count -ne 1){return $null}
    $registeredVersion=[regex]::Match([string]$installed[0].Version,'^\d+(?:\.\d+){2,4}').Value
    $packageVersion=[regex]::Match([string]$Package.Version,'^\d+(?:\.\d+){2,4}').Value
    if(-not $registeredVersion -or -not $packageVersion){return $null}
    if($Product.Id -ceq 'sogou' -and $registeredVersion -cne $packageVersion){return $null}
    if($Product.Id -ne 'sogou' -and ($registeredVersion.Split('.')[0..2] -join '.') -cne ($packageVersion.Split('.')[0..2] -join '.')){return $null}
    $candidates=New-Object 'System.Collections.Generic.List[string]'
    $registeredRoots=New-Object 'System.Collections.Generic.List[string]'
    $existingPath=[string](Get-WBValue $installed[0] 'ExecutablePath');if($existingPath){$candidates.Add($existingPath)}
    foreach($record in @($Snapshot.Inventory|Where-Object{Test-WBAlias ([string](Get-WBValue $_ 'Name')) $Product.Aliases})){
        if((Get-WBValue $record 'Source') -eq 'Shortcut'){$candidates.Add([string](Get-WBValue $record 'TargetPath'))}
        if((Get-WBValue $record 'Source') -eq 'Registry'){
            if([regex]::Match([string](Get-WBValue $record 'Version'),'^\d+(?:\.\d+){2,4}').Value -cne $registeredVersion){continue}
            $location=[string](Get-WBValue $record 'InstallLocation')
            if($location){$registeredRoots.Add([IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($location.Trim('"'))))}
            else{try{$uninstall=ConvertFrom-WBCommand ([string](Get-WBValue $record 'UninstallString'));$registeredRoots.Add([IO.Path]::GetDirectoryName($uninstall.FilePath))}catch{}}
        }
    }
    if($registeredRoots.Count -eq 0){return $null}
    foreach($directory in @($registeredRoots.ToArray()|Select-Object -Unique)){$candidates.Add([IO.Path]::Combine($directory,$mainName))}
    foreach($path in @($candidates.ToArray()|Select-Object -Unique)){
        try{
            if(-not $path -or [IO.Path]::GetFileName($path) -ine $mainName){continue}
            $matchingRoots=@($registeredRoots.ToArray()|Where-Object{Test-WBProductPath -Exe $path -Location $_})
            if($matchingRoots.Count -eq 0){continue}
            $directory=$matchingRoots[0]
            $proof=Test-WBProductRuntimeFile -Product $Product -Path $path
            $runtimeVersion=[regex]::Match($proof.Version,'^\d+(?:\.\d+){2,4}').Value
            if($runtimeVersion -cne $registeredVersion){continue}
            return [pscustomobject]@{Path=$proof.Path;Directory=$directory;Version=$proof.Version}
        }catch{}
    }
    return $null
}

function Get-WBInstalledSogouRuntime($Product,$Package,$Snapshot) {if($Product.Id -ceq 'sogou'){Get-WBInstalledProductRuntime $Product $Package $Snapshot}}

function Get-WBInstallRuntimeApproval([string]$Root,$Product,$Package,$State,$Snapshot=$null,$Processes=$null) {
    $pending=[pscustomobject]@{Complete=$false;ApprovedProcessIds=@()}
    if(-not $State.RootExited -or $State.ExitCode -ne 0 -or $Product.Id -notin @('sogou','wechat','qq') -or @($State.ActiveProcessIds).Count -eq 0){return $pending}
    try{
        if($null -eq $Snapshot){$Snapshot=Get-WBSnapshot $Root;Assert-WBSnapshotReady $Snapshot}
        $runtime=Get-WBInstalledProductRuntime -Product $Product -Package $Package -Snapshot $Snapshot
        if(-not $runtime){return $pending}
        $approved=New-Object 'System.Collections.Generic.List[uint32]'
        foreach($processId in @($State.ActiveProcessIds)){
            $found=@(if($null -eq $Processes){Get-CimInstance Win32_Process -Filter ('ProcessId='+[uint32]$processId) -ErrorAction Stop}else{$Processes|Where-Object ProcessId -eq $processId})
            if($found.Count -ne 1){return $pending}
            $path=[string]$found[0].ExecutablePath;$command=[string]$found[0].CommandLine
            if(-not $path -or -not $command -or -not (Test-WBProductPath -Exe $path -Location $runtime.Directory)){return $pending}
            if(-not (Test-WBNormalRuntimeCommandLine -Path $path -CommandLine $command)){return $pending}
            $proof=Test-WBProductRuntimeFile -Product $Product -Path $path
            if([IO.Path]::GetFileName($path) -ieq [IO.Path]::GetFileName($runtime.Path) -and $proof.Version -cne $runtime.Version){return $pending}
            $approved.Add([uint32]$processId)
        }
        return [pscustomobject]@{Complete=$true;ApprovedProcessIds=$approved.ToArray()}
    }catch{return $pending}
}
