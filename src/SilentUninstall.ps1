# Standalone, read-only rule provider for Windows PowerShell 5.1.
# The caller owns registry-command parsing, Microsoft filtering, selections,
# fingerprint revalidation and execution. No vendor code is loaded or launched.

function Get-WBInteractiveUninstallReason([string]$Path,$Record=$null) {
    # User requested vendor windows for both 360 products after real testing.
    if($null -ne $Record -and $Record.PSObject.Properties['Name'] -and
       (([string]$Record.Name -replace '\s','') -match '^360安全(?:浏览器|卫士)(?:[（(]?[vV]?[0-9][0-9.]*[）)]?)?$')){
        return '按设置使用360厂商卸载窗口，请手动确认。'
    }
    # Exact supplied sample: NSIS uninstall section is empty; deletion is
    # reached only through its custom page callback. /S skips that page.
    # Do not generalize this restriction by display name or version alone.
    try {
        if($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.Substring(2) -match '[:\x00-\x1f]' -or [IO.Path]::GetExtension($Path) -ine '.exe'){return ''}
        if((Get-Item -LiteralPath $Path -ErrorAction Stop).Length -notin @(3376432,1713368,664760,4953680,1295256,5717584,6831696,1422080)){return ''}
        switch((Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash){
            {$_ -cin @('AD3EF1944CBC383529E2F315708726E05DE083780BFE41D40A76A0E6B037E133','7851B6F0B5112C7265817ACE9BD6B577CC957296363B177A9FB0C6C90A8AA2EA','CA2004E16EA968E71C615A3C11ADE1EB505A013BB11D5C62DCD3DF7CE713D5DD','D33BD27E00CA7FF3F4C0A109F7DAF781FD04EEA04A693224D2BE289D222E28FA','61392A4EE41DD4F01C79D7032C0BF07B89B9533237DA535EF61F9F8A837557BD')} {return '按设置使用360厂商卸载窗口，请手动确认。'}
            'CE79E707D7D6C55BE2F1609266662CDA99410B48A7408227213B404896B6A0F0' {return '此版2345的 /S 会跳过实际卸载；需在厂商窗口确认。'}
            '260C8B65D7BF00A2F91E916D4B35CCB79E22EA6ADE551BBD2A0FFFACC37B991D' {return '此版2345的 /S 会跳过实际卸载；需在厂商窗口确认。'}
            '86047BA3A1D9314EE0E05D79D312B0893389D63842787CC19F996D236CB6A9DD' {return '此版2345好压检测到静默模式会直接退出；需在厂商窗口确认。'}
        }
    } catch {}
    return ''
}

function Test-WBSilentChromeIdentity([string]$ProductName,[string]$CompanyName,[string]$SignatureStatus,[string]$SignerName) {
    # Inputs come from the current executable's version resource and Windows
    # Authenticode verification, never from a registry record's publisher/name.
    return ($ProductName -ceq 'Google Chrome Installer' -and $CompanyName -ceq 'Google LLC' -and
            $SignatureStatus -ceq 'Valid' -and $SignerName -ceq 'Google LLC')
}

function Get-WBUninstallEngine {
    [CmdletBinding()]
    param([string]$Path)

    $stream=$null
    try {
        # Literal local EXE only; no wildcard/provider/UNC/device/alternate stream.
        if($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.Substring(2) -match '[:\x00-\x1f]' -or [IO.Path]::GetExtension($Path) -ine '.exe'){return $null}
        $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $length=$stream.Length
        if($length -lt 256 -or $length -gt 16777216){return $null}
        $bytes=New-Object byte[] ([int]$length)
        $read=0
        while($read -lt $bytes.Length) {
            $count=$stream.Read($bytes,$read,$bytes.Length-$read)
            if($count -le 0){return $null}
            $read+=$count
        }
        if($stream.Length -ne $length){return $null}
        if($bytes[0] -ne 77 -or $bytes[1] -ne 90){return $null}
        $pe=[BitConverter]::ToInt32($bytes,60)
        if($pe -lt 64 -or $pe -gt $length-24){return $null}
        if([BitConverter]::ToUInt32($bytes,$pe) -ne 17744){return $null}
        $sections=[BitConverter]::ToUInt16($bytes,$pe+6)
        $optionalSize=[BitConverter]::ToUInt16($bytes,$pe+20)
        $characteristics=[BitConverter]::ToUInt16($bytes,$pe+22)
        if(($characteristics -band 2) -eq 0 -or ($characteristics -band 8192) -ne 0){return $null}
        $optional=$pe+24
        $table=$optional+$optionalSize
        if($sections -lt 1 -or $sections -gt 96 -or $optionalSize -lt 96 -or $table+40*$sections -gt $length){return $null}
        $magic=[BitConverter]::ToUInt16($bytes,$optional)
        if($magic -notin @(267,523) -or ($magic -eq 523 -and $optionalSize -lt 112)){return $null}
        $overlay=[long][BitConverter]::ToUInt32($bytes,$optional+60)
        if($overlay -lt $table+40*$sections -or $overlay -gt $length){return $null}
        for($i=0;$i -lt $sections;$i++) {
            $section=$table+40*$i
            $size=[long][BitConverter]::ToUInt32($bytes,$section+16)
            $offset=[long][BitConverter]::ToUInt32($bytes,$section+20)
            if($size -eq 0){continue}
            if($offset -lt $table+40*$sections -or $offset+$size -gt $length){return $null}
            $overlay=[Math]::Max($overlay,$offset+$size)
        }
        $ascii=[Text.Encoding]::ASCII.GetString($bytes)
        # IQIYI's supplied sample actively disables generic NSIS /S. Its own
        # full-uninstall switch takes priority over framework identification.
        $sha=[Security.Cryptography.SHA256]::Create()
        try {$hash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','')}
        finally {$sha.Dispose()}
        if($hash -ceq '0C6BF96AC281F2ECABDF6AC58E3AE1C044D7B38E339E40CF283B101F4302D4D3'){return 'IQIYIQuiet'}
        # NSIS firstheader: flags, DEADBEEF, NullsoftInst, header length, total
        # payload length. The uninstaller bit is mandatory; an installer is not
        # an uninstall entry. The loader searches 512-byte boundaries.
        $position=$ascii.IndexOf('NullsoftInst',[StringComparison]::Ordinal)
        while($position -ge 0) {
            $header=$position-8
            if($header -ge $overlay -and $header % 512 -eq 0 -and $header+28 -le $length) {
                $flags=[BitConverter]::ToUInt32($bytes,$header)
                $signature=[BitConverter]::ToUInt32($bytes,$header+4)
                $headerLength=[BitConverter]::ToInt32($bytes,$header+20)
                $payloadLength=[BitConverter]::ToInt32($bytes,$header+24)
                if(($flags -band 1) -eq 1 -and $flags -le 15 -and $signature -eq 3735928559 -and
                   $headerLength -gt 0 -and $headerLength -le 16777216 -and
                   $payloadLength -gt 28 -and $header+$payloadLength -le $length){return 'NSIS'}
            }
            $position=$ascii.IndexOf('NullsoftInst',$position+1,[StringComparison]::Ordinal)
        }
        # Inno's SelectMode reads the DOS-header mode DWORD at 0x30. Merely
        # containing 'Inno Setup' or being named unins000.exe is not enough.
        if([BitConverter]::ToUInt32($bytes,48) -eq 1851092553 -and
           ($ascii.Contains('Inno Setup Uninstall Log (b)'+[char]0) -or $ascii.Contains('Inno Setup Uninstall Log (b) 64-bit'+[char]0)) -and
           $ascii.Contains('Inno Setup Messages (')){return 'InnoSetup'}

        # Chrome's official uninstall contract is portable across versions.
        # Verify this executable's product and trusted signer while our read
        # handle prevents writes/replacement. No vendor DLL is loaded.
        $version=[Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        if($version.ProductName -ceq 'Google Chrome Installer' -and $version.CompanyName -ceq 'Google LLC' -and
           $ascii.Contains('force-uninstall') -and $ascii.Contains('uninstall')) {
            $signature=Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $signer=''
            if($null -ne $signature.SignerCertificate) {
                $signer=$signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)
            }
            if(Test-WBSilentChromeIdentity $version.ProductName $version.CompanyName ([string]$signature.Status) $signer){return 'Chrome'}
        }

        # Exact current WinRAR binary, not vendor/display-name guesses. SHA-256 is
        # computed over the already bounded read, without a second file read.
        # Switch evidence and current product/signature observations are in docs.
        switch($hash) {
            'A87E6F5BEBE9BEA34E7E70451661BB626994A57E512C23003B33B2456CE049E3' {return 'RabbitQuiet'}
            'AD3EF1944CBC383529E2F315708726E05DE083780BFE41D40A76A0E6B037E133' {return '360BrowserQuiet'}
            '7851B6F0B5112C7265817ACE9BD6B577CC957296363B177A9FB0C6C90A8AA2EA' {return '360SafeQuiet'}
            'A393DA11AD8B070851277434F026099803FA34883C5A9A0727A78D606E62124B' {return 'WPSQuiet'}
            '820554B10BA6E9CFB9A610E7598366991DF1970726A9CC5ABBA216F04EE5DD7E' {return 'RabbitQuiet'}
            'D33BD27E00CA7FF3F4C0A109F7DAF781FD04EEA04A693224D2BE289D222E28FA' {return '360BrowserQuiet'}
            'CA2004E16EA968E71C615A3C11ADE1EB505A013BB11D5C62DCD3DF7CE713D5DD' {return '360BrowserQuiet'}
            '61392A4EE41DD4F01C79D7032C0BF07B89B9533237DA535EF61F9F8A837557BD' {return '360SafeQuiet'}
            'C893BAB6E0159AD6A3BAEA054F7341DD543AC0CA446671CE07AA93E97B540DC2' {return 'WinRAR'}
            '1D027D7D09F37675E4C27AD6279EE927ADC63CB68D337B7D821BA3254F216EEA' {return 'DoubaoQuiet'}
            'D9EC2B9483512EDC05779E6249B604F1C80F6675032F156D823CAD3CB2E7E1CC' {return 'ArmouryCrateQuiet'}
            'BB71380FBE93C3EE262906760BA1294CAE4E70053538F8D04B5B190452F63EAA' {return 'ASUSFrameworkUninstall'}
        }
        return $null
    } catch {
        # Missing, unreadable, busy or malformed files are unsupported evidence.
        return $null
    } finally {
        if($null -ne $stream){$stream.Dispose()}
    }
}

function Get-WBSilentArgumentTokens([string]$Arguments) {
    # Decode only for whole-token comparisons; never reconstruct registered
    # arguments. Handle Windows backslash-before-quote rules without a native
    # argument-parser DLL or a dependency on Main/System modules.
    if($Arguments.Length -gt 32700 -or $Arguments -match '[\x00-\x1f]'){return $null}
    $values=New-Object 'System.Collections.Generic.List[string]'
    $i=0
    while($i -lt $Arguments.Length) {
        while($i -lt $Arguments.Length -and $Arguments[$i] -eq ' '){$i++}
        if($i -ge $Arguments.Length){break}
        $value=New-Object Text.StringBuilder
        $quoted=$false
        while($i -lt $Arguments.Length) {
            $c=$Arguments[$i]
            if($c -eq ' ' -and -not $quoted){break}
            if($c -eq '\') {
                $start=$i
                while($i -lt $Arguments.Length -and $Arguments[$i] -eq '\'){$i++}
                $slashes=$i-$start
                if($i -lt $Arguments.Length -and $Arguments[$i] -eq '"') {
                    [void]$value.Append(('\'*[int][Math]::Floor($slashes/2)))
                    if($slashes % 2 -eq 1){[void]$value.Append('"')}else{$quoted=-not $quoted}
                    $i++
                } else {[void]$value.Append(('\'*$slashes))}
                continue
            }
            if($c -eq '"'){$quoted=-not $quoted}else{[void]$value.Append($c)}
            $i++
        }
        if($quoted){return $null}
        $values.Add($value.ToString())
        if($values.Count -gt 256){return $null}
    }
    return [pscustomobject]@{Tokens=@($values.ToArray())}
}

function Get-WBUninstallAutomation {
    [CmdletBinding()]
    param($Record,$Command)

    try {
        if($null -eq $Command -or $Command.Action -notin @('ManualUninstall','AutoUninstall')){return $null}
        $arguments=[string]$Command.Arguments
        $parsed=Get-WBSilentArgumentTokens $arguments
        if($null -eq $parsed){return $null}
        $tokens=@($parsed.Tokens)
        # Do not synthesize data-deletion, reboot, or private Inno phase/mode
        # behavior. This mirrors the main caller's personal-data protection.
        $normalized=$tokens -join ' '
        if($normalized -imatch '(delete|remove)[-_ ]?(profile|userdata|user-data)|(?:^|\s)(?:/purge|--purge)(?:\s|$)'){return $null}
        foreach($token in $tokens) {
            if($token -imatch '^/(?:FORCERESTART|RESTART|REGSVRMODE|UNINSTMODE)(?:=|$)|^/(?:SL5|SECONDPHASE|FIRSTPHASEWND|INITPROCWND)='){return $null}
        }
        if($Command.PSObject.Properties['Backend'] -and $Command.Backend -eq 'Rundll') {
            return Get-WBNvidiaUninstallAutomation -Command $Command -Tokens $tokens
        }
        if(Get-WBInteractiveUninstallReason -Path ([string]$Command.FilePath) -Record $Record){return $null}
        $engine=Get-WBUninstallEngine -Path ([string]$Command.FilePath)
        if(-not $engine){return $null}
        $add=New-Object 'System.Collections.Generic.List[string]'
        switch($engine) {
            'WPSQuiet' {
                # Supplied 11.1.0.9021: /s enters its uninstall worker and waits
                # for completion. Explicitly retain user information.
                if(@($tokens|Where-Object {$_ -cnotin @('/s','/saveUserInfo')}).Count){return $null}
                if($tokens -cnotcontains '/s'){$add.Add('/s')}
                if($tokens -cnotcontains '/saveUserInfo'){$add.Add('/saveUserInfo')}
                $reason='WPS卸载器指纹匹配；使用内置静默卸载分支并保留用户资料。'
            }
            'IQIYIQuiet' {
                # /S is reset to normal mode by this exact sample. Do not use
                # its separate -uinst -s partial-removal mode.
                if(@($tokens|Where-Object {$_ -cne '/SilentUninstall=on'}).Count){return $null}
                if($tokens -cnotcontains '/SilentUninstall=on'){$add.Add('/SilentUninstall=on')}
                $reason='爱奇艺卸载器指纹匹配；使用专用完整静默卸载参数。'
            }
            'RabbitQuiet' {
                # /s alone is lost by this sample's temporary-child handoff.
                # Enter its /u branch with the existing adjacent uninstall log.
                # Bind that log into execution-time command/hash revalidation.
                $exe=[IO.Path]::GetFullPath([string]$Command.FilePath)
                $dat=Join-Path ([IO.Path]::GetDirectoryName($exe)) 'Unins.dat'
                $file=Get-Item -LiteralPath $dat -ErrorAction Stop
                if($file.PSIsContainer -or $file.Length -lt 1 -or $file.Length -gt 16777216 -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){return $null}
                $parent=$file.Directory
                while($null -ne $parent){if($parent.Attributes -band [IO.FileAttributes]::ReparsePoint){return $null};$parent=$parent.Parent}
                for($i=0;$i -lt $tokens.Count;$i++) {
                    if($tokens[$i] -ceq '/s'){continue}
                    if($tokens[$i] -cne '/u' -or $i+1 -ge $tokens.Count){return $null}
                    $i++
                    if($tokens[$i] -ine $dat){return $null}
                }
                return [pscustomobject]@{Arguments=('/s /u "'+$dat+'"');Rule=$engine;PayloadPaths=@($dat);Reason='超级兔子卸载器指纹匹配；使用静默分支及原卸载清单，避免临时进程丢失静默参数。'}
            }
            '360BrowserQuiet' { return $null } # User requests vendor windows.
            '360SafeQuiet' { return $null }
            'DoubaoQuiet' {
                # This exact sample parses --quiet and skips the confirmation
                # dialog before entering the same full removal routine.
                if(@($tokens|Where-Object {$_ -cne '--quiet'}).Count){return $null}
                if($tokens -cnotcontains '--quiet'){$add.Add('--quiet')}
                $reason='豆包卸载器指纹匹配；已静态核对 --quiet 参数解析、确认窗口跳过及完整卸载分支。'
            }
            'ArmouryCrateQuiet' {
                # Embedded SDK declares case-sensitive Quiet/NoRestart options.
                # NoRestart also prevents its generated cleanup batch reboot.
                if(@($tokens|Where-Object {$_ -cnotin @('-q','-n','--Quiet','--NoRestart')}).Count){return $null}
                if($tokens -cnotcontains '-q' -and $tokens -cnotcontains '--Quiet'){$add.Add('-q')}
                if($tokens -cnotcontains '-n' -and $tokens -cnotcontains '--NoRestart'){$add.Add('-n')}
                $reason='Armoury Crate 卸载器指纹匹配；使用内置 Quiet 分支，并禁止自动重启。'
            }
            'ASUSFrameworkUninstall' {
                # Exact sample WinMain calls full removal; /uninstall then
                # exits before the reinstall/progress UI. Do not invent mode.
                if($tokens -cnotcontains '/uninstall' -or @($tokens|Where-Object {$_ -cnotin @('/uninstall','/quiet')}).Count){return $null}
                $reason='ASUS Framework 卸载器指纹匹配；已登记的 /uninstall 分支执行卸载后直接退出。'
            }
            'NSIS' {
                $silent=$false
                foreach($token in $tokens) {
                    # These special parameters consume the rest of the raw
                    # command line as a directory, including any '/S' text.
                    if($token -cmatch '^(?:_\?=|/D=)'){break}
                    if($token -ceq '/S'){$silent=$true}
                }
                if(-not $silent){$add.Add('/S')}
                $reason='已验证 NSIS 卸载器二进制头；使用官方区分大小写的 /S 静默规则。'
            }
            'InnoSetup' {
                foreach($flag in @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART')) {
                    if($tokens -notcontains $flag){$add.Add($flag)}
                }
                $reason='已验证 Inno 卸载模式与日志/消息标记；隐藏进度、抑制提示并禁止自动重启。'
            }
            'WinRAR' {
                if($tokens -cnotcontains '/S'){$add.Add('/S')}
                $reason='当前 WinRAR 7.23 卸载器 SHA-256 匹配固定证据；/S 来自该文件的静态命令行解析分析。'
            }
            'Chrome' {
                # setup.exe also installs/repairs: never invent uninstall mode
                # or installation scope/channel. Keep the registered flags.
                $switchTokens=New-Object 'System.Collections.Generic.List[string]'
                foreach($token in $tokens){if($token -ceq '--'){break};$switchTokens.Add($token)}
                if($switchTokens -cnotcontains '--uninstall'){return $null}
                if($switchTokens -cnotcontains '--force-uninstall'){$add.Add('--force-uninstall')}
                $reason='当前文件产品为 Google Chrome Installer 且 Google LLC 签名有效；保留已登记卸载模式和范围，按 Chromium 官方资料追加 --force-uninstall，不删除用户资料。'
            }
            default {return $null}
        }
        # Prefixing preserves NSIS _?= and /D= last-parameter semantics, all
        # quotes and exact registered arguments. Inno SILENT can remain: its
        # independent VerySilent boolean suppresses progress when both are set.
        $result=$arguments
        if($add.Count -gt 0) {
            $result=$add -join ' '
            if($arguments.Length -gt 0){$result+=' '+$arguments}
        }
        if($result.Length -gt 32700){return $null}
        return [pscustomobject]@{Arguments=$result;Rule=$engine;Reason=$reason}
    } catch {return $null}
}

function Get-WBNvidiaUninstallAutomation {
    param($Command,[string[]]$Tokens)
    # NVIDIA's documented Display.Driver contract, restricted to the inspected
    # DLL sample, exact export/package and Windows host. No DLL is loaded.
    $stream=$null
    try {
        if($Command.Backend -cne 'Rundll' -or @($Command.PayloadPaths).Count -ne 1){return $null}
        $hostPaths=@((Join-Path $env:windir 'System32\rundll32.exe'),(Join-Path $env:windir 'SysWOW64\rundll32.exe'))
        if($Command.FilePath -notin $hostPaths){return $null}
        $dll=[string]$Command.PayloadPaths[0]
        if($dll -notmatch '^[A-Za-z]:\\' -or $dll.Substring(2) -match '[:\x00-\x1f]' -or [IO.Path]::GetFileName($dll) -ine 'NVI2.DLL'){return $null}
        if($Tokens.Count -lt 2 -or $Tokens[0] -cne ($dll+',UninstallPackage') -or $Tokens[1] -cne 'Display.Driver'){return $null}
        for($i=2;$i -lt $Tokens.Count;$i++){if($Tokens[$i] -cnotin @('-silent','-n')){return $null}}
        $stream=[IO.File]::Open($dll,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        if($stream.Length -ne 6863592){return $null}
        $sha=[Security.Cryptography.SHA256]::Create()
        try{$hash=([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','')}finally{$sha.Dispose()}
        if($hash -cne '6481B29AD7361E5FA1A653C06EA90D831827E573B45548A00DEC407903A3EE0F'){return $null}
        # Unlike EXE flags, rundll32 options MUST follow the DLL/export/package.
        $invocationArguments=[string]$Command.Arguments
        foreach($flag in @('-silent','-n')){if($Tokens -cnotcontains $flag){$invocationArguments+=' '+$flag}}
        if($invocationArguments.Length -gt 32700){return $null}
        return [pscustomobject]@{Arguments=$invocationArguments;Rule='NvidiaDisplayQuiet';Reason='NVIDIA DLL 指纹匹配；保留 Display.Driver 范围，按官方文档追加 -silent -n。'}
    }catch{return $null}finally{if($null -ne $stream){$stream.Dispose()}}
}
