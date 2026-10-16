function Invoke-WBHttp([string]$Uri,[string[]]$AllowedHosts,[string]$Destination='', [string]$CancelPath='') {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $current=$Uri
    for($redirect=0;$redirect -lt 8;$redirect++){
        if(-not (Test-WBAllowedUri $current $AllowedHosts)){throw '安装来源或重定向地址不在允许的 HTTPS 官网域名中。'}
        if($CancelPath -and (Test-Path -LiteralPath $CancelPath)){throw '用户已取消。'}
        $request=[Net.HttpWebRequest]::Create($current);$request.AllowAutoRedirect=$false;$request.Timeout=30000;$request.ReadWriteTimeout=30000;$request.UserAgent='Mozilla/5.0 USB-WinBatch/0.1';$request.AutomaticDecompression=[Net.DecompressionMethods]::GZip -bor [Net.DecompressionMethods]::Deflate
        $response=$null;$stream=$null;$output=$null
        try{
            $response=$request.GetResponse();$code=[int]$response.StatusCode
            if($code -in @(301,302,303,307,308)){
                $location=$response.Headers['Location'];if(-not $location){throw '下载重定向缺少目标。'}
                $current=(New-Object Uri([Uri]$current,$location)).AbsoluteUri;continue
            }
            if($code -ne 200){throw ('官网返回异常状态：'+$code)}
            $stream=$response.GetResponseStream()
            if($Destination){$output=[IO.File]::Open($Destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)}else{$output=New-Object IO.MemoryStream}
            $buffer=New-Object byte[] 65536;$total=[long]0;$timer=[Diagnostics.Stopwatch]::StartNew()
            while(($count=$stream.Read($buffer,0,$buffer.Length)) -gt 0){
                if($CancelPath -and (Test-Path -LiteralPath $CancelPath)){throw '用户已取消。'}
                if($timer.Elapsed.TotalMinutes -gt 15){throw '下载超过 15 分钟，停止本批处理。'}
                $total+=$count;if(($Destination -and $total -gt 2147483648) -or (-not $Destination -and $total -gt 8388608)){throw '下载内容超过允许大小。'}
                $output.Write($buffer,0,$count)
            }
            if($total -le 0){throw '下载结果为空。'}
            if($response.ContentLength -ge 0 -and -not $response.ContentEncoding -and $response.ContentLength -ne $total){throw '下载长度不完整。'}
            if($Destination){return [pscustomobject]@{FinalUrl=$current;Length=$total}}
            return [Text.Encoding]::UTF8.GetString($output.ToArray())
        }finally{if($output){$output.Dispose()};if($stream){$stream.Dispose()};if($response){$response.Dispose()}}
    }
    throw '官网重定向次数过多。'
}

function Resolve-WBDownload($Product,[string]$CancelPath='') {
    $download=$Product.Download
    $is32=(-not [Environment]::Is64BitOperatingSystem)
    if($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64'){throw '第一版尚未验证 ARM64 安装包，请人工处理。'}
    if($is32 -and (Get-WBValue $download 'X86Url')){$url=[string]$download.X86Url}
    elseif($is32 -and (Get-WBValue $download 'Architecture') -eq 'x64'){throw '该下载规则仅适用于 64 位系统，请从官网选择受支持版本。'}
    elseif($download.Mode -eq 'Direct'){$url=[string]$download.Url}
    elseif($download.Mode -eq 'PageLink'){
        $text=Invoke-WBHttp -Uri $download.PageUrl -AllowedHosts $download.AllowedHosts -CancelPath $CancelPath
        $captured=Get-WBDownloadCapture -Text $text -Pattern $download.Pattern
        $url=[Net.WebUtility]::HtmlDecode($captured.Replace('\/','/'))
        if($url.StartsWith('//')){$url='https:'+$url}
        elseif(-not [Uri]::IsWellFormedUriString($url,[UriKind]::Absolute)){$url=(New-Object Uri([Uri]$download.PageUrl,$url)).AbsoluteUri}
    }else{throw '没有经过核实的自动下载规则，请选择本地官方安装包。'}
    if(-not (Test-WBAllowedUri $url $download.AllowedHosts)){throw '解析出的安装包地址不属于允许的官网来源。'}
    return $url
}

function Test-WBInstaller([string]$Path,$Product) {
    if(-not (Test-Path -LiteralPath $Path -PathType Leaf) -or [IO.Path]::GetExtension($Path) -ine '.exe'){throw '请选择存在的官方 EXE 安装包。'}
    $file=Get-Item -LiteralPath $Path -ErrorAction Stop
    if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw '不接受重解析点作为安装包。'}
    $stream=[IO.File]::OpenRead($file.FullName)
    try{if($stream.ReadByte() -ne 77 -or $stream.ReadByte() -ne 90){throw '文件不是有效的 Windows 可执行安装包。'}}finally{$stream.Dispose()}
    $sig=Get-AuthenticodeSignature -LiteralPath $file.FullName -ErrorAction Stop
    if($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate){throw ('安装包签名未验证通过：'+$sig.Status)}
    $signer=$sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)
    if($signer -notin @($Product.AllowedSignerNames)){throw ('安装包发布者不符合 '+$Product.Name+' 规则：'+$signer)}
    $metadata=@($file.VersionInfo.ProductName,$file.VersionInfo.FileDescription)|Where-Object{$_}
    $matched=$false
    foreach($name in $metadata){foreach($expected in @($Product.ProductNames)){if($name.Trim() -ieq ([string]$expected).Trim()){$matched=$true}}}
    if(-not $matched){throw ('安装包产品信息与 '+$Product.Name+' 不符，拒绝运行。')}
    [pscustomobject]@{Path=$file.FullName;Sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash;Signer=$signer;ProductName=$file.VersionInfo.ProductName;Version=$file.VersionInfo.ProductVersion;Length=$file.Length}
}

function Get-WBPackage([string]$Root,$Product,[string]$LocalPath='',[string]$CancelPath='') {
    Assert-WBPlatform
    if($LocalPath){$evidence=Test-WBInstaller -Path $LocalPath -Product $Product;$evidence|Add-Member -NotePropertyName Source -NotePropertyValue '用户选择的本地包（版本未与官网比较）';return $evidence}
    $url=Resolve-WBDownload -Product $Product -CancelPath $CancelPath
    if($Product.Id -ceq 'qq'){$url=Get-WBQQAuthorizedDownload -OriginalUrl $url}
    $folder=Join-Path $Root ('packages\'+$Product.Id);[IO.Directory]::CreateDirectory($folder)|Out-Null
    $name=(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)+'.exe'
    $path=Join-Path $folder $name;$part=$path+'.part'
    try{
        $downloadResult=Invoke-WBHttp -Uri $url -AllowedHosts $Product.Download.AllowedHosts -Destination $part -CancelPath $CancelPath
        Move-Item -LiteralPath $part -Destination $path -ErrorAction Stop
        $evidence=Test-WBInstaller -Path $path -Product $Product
        $source=([Uri]$downloadResult.FinalUrl).GetLeftPart([UriPartial]::Path)
        $evidence|Add-Member -NotePropertyName Source -NotePropertyValue $source
        Write-WBJson -Path ($path+'.json') -Value $evidence
        return $evidence
    }catch{
        # Keep failed downloads quarantined as non-executable files. Never launch them.
        if(Test-Path -LiteralPath $path){Move-Item -LiteralPath $path -Destination ($path+'.rejected') -ErrorAction SilentlyContinue}
        throw
    }
}

function Get-WBQQAuthorizedDownload([string]$OriginalUrl) {
    if(-not (Test-WBAllowedUri $OriginalUrl @('qqdl.gtimg.cn'))){throw 'QQ 原始下载来源异常。'}
    $endpoint='https://im.qq.com/http2rpc/gotrpc/noauth/trpc.qqntv2.urlsign.UrlSign/GetSign'
    $request=[Net.HttpWebRequest]::Create($endpoint);$request.Method='POST';$request.AllowAutoRedirect=$false;$request.Timeout=30000;$request.ReadWriteTimeout=30000
    $request.ContentType='application/json';$request.UserAgent='Mozilla/5.0 USB-WinBatch/0.1';$request.Referer='https://im.qq.com/'
    $request.Headers['Origin']='https://im.qq.com';$request.Headers['x-oidb']='{"uint32_command":"0x9b8e","uint32_service_type":1}'
    $body=[Text.Encoding]::UTF8.GetBytes((@{url=$OriginalUrl}|ConvertTo-Json -Compress));$request.ContentLength=$body.Length
    $stream=$request.GetRequestStream();try{$stream.Write($body,0,$body.Length)}finally{$stream.Dispose()}
    $response=$null;$reader=$null
    try{
        $response=$request.GetResponse();if([int]$response.StatusCode -ne 200){throw 'QQ 官网下载授权响应异常。'}
        $reader=New-Object IO.StreamReader($response.GetResponseStream(),[Text.Encoding]::UTF8)
        $json=$reader.ReadToEnd();if($json.Length -gt 1048576){throw 'QQ 官网授权响应过大。'}
        return Get-WBQQAuthorizedUrl -OriginalUrl $OriginalUrl -Response ($json|ConvertFrom-Json -ErrorAction Stop)
    }finally{if($reader){$reader.Dispose()};if($response){$response.Dispose()}}
}
