function Assert-WBPlainLocalPath([string]$Path) {
    if($Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2) -match '[:*?\x00-\x1f]' -or $Path -ne [IO.Path]::GetFullPath($Path)){throw '程序文件路径不符合移除规则。'}
    $current=$Path
    while($current){
        $item=Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw '不处理链接或重解析目录中的程序文件。'}
        $current=[IO.Path]::GetDirectoryName($current)
    }
}

function Get-WBPortableProfile([string]$Path) {
    # Exact files supplied in the user's read-only reports. Never infer a
    # removable folder from a product name, shortcut name or publisher alone.
    if($Path -match '^[A-Za-z]:\\LaoMaoTao\\LaoMaoTao\.exe$'){
        return [pscustomobject]@{Hash='AF3A4CF11FC1BF5129C92A1D36C1A7015990CE5F64E567B4DE1E180DE9278C65';Hashes=@('AF3A4CF11FC1BF5129C92A1D36C1A7015990CE5F64E567B4DE1E180DE9278C65','AA885BE1AFBA7BCFACF746F3EAC83FD60182F203AC5E80E8BD593AF5DCBE6B99');Reason='移除已核实的老毛桃主程序及对应快捷方式；保留 Data 配置，保存恢复备份。'}
    }
    switch($Path.ToLowerInvariant()){
        'c:\programdata\soft\dtldownloader.exe' {return [pscustomobject]@{Hash='F545C4EFFD4C503C72B00953700B81E736C0CD66900626CE734195845A753CAA';Reason='移除已核实的驱动人生下载器及对应快捷方式；不改动驱动和其他程序，保存恢复备份。'}}
        'c:\programdata\soft\dtldownl.exe' {return [pscustomobject]@{Hash='F4C145EFA59705B546E44A1537CCAFD431F78763D15C8E334D12042B41CDE979';Reason='移除已核实的驱动人生下载器及对应快捷方式；不改动驱动和其他程序，保存恢复备份。'}}
    }
    return $null
}

function Get-WBPortableRemovalSpec($Record,[object[]]$Inventory) {
    if($Record.Source -cne 'Shortcut'){return $null}
    $main=[string]$Record.TargetPath;$profile=Get-WBPortableProfile $main
    if($null -eq $profile){return $null}
    try{
        Assert-WBPlainLocalPath $main
        $hashes=@($profile.Hash)
        if($profile.PSObject.Properties['Hashes']){$hashes=@($profile.Hashes)}
        if($hashes -cnotcontains (Get-FileHash -LiteralPath $main -Algorithm SHA256).Hash){return $null}
        $links=@($Inventory|Where-Object{$_.Source -ceq 'Shortcut' -and $_.TargetPath -ieq $main -and [IO.Path]::GetExtension([string]$_.Path) -ieq '.lnk'}|ForEach-Object{[string]$_.Path}|Sort-Object -Unique)
        if(-not $links.Count -or $links -inotcontains ([string]$Record.Path)){return $null}
        foreach($link in $links){Assert-WBPlainLocalPath $link}
        return [pscustomobject]@{FilePath=$main;Arguments='';Backend='PortableFiles';PayloadPaths=$links;Action='PortableRemove';Rule='KnownPortable';Reason=$profile.Reason}
    }catch{return $null}
}

function Initialize-WBPortableRemovalNative {
    if('USBAppManager.PortableFiles' -as [type]){return}
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
namespace USBAppManager {
 public static class PortableFiles {
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
  static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
  static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle,StringBuilder path,uint size,uint flags);
  [DllImport("kernel32.dll",SetLastError=true)]
  [return:MarshalAs(UnmanagedType.Bool)]
  static extern bool SetFileInformationByHandle(SafeFileHandle handle,int kind,ref byte data,uint size);
  public static void Remove(string[] paths,string[] hashes,string folder) {
   if(paths.Length==0 || paths.Length!=hashes.Length) throw new ArgumentException("Invalid file set");
   var inputs=new List<FileStream>();
   try {
    for(int i=0;i<paths.Length;i++) {
     // READ + DELETE; share READ only pins each file against modification and
     // replacement. Open reparse points themselves, never follow the last link.
     var handle=CreateFileW(paths[i],0x80010000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
     if(handle.IsInvalid){int error=Marshal.GetLastWin32Error();handle.Dispose();throw new Win32Exception(error);}
     FileStream input;
     try{input=new FileStream(handle,FileAccess.Read);}catch{handle.Dispose();throw;}
     inputs.Add(input);
     var finalPath=new StringBuilder(32768);
     uint n=GetFinalPathNameByHandleW(handle,finalPath,(uint)finalPath.Capacity,0);
     if(n==0 || n>=finalPath.Capacity || !String.Equals(finalPath.ToString(),@"\\?\"+paths[i],StringComparison.OrdinalIgnoreCase))throw new IOException("Resolved file path changed");
     string hash;
     using(var sha=SHA256.Create()){hash=BitConverter.ToString(sha.ComputeHash(input)).Replace("-","");}
     if(!String.Equals(hash,hashes[i],StringComparison.Ordinal)) throw new IOException("File changed before removal");
     input.Position=0;
    }
    // Back up ALL exact bytes before marking ANY source for deletion.
    for(int i=0;i<inputs.Count;i++) {
     using(var output=new FileStream(Path.Combine(folder,i.ToString("D4")+".bak"),FileMode.CreateNew,FileAccess.Write,FileShare.None)) {
      inputs[i].CopyTo(output);output.Flush(true);
     }
     using(var check=File.OpenRead(Path.Combine(folder,i.ToString("D4")+".bak")))
     using(var sha=SHA256.Create()) {
      if(BitConverter.ToString(sha.ComputeHash(check)).Replace("-","")!=hashes[i])throw new IOException("Backup verification failed");
     }
    }
    for(int i=0;i<inputs.Count;i++) {
     byte delete=1;
     if(!SetFileInformationByHandle(inputs[i].SafeFileHandle,4,ref delete,1))throw new Win32Exception(Marshal.GetLastWin32Error());
    }
   } finally {foreach(var input in inputs)input.Dispose();}
  }
 }
}
'@ -ErrorAction Stop
}

function Invoke-WBPortableRemoval($Target,$Snapshot,[string]$Session,[string]$CancelPath) {
    if(Test-Path -LiteralPath $CancelPath){throw '用户已取消。'}
    Assert-WBSnapshotReady $Snapshot
    $spec=Get-WBPortableRemovalSpec $Target.Record $Snapshot.Inventory
    if($null -eq $spec -or (Get-WBUninstallInvocationFingerprint $spec) -cne $Target.InvocationFingerprint -or (Get-WBCommandFileHash $spec) -cne $Target.FileHash){throw '程序或快捷方式自扫描后已变化，请重新扫描。'}
    $main=$spec.FilePath
    $processes=@(Get-CimInstance Win32_Process -Filter ("Name='"+[IO.Path]::GetFileName($main)+"'") -OperationTimeoutSec 10 -ErrorAction Stop)
    if(@($processes|Where-Object{-not $_.ExecutablePath -or $_.ExecutablePath -ieq $main}).Count){throw '目标程序正在运行或无法核实，请先关闭它再重新扫描。'}
    $services=@(Get-CimInstance Win32_Service -OperationTimeoutSec 10 -ErrorAction Stop|Where-Object{$_.PathName -and $_.PathName.IndexOf($main,[StringComparison]::OrdinalIgnoreCase) -ge 0})
    if($services.Count){throw '发现关联服务，暂停文件移除，请核实安装状态。'}
    $files=@($main)+@($spec.PayloadPaths)
    $manifest=@();$shell=New-Object -ComObject WScript.Shell
    try{
        foreach($path in $files){
            Assert-WBPlainLocalPath $path
            if($path -ine $main){
                $link=$shell.CreateShortcut($path)
                try{if($link.TargetPath -ine $main){throw '快捷方式指向已变化。'}}finally{[void][Runtime.InteropServices.Marshal]::ReleaseComObject($link)}
            }
            $manifest+=[pscustomobject]@{OriginalPath=$path;BackupFile=('{0:D4}.bak' -f $manifest.Count);SHA256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
        }
    }finally{[void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell)}
    if((Get-WBCommandFileHash $spec) -cne $Target.FileHash){throw '文件复核不一致，请重新扫描。'}
    Assert-WBPlainLocalPath ([IO.Path]::GetFullPath($Session))
    $backup=Join-Path $Session ('文件备份-'+[guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($backup);Assert-WBPlainLocalPath $backup
    Write-WBJson (Join-Path $backup '恢复清单.json') ([pscustomobject]@{Product=$Target.Name;Files=$manifest})
    [IO.File]::WriteAllText((Join-Path $backup '恢复说明.txt'),'按恢复清单将 .bak 文件复制回 OriginalPath 并恢复原文件名；已有同名文件时不要覆盖。此备份不包含配置、个人文件或其他软件。',[Text.UTF8Encoding]::new($true))
    Initialize-WBPortableRemovalNative
    if(Test-Path -LiteralPath $CancelPath){throw '用户已取消，尚未移除文件。'}
    try{
        [USBAppManager.PortableFiles]::Remove([string[]]$files,[string[]]@($manifest|ForEach-Object SHA256),$backup)
        if(@($files|Where-Object{Test-Path -LiteralPath $_}).Count){throw '复查仍有目标文件，可能被占用或重新生成。'}
    }catch{throw ('文件移除未完全确认：'+$_.Exception.Message+'；请查看备份及恢复清单：'+$backup)}
    return $backup
}
