# Dot sourced by WinBatch.System; native compilation is deliberately lazy.
function Initialize-WBProcessNative {
    if ('USBWinBatch.ProcessJob' -as [type]) { return }
    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
namespace USBWinBatch {
    public sealed class ProcessJob : IDisposable {
        public const string Name = @"Global\USBWinBatchV1.ActiveInstaller";
        const uint Query = 4, Suspended = 4, NoWindow = 0x08000000;
        const int BasicProcessIds = 3;
        IntPtr job, process;
        EventWaitHandle armed, release; Process keeper; bool released;
        [StructLayout(LayoutKind.Sequential)] struct Accounting {
            public long User, Kernel, PeriodUser, PeriodKernel;
            public uint Faults, Total, Active, Terminated;
        }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Startup {
            public uint cb; public string reserved, desktop, title;
            public uint x,y,width,height,xChars,yChars,fill,flags;
            public ushort show,reservedSize; public IntPtr reservedData,input,output,error;
        }
        [StructLayout(LayoutKind.Sequential)] struct ProcessInfo {
            public IntPtr process, thread; public uint id, threadId;
        }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern IntPtr OpenJobObjectW(uint access, bool inherit, string name);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool QueryInformationJobObject(IntPtr job, int infoClass, out Accounting info, uint size, IntPtr returned);
        [DllImport("kernel32.dll", SetLastError=true, EntryPoint="QueryInformationJobObject")]
        static extern bool QueryProcessIds(IntPtr job, int infoClass, IntPtr info, uint size, IntPtr returned);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern bool CreateProcessW(string app, StringBuilder command, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string cwd, ref Startup startup, out ProcessInfo info);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
        [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr process, uint code);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
        [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint ms);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint id);
        [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForMultipleObjects(uint count, IntPtr[] handles, bool all, uint ms);
        static Exception Error(string operation) { return new Win32Exception(Marshal.GetLastWin32Error(), operation); }
        static uint Count(IntPtr handle) {
            Accounting info;
            if (!QueryInformationJobObject(handle, 1, out info, (uint)Marshal.SizeOf(typeof(Accounting)), IntPtr.Zero)) throw Error("Query installer job");
            return info.Active;
        }
        public static void AssertNoActive() {
            IntPtr handle=OpenJobObjectW(Query, false, Name);
            if (handle==IntPtr.Zero) {
                int error=Marshal.GetLastWin32Error();
                if(error==2) return;
                throw new Win32Exception(error,"Cannot inspect outstanding installer job");
            }
            try { if(Count(handle)!=0) throw new InvalidOperationException("A supervised installer process tree is still active."); }
            finally { CloseHandle(handle); }
        }
        // QUERY only. Keep this object alive until all recovery rechecks/actions
        // finish: even an empty job cannot be replaced while this handle exists.
        public static ProcessJob OpenOutstanding() { return OpenOutstanding(Name); }
        public static ProcessJob OpenOutstanding(string name) {
            IntPtr handle=OpenJobObjectW(Query,false,name);
            if(handle==IntPtr.Zero) {
                int error=Marshal.GetLastWin32Error();
                if(error==2) return null;
                throw new Win32Exception(error,"Open outstanding job for recovery");
            }
            return new ProcessJob { job=handle };
        }
        public void RecheckRecoverySubset(uint[] approved) {
            if(job==IntPtr.Zero || approved==null) throw new InvalidOperationException("Recovery query handle is closed.");
            HashSet<uint> allowed=new HashSet<uint>(approved);
            foreach(uint id in ActiveProcessIds) {
                if(!allowed.Contains(id)) {
                    using(RecoveryProcess member=RecoveryProcess.Open(id)) {
                        if(member==null) continue;
                        throw new InvalidOperationException("Recovery refused late/unknown job PID "+id+" ["+member.Path+"]");
                    }
                }
            }
        }
        public void StopRecoveryWorker(RecoveryProcess worker,uint[] approved) {
            RecheckRecoverySubset(approved);
            worker.Stop();
        }
        public void SignalRecoveryRelease(EventWaitHandle gate,uint[] approved) {
            RecheckRecoverySubset(approved);
            if(!gate.Set()) throw new InvalidOperationException("Keeper release event could not be signalled.");
        }
        public static ProcessJob Create() {
            Stopwatch clock=Stopwatch.StartNew();
            while(true) {
                IntPtr handle=CreateJobObjectW(IntPtr.Zero,Name);
                int error=Marshal.GetLastWin32Error();
                if(handle==IntPtr.Zero) throw new Win32Exception(error,"Create installer job");
                if(error!=183) return new ProcessJob { job=handle };
                bool active;
                try { active=Count(handle)!=0; } finally { CloseHandle(handle); }
                if(active || clock.Elapsed.TotalSeconds>=2) throw new InvalidOperationException("An installer job is already reserved or active.");
                // Let a drained keeper close, but NEVER reuse an existing job:
                // an empty job may still belong to another suspended launch.
                Thread.Sleep(25);
            }
        }
        // The named job loses its name on last-handle close on Windows, even
        // while members run. A detached, unassigned keeper holds QUERY access.
        // READY precedes any vendor execution; ARMED or worker death starts drain.
        public void Protect(string sourcePath) {
            string token=@"Local\USBWinBatchV1."+Guid.NewGuid().ToString("N");
            using(EventWaitHandle ready=new EventWaitHandle(false,EventResetMode.ManualReset,token+".Ready")) {
                armed=new EventWaitHandle(false,EventResetMode.ManualReset,token+".Armed");
                release=new EventWaitHandle(false,EventResetMode.ManualReset,token+".Release");
                string code=". '"+sourcePath.Replace("'","''")+"'; Initialize-WBProcessNative; [USBWinBatch.ProcessJob]::Keep('"+token+"',"+Process.GetCurrentProcess().Id+")";
                ProcessStartInfo start=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),@"WindowsPowerShell\v1.0\powershell.exe"));
                start.Arguments="-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "+Convert.ToBase64String(Encoding.Unicode.GetBytes(code));
                start.UseShellExecute=false; start.CreateNoWindow=true;
                keeper=Process.Start(start);
                Stopwatch clock=Stopwatch.StartNew();
                while(!ready.WaitOne(50)) {
                    if(keeper.HasExited || clock.Elapsed.TotalSeconds>=30) throw new InvalidOperationException("Installer job keeper could not acquire a durable handle; nothing launched.");
                }
                if(keeper.HasExited) throw new InvalidOperationException("Installer job keeper exited before launch.");
            }
        }
        public static void Keep(string token, int workerId) {
            IntPtr handle=OpenJobObjectW(Query,false,Name);
            if(handle==IntPtr.Zero) throw Error("Keeper open installer job");
            IntPtr worker=IntPtr.Zero;
            try {
                using(EventWaitHandle ready=EventWaitHandle.OpenExisting(token+".Ready"))
                using(EventWaitHandle gate=EventWaitHandle.OpenExisting(token+".Armed"))
                using(EventWaitHandle releaseGate=EventWaitHandle.OpenExisting(token+".Release")) {
                    worker=OpenProcess(0x100000,false,(uint)workerId);
                    if(worker==IntPtr.Zero) throw Error("Keeper open worker lifetime handle");
                    ready.Set();
                    if(worker!=IntPtr.Zero) {
                        uint wait=WaitForMultipleObjects(2,new IntPtr[] {gate.SafeWaitHandle.DangerousGetHandle(),worker},false,UInt32.MaxValue);
                        if(wait==UInt32.MaxValue) throw Error("Keeper wait for launch or worker exit");
                    }
                    while(Count(handle)!=0) { if(releaseGate.WaitOne(50)) break; }
                }
            } finally { if(worker!=IntPtr.Zero) CloseHandle(worker); CloseHandle(handle); }
        }
        // Arguments is an already serialized Windows argv tail, not a shell expression.
        // Quote argv[0] even with spaces; double backslashes preceding quotes/end.
        static string Quote(string value) {
            StringBuilder text=new StringBuilder("\""); int slashes=0;
            foreach(char c in value) {
                if(c=='\\') { slashes++; continue; }
                if(c=='\"') text.Append('\\',slashes*2+1); else text.Append('\\',slashes);
                text.Append(c); slashes=0;
            }
            text.Append('\\',slashes*2); return text.Append('"').ToString();
        }
        public void Start(string path, string arguments) {
            if(job==IntPtr.Zero || process!=IntPtr.Zero) throw new InvalidOperationException("Invalid job launch state.");
            if(keeper==null || keeper.HasExited) throw new InvalidOperationException("Durable installer job keeper is unavailable; nothing launched.");
            path=Path.GetFullPath(path);
            if(path.IndexOf('\0')>=0 || (arguments!=null && arguments.IndexOf('\0')>=0)) throw new ArgumentException("NUL in command line");
            Startup startup=new Startup(); startup.cb=(uint)Marshal.SizeOf(typeof(Startup));
            ProcessInfo info;
            if(!CreateProcessW(path,new StringBuilder(Quote(path)+(String.IsNullOrEmpty(arguments)?"":" "+arguments)),IntPtr.Zero,IntPtr.Zero,false,Suspended | NoWindow,IntPtr.Zero,Path.GetDirectoryName(path),ref startup,out info)) throw Error("Create suspended installer");
            bool resumed=false;
            try {
                if(!AssignProcessToJobObject(job,info.process)) throw Error("Assign suspended installer to job");
                if(ResumeThread(info.thread)==UInt32.MaxValue) throw Error("Resume supervised installer");
                resumed=true; process=info.process;
                if(armed!=null) armed.Set();
            } finally {
                if(!resumed) {
                    // This is the ONLY termination path: our newly created, NEVER resumed process.
                    if(TerminateProcess(info.process,1)) WaitForSingleObject(info.process,5000);
                    CloseHandle(info.process);
                }
                CloseHandle(info.thread);
            }
        }
        // JobObjectBasicProcessIdList has two DWORDs followed by ULONG_PTR PIDs.
        // ERROR_MORE_DATA is a retry, never permission to use a truncated list.
        public uint[] ActiveProcessIds {
            get {
                int capacity=16;
                for(int attempt=0;attempt<32;attempt++) {
                    if(capacity<=0 || capacity>1048576) throw new InvalidOperationException("Installer process list exceeds safe capacity.");
                    int bytes=checked(8+capacity*IntPtr.Size);
                    IntPtr buffer=Marshal.AllocHGlobal(bytes);
                    try {
                        if(!QueryProcessIds(job,BasicProcessIds,buffer,(uint)bytes,IntPtr.Zero)) {
                            int error=Marshal.GetLastWin32Error();
                            if(error!=234) throw new Win32Exception(error,"Enumerate installer job processes");
                            int assigned=Marshal.ReadInt32(buffer,0);
                            capacity=Math.Max(checked(capacity*2),assigned);
                            if(capacity>1048576) throw new InvalidOperationException("Installer process list exceeds safe capacity.");
                            continue;
                        }
                        int total=Marshal.ReadInt32(buffer,0), length=Marshal.ReadInt32(buffer,4);
                        if(total<0 || length<0 || length>capacity) throw new InvalidOperationException("Invalid installer process list.");
                        if(total!=length) { capacity=Math.Max(checked(capacity*2),total); continue; }
                        List<uint> ids=new List<uint>(length);
                        for(int i=0;i<length;i++) {
                            long value=Marshal.ReadIntPtr(buffer,8+i*IntPtr.Size).ToInt64();
                            if(value<=0 || value>UInt32.MaxValue) throw new InvalidOperationException("Invalid installer process id.");
                            // The job list can briefly retain an exited process
                            // whose handle is still open (including our root).
                            // Test liveness without blocking; access/query errors
                            // are uncertainty and must never permit release.
                            IntPtr member=OpenProcess(0x100000,false,(uint)value);
                            if(member==IntPtr.Zero) {
                                int error=Marshal.GetLastWin32Error();
                                if(error==87) continue; // PID ceased to exist.
                                throw new Win32Exception(error,"Inspect installer job member lifetime");
                            }
                            try {
                                uint status=WaitForSingleObject(member,0);
                                if(status==258) ids.Add((uint)value);
                                else if(status!=0) throw Error("Inspect installer job member exit");
                            } finally { CloseHandle(member); }
                        }
                        return ids.ToArray();
                    } finally { Marshal.FreeHGlobal(buffer); }
                }
                throw new InvalidOperationException("Installer process list did not stabilize.");
            }
        }
        public bool RootExited {
            get {
                if(process==IntPtr.Zero) return false;
                uint status=WaitForSingleObject(process,0);
                if(status==0) return true;
                if(status==258) return false;
                throw Error("Inspect installer root exit");
            }
        }
        public int? RootExitCode {
            get {
                if(!RootExited) return null;
                uint code; if(!GetExitCodeProcess(process,out code)) throw Error("Read installer root exit code");
                return unchecked((int)code);
            }
        }
        // Only the explicit completion-evidence path may surrender a live job.
        // Re-query after callback execution, immediately before release; any new
        // unapproved PID or pending cancellation leaves the durable guard intact.
        public int TryReleaseApproved(uint[] approvedProcessIds, string cancelPath) {
            // Backward-compatible callers can only certify a zero exit code.
            return TryReleaseApproved(approvedProcessIds,cancelPath,0);
        }
        public int TryReleaseApproved(uint[] approvedProcessIds, string cancelPath, int expectedRootCode) {
            if(released || release==null || approvedProcessIds==null || approvedProcessIds.Length==0) return -1;
            HashSet<uint> approved=new HashSet<uint>(approvedProcessIds);
            if(approved.Contains(0) || RootExitCode!=expectedRootCode) return -1;
            uint[] live=ActiveProcessIds;
            if(live.Length==0) return -1;
            foreach(uint id in live) if(!approved.Contains(id)) return -1;
            if(RootExitCode!=expectedRootCode || (!String.IsNullOrEmpty(cancelPath) && File.Exists(cancelPath))) return -1;
            live=ActiveProcessIds;
            if(live.Length==0) return -1;
            foreach(uint id in live) if(!approved.Contains(id)) return -1;
            if(RootExitCode!=expectedRootCode || (!String.IsNullOrEmpty(cancelPath) && File.Exists(cancelPath))) return -1;
            release.Set(); released=true;
            return live.Length;
        }
        public uint ActiveCount { get { return Count(job); } }
        public int ExitCode {
            get { uint code; if(WaitForSingleObject(process,UInt32.MaxValue)!=0) throw Error("Wait for installer exit"); if(!GetExitCodeProcess(process,out code)) throw Error("Read installer exit code"); return unchecked((int)code); }
        }
        public void Dispose() {
            if(armed!=null) { armed.Set(); armed.Dispose(); armed=null; }
            bool drained=false;
            try { drained=job!=IntPtr.Zero && Count(job)==0; } catch { /* Cleanup must still close owned handles. */ }
            if(process!=IntPtr.Zero) { CloseHandle(process); process=IntPtr.Zero; }
            // No KILL_ON_JOB_CLOSE: closing handles never kills vendor processes.
            if(job!=IntPtr.Zero) { CloseHandle(job); job=IntPtr.Zero; }
            if(release!=null) { release.Dispose(); release=null; }
            if(keeper!=null) { if(drained || released) keeper.WaitForExit(5000); keeper.Dispose(); keeper=null; }
            GC.SuppressFinalize(this);
        }
        ~ProcessJob() { if(process!=IntPtr.Zero) CloseHandle(process); if(job!=IntPtr.Zero) CloseHandle(job); }
    }
    // Pinned process identity/lifetime. WMI command lines are accepted only when
    // their creation time matches this native handle (WMI precision is 1 us).
    public sealed class RecoveryProcess : IDisposable {
        IntPtr handle;
        public uint Id { get; private set; }
        public long CreationTime { get; private set; }
        public string Path { get; private set; }
        [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint a,bool i,uint id);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr h,out long c,out long e,out long k,out long u);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageNameW(IntPtr h,uint f,StringBuilder p,ref uint n);
        [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h,uint ms);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr h,uint code);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
        [DllImport("shell32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CommandLineToArgvW(string line,out int count);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
        static Exception Error(string s) { return new Win32Exception(Marshal.GetLastWin32Error(),s); }
        public static RecoveryProcess Open(uint id) {
            IntPtr h=OpenProcess(0x101000,false,id);
            if(h==IntPtr.Zero) {
                int error=Marshal.GetLastWin32Error();
                if(error==87) return null;
                throw new Win32Exception(error,"Inspect recovery PID "+id);
            }
            RecoveryProcess p=new RecoveryProcess { handle=h,Id=id };
            try {
                if(!p.IsAlive) { p.Dispose(); return null; }
                long c,e,k,u;
                if(!GetProcessTimes(h,out c,out e,out k,out u)) throw Error("Read creation time PID "+id);
                p.CreationTime=c;
                StringBuilder path=new StringBuilder(32768); uint size=(uint)path.Capacity;
                if(!QueryFullProcessImageNameW(h,0,path,ref size)) throw Error("Read image path PID "+id);
                p.Path=path.ToString(); return p;
            } catch { p.Dispose(); throw; }
        }
        public bool IsAlive {
            get {
                if(handle==IntPtr.Zero) throw new ObjectDisposedException("RecoveryProcess");
                uint state=WaitForSingleObject(handle,0);
                if(state==258) return true;
                if(state==0) return false;
                throw Error("Inspect pinned PID "+Id);
            }
        }
        public bool WaitForExit(int ms) {
            uint state=WaitForSingleObject(handle,(uint)ms);
            if(state==0) return true;
            if(state==258) return false;
            throw Error("Wait for recovery PID "+Id);
        }
        internal void Stop() {
            if(Id==(uint)Process.GetCurrentProcess().Id) throw new InvalidOperationException("Cannot stop the recovery caller.");
            if(!IsAlive) return;
            IntPtr target=OpenProcess(0x101001,false,Id);
            if(target==IntPtr.Zero) throw Error("Open verified worker PID "+Id);
            try {
                long c,e,k,u;
                if(!GetProcessTimes(target,out c,out e,out k,out u)) throw Error("Recheck worker creation time");
                if(c!=CreationTime) throw new InvalidOperationException("Worker PID was reused.");
                if(!TerminateProcess(target,1)) throw Error("Stop verified WinBatch worker");
                if(!WaitForExit(5000)) throw new InvalidOperationException("Verified worker did not exit.");
            } finally { CloseHandle(target); }
        }
        public static string[] ParseArguments(string line) {
            if(String.IsNullOrWhiteSpace(line) || line.Length>32767 || line.IndexOf('\0')>=0) throw new ArgumentException("Missing or invalid command line.");
            int count; IntPtr memory=CommandLineToArgvW(line,out count);
            if(memory==IntPtr.Zero) throw Error("Parse recovery argv");
            try {
                if(count<1 || count>1024) throw new ArgumentException("Invalid argument count.");
                string[] args=new string[count];
                for(int i=0;i<count;i++) args[i]=Marshal.PtrToStringUni(Marshal.ReadIntPtr(memory,i*IntPtr.Size));
                return args;
            } finally { LocalFree(memory); }
        }
        public void Dispose() { if(handle!=IntPtr.Zero) { CloseHandle(handle); handle=IntPtr.Zero; } GC.SuppressFinalize(this); }
        ~RecoveryProcess() { if(handle!=IntPtr.Zero) CloseHandle(handle); }
    }
}
"@ -ErrorAction Stop
}

function Open-WBExecutionGuard([scriptblock]$GuardQuery) {
    Initialize-WBProcessNative
    if($GuardQuery){return (& $GuardQuery)}
    return [USBWinBatch.ProcessJob]::OpenOutstanding()
}

function Get-WBRecoveryProcess([uint32]$ProcessId) {
    $handle=[USBWinBatch.RecoveryProcess]::Open($ProcessId)
    if($null -eq $handle){return $null}
    try {
        $rows=@(Get-CimInstance Win32_Process -Filter ("ProcessId="+$ProcessId) -ErrorAction Stop)
        if(-not $handle.IsAlive){$handle.Dispose();return $null}
        if($rows.Count -ne 1 -or -not $rows[0].CreationDate -or -not $rows[0].CommandLine -or -not $rows[0].ExecutablePath){throw '进程命令行、路径或创建时间不可读。'}
        $row=$rows[0]
        $time=([datetime]$row.CreationDate).ToUniversalTime().ToFileTimeUtc()
        if([decimal]::Truncate(([decimal]$time/10)) -ne [decimal]::Truncate(([decimal]$handle.CreationTime/10)) -or [IO.Path]::GetFullPath($row.ExecutablePath) -ine $handle.Path){throw '进程身份或创建时间不一致，可能发生 PID 重用。'}
        return [pscustomobject]@{Id=$ProcessId;Path=$handle.Path;CommandLine=[string]$row.CommandLine;CreationTime=$handle.CreationTime;ParentId=[uint32]$row.ParentProcessId;Handle=$handle}
    } catch {
        $path=$handle.Path;$handle.Dispose()
        throw ("PID {0} [{1}]：{2}" -f $ProcessId,$path,$_.Exception.Message)
    }
}

function Test-WBRecoveryPowerShell([string]$Path) {
    $paths=@((Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'),(Join-Path $env:windir 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'))
    return ([IO.Path]::GetFullPath($Path) -iin $paths)
}

# Never evaluate the decoded text. Match the complete v0.2.2 keeper grammar.
function ConvertFrom-WBRecoveryKeeperCommand([string]$Path,[string]$CommandLine,[string]$Root) {
    if(-not (Test-WBRecoveryPowerShell $Path)){return $null}
    $a=@([USBWinBatch.RecoveryProcess]::ParseArguments($CommandLine))
    if($a.Count -ne 7 -or [IO.Path]::GetFullPath($a[0]) -ine $Path -or $a[1] -ine '-NoProfile' -or $a[2] -ine '-NonInteractive' -or $a[3] -ine '-ExecutionPolicy' -or $a[4] -ine 'Bypass' -or $a[5] -ine '-EncodedCommand'){return $null}
    try{$code=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($a[6]))}catch{return $null}
    $pattern="\A\. '(?<source>(?:[^']|'')+)'; Initialize-WBProcessNative; \[USBWinBatch\.ProcessJob\]::Keep\('(?<token>Local\\USBWinBatchV1\.[0-9a-f]{32})',(?<worker>[1-9][0-9]*)\)\z"
    $match=[regex]::Match($code,$pattern)
    if(-not $match.Success){return $null}
    $source=$match.Groups['source'].Value.Replace("''", "'")
    if(-not [IO.Path]::IsPathRooted($source) -or [IO.Path]::GetFullPath($source) -ine (Join-Path ([IO.Path]::GetFullPath($Root)) 'src\ProcessSupervisor.ps1')){return $null}
    $workerId=0L
    if(-not [long]::TryParse($match.Groups['worker'].Value,[ref]$workerId) -or $workerId -gt [uint32]::MaxValue){return $null}
    return [pscustomobject]@{Token=$match.Groups['token'].Value;WorkerId=[uint32]$workerId;Source=$source}
}

function Get-WBRecoveryKeepers([string]$Root) {
    $found=New-Object 'System.Collections.Generic.List[object]'
    try {
        foreach($row in @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction Stop)){
            if(-not $row.CommandLine -or -not $row.ExecutablePath){throw ("无法核实 PowerShell PID {0} 的 keeper 身份；请在管理员模式检查。" -f $row.ProcessId)}
            $identity=ConvertFrom-WBRecoveryKeeperCommand $row.ExecutablePath $row.CommandLine $Root
            if($null -eq $identity){continue}
            $process=Get-WBRecoveryProcess ([uint32]$row.ProcessId)
            if($null -eq $process){continue}
            try {
                $fresh=ConvertFrom-WBRecoveryKeeperCommand $process.Path $process.CommandLine $Root
                if($null -eq $fresh -or $fresh.Token -cne $identity.Token -or $fresh.WorkerId -ne $process.ParentId){throw 'keeper 命令与父进程不一致。'}
                $found.Add([pscustomobject]@{Process=$process;Token=$fresh.Token;WorkerId=$fresh.WorkerId})
            } catch {$process.Handle.Dispose();throw}
        }
        return $found.ToArray()
    } catch {foreach($keeper in $found){$keeper.Process.Handle.Dispose()};throw}
}

function Test-WBRecoveryWorker($Worker,$Keeper,[string]$Root) {
    if($Worker.Id -eq $PID -or $Worker.Id -ne $Keeper.WorkerId -or $Worker.CreationTime -ge $Keeper.Process.CreationTime -or -not (Test-WBRecoveryPowerShell $Worker.Path)){return $false}
    $a=@([USBWinBatch.RecoveryProcess]::ParseArguments($Worker.CommandLine))
    if([IO.Path]::GetFullPath($a[0]) -ine $Worker.Path){return $false}
    $i=1;$seen=@{}
    while($i -lt $a.Count -and $a[$i] -ine '-File'){
        $flag=$a[$i].ToLowerInvariant()
        if($seen.ContainsKey($flag)){return $false};$seen[$flag]=$true
        if($flag -in @('-noprofile','-noninteractive','-sta')){$i++;continue}
        if($flag -eq '-executionpolicy' -and $i+1 -lt $a.Count -and $a[$i+1] -ieq 'Bypass'){$i+=2;continue}
        return $false
    }
    if($i+1 -ge $a.Count -or $a[$i] -ine '-File' -or -not [IO.Path]::IsPathRooted($a[$i+1]) -or [IO.Path]::GetFullPath($a[$i+1]) -ine (Join-Path ([IO.Path]::GetFullPath($Root)) 'WinBatch.ps1')){return $false}
    $i+=2;$parameters=@{}
    while($i -lt $a.Count){
        $name=$a[$i].ToLowerInvariant()
        if($name -notin @('-mode','-requestpath','-outputpath') -or $parameters.ContainsKey($name) -or $i+1 -ge $a.Count -or [string]::IsNullOrWhiteSpace($a[$i+1]) -or $a[$i+1].StartsWith('-')){return $false}
        $parameters[$name]=$a[$i+1];$i+=2
    }
    return ($parameters.ContainsKey('-mode') -and $parameters['-mode'] -ieq 'Run')
}

function Test-WBRecoveryBrowserArguments([string]$Path,[string]$CommandLine) {
    $a=@([USBWinBatch.RecoveryProcess]::ParseArguments($CommandLine))
    if([IO.Path]::GetFullPath($a[0]) -ine $Path){return $false}
    foreach($argument in @($a | Select-Object -Skip 1)){
        if($argument -match '[\x00-\x1f]'){return $false}
        if($argument -match '^[-/]+'){
            $key=($argument -replace '^[-/]+','' -split '[=:]',2)[0]
            # Runtime Chromium switches vary by version. Reject maintenance
            # operations after native argv parsing, rather than a brittle flag
            # allowlist. Also reject wrapped/compound maintenance switches.
            if($key -match '(?i)(install|repair|updat|maintenance|setup|remove|cleanup|recover|register|migration)' -and $key -notin @('disable-component-update')){return $false}
            if($key -match '(?i)^(system-level|user-level|multi-install|force-delete-profile|make-default-browser|on-os-upgrade)$'){return $false}
            if($key -ieq 'type' -and $argument -notmatch '(?i)^--type=(renderer|utility|gpu-process|crashpad-handler|ppapi|ppapi-broker)$'){return $false}
            continue
        }
        # Positional arguments must be browser documents/URLs, not scripts or
        # installer payloads. Empty argv entries have no maintenance meaning.
        if($argument -eq ''){continue}
        if([IO.Path]::GetFileName($Path) -ieq 'iexplore.exe' -and $argument -match '^(?:SCODEF|CREDAT):[0-9]+$'){continue}
        $uri=$null
        if([Uri]::TryCreate($argument,[UriKind]::Absolute,[ref]$uri) -and $uri.Scheme -in @('http','https','about','chrome','edge')){continue}
        return $false
    }
    return $true
}

# Private shared predicate: {Path, CommandLine} -> Boolean. Caller must bind
# this pair to the live PID; the CIM wrapper below performs that binding.
function Get-WBRegisteredBrowserExecutables {
    foreach($hive in @('CurrentUser','LocalMachine')){
        foreach($view in @('Registry32','Registry64')){
            $base=$null;$clients=$null
            try{
                $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::$hive,[Microsoft.Win32.RegistryView]::$view)
                $clients=$base.OpenSubKey('SOFTWARE\Clients\StartMenuInternet')
                if($null -eq $clients){continue}
                foreach($name in $clients.GetSubKeyNames()){
                    $entry=$null
                    try{
                        $entry=$clients.OpenSubKey($name+'\shell\open\command')
                        if($null -eq $entry){continue}
                        $command=[Environment]::ExpandEnvironmentVariables([string]$entry.GetValue('',''))
                        $args=@([USBWinBatch.RecoveryProcess]::ParseArguments($command))
                        if($args.Count -and $args[0] -match '^[A-Za-z]:\\' -and [IO.Path]::GetExtension($args[0]) -ieq '.exe'){[IO.Path]::GetFullPath($args[0])}
                    }catch{}finally{if($null -ne $entry){$entry.Dispose()}}
                }
            }catch{}finally{if($null -ne $clients){$clients.Dispose()};if($null -ne $base){$base.Dispose()}}
        }
    }
}

function Test-WBRecoveryBrowser($Process) {
    try {
        if($null -eq $Process -or -not $Process.Path -or -not $Process.CommandLine){return $false}
        $leaf=[IO.Path]::GetFileName($Process.Path)
        $registered=$false
        if($leaf -ieq 'chrome.exe'){$product='Google Chrome';$signers=@('Google LLC','Google Inc')}
        elseif($leaf -ieq 'msedge.exe'){$product='Microsoft Edge';$signers=@('Microsoft Corporation')}
        elseif($leaf -ieq 'SogouExplorer.exe'){$product='SogouExplorer';$signers=@('Beijing Sogou Technology Development Co., Ltd.')}
        elseif($leaf -ieq 'iexplore.exe'){$product='Internet Explorer';$signers=@('Microsoft Corporation','Microsoft Windows')}
        elseif($leaf -iin @('360se.exe','360chrome.exe','360chromeX.exe','firefox.exe','QQBrowser.exe','2345Explorer.exe')){$registered=$true;$product='';$signers=@()}
        else{return $false}
        Initialize-WBProcessNative
        if(-not (Test-WBRecoveryBrowserArguments $Process.Path $Process.CommandLine)){return $false}
        $version=[Diagnostics.FileVersionInfo]::GetVersionInfo($Process.Path)
        if($registered){
            if(-not $version.ProductName -or $version.ProductName -match '(?i)install|setup|update|repair|卸载|安装'){return $false}
            if(@(Get-WBRegisteredBrowserExecutables) -inotcontains ([IO.Path]::GetFullPath($Process.Path))){return $false}
        }elseif($version.ProductName -cne $product){return $false}
        if(-not (Get-Command Get-WBOfflineSignature -ErrorAction SilentlyContinue)){. (Join-Path $PSScriptRoot 'OfflineSignature.ps1')}
        $signature=Get-WBOfflineSignature -Path $Process.Path
        if($signature.Status -ne 'Valid' -or -not $signature.SignerName){return $false}
        return ($registered -or $signature.SignerName -cin $signers)
    } catch {return $false}
}

# Shared private read-only classifier for completion probes. Input is a
# Win32_Process CIM record with ProcessId, CreationDate, ExecutablePath and
# CommandLine. Re-read its native identity and command line; a stale/missing
# record, exited process, invalid signature or any inspection error is FALSE.
function Test-WBRecoverableBrowserProcess($ProcessCimRecord) {
    $current=$null
    try {
        if($null -eq $ProcessCimRecord){return $false}
        $id=[long]$ProcessCimRecord.ProcessId
        if($id -le 0 -or $id -gt [uint32]::MaxValue -or -not $ProcessCimRecord.CreationDate -or -not $ProcessCimRecord.ExecutablePath -or -not $ProcessCimRecord.CommandLine){return $false}
        Initialize-WBProcessNative
        $current=Get-WBRecoveryProcess ([uint32]$id)
        if($null -eq $current){return $false}
        $time=([datetime]$ProcessCimRecord.CreationDate).ToUniversalTime().ToFileTimeUtc()
        if([decimal]::Truncate(([decimal]$time/10)) -ne [decimal]::Truncate(([decimal]$current.CreationTime/10)) -or [IO.Path]::GetFullPath($ProcessCimRecord.ExecutablePath) -ine $current.Path -or $ProcessCimRecord.CommandLine -cne $current.CommandLine){return $false}
        return (Test-WBRecoveryBrowser $current)
    } catch {return $false}
    finally {if($null -ne $current){$current.Handle.Dispose()}}
}

function Get-WBRecoverySnapshot($Guard,[string]$Root) {
    $members=New-Object 'System.Collections.Generic.List[object]';$keepers=@();$worker=$null;$inspectionError=''
    try {
        foreach($id in @($Guard.ActiveProcessIds)){
            $process=Get-WBRecoveryProcess $id
            if($null -eq $process){continue}
            $members.Add($process)
            $process | Add-Member -NotePropertyName Kind -NotePropertyValue 'Unknown'
            try{if(Test-WBRecoveryBrowser $process){$process.Kind='NormalBrowser'}}catch{$inspectionError=$_.Exception.Message}
        }
        try {
            $keepers=@(Get-WBRecoveryKeepers $Root)
            if($keepers.Count -eq 1){$worker=Get-WBRecoveryProcess $keepers[0].WorkerId}
        } catch {$inspectionError=$_.Exception.Message}
        return [pscustomobject]@{Members=$members.ToArray();Keepers=$keepers;Worker=$worker;InspectionError=$inspectionError}
    } catch {
        foreach($process in $members){$process.Handle.Dispose()}
        foreach($keeper in $keepers){$keeper.Process.Handle.Dispose()}
        if($null -ne $worker){$worker.Handle.Dispose()}
        throw
    }
}

function Close-WBRecoverySnapshot($Snapshot) {
    if($null -eq $Snapshot){return}
    foreach($process in @($Snapshot.Members)){$process.Handle.Dispose()}
    foreach($keeper in @($Snapshot.Keepers)){$keeper.Process.Handle.Dispose()}
    if($null -ne $Snapshot.Worker){$Snapshot.Worker.Handle.Dispose()}
}

function ConvertTo-WBRecoveryDiagnosis($Snapshot) {
    foreach($process in @($Snapshot.Members)){
        [pscustomobject]@{PID=$process.Id;Path=$process.Path;Kind=$process.Kind;CommandLine=$process.CommandLine;CreationTime=$process.CreationTime}
    }
    foreach($keeper in @($Snapshot.Keepers)){
        [pscustomobject]@{PID=$keeper.Process.Id;Path=$keeper.Process.Path;Kind='Keeper';CommandLine=$keeper.Process.CommandLine;CreationTime=$keeper.Process.CreationTime}
    }
    if($null -ne $Snapshot.Worker){
        $p=$Snapshot.Worker
        [pscustomobject]@{PID=$p.Id;Path=$p.Path;Kind='WorkerCandidate';CommandLine=$p.CommandLine;CreationTime=$p.CreationTime}
    }
}

function Get-WBExecutionStateInfo {
    [CmdletBinding()]
    param([string]$Root=(Split-Path -Parent $PSScriptRoot),[scriptblock]$GuardQuery)
    $guard=$null;$snapshot=$null;$present=$false
    try {
        $guard=Open-WBExecutionGuard $GuardQuery
        if($null -eq $guard){return [pscustomobject]@{State='Absent';GuardPresent=$false;Message='当前没有安装或卸载作业守护。';Processes=@();Error=''}}
        $present=$true;$snapshot=Get-WBRecoverySnapshot $guard $Root
        $state='Blocked'
        if(-not $snapshot.InspectionError -and @($snapshot.Members | Where-Object Kind -ne 'NormalBrowser').Count -eq 0){
            if(@($snapshot.Members).Count){$state='BrowserOnly'}else{$state='EmptyReservation'}
        }
        return [pscustomobject]@{State=$state;GuardPresent=$true;Message='只读诊断；浏览器分类不表示安装或卸载成功，空作业也可能仍在等待启动。';Processes=@(ConvertTo-WBRecoveryDiagnosis $snapshot);Error=$snapshot.InspectionError}
    } catch {
        return [pscustomobject]@{State='Blocked';GuardPresent=$present;Message='无法安全核实作业，请在管理员模式检查 PID。';Processes=@();Error=$_.Exception.Message}
    } finally {Close-WBRecoverySnapshot $snapshot;if($null -ne $guard){$guard.Dispose()}}
}

function Assert-WBRecoveryIdentity($Original,$Fresh) {
    if($null -eq $Fresh -or $Original.Id -ne $Fresh.Id -or $Original.CreationTime -ne $Fresh.CreationTime -or $Original.Path -ine $Fresh.Path -or $Original.CommandLine -cne $Fresh.CommandLine){throw ('进程身份已变化，拒绝恢复 PID '+$Original.Id+' ['+$Original.Path+']。')}
}

function Assert-WBRecoveryMembers($Guard,$Snapshot) {
    $approved=@{}
    foreach($process in @($Snapshot.Members)){$approved[[uint32]$process.Id]=$process}
    foreach($id in @($Guard.ActiveProcessIds)){
        if(-not $approved.ContainsKey([uint32]$id)){
            $late=Get-WBRecoveryProcess $id
            if($null -eq $late){continue}
            try{throw ("出现新成员，拒绝恢复 PID {0} [{1}]。" -f $id,$late.Path)}finally{$late.Handle.Dispose()}
        }
        $fresh=Get-WBRecoveryProcess $id
        if($null -eq $fresh){continue}
        try{Assert-WBRecoveryIdentity $approved[[uint32]$id] $fresh;if(-not (Test-WBRecoveryBrowser $fresh)){throw ("不再是已核实普通浏览器 PID {0} [{1}]。" -f $id,$fresh.Path)}}finally{$fresh.Handle.Dispose()}
    }
}

function Repair-WBExecutionState {
    [CmdletBinding()]
    param([string]$Root=(Split-Path -Parent $PSScriptRoot),[scriptblock]$GuardQuery)
    $result=[pscustomobject]@{State='Failed';Message='';Percent=0;Results=@();ReportPath='';Error='';Recovered=$false}
    $guard=$null;$snapshot=$null;$gate=$null;$armed=$null
    try {
        $guard=Open-WBExecutionGuard $GuardQuery
        if($null -eq $guard){$result.State='Completed';$result.Percent=100;$result.Message='当前没有遗留守护，无需恢复。请重新扫描应用状态。';return $result}
        $snapshot=Get-WBRecoverySnapshot $guard $Root
        $result.Results=@(ConvertTo-WBRecoveryDiagnosis $snapshot)
        $blocked=@($snapshot.Members | Where-Object Kind -ne 'NormalBrowser')
        if($blocked.Count){throw ('仍有安装器、卸载器或未知成员，未操作任何厂商进程：'+(($blocked | ForEach-Object {"PID $($_.Id) [$($_.Path)] $($_.CommandLine)"}) -join '; ')+'。请等待其自然结束后重试；若需人工处理，请先核实该 PID。')}
        if($snapshot.InspectionError){throw $snapshot.InspectionError}
        if(@($snapshot.Keepers).Count -ne 1){throw 'keeper 所有权证据不足或存在多个 keeper；保留守护。请查看进程诊断并在管理员模式重试。'}
        $keeper=$snapshot.Keepers[0];$worker=$snapshot.Worker
        if($null -ne $worker){
            if(-not (Test-WBRecoveryWorker $worker $keeper $Root)){throw ("worker 身份、根目录或创建顺序不符，拒绝操作 PID {0} [{1}] {2}" -f $worker.Id,$worker.Path,$worker.CommandLine)}
            if(@($snapshot.Members).Count -eq 0){throw ("空作业仍有活着的 owner，可能等待启动；保留预约。PID {0} [{1}]" -f $worker.Id,$worker.Path)}
        }
        $armed=[Threading.EventWaitHandle]::OpenExisting(($keeper.Token+'.Armed'),[Security.AccessControl.EventWaitHandleRights]::Synchronize)
        $gate=[Threading.EventWaitHandle]::OpenExisting(($keeper.Token+'.Release'),[Security.AccessControl.EventWaitHandleRights]::Modify)
        if($null -ne $worker -and -not $armed.WaitOne(0)){throw 'owner 尚未确认启动，不能清理待启动预约。'}
        $approved=[uint32[]]@($snapshot.Members | ForEach-Object {$_.Id})
        Assert-WBRecoveryMembers $guard $snapshot
        $fresh=Get-WBRecoveryProcess $keeper.Process.Id
        try{Assert-WBRecoveryIdentity $keeper.Process $fresh}finally{if($null -ne $fresh){$fresh.Handle.Dispose()}}
        if($null -ne $worker -and $worker.Handle.IsAlive){
            $fresh=Get-WBRecoveryProcess $worker.Id
            try{Assert-WBRecoveryIdentity $worker $fresh;if(-not (Test-WBRecoveryWorker $fresh $keeper $Root)){throw 'worker 二次身份检查失败。'}}finally{if($null -ne $fresh){$fresh.Handle.Dispose()}}
            # Native subset check is immediately adjacent to termination, with
            # the same held job and pinned worker identity. Never stop vendors.
            $guard.StopRecoveryWorker($worker.Handle,$approved)
        }
        Assert-WBRecoveryMembers $guard $snapshot
        $guard.SignalRecoveryRelease($gate,$approved)
        if(-not $keeper.Process.Handle.WaitForExit(5000)){throw ('释放已发送，但 keeper 尚未退出。PID '+$keeper.Process.Id+' ['+$keeper.Process.Path+']')}
        # Holding our QUERY handle necessarily keeps the name alive. Drop it
        # only after rechecks and owner/keeper exit, then verify actual absence.
        $guard.Dispose();$guard=$null
        $clock=[Diagnostics.Stopwatch]::StartNew();$delay=25
        while($true){
            $remaining=Open-WBExecutionGuard $GuardQuery
            if($null -eq $remaining){break}
            $remaining.Dispose()
            if($clock.ElapsedMilliseconds -ge 5000){throw '释放后守护仍存在（或有新的批次）；未确认恢复。请重新查看 PID 诊断。'}
            Start-Sleep -Milliseconds $delay;$delay=[math]::Min(400,$delay*2)
        }
        $result.State='Completed';$result.Percent=100;$result.Recovered=$true
        $result.Message='已释放证据一致的遗留守护，保留所有浏览器及厂商进程。这不代表卸载成功；请重新扫描后查看应用状态。'
    } catch {$result.Error=$_.Exception.Message;$result.Message='恢复未完成：'+$result.Error}
    finally {if($null -ne $gate){$gate.Dispose()};if($null -ne $armed){$armed.Dispose()};Close-WBRecoverySnapshot $snapshot;if($null -ne $guard){$guard.Dispose()}}
    return $result
}

function Assert-WBNoActiveInstaller {
    Initialize-WBProcessNative
    try{[USBWinBatch.ProcessJob]::AssertNoActive()}catch{
        $info=Get-WBExecutionStateInfo
        $details=(@($info.Processes | ForEach-Object {"PID $($_.PID) [$($_.Path)] $($_.Kind)"}) -join '; ')
        throw ('上一批安装或卸载尚未结束。'+$details+' '+$info.Error+' 请等待厂商窗口完成；若管理器曾被强制关闭，请点击“恢复执行状态”，恢复后重新扫描。')
    }
}

# CompletionProbe is opt-in: the caller supplies independent completion evidence.
# Uninstall callers must additionally prove the original installed identity gone.
# It receives {RootExited,ExitCode,ActiveProcessIds} and must return exactly one
# object with a Boolean Complete=$true and a nonempty list of approved PIDs.
# CompletionSuccessCodes defaults to zero. Product-specific success lists are
# explicit; uninstall-only inspection below does not redefine success codes.
# Uninstall callers may inspect other terminal codes: their probe must prove
# removal and browser-only survivors. The original code is returned unchanged;
# releasing a browser wait is not a claim that the vendor operation succeeded.
function Invoke-WBProcess([string]$FilePath,[string]$Arguments,[string]$CancelPath,[double]$TimeoutMinutes=30,[scriptblock]$CompletionProbe,[int[]]$CompletionSuccessCodes=@(0),[switch]$InspectNonzeroExit) {
    if ($CancelPath -and [IO.File]::Exists($CancelPath)) {
        return [pscustomobject]@{ExitCode=$null;TimedOut=$false;Cancelled=$true;TrackingWarning=$false}
    }
    if ([double]::IsNaN($TimeoutMinutes) -or [double]::IsInfinity($TimeoutMinutes) -or $TimeoutMinutes -lt 0) { throw 'TimeoutMinutes must be finite and nonnegative.' }
    Initialize-WBProcessNative
    try{$job=[USBWinBatch.ProcessJob]::Create()}catch{
        $info=Get-WBExecutionStateInfo
        $details=(@($info.Processes | ForEach-Object {"PID $($_.PID) [$($_.Path)] $($_.Kind)"}) -join '; ')
        throw ('安装或卸载作业仍被占用（空作业可能在等待启动）。'+$details+' '+$info.Error+' 请查看进程诊断；若旧管理器已异常退出，可点击“恢复执行状态”后重新扫描。原始原因：'+$_.Exception.Message)
    }
    try {
        # Close the cancellation window introduced by initialization/reservation.
        if ($CancelPath -and [IO.File]::Exists($CancelPath)) {
            return [pscustomobject]@{ExitCode=$null;TimedOut=$false;Cancelled=$true;TrackingWarning=$false}
        }
        $job.Protect((Join-Path $PSScriptRoot 'ProcessSupervisor.ps1'))
        if ($CancelPath -and [IO.File]::Exists($CancelPath)) {
            return [pscustomobject]@{ExitCode=$null;TimedOut=$false;Cancelled=$true;TrackingWarning=$false}
        }
        $job.Start($FilePath,$Arguments)
        $timer=[Diagnostics.Stopwatch]::StartNew();$cancelled=$false;$nextProbe=0
        # Private override for native fixture tests; production defaults to 1.5s.
        $probeInterval=1500
        $configured=Get-Variable -Name WBCompletionProbeIntervalMilliseconds -Scope Script -ErrorAction SilentlyContinue
        if ($configured -and $configured.Value -is [int] -and $configured.Value -ge 100 -and $configured.Value -le 10000) { $probeInterval=$configured.Value }
        while ($true) {
            if ($CancelPath -and [IO.File]::Exists($CancelPath)) { $cancelled=$true }
            if ($job.ActiveCount -eq 0) { break }
            # Cancellation waits for natural completion, bounded by the deadline.
            if ($timer.Elapsed.TotalMinutes -ge $TimeoutMinutes) {
                return [pscustomobject]@{ExitCode=$null;TimedOut=$true;Cancelled=$cancelled;TrackingWarning=$false}
            }
            if ($CompletionProbe -and -not $cancelled -and $timer.ElapsedMilliseconds -ge $nextProbe -and $job.RootExited -and ($InspectNonzeroExit -or $CompletionSuccessCodes -contains $job.RootExitCode)) {
                $nextProbe=$timer.ElapsedMilliseconds+$probeInterval
                try {
                    $expectedRootCode=[int]$job.RootExitCode
                    $state=[pscustomobject]@{RootExited=$true;ExitCode=$expectedRootCode;ActiveProcessIds=@($job.ActiveProcessIds)}
                    $answer=@(& { $ErrorActionPreference='Stop'; & $CompletionProbe $state })
                    if ($answer.Count -eq 1 -and $null -ne $answer[0] -and $answer[0] -isnot [bool]) {
                        $decision=$answer[0]
                        # A target-specific probe may report removed registration
                        # plus input-method background processes. Stop waiting,
                        # retain the durable guard, and require restart. This
                        # path NEVER calls TryReleaseApproved or kills vendors.
                        if($InspectNonzeroExit -and $decision.PSObject.Properties['RestartRequired'] -and $decision.RestartRequired -is [bool] -and $decision.RestartRequired -and $decision.Complete -is [bool] -and -not $decision.Complete){
                            $pendingIds=@($decision.PendingProcessIds)
                            $live=@($job.ActiveProcessIds)
                            $matches=$live.Count -gt 0 -and $pendingIds.Count -eq $live.Count
                            foreach($id in $pendingIds){
                                if(($id -isnot [int] -and $id -isnot [long] -and $id -isnot [uint32] -and $id -isnot [uint64]) -or $id -le 0 -or $id -gt [uint32]::MaxValue -or $live -notcontains $id){$matches=$false;break}
                            }
                            if(@($pendingIds|Sort-Object -Unique).Count -ne $pendingIds.Count){$matches=$false}
                            if($matches -and $job.RootExited -and $job.RootExitCode -eq $expectedRootCode -and -not ($CancelPath -and [IO.File]::Exists($CancelPath)) -and $timer.Elapsed.TotalMinutes -lt $TimeoutMinutes){
                                return [pscustomobject]@{ExitCode=$expectedRootCode;TimedOut=$false;Cancelled=$false;TrackingWarning=$false;RestartRequired=$true}
                            }
                        }
                        if ($decision.Complete -is [bool] -and $decision.Complete -eq $true) {
                            $approved=@($decision.ApprovedProcessIds)
                            $valid=$approved.Count -gt 0
                            foreach ($id in $approved) {
                                if (($id -isnot [int] -and $id -isnot [long] -and $id -isnot [uint32] -and $id -isnot [uint64]) -or $id -le 0 -or $id -gt [uint32]::MaxValue) { $valid=$false;break }
                            }
                            if ($CancelPath -and [IO.File]::Exists($CancelPath)) { $cancelled=$true }
                            if ($valid -and -not $cancelled -and $timer.Elapsed.TotalMinutes -lt $TimeoutMinutes) {
                                $retained=$job.TryReleaseApproved([uint32[]]$approved,$CancelPath,$expectedRootCode)
                                if ($retained -ge 0) {
                                    return [pscustomobject]@{ExitCode=$expectedRootCode;TimedOut=$false;Cancelled=$false;TrackingWarning=$false;CompletedByEvidence=$true;RetainedRuntimeCount=$retained}
                                }
                            }
                        }
                    }
                } catch { # A probe error or malformed result must keep the original guard.
                }
            }
            Start-Sleep -Milliseconds 100
        }
        return [pscustomobject]@{ExitCode=$job.ExitCode;TimedOut=$false;Cancelled=$cancelled;TrackingWarning=$false}
    } finally { $job.Dispose() }
}
