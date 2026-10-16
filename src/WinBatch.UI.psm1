#requires -Version 5.1
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Get-WBDemoSnapshot {
    param([Parameter(Mandatory=$true)][string]$Root)
    # Demo is a direct, synthetic backend call: no worker, scan or installer process.
    Import-Module (Join-Path $Root 'src\WinBatch.System.psm1') -ErrorAction Stop -DisableNameChecking
    return (Get-WBSnapshot -Root $Root -Demo)
}
function Add-WBControl {
    param($Context,[string]$Name,$Control)
    $Control.Name=$Name; $Context.Controls[$Name]=$Control
    return $Control
}

function New-WBButton {
    param($Context,[string]$Name,[string]$Text,[int]$Width=112)
    $b=New-Object Windows.Forms.Button
    $b.Text=$Text; $b.Width=$Width; $b.Height=29; $b.Margin=New-Object Windows.Forms.Padding(3)
    return (Add-WBControl $Context $Name $b)
}

function Set-WBActivity {
    param($Context,[string]$Message)
    $Context.Controls.Activity.Text=$Message
}

function Update-WBFilter {
    param($Context,[switch]$SnapshotRefresh)
    if ($Context.Operation -ne 'None' -and -not $SnapshotRefresh) { return }
    $grid=$Context.Controls.Targets
    $null=$grid.EndEdit()
    # A current cell cannot be hidden. Keep the rows themselves (and their checks).
    $grid.CurrentCell=$null
    $query=$Context.Controls.Search.Text.Trim()
    foreach ($row in $grid.Rows) {
        $source=([string]$row.Cells['Evidence'].Value -split ' / ',2)[0]
        $fields=@([string]$row.Tag.Name,[string]$row.Tag.Publisher,[string]$row.Tag.Source,$source)
        $matches=[string]::IsNullOrEmpty($query)
        foreach ($field in $fields) {
            if ($field.IndexOf($query,[StringComparison]::OrdinalIgnoreCase) -ge 0) { $matches=$true;break }
        }
        $row.Visible=$matches
    }
    Update-WBAvailability $Context
}

function Clear-WBSelection {
    param($Context)
    if ($Context.Operation -ne 'None') { return }
    $null=$Context.Controls.Targets.EndEdit()
    foreach ($row in $Context.Controls.Targets.Rows) { $row.Cells['Selected'].Value=$false }
    foreach ($id in @('qq','wechat','sogou')) { $Context.Controls[('Install_'+$id)].Checked=$false }
    Update-WBAvailability $Context
}

function Update-WBAvailability {
    param($Context)
    $idle=$Context.Operation -eq 'None'
    $Context.Controls.Scan.Enabled=$idle
    $Context.Controls.ManualApps.Enabled=$idle
    $Context.Controls.Recover.Enabled=$idle -and -not $Context.Demo
    $Context.Controls.SilentOnly.Enabled=$idle
    $Context.Controls.Targets.Enabled=$idle -and $null -ne $Context.Snapshot
    $Context.Controls.Search.Enabled=$idle -and $null -ne $Context.Snapshot
    $Context.Controls.ClearSelection.Enabled=$idle -and $null -ne $Context.Snapshot
    $localPackages=$Context.Controls.LocalPackages.Checked
    $Context.Controls.LocalPackages.Enabled=$idle -and $null -ne $Context.Snapshot
    foreach ($id in @('qq','wechat','sogou')) {
        $Context.Controls[('Install_'+$id)].Enabled=$idle -and $null -ne $Context.Snapshot
        $Context.Controls[('Package_'+$id)].Enabled=$idle -and $null -ne $Context.Snapshot -and $localPackages
        $Context.Controls[('Browse_'+$id)].Enabled=$idle -and $null -ne $Context.Snapshot -and $localPackages
        $Context.Controls[('Package_'+$id)].Visible=$localPackages
        $Context.Controls[('Browse_'+$id)].Visible=$localPackages
        $Context.Controls[('AutoSource_'+$id)].Visible=-not $localPackages
        $Context.Controls[('Official_'+$id)].Enabled=$idle -and $null -ne $Context.Snapshot
    }
    $selectedCount=0;$visibleCount=0
    foreach ($row in $Context.Controls.Targets.Rows) {
        if ($row.Visible) { $visibleCount++ }
        if ($row.Cells['Selected'].Value -eq $true -and $row.Tag.Action -in @('AutoUninstall','ManualUninstall','AppxUninstall','Shortcut','PortableRemove')) { $selectedCount++ }
    }
    $Context.Controls.SelectionCount.Text=('已选 {0} 项 · 显示 {1}/{2}' -f $selectedCount,$visibleCount,$Context.Controls.Targets.Rows.Count)
    $hasSelection=$selectedCount -gt 0
    foreach ($id in @('qq','wechat','sogou')) { if ($Context.Controls[('Install_'+$id)].Checked) { $hasSelection=$true } }
    $Context.Controls.Execute.Enabled=$idle -and -not $Context.Demo -and $null -ne $Context.Snapshot -and $hasSelection -and -not $Context.Executed
    $Context.Controls.Cancel.Enabled=-not $idle -and -not $Context.CancelRequested
    $Context.Controls.Report.Enabled=$idle -and -not [string]::IsNullOrEmpty($Context.SessionPath)
}

function Set-WBSnapshot {
    param($Context,$Snapshot)
    if ($null -eq $Snapshot -or [string]::IsNullOrWhiteSpace([string]$Snapshot.Computer) -or [string]::IsNullOrWhiteSpace([string]$Snapshot.UserSid)) { throw '扫描报告缺少电脑或用户身份，不能用于执行。' }
    $Context.Snapshot=$Snapshot
    $Context.Controls.MachineUser.Text=('电脑：{0}    操作用户：{1}    扫描时间：{2}' -f $Snapshot.Computer,$Snapshot.User,$Snapshot.ScanTime)
    $grid=$Context.Controls.Targets; $grid.Rows.Clear()
    $actions=@{AutoUninstall='静默卸载';ManualUninstall='需手动';AppxUninstall='卸载商店应用';Review='无可用入口';Shortcut='移除快捷方式';PortableRemove='移除程序文件'}
    foreach ($target in @($Snapshot.Targets)) {
        if ($null -eq $target) { continue }
        $allowed=$target.Action -in @('AutoUninstall','ManualUninstall','AppxUninstall','Shortcut','PortableRemove')
        $selected=$false
        $actionText=$actions[[string]$target.Action]
        if (-not $actionText) { $actionText='未知方式（不可选）' }
        $sourceText=switch ([string]$target.Source) { 'Registry' {'已安装程序'} 'Appx' {'Windows应用'} 'Shortcut' {'快捷方式'} default {'待核实来源'} }
        $location=[string]$target.InstallLocation
        if($target.Action -eq 'PortableRemove'){$location=[IO.Path]::GetDirectoryName([string]$target.Record.TargetPath)}
        if (-not $location -and $target.Source -eq 'Shortcut' -and [IO.Path]::IsPathRooted([string]$target.Identity)) { $location=[IO.Path]::GetDirectoryName([string]$target.Identity) }
        if (-not $location) { $location='未登记目录（请人工核实）' }
        $index=$grid.Rows.Add([bool]$selected,[string]$target.Name,[string]$target.Version,[string]$target.Publisher,$actionText,[string]$target.Reason,($sourceText+' / '+$location))
        $row=$grid.Rows[$index]; $row.Tag=$target; $row.Cells['Selected'].ReadOnly=-not $allowed
        $row.Cells['Name'].ToolTipText=('产品标识：{0}; 来源：{1}; 身份：{2}; 目录：{3}; 指纹：{4}' -f $target.ProductId,$target.Source,$target.Identity,$target.InstallLocation,$target.Fingerprint)
        if ($null -ne $target.PSObject.Properties['Scope']) { $row.Cells['Name'].ToolTipText += '; 范围：'+[string]$target.Scope }
        if ($null -ne $target.PSObject.Properties['Risk'] -and $target.Risk) { $row.Cells['Name'].ToolTipText += '; 风险：'+(@($target.Risk) -join '；') }
        $row.Cells['Evidence'].ToolTipText=$row.Cells['Name'].ToolTipText
        if (-not $allowed) { $row.DefaultCellStyle.BackColor=[Drawing.Color]::FromArgb(245,242,232); $row.DefaultCellStyle.ForeColor=[Drawing.Color]::DimGray }
    }
    foreach ($id in @('qq','wechat','sogou')) {
        $entry=@($Snapshot.Installations | Where-Object { $_.Id -eq $id } | Select-Object -First 1)
        $state='Unknown'; $version='状态未知'; $url=''
        if ($entry.Count -gt 0) { $state=[string]$entry[0].State; $version=[string]$entry[0].Version; $url=[string]$entry[0].OfficialPage }
        $Context.Controls[('Install_'+$id)].Checked=$false
        $stateText=switch ($state) { 'Present' {'已存在'} 'Missing' {'未安装'} default {'状态待核实'} }
        $Context.Controls[('InstallState_'+$id)].Text=('{0}  {1}' -f $stateText,$version)
        $automatic=$entry.Count -gt 0 -and $null -ne $entry[0].PSObject.Properties['InstallMode'] -and $entry[0].InstallMode -eq 'Silent'
        $Context.Controls[('AutoSource_'+$id)].Text=switch($state){'Present'{'已存在，跳过安装'} 'Missing'{if($automatic){'自动下载 → 自动安装'}else{'自动下载 → 人工安装'}} default{'状态待核实，暂停安装'}}
        $Context.Controls[('Official_'+$id)].Tag=[pscustomobject]@{Id=$id;Url=$url}
    }
    $visibleWarnings=@($Snapshot.Warnings|Where-Object{$_ -notlike '扫描范围：*'})
    Set-WBActivity $Context ('扫描完成：{0} 个应用，请勾选要处理的项目。{1}' -f $grid.Rows.Count,($visibleWarnings -join '；'))
    Update-WBFilter $Context -SnapshotRefresh
}

function Get-WBExecutionRequest {
    param($Context)
    if ($Context.Demo) { throw '演示模式禁止执行。' }
    if ($Context.Operation -ne 'None' -or $null -eq $Context.Snapshot -or $Context.Executed) { throw '请先完成一次新的扫描并预览。' }
    $null=$Context.Controls.Targets.EndEdit()
    $targets=@()
    foreach ($row in $Context.Controls.Targets.Rows) {
        if ($row.Cells['Selected'].Value -eq $true -and $row.Tag.Action -in @('AutoUninstall','ManualUninstall','AppxUninstall','Shortcut','PortableRemove')) { $targets += [string]$row.Tag.Id }
    }
    $installs=@(); $paths=[ordered]@{}
    foreach ($id in @('qq','wechat','sogou')) {
        $path=''
        if($Context.Controls.LocalPackages.Checked){$path=$Context.Controls[('Package_'+$id)].Text.Trim()}
        $paths[$id]=$path
        if ($Context.Controls[('Install_'+$id)].Checked) {
            if ($path -and (-not (Test-Path -LiteralPath $path -PathType Leaf) -or [IO.Path]::GetExtension($path) -ine '.exe')) { throw ('请选择存在的 EXE 安装包，或留空自动从官方获取：'+$id) }
            $installs += $id
        }
    }
    if ($targets.Count -eq 0 -and $installs.Count -eq 0) { throw '尚未选择任何卸载、快捷方式或安装项目。' }
    if ([string]::IsNullOrWhiteSpace($Context.SnapshotPath)) { throw '缺少扫描报告路径，请重新扫描。' }
    [pscustomobject]@{
        Computer=[string]$Context.Snapshot.Computer;MachineId=[string]$Context.Snapshot.MachineId;UserSid=[string]$Context.Snapshot.UserSid
        TargetIds=@($targets | Select-Object -Unique);InstallIds=@($installs)
        PackagePaths=$paths;SilentOnly=[bool]$Context.Controls.SilentOnly.Checked;Confirmed=$true;SnapshotPath=$Context.SnapshotPath
    }
}

function New-WBSession {
    param($Context)
    $candidates=@((Join-Path $Context.Root 'logs'))
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { $candidates += Join-Path $env:LOCALAPPDATA 'USB-AppManager\logs' }
    foreach ($base in $candidates) {
        $session=Join-Path $base ((Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N'))
        try {
            $null=[IO.Directory]::CreateDirectory($session)
            $probe=Join-Path $session '.write-check'
            [IO.File]::WriteAllText($probe,'ok',(New-Object Text.UTF8Encoding($true)));[IO.File]::Delete($probe)
            $Context.SessionPath=$session; $Context.SnapshotPath=Join-Path $session 'scan.json'; $Context.StatusPath=Join-Path $session 'status.json'
            $Context.Controls.LogPath.Text='本次报告目录：'+$session
            return
        } catch {
            try { if ([IO.Directory]::Exists($session) -and [IO.Directory]::GetFileSystemEntries($session).Length -eq 0) { [IO.Directory]::Delete($session) } } catch { }
        }
    }
    throw '工具目录和本地日志目录均不可写，已停止操作。'
}

function ConvertTo-WBProcessArgument {
    param([string]$Value)
    # Quote a single argument according to Windows CommandLineToArgvW rules.
    return ('"'+[regex]::Replace([regex]::Replace($Value,'(\\*)"','$1$1\"'),'(\\+)$','$1$1')+'"')
}

function Start-WBChildProcess {
    param($Context,[ValidateSet('Scan','Run','Recover')][string]$Mode,[string]$RequestPath)
    $entry=Join-Path $Context.Root 'WinBatch.ps1'
    if (-not (Test-Path -LiteralPath $entry -PathType Leaf)) { throw ('找不到入口脚本：'+$entry) }
    if ($Mode -ne 'Scan' -and $Context.Demo) { throw '演示模式禁止执行。' }
    $arguments=@('-NoProfile','-STA','-ExecutionPolicy','Bypass','-File',(ConvertTo-WBProcessArgument $entry),'-Mode',$Mode)
    if ($Mode -eq 'Scan') {
        $arguments += @('-OutputPath',(ConvertTo-WBProcessArgument $Context.SnapshotPath))
        if ($Context.Demo) { $arguments += '-Demo' }
    } elseif($Mode -eq 'Run') { $arguments += @('-RequestPath',(ConvertTo-WBProcessArgument $RequestPath),'-OutputPath',(ConvertTo-WBProcessArgument $Context.StatusPath)) }
    else { $arguments += @('-OutputPath',(ConvertTo-WBProcessArgument $Context.StatusPath)) }
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $info.Arguments=$arguments -join ' ';$info.WorkingDirectory=$Context.Root;$info.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
    if ($Mode -in @('Run','Recover')) { $info.UseShellExecute=$true;$info.Verb='runas' }
    else { $info.UseShellExecute=$false;$info.CreateNoWindow=$true }
    $process=[Diagnostics.Process]::Start($info)
    if ($null -eq $process) { throw '无法启动后台进程。' }
    $Context.Process=$process;$Context.Operation=$Mode
    if ($Mode -eq 'Scan') { $Context.ScanLaunchCount++ }
    $Context.CancelRequested=$false;$Context.ExitPolls=0;$Context.LastStatus=$null
    $Context.Controls.Progress.Style=[Windows.Forms.ProgressBarStyle]::Marquee
    Update-WBAvailability $Context; $Context.Timer.Start()
}

function Start-WBScan {
    param($Context)
    if ($Context.Operation -ne 'None') { return }
    try {
        $Context.Snapshot=$null;$Context.Executed=$false;$Context.CloseWhenDone=$false;$Context.ReportPath=''
        $Context.Controls.Targets.Rows.Clear();$Context.Controls.Results.Items.Clear()
        New-WBSession $Context
        Set-WBActivity $Context '正在只读扫描；本阶段仅写入报告，不卸载、安装或下载软件。'
        Start-WBChildProcess $Context 'Scan'
    } catch { Set-WBActivity $Context ('扫描未启动：'+$_.Exception.Message);Update-WBAvailability $Context }
}

function Start-WBRecovery {
    param($Context)
    if($Context.Demo -or $Context.Operation -ne 'None'){return}
    try{
        $Context.Snapshot=$null;$Context.Executed=$true;$Context.Controls.Targets.Rows.Clear()
        $Context.Controls.Results.Items.Clear();New-WBSession $Context
        Start-WBChildProcess $Context 'Recover'
        Set-WBActivity $Context '正在检查残留执行状态；恢复后请重新扫描。'
    }catch{Set-WBActivity $Context ('未能恢复：'+$_.Exception.Message);Update-WBAvailability $Context}
}

function New-WBConfirmationDialog {
    param($Context,$Request)
    $dialog=New-Object Windows.Forms.Form
    $dialog.Text='确认执行';$dialog.ClientSize=New-Object Drawing.Size(760,460)
    $dialog.FormBorderStyle='FixedDialog';$dialog.MaximizeBox=$false;$dialog.MinimizeBox=$false
    $dialog.StartPosition='CenterParent';$dialog.ShowInTaskbar=$false
    $dialog.Font=$Context.Form.Font;$dialog.AutoScaleMode='Dpi'
    $layout=New-Object Windows.Forms.TableLayoutPanel
    $layout.Dock='Fill';$layout.Padding=New-Object Windows.Forms.Padding(12)
    $layout.ColumnCount=1;$layout.RowCount=4
    foreach ($height in @(52,0,64,38)) {
        if ($height -eq 0) { $null=$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100))) }
        else { $null=$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,$height))) }
    }
    $dialog.Controls.Add($layout)
    $summary=New-Object Windows.Forms.Label
    $summary.Dock='Fill';$summary.TextAlign='MiddleLeft'
    $summary.Text=("电脑：{0}    用户：{1}`r`n处理 {2} 项，安装 {3} 项（包含搜索隐藏的选择）" -f $Request.Computer,$Context.Snapshot.User,$Request.TargetIds.Count,$Request.InstallIds.Count)
    $layout.Controls.Add($summary,0,0)
    $items=New-Object Windows.Forms.DataGridView
    $items.Name='PlanItems';$items.Dock='Fill';$items.ReadOnly=$true
    $items.AllowUserToAddRows=$false;$items.AllowUserToDeleteRows=$false;$items.AllowUserToResizeRows=$false
    $items.RowHeadersVisible=$false;$items.AutoGenerateColumns=$false;$items.ScrollBars='Both'
    $items.AutoSizeColumnsMode='Fill';$items.AutoSizeRowsMode='AllCells';$items.DefaultCellStyle.WrapMode='True'
    $items.BackgroundColor=[Drawing.SystemColors]::Window;$items.SelectionMode='FullRowSelect'
    foreach ($spec in @(@('Action','操作',18,110),@('Name','应用名称',42,240),@('Risk','风险提示',40,230))) {
        $column=New-Object Windows.Forms.DataGridViewTextBoxColumn
        $column.Name=$spec[0];$column.HeaderText=$spec[1];$column.FillWeight=$spec[2];$column.MinimumWidth=$spec[3];$column.SortMode='NotSortable'
        $null=$items.Columns.Add($column)
    }
    $actions=@{AutoUninstall='卸载';ManualUninstall='人工卸载';AppxUninstall='卸载商店应用';Shortcut='移除快捷方式';PortableRemove='移除程序文件'}
    foreach ($target in @($Context.Snapshot.Targets)) {
        if ($null -eq $target -or $Request.TargetIds -notcontains [string]$target.Id) { continue }
        $risk=''
        if ($null -ne $target.PSObject.Properties['Risk']) { $risk=@($target.Risk) -join '；' }
        if($target.Action -eq 'PortableRemove'){$risk=[string]$target.Reason}
        $actionText=$actions[[string]$target.Action]
        if($Request.PSObject.Properties['SilentOnly'] -and $Request.SilentOnly -and $target.Action -eq 'ManualUninstall'){$actionText='跳过（无法静默）'}
        $index=$items.Rows.Add($actionText,[string]$target.Name,$risk)
        $items.Rows[$index].Cells['Name'].ToolTipText=[string]$target.Name
        if ($risk) { $items.Rows[$index].Cells['Risk'].Style.ForeColor=[Drawing.Color]::Firebrick;$items.Rows[$index].Cells['Risk'].ToolTipText=$risk }
    }
    $names=@{qq='QQ';wechat='微信';sogou='搜狗高速浏览器'}
    foreach ($id in $Request.InstallIds) { $null=$items.Rows.Add('安装',$names[$id],'') }
    $layout.Controls.Add($items,0,1)
    $help=New-Object Windows.Forms.Label
    $help.Dock='Fill';$help.TextAlign='MiddleLeft'
    $help.Text="确认后申请管理员权限；先准备安装包，再处理勾选项并复查。`r`n厂商窗口请保留个人数据、取消附加安装。安装包默认从官网获取并校验。`r`n不自动重启；取消会等待当前操作结束。"
    $layout.Controls.Add($help,0,2)
    $buttons=New-Object Windows.Forms.FlowLayoutPanel
    $buttons.Dock='Fill';$buttons.FlowDirection='RightToLeft';$buttons.WrapContents=$false
    $cancel=New-Object Windows.Forms.Button
    $cancel.Text='返回';$cancel.Width=100;$cancel.Height=29;$cancel.DialogResult='No'
    $confirm=New-Object Windows.Forms.Button
    $confirm.Text='确认执行';$confirm.Width=110;$confirm.Height=29;$confirm.DialogResult='Yes'
    $buttons.Controls.Add($cancel);$buttons.Controls.Add($confirm);$layout.Controls.Add($buttons,0,3)
    $dialog.AcceptButton=$cancel;$dialog.CancelButton=$cancel
    return $dialog
}

function Show-WBExecutionConfirmation {
    param($Context,$Request)
    $dialog=New-WBConfirmationDialog $Context $Request
    try { return $dialog.ShowDialog($Context.Form) } finally { $dialog.Dispose() }
}

function Start-WBExecution {
    param($Context)
    if ($Context.Demo -or $Context.Operation -ne 'None') { return }
    try {
        $request=Get-WBExecutionRequest $Context
        $answer=Show-WBExecutionConfirmation $Context $request
        if ($answer -ne [Windows.Forms.DialogResult]::Yes) { Set-WBActivity $Context '已取消确认，未执行任何变更。';return }
        $requestPath=Join-Path $Context.SessionPath 'request.json'
        [IO.File]::WriteAllText($requestPath,($request | ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding($true)))
        Start-WBChildProcess $Context 'Run' $requestPath
        $Context.Executed=$true
        Set-WBActivity $Context '正在执行；如有厂商窗口请按提示完成。请求取消会在当前操作结束后停止。'
    } catch { Set-WBActivity $Context ('未开始执行：'+$_.Exception.Message);Update-WBAvailability $Context }
}

function Request-WBCancellation {
    param($Context)
    if ($Context.Operation -eq 'None' -or $Context.CancelRequested) { return }
    try {
        [IO.File]::WriteAllText((Join-Path $Context.SessionPath 'cancel.flag'),(Get-Date).ToString('o'),(New-Object Text.UTF8Encoding($true)))
        $Context.CancelRequested=$true
        if ($Context.Operation -eq 'Run') { Set-WBActivity $Context '已请求取消：等待当前操作返回，在操作之间停止；不会强杀安装器。' }
        else { Set-WBActivity $Context '已请求取消；只读扫描进程结束前请稍候。' }
        Update-WBAvailability $Context
    } catch { Set-WBActivity $Context ('取消标记写入失败，请等待并重试：'+$_.Exception.Message) }
}

function Set-WBRunStatus {
    param($Context,$Status)
    $Context.LastStatus=$Status
    $Context.Controls.Progress.Style=[Windows.Forms.ProgressBarStyle]::Continuous
    $percent=0.0
    if ([double]::TryParse([string]$Status.Percent,[ref]$percent)) { $Context.Controls.Progress.Value=[int][Math]::Max(0,[Math]::Min(100,$percent)) }
    $message=[string]$Status.Message
    if ($Status.Error) { $message += '  错误：'+[string]$Status.Error }
    if ($Context.CancelRequested) { $message += '（已请求取消，等待当前操作结束）' }
    $stateText=switch ($Status.State) { 'Running' {'进行中'} 'Completed' {'批次已结束'} 'Failed' {'已停止 / 请查看原因'} 'Cancelled' {'已取消'} default {[string]$Status.State} }
    Set-WBActivity $Context ('[{0}] {1}' -f $stateText,$message)
    $Context.Controls.Results.Items.Clear()
    foreach ($result in @($Status.Results)) {
        if ($null -eq $result) { continue }
        $name=[string]$result.Name;if (-not $name) { $name=[string]$result.Product };if (-not $name) { $name=[string]$result.Id }
        $state=[string]$result.State;if (-not $state) { $state=[string]$result.Status }
        $detail=[string]$result.Message;if (-not $detail) { $detail=[string]$result.Details };if (-not $detail) { $detail=[string]$result.Reason }
        if ($result.PID) { $name='PID '+[string]$result.PID;$state=[string]$result.Kind;$detail=[string]$result.Path }
        if ($result.Error) { $detail += ' '+[string]$result.Error }
        if (-not $detail) { $detail=$result | ConvertTo-Json -Compress -Depth 5 }
        $item=New-Object Windows.Forms.ListViewItem($name)
        $null=$item.SubItems.Add($state);$null=$item.SubItems.Add($detail);$null=$Context.Controls.Results.Items.Add($item)
    }
    if ($Status.ReportPath) { $Context.ReportPath=[string]$Status.ReportPath;$Context.Controls.LogPath.Text='报告：'+$Context.ReportPath }
}

function Complete-WBOperation {
    param($Context,[string]$Message)
    $Context.Timer.Stop()
    if ($null -ne $Context.Process) { $Context.Process.Dispose();$Context.Process=$null }
    $Context.Operation='None';$Context.Controls.Progress.Style=[Windows.Forms.ProgressBarStyle]::Continuous
    if ($Message) { Set-WBActivity $Context $Message }
    Update-WBAvailability $Context
    if ($Context.CloseWhenDone) { $Context.Form.Close() }
}

function Resolve-WBCloseChoice {
    param($Context,$EventArgs,[Windows.Forms.DialogResult]$Answer)
    if ($Answer -ne [Windows.Forms.DialogResult]::Yes) { return }
    # MessageBox pumps timer events. Recheck after confirmation rather than
    # relying on the operation state from before the dialog was displayed.
    if ($Context.Operation -eq 'None') { $EventArgs.Cancel=$false;return }
    Request-WBCancellation $Context
    if ($Context.CancelRequested) { $Context.CloseWhenDone=$true }
}

function Invoke-WBPoll {
    param($Context)
    if ($Context.Operation -eq 'None' -or $null -eq $Context.Process) { return }
    try {
        $exited=$Context.Process.HasExited
        if ($Context.Operation -eq 'Scan') {
            if (-not $exited) { return }
            if ($Context.CancelRequested) {
                $Context.Snapshot=$null;$Context.Controls.Targets.Rows.Clear()
                Complete-WBOperation $Context '只读扫描已取消；未执行任何变更。请重新扫描。'
                return
            }
            if ($Context.Process.ExitCode -ne 0) { throw ('扫描进程失败，退出码：'+$Context.Process.ExitCode) }
            $snapshot=[IO.File]::ReadAllText($Context.SnapshotPath,[Text.Encoding]::UTF8) | ConvertFrom-Json -ErrorAction Stop
            Set-WBSnapshot $Context $snapshot;Complete-WBOperation $Context '';return
        }
        if (Test-Path -LiteralPath $Context.StatusPath -PathType Leaf) {
            try {
                $status=[IO.File]::ReadAllText($Context.StatusPath,[Text.Encoding]::UTF8) | ConvertFrom-Json -ErrorAction Stop
                if ($null -ne $status -and $status.State -in @('Running','Completed','Failed','Cancelled')) { Set-WBRunStatus $Context $status }
            } catch { } # A partially replaced JSON file is retried on the next timer tick.
        }
        if ($exited) {
            if ($null -ne $Context.LastStatus -and $Context.LastStatus.State -in @('Completed','Failed','Cancelled')) {
                $final=$Context.LastStatus
                $stateText=switch ($final.State) { 'Completed' {'批次已结束'} 'Cancelled' {'已取消'} default {'已停止，请查看原因'} }
                $message=('{0}：{1}；结果 {2} 项。可打开报告目录查看详情。' -f $stateText,$final.Message,@($final.Results).Count)
                if ($final.Error) { $message += ' 错误：'+[string]$final.Error }
                if ($Context.Process.ExitCode -ne 0) { $message += ' 进程退出码：'+$Context.Process.ExitCode }
                Complete-WBOperation $Context $message
            } else {
                $Context.ExitPolls++
                if ($Context.ExitPolls -ge 6) { throw ('执行进程已退出，但没有有效的最终状态。退出码：'+$Context.Process.ExitCode+'；请查看报告目录。') }
            }
        }
    } catch {
        # Keep controls locked if an installer is still running.
        if ($Context.Process.HasExited) { Complete-WBOperation $Context ('操作失败：'+$_.Exception.Message) }
        else { Set-WBActivity $Context ('状态读取异常，仍在等待当前操作：'+$_.Exception.Message) }
    }
}

function Get-WBOfficialUri {
    param([string]$Id,[string]$Url)
    $uri=$null
    if (-not [Uri]::TryCreate($Url,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -notin @('http','https') -or $uri.UserInfo) { throw '官网链接无效，仅允许 HTTP(S) 厂商网页。' }
    $domains=@{qq=@('qq.com');wechat=@('qq.com','weixin.com','wechat.com');sogou=@('sogou.com')}
    $allowed=$false
    foreach ($domain in $domains[$Id]) { if ($uri.DnsSafeHost -ieq $domain -or $uri.DnsSafeHost.EndsWith('.'+$domain,[StringComparison]::OrdinalIgnoreCase)) { $allowed=$true } }
    if ($Id -eq 'sogou' -and $uri.DnsSafeHost -ieq 'sogou.browser.qq.com') { $allowed=$true }
    if (-not $allowed) { throw '官网链接不属于该软件的允许厂商域名。' }
    return $uri
}

function Open-WBOfficialPage {
    param($Context,[string]$Id,[string]$Url)
    $uri=Get-WBOfficialUri -Id $Id -Url $Url
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$uri.AbsoluteUri;$info.UseShellExecute=$true;$null=[Diagnostics.Process]::Start($info)
}

function New-WBWindowContext {
    param([Parameter(Mandatory=$true)][string]$Root,[switch]$Demo)
    [Windows.Forms.Application]::EnableVisualStyles()
    $form=New-Object Windows.Forms.Form
    $form.Text='U盘应用管理 v0.3.7 · 全部应用版'
    $form.Size=New-Object Drawing.Size(1080,720);$form.MinimumSize=New-Object Drawing.Size(1080,720)
    $form.StartPosition=[Windows.Forms.FormStartPosition]::CenterScreen
    $form.Font=New-Object Drawing.Font('Microsoft YaHei UI',9)
    $form.AutoScaleMode=[Windows.Forms.AutoScaleMode]::Dpi
    $c=[pscustomobject]@{
        Root=[IO.Path]::GetFullPath($Root);Demo=[bool]$Demo;Form=$form;Controls=@{}
        Snapshot=$null;SnapshotPath='';SessionPath='';StatusPath='';ReportPath=''
        Process=$null;Timer=$null;Operation='None';ScanLaunchCount=0
        CancelRequested=$false;CloseWhenDone=$false;Executed=$false;ExitPolls=0;LastStatus=$null
    }
    $form.Tag=$c
    $layout=New-Object Windows.Forms.TableLayoutPanel
    $layout.Dock='Fill';$layout.Padding=New-Object Windows.Forms.Padding(10,6,10,6)
    $layout.ColumnCount=1;$layout.RowCount=4
    foreach ($height in @(34,36,0,96)) {
        if ($height -eq 0) { $null=$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100))) }
        else { $null=$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,$height))) }
    }
    $form.Controls.Add($layout)
    $workspace=New-Object Windows.Forms.SplitContainer
    $workspace.Orientation='Horizontal';$workspace.Size=New-Object Drawing.Size(1040,500)
    $workspace.Dock='Fill';$workspace.SplitterWidth=8;$workspace.SplitterDistance=312
    $workspace.Panel1MinSize=240;$workspace.Panel2MinSize=140;$workspace.FixedPanel='Panel2'
    $workspace.BackColor=[Drawing.SystemColors]::ControlDark
    $workspace.Panel1.BackColor=[Drawing.SystemColors]::Control;$workspace.Panel2.BackColor=[Drawing.SystemColors]::Control
    $null=Add-WBControl $c 'ResultsSplitter' $workspace;$layout.Controls.Add($workspace,0,2)
    $appLayout=New-Object Windows.Forms.TableLayoutPanel
    $appLayout.Dock='Fill';$appLayout.ColumnCount=1;$appLayout.RowCount=2
    $null=$appLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)))
    $null=$appLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,164)))
    $workspace.Panel1.Controls.Add($appLayout)
    $machine=New-Object Windows.Forms.Label
    $machine.Dock='Fill';$machine.TextAlign='MiddleLeft';$machine.AutoEllipsis=$true
    $machine.Text='当前电脑：'+$env:COMPUTERNAME+'    当前用户：'+[Security.Principal.WindowsIdentity]::GetCurrent().Name+'    尚未扫描'
    $null=Add-WBControl $c 'MachineUser' $machine;$layout.Controls.Add($machine,0,0)
    $toolbar=New-Object Windows.Forms.FlowLayoutPanel
    $toolbar.Dock='Fill';$toolbar.WrapContents=$false
    $scan=New-WBButton $c 'Scan' '扫描全部应用' 122
    $scan.Add_Click({param($sender,$eventArgs) Start-WBScan $sender.FindForm().Tag})
    $toolbar.Controls.Add($scan)
    $report=New-WBButton $c 'Report' '打开报告目录' 128
    $report.Add_Click({
        param($sender,$eventArgs)
        $ctx=$sender.FindForm().Tag
        try {
            $path=$ctx.SessionPath
            if ($ctx.ReportPath -and (Test-Path -LiteralPath $ctx.ReportPath)) {
                if (Test-Path -LiteralPath $ctx.ReportPath -PathType Container) { $path=$ctx.ReportPath }
                else { $path=Split-Path -Parent $ctx.ReportPath }
            }
            if (-not (Test-Path -LiteralPath $path -PathType Container)) { throw '报告目录不存在。' }
            $info=New-Object Diagnostics.ProcessStartInfo
            $info.FileName=[IO.Path]::GetFullPath($path);$info.UseShellExecute=$true;$null=[Diagnostics.Process]::Start($info)
        } catch { Set-WBActivity $ctx ('无法打开报告：'+$_.Exception.Message) }
    })
    $toolbar.Controls.Add($report)
    $manual=New-WBButton $c 'ManualApps' '打开系统卸载列表' 156
    $manual.Add_Click({
        param($sender,$eventArgs)
        $ctx=$sender.FindForm().Tag
        if ($ctx.Operation -ne 'None') { return }
        try {
            $info=New-Object Diagnostics.ProcessStartInfo
            $info.FileName='ms-settings:appsfeatures';$info.UseShellExecute=$true
            $null=[Diagnostics.Process]::Start($info)
            Set-WBActivity $ctx '已打开系统卸载列表，可核对“需核实”项。完成后重新扫描；保留应用不可选。'
        } catch { Set-WBActivity $ctx ('无法打开系统卸载列表：'+$_.Exception.Message) }
    })
    $toolbar.Controls.Add($manual)
    $recover=New-WBButton $c 'Recover' '恢复执行状态' 116
    $recover.Add_Click({param($sender,$eventArgs) Start-WBRecovery $sender.FindForm().Tag})
    $toolbar.Controls.Add($recover)
    $silent=New-Object Windows.Forms.CheckBox
    $silent.Text='仅静默卸载';$silent.Checked=$false;$silent.AutoSize=$true;$silent.Margin=New-Object Windows.Forms.Padding(8,8,0,0)
    $silent.Add_CheckedChanged({param($sender,$eventArgs) if($sender.FindForm()){Update-WBAvailability $sender.FindForm().Tag}})
    $null=Add-WBControl $c 'SilentOnly' $silent;$toolbar.Controls.Add($silent)
    $mode=New-Object Windows.Forms.Label
    $mode.AutoSize=$true;$mode.Margin=New-Object Windows.Forms.Padding(12,8,0,0)
    if ($Demo) { $mode.Text='演示模式：始终禁止执行';$mode.ForeColor=[Drawing.Color]::Firebrick }
    else { $mode.Text='当前用户 + 系统 · 排除微软' }
    $null=Add-WBControl $c 'Scope' $mode
    $toolbar.Controls.Add($mode);$layout.Controls.Add($toolbar,0,1)
    $targetGroup=New-Object Windows.Forms.GroupBox
    $targetGroup.Text='全部应用';$targetGroup.Dock='Fill'
    $targetLayout=New-Object Windows.Forms.TableLayoutPanel
    $targetLayout.Dock='Fill';$targetLayout.ColumnCount=1;$targetLayout.RowCount=2
    $null=$targetLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,34)))
    $null=$targetLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)))
    $searchBar=New-Object Windows.Forms.TableLayoutPanel
    $searchBar.Dock='Fill';$searchBar.ColumnCount=4;$searchBar.RowCount=1
    foreach ($width in @(46,0,190,108)) {
        if ($width -eq 0) { $null=$searchBar.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent,100))) }
        else { $null=$searchBar.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Absolute,$width))) }
    }
    $searchLabel=New-Object Windows.Forms.Label
    $searchLabel.Text='搜索';$searchLabel.Dock='Fill';$searchLabel.TextAlign='MiddleLeft';$searchBar.Controls.Add($searchLabel,0,0)
    $search=New-Object Windows.Forms.TextBox
    $search.Dock='Fill';$search.Margin=New-Object Windows.Forms.Padding(3,5,3,3)
    $search.AccessibleName='搜索名称、发布者或来源'
    $search.Add_TextChanged({param($sender,$eventArgs) if ($sender.FindForm()) { Update-WBFilter $sender.FindForm().Tag }})
    $null=Add-WBControl $c 'Search' $search;$searchBar.Controls.Add($search,1,0)
    $count=New-Object Windows.Forms.Label
    $count.Dock='Fill';$count.TextAlign='MiddleCenter'
    $null=Add-WBControl $c 'SelectionCount' $count;$searchBar.Controls.Add($count,2,0)
    $clear=New-WBButton $c 'ClearSelection' '清空选择' 102
    $clear.Dock='Fill';$clear.Add_Click({param($sender,$eventArgs) Clear-WBSelection $sender.FindForm().Tag})
    $searchBar.Controls.Add($clear,3,0);$targetLayout.Controls.Add($searchBar,0,0)
    $grid=New-Object Windows.Forms.DataGridView
    $grid.Dock='Fill';$grid.AllowUserToAddRows=$false;$grid.AllowUserToDeleteRows=$false
    $grid.RowHeadersVisible=$false;$grid.AutoGenerateColumns=$false;$grid.MultiSelect=$false
    $grid.SelectionMode='FullRowSelect';$grid.AutoSizeColumnsMode='Fill';$grid.BackgroundColor=[Drawing.SystemColors]::Window
    $grid.AllowUserToResizeRows=$false;$grid.RowTemplate.Height=27
    $grid.ColumnHeadersHeightSizeMode='AutoSize';$grid.EditMode='EditOnEnter'
    $check=New-Object Windows.Forms.DataGridViewCheckBoxColumn
    $check.Name='Selected';$check.HeaderText='选择';$check.FillWeight=5;$check.MinimumWidth=44;$check.SortMode='NotSortable'
    $null=$grid.Columns.Add($check)
    foreach ($spec in @(@('Name','名称',19,145),@('Version','版本',8,62),@('Publisher','发布者',12,86),@('Action','处理方式',13,120),@('Reason','处理原因',24,170),@('Evidence','来源 / 产品目录',19,140))) {
        $column=New-Object Windows.Forms.DataGridViewTextBoxColumn
        $column.Name=$spec[0];$column.HeaderText=$spec[1];$column.FillWeight=$spec[2];$column.MinimumWidth=$spec[3];$column.ReadOnly=$true;$column.SortMode='NotSortable'
        $null=$grid.Columns.Add($column)
    }
    $grid.Add_CurrentCellDirtyStateChanged({param($sender,$eventArgs) if ($sender.IsCurrentCellDirty) { $null=$sender.CommitEdit([Windows.Forms.DataGridViewDataErrorContexts]::Commit) }})
    $grid.Add_CellValueChanged({param($sender,$eventArgs) if ($sender.FindForm()) { Update-WBAvailability $sender.FindForm().Tag }})
    $grid.Add_DataError({param($sender,$eventArgs) $eventArgs.ThrowException=$false})
    $null=Add-WBControl $c 'Targets' $grid;$targetLayout.Controls.Add($grid,0,1)
    $targetGroup.Controls.Add($targetLayout);$appLayout.Controls.Add($targetGroup,0,0)
    $installGroup=New-Object Windows.Forms.GroupBox
    $installGroup.Dock='Fill';$installGroup.Text='安装软件（自动下载，已安装则跳过）'
    $installLayout=New-Object Windows.Forms.TableLayoutPanel
    $installLayout.Dock='Fill';$installLayout.ColumnCount=5;$installLayout.RowCount=3
    foreach ($width in @(165,165,0,82,64)) {
        if ($width -eq 0) { $null=$installLayout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent,100))) }
        else { $null=$installLayout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Absolute,$width))) }
    }
    $names=@{qq='QQ';wechat='微信';sogou='搜狗高速浏览器'};$i=0
    foreach ($id in @('qq','wechat','sogou')) {
        $null=$installLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,33.333)))
        $cb=New-Object Windows.Forms.CheckBox
        $cb.Text=$names[$id];$cb.Dock='Fill'
        $cb.Add_CheckedChanged({param($sender,$eventArgs) if ($sender.FindForm()) { Update-WBAvailability $sender.FindForm().Tag }})
        $null=Add-WBControl $c ('Install_'+$id) $cb;$installLayout.Controls.Add($cb,0,$i)
        $label=New-Object Windows.Forms.Label
        $label.Text='等待扫描';$label.Dock='Fill';$label.TextAlign='MiddleLeft';$label.AutoEllipsis=$true
        $null=Add-WBControl $c ('InstallState_'+$id) $label;$installLayout.Controls.Add($label,1,$i)
        $box=New-Object Windows.Forms.TextBox
        $box.Dock='Fill';$box.Margin=New-Object Windows.Forms.Padding(3,5,3,3)
        $sourcePanel=New-Object Windows.Forms.Panel
        $sourcePanel.Dock='Fill';$sourcePanel.Margin=New-Object Windows.Forms.Padding(0)
        $sourcePanel.Controls.Add($box)
        $null=Add-WBControl $c ('Package_'+$id) $box
        $autoSource=New-Object Windows.Forms.Label
        $autoSource.Text='自动从官网下载 → 校验 → 安装';$autoSource.Dock='Fill';$autoSource.TextAlign='MiddleLeft'
        $null=Add-WBControl $c ('AutoSource_'+$id) $autoSource;$sourcePanel.Controls.Add($autoSource)
        $installLayout.Controls.Add($sourcePanel,2,$i)
        $browse=New-WBButton $c ('Browse_'+$id) '选择包…' 76
        $browse.Tag=$id;$browse.Dock='Fill'
        $browse.Add_Click({
            param($sender,$eventArgs)
            $ctx=$sender.FindForm().Tag
            if ($ctx.Operation -ne 'None' -or -not $ctx.Controls.LocalPackages.Checked) { return }
            $dialog=New-Object Windows.Forms.OpenFileDialog
            $dialog.Title='选择本地官方 EXE 安装包（执行前由后端校验签名）'
            $dialog.Filter='EXE 安装包 (*.exe)|*.exe';$dialog.CheckFileExists=$true;$dialog.Multiselect=$false
            try { if ($dialog.ShowDialog($ctx.Form) -eq [Windows.Forms.DialogResult]::OK) { $ctx.Controls[('Package_'+$sender.Tag)].Text=$dialog.FileName } } finally { $dialog.Dispose() }
        })
        $installLayout.Controls.Add($browse,3,$i)
        $link=New-Object Windows.Forms.LinkLabel
        $link.Text='官网';$link.Dock='Fill';$link.TextAlign='MiddleCenter';$link.Tag=[pscustomobject]@{Id=$id;Url=''}
        $link.Add_LinkClicked({param($sender,$eventArgs) $ctx=$sender.FindForm().Tag;try { Open-WBOfficialPage $ctx $sender.Tag.Id $sender.Tag.Url } catch { Set-WBActivity $ctx $_.Exception.Message }})
        $null=Add-WBControl $c ('Official_'+$id) $link;$installLayout.Controls.Add($link,4,$i)
        $i++
    }
    $installHost=New-Object Windows.Forms.TableLayoutPanel
    $installHost.Dock='Fill';$installHost.ColumnCount=1;$installHost.RowCount=3
    $null=$installHost.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,24)))
    $null=$installHost.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)))
    $null=$installHost.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,36)))
    $localOption=New-Object Windows.Forms.CheckBox
    $localOption.Text='高级选项：使用已有安装包（可选）';$localOption.Dock='Fill'
    $localOption.Add_CheckedChanged({param($sender,$eventArgs) if($sender.FindForm()){Update-WBAvailability $sender.FindForm().Tag}})
    $null=Add-WBControl $c 'LocalPackages' $localOption;$installHost.Controls.Add($localOption,0,0)
    $installHost.Controls.Add($installLayout,0,1)
    $help=New-Object Windows.Forms.Label
    $help.Dock='Fill';$help.TextAlign='MiddleLeft'
    $help.Text='按需勾选安装。如出现厂商窗口，请按提示完成并取消附加安装。'
    $null=Add-WBControl $c 'InstallHelp' $help;$installHost.Controls.Add($help,0,2)
    $installGroup.Controls.Add($installHost);$appLayout.Controls.Add($installGroup,0,1)
    $resultsGroup=New-Object Windows.Forms.GroupBox
    $resultsGroup.Dock='Fill';$resultsGroup.Text='执行结果 / 汇总（拖动上方分隔线调整高度）'
    $results=New-Object Windows.Forms.ListView
    $results.Dock='Fill';$results.View='Details';$results.FullRowSelect=$true;$results.GridLines=$true
    $null=$results.Columns.Add('项目',220);$null=$results.Columns.Add('结果',125);$null=$results.Columns.Add('详情',660)
    $null=Add-WBControl $c 'Results' $results;$resultsGroup.Controls.Add($results);$workspace.Panel2.Controls.Add($resultsGroup)
    $footer=New-Object Windows.Forms.TableLayoutPanel
    $footer.Dock='Fill';$footer.ColumnCount=2;$footer.RowCount=3
    $null=$footer.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent,100)))
    $null=$footer.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Absolute,275)))
    foreach ($h in @(32,24,34)) { $null=$footer.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,$h))) }
    $activity=New-Object Windows.Forms.Label
    $activity.Dock='Fill';$activity.AutoEllipsis=$true;$activity.TextAlign='MiddleLeft';$activity.Text='尚未扫描。点击“扫描全部应用”开始。'
    $null=Add-WBControl $c 'Activity' $activity;$footer.Controls.Add($activity,0,0);$footer.SetColumnSpan($activity,2)
    $progress=New-Object Windows.Forms.ProgressBar
    $progress.Dock='Fill';$progress.MarqueeAnimationSpeed=30
    $null=Add-WBControl $c 'Progress' $progress;$footer.Controls.Add($progress,0,1);$footer.SetColumnSpan($progress,2)
    $logLabel=New-Object Windows.Forms.Label
    $logLabel.Dock='Fill';$logLabel.AutoEllipsis=$true;$logLabel.TextAlign='MiddleLeft';$logLabel.Text='完成后可打开报告查看结果。'
    $null=Add-WBControl $c 'LogPath' $logLabel;$footer.Controls.Add($logLabel,0,2)
    $buttons=New-Object Windows.Forms.FlowLayoutPanel
    $buttons.Dock='Fill';$buttons.FlowDirection='RightToLeft';$buttons.WrapContents=$false
    $execute=New-WBButton $c 'Execute' '执行所选' 148
    $execute.Add_Click({param($sender,$eventArgs) Start-WBExecution $sender.FindForm().Tag})
    $cancel=New-WBButton $c 'Cancel' '请求取消' 112
    $cancel.Add_Click({param($sender,$eventArgs) Request-WBCancellation $sender.FindForm().Tag})
    $buttons.Controls.Add($execute);$buttons.Controls.Add($cancel)
    $footer.Controls.Add($buttons,1,2);$layout.Controls.Add($footer,0,3)
    $timer=New-Object Windows.Forms.Timer
    $timer.Interval=500
    # A CommandInfo keeps module-private poll resolution inside the closure.
    $pollCommand=Get-Command Invoke-WBPoll
    $timer.Add_Tick({ & $pollCommand $c }.GetNewClosure());$c.Timer=$timer
    $form.Add_FormClosing({
        param($sender,$eventArgs)
        $ctx=$sender.Tag
        if ($ctx.Operation -ne 'None') {
            $eventArgs.Cancel=$true
            $answer=[Windows.Forms.MessageBox]::Show($sender,'操作尚未结束。是否请求取消，并在当前操作安全结束后关闭？不会强杀安装器。','操作进行中',[Windows.Forms.MessageBoxButtons]::YesNo,[Windows.Forms.MessageBoxIcon]::Question,[Windows.Forms.MessageBoxDefaultButton]::Button2)
            Resolve-WBCloseChoice $ctx $eventArgs $answer
        }
    })
    Update-WBAvailability $c
    return $c
}

function Show-WBWindow {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Root,[switch]$Demo,[string]$SmokeTestPath)
    if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') { throw 'Windows 界面需要 STA；请使用 powershell.exe -STA 启动。' }
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { throw '项目根目录不存在。' }
    $context=New-WBWindowContext -Root $Root -Demo:($Demo -or -not [string]::IsNullOrWhiteSpace($SmokeTestPath))
    try {
        if (-not [string]::IsNullOrWhiteSpace($SmokeTestPath)) {
            $autoScan=$context.ScanLaunchCount -ne 0
            Set-WBSnapshot $context (Get-WBDemoSnapshot -Root $context.Root)
            $context.Form.CreateControl();$null=$context.Form.Handle;$context.Form.PerformLayout()
            # Hidden ancestors make CreateControl skip their children. Creating each
            # native handle recursively lets DrawToBitmap render without Show/ShowDialog.
            $pending=New-Object Collections.Queue
            $pending.Enqueue($context.Form)
            while ($pending.Count -gt 0) {
                $control=$pending.Dequeue()
                $control.CreateControl();$null=$control.Handle;$control.PerformLayout()
                foreach ($child in $control.Controls) { $pending.Enqueue($child) }
            }
            $bitmap=New-Object Drawing.Bitmap($context.Form.Width,$context.Form.Height)
            try {
                $context.Form.DrawToBitmap($bitmap,(New-Object Drawing.Rectangle(0,0,$bitmap.Width,$bitmap.Height)))
                $bitmap.Save([IO.Path]::GetFullPath($SmokeTestPath),[Drawing.Imaging.ImageFormat]::Png)
            } finally { $bitmap.Dispose() }
            [pscustomobject]@{
                Demo=$context.Demo;ExecuteEnabled=$context.Controls.Execute.Enabled
                AutoScanStarted=$autoScan;ScanLaunchCount=$context.ScanLaunchCount
                TargetCount=$context.Controls.Targets.Rows.Count;ProtectedCount=@($context.Snapshot.Protected).Count
                Controls=@($context.Controls.Keys | Sort-Object);Screenshot=[IO.Path]::GetFullPath($SmokeTestPath)
            } | ConvertTo-Json -Depth 5
        } else { $null=$context.Form.ShowDialog() }
    } finally { $context.Timer.Stop();$context.Timer.Dispose();$context.Form.Dispose() }
}
Export-ModuleMember -Function Show-WBWindow
