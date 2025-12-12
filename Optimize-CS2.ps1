#Requires -RunAsAdministrator
<#!
.SYNOPSIS
  Optimiza Windows 11 para gaming (CS2) priorizando latencia, input-lag y estabilidad.
  Incluye men? interactivo, respaldo y funci?n de restauraci?n completa.
.NOTES
  - No elimina componentes cr?ticos (Store, Windows Update, audio, red, drivers, Xbox).
  - Optimizaci?n agresiva pero segura; reversible con Restore-Defaults.
  - Compatible con Windows 11 22H2+.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$BackupPath = Join-Path $env:ProgramData 'CS2_Optimize_Backup.json'
$script:Backup = @{}

function ConvertTo-Hashtable {
    param([object]$InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $hash = @{}
        foreach ($k in $InputObject.Keys) { $hash[$k] = ConvertTo-Hashtable $InputObject[$k] }
        return $hash
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
        return @($InputObject | ForEach-Object { ConvertTo-Hashtable $_ })
    }
    if ($InputObject -is [psobject]) {
        $hash = @{}
        foreach ($p in $InputObject.PSObject.Properties) { $hash[$p.Name] = ConvertTo-Hashtable $p.Value }
        return $hash
    }
    return $InputObject
}

function Write-Action {
    param([string]$Message, [ConsoleColor]$Color = 'Cyan')
    Write-Host "[*] $Message" -ForegroundColor $Color
}

function Load-Backup {
    if (Test-Path $BackupPath) {
        $raw = Get-Content $BackupPath -Raw | ConvertFrom-Json
        $script:Backup = ConvertTo-Hashtable $raw
    } else {
        $script:Backup = @{}
    }
}

function Save-Backup {
    $script:Backup | ConvertTo-Json -Depth 8 | Set-Content -Path $BackupPath -Encoding ASCII
}

function Remember {
    param([string]$Section, [string]$Name, [object]$Value)
    if (-not $script:Backup.ContainsKey($Section)) { $script:Backup[$Section] = @{} }
    if (-not $script:Backup[$Section].ContainsKey($Name)) { $script:Backup[$Section][$Name] = $Value }
}

function New-RestorePointSafe {
    Write-Action "Creando punto de restauracion..."
    try {
        Checkpoint-Computer -Description "CS2_Optimize" -RestorePointType "MODIFY_SETTINGS"
        Write-Action "Punto de restauracion creado."
    } catch {
        Write-Action "No se pudo crear el punto de restauracion (tal vez deshabilitado). Continuando..." "Yellow"
    }
}

function Set-RegistryValueSafe {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )
    $regPath = $Path
    if ($Path -notmatch '^Registry::') { $regPath = "Registry::$Path" }
    $existing = (Get-ItemProperty -Path $regPath -Name $Name -ErrorAction SilentlyContinue).$Name
    Remember 'Registry' "$Path|$Name" $existing
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    $prop = Get-ItemProperty -Path $regPath -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $prop) {
        New-ItemProperty -Path $regPath -Name $Name -Value $Value -PropertyType $Type | Out-Null
    } else {
        Set-ItemProperty -Path $regPath -Name $Name -Value $Value | Out-Null
    }
}

function Restore-RegistryValues {
    if (-not $script:Backup.ContainsKey('Registry')) { return }
    foreach ($key in $script:Backup['Registry'].Keys) {
        $parts = $key -split '\\|', 2
        $path, $name = $parts[0], $parts[1]
        $value = $script:Backup['Registry'][$key]
        if ($null -eq $value) {
            Remove-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        } else {
            Set-ItemProperty -Path $path -Name $name -Value $value
        }
    }
}

function Set-ServiceSafe {
    param([string]$Name,[string]$StartupType,[bool]$StopNow = $false)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return }
    Remember 'Service' $Name $svc.StartType.ToString()
    Set-Service -Name $Name -StartupType $StartupType
    if ($StopNow -and $svc.Status -ne 'Stopped') {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    }
}

function Restore-Services {
    if (-not $script:Backup.ContainsKey('Service')) { return }
    foreach ($svc in $script:Backup['Service'].Keys) {
        $startType = $script:Backup['Service'][$svc]
        try {
            Set-Service -Name $svc -StartupType $startType
            if ($startType -ne 'Disabled') { Start-Service -Name $svc -ErrorAction SilentlyContinue }
        } catch {}
    }
}

function Disable-TaskSafe {
    param([string]$TaskPath)
    $task = Get-ScheduledTask -TaskPath $TaskPath.Substring(0, $TaskPath.LastIndexOf('\\') + 1) `
        -TaskName ($TaskPath.Split('\\')[-1]) -ErrorAction SilentlyContinue
    if ($null -eq $task) { return }
    Remember 'Tasks' $TaskPath $task.State
    Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath | Out-Null
}

function Restore-Tasks {
    if (-not $script:Backup.ContainsKey('Tasks')) { return }
    foreach ($t in $script:Backup['Tasks'].Keys) {
        $state = $script:Backup['Tasks'][$t]
        try {
            $taskName = $t.Split('\\')[-1]
            $taskPath = $t.Substring(0, $t.LastIndexOf('\\') + 1)
            if ($state -eq 'Ready' -or $state -eq 'Running') {
                Enable-ScheduledTask -TaskName $taskName -TaskPath $taskPath | Out-Null
            }
        } catch {}
    }
}

function Set-UltimatePlan {
    Write-Action "Creando/activando plan Ultimate Performance personalizado..."
    $currentPlan = (powercfg /GETACTIVESCHEME) 2>$null
    if ($currentPlan -match '\: ([a-f0-9\-]+)\s') { Remember 'Power' 'PreviousPlan' $Matches[1] }

    $existing = powercfg /L 2>$null | Select-String -Pattern '([a-f0-9\-]+)\s+\(CS2 Ultimate Performance\)'
    if ($existing) {
        $newGuid = $existing.Matches[0].Groups[1].Value
    } else {
        $dup = (powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61) 2>$null
        $newGuid = $dup | Select-String -Pattern 'GUID: ([a-f0-9\-]+)' | ForEach-Object { $_.Matches[0].Groups[1].Value }
        if (-not $newGuid) { $newGuid = 'e9a42b02-d5df-448d-aa00-03f14749eb61' }
        powercfg -changename $newGuid "CS2 Ultimate Performance" | Out-Null
    }

    powercfg -setactive $newGuid | Out-Null
    powercfg -setacvalueindex $newGuid SUB_VIDEO VIDEOIDLE 0 | Out-Null
    powercfg -setacvalueindex $newGuid SUB_SLEEP STANDBYIDLE 0 | Out-Null

    $active = (powercfg /GETACTIVESCHEME) 2>$null
    if ($active -notmatch $newGuid) {
        powercfg -setactive $newGuid | Out-Null
    }
}

function Restore-PowerPlan {
    if ($script:Backup.ContainsKey('Power') -and $script:Backup['Power'].ContainsKey('PreviousPlan')) {
        $guid = $script:Backup['Power']['PreviousPlan']
        Write-Action "Restaurando plan de energia previo ($guid)..."
        powercfg -setactive $guid | Out-Null
    }
}

Add-Type -Namespace Timer -Name NativeMethods -MemberDefinition @"
    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern uint NtSetTimerResolution(uint DesiredResolution, bool SetResolution, out uint CurrentResolution);
"@
function Set-TimerResolution {
    param([double]$Milliseconds = 0.5)
    $desired = [uint32]($Milliseconds * 10000)
    [uint32]$current = 0
    [Timer.NativeMethods]::NtSetTimerResolution($desired, $true, [ref]$current) | Out-Null
    Remember 'Timer' 'Requested' $current
    Write-Action "Timer resolution solicitada: $Milliseconds ms"
}

function Restore-TimerResolution {
    if ($script:Backup.ContainsKey('Timer') -and $script:Backup['Timer'].ContainsKey('Requested')) {
        [uint32]$current = 0
        [Timer.NativeMethods]::NtSetTimerResolution($script:Backup['Timer']['Requested'], $false, [ref]$current) | Out-Null
    }
}

function Restore-NetworkTweaks {
    if ($script:Backup.ContainsKey('NICPower')) {
        foreach ($nic in $script:Backup['NICPower'].Keys) {
            $pm = $script:Backup['NICPower'][$nic]
            try {
                Set-NetAdapterPowerManagement -Name $nic -WakeOnMagicPacket $pm.WakeOnMagicPacket -WakeOnPattern $pm.WakeOnPattern -DeviceSleepOnDisconnect $pm.DeviceSleepOnDisconnect -ReduceSpeedOnPowerDown $pm.ReduceSpeedOnPowerDown -ErrorAction SilentlyContinue
            } catch {}
        }
    }
    if ($script:Backup.ContainsKey('InterfaceMetric')) {
        foreach ($alias in $script:Backup['InterfaceMetric'].Keys) {
            $meta = $script:Backup['InterfaceMetric'][$alias]
            try {
                Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -AutomaticMetric $meta.AutomaticMetric -ErrorAction SilentlyContinue
                if (-not $meta.AutomaticMetric) {
                    Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -InterfaceMetric $meta.InterfaceMetric -ErrorAction SilentlyContinue
                }
            } catch {}
        }
    }
}

function Prompt-Restart {
    $resp = Read-Host "Reiniciar ahora? (S/N)"
    if ($resp -match '^[sS]') {
        Write-Action "Reiniciando en 5 segundos..." "Green"
        shutdown /r /t 5 | Out-Null
    } else {
        Write-Action "Reinicio pendiente. Hazlo despues para aplicar todo." "Yellow"
    }
}

function Optimize-SchedulerAndGPU {
    Write-Action "Ajustando scheduler multimedia y prioridad GPU..."
    Set-RegistryValueSafe 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' 'NetworkThrottlingIndex' 0xffffffff ([Microsoft.Win32.RegistryValueKind]::DWord)
    Set-RegistryValueSafe 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' 'SystemResponsiveness' 10
    $gamesKey = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
    Set-RegistryValueSafe $gamesKey 'GPU Priority' 8
    Set-RegistryValueSafe $gamesKey 'Priority' 6
    Set-RegistryValueSafe $gamesKey 'Scheduling Category' 'High' ([Microsoft.Win32.RegistryValueKind]::String)
    Set-RegistryValueSafe 'HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' 'HwSchMode' 2
    Set-RegistryValueSafe 'HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR' 'AllowGameDVR' 0
}

function Optimize-Network {
    Write-Action "Optimizando TCP global..."
    $tcp = Get-NetTCPSetting -SettingName InternetCustom -ErrorAction SilentlyContinue
    if ($null -eq $tcp) { Write-Action "InternetCustom no disponible, saltando ajustes TCP" "Yellow"; return }
    Remember 'TCPSetting' 'Internet' (Get-NetTCPSetting -SettingName Internet)
    Set-NetTCPSetting -SettingName InternetCustom -AutoTuningLevelLocal Normal -ScalingHeuristics Disabled -EcnCapability Disabled -Timestamps Disabled -MemoryPressureProtection Enabled -InitialCongestionWindow 10 -MinRto 300 | Out-Null
    Set-NetTCPSetting -SettingName Internet -AutoTuningLevelLocal Normal | Out-Null
    Write-Action "Desactivando ahorro de energía de adaptadores..."
    $adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -or $_.Status -eq 'Dormant' }
    foreach ($nic in $adapters) {
        $pm = Get-NetAdapterPowerManagement -Name $nic.Name
        Remember 'NICPower' $nic.Name $pm
        try {
            Set-NetAdapterPowerManagement -Name $nic.Name -WakeOnMagicPacket Enabled -WakeOnPattern Disabled -DeviceSleepOnDisconnect Disabled -ReduceSpeedOnPowerDown Disabled -ErrorAction Stop
        } catch {
            # Si alguna propiedad no existe en el adaptador, lo ignoramos
        }
    }
    Write-Action "Aplicando desactivaci?n de Nagle por interfaz..."
    $ifaces = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
    foreach ($nic in $ifaces) {
        $guid = ($nic | Get-NetAdapterAdvancedProperty -DisplayName 'Network Address' -ErrorAction SilentlyContinue).RegistryKeyword
        if (-not $guid) { $guid = (Get-WmiObject Win32_NetworkAdapter -Filter "Name='$($nic.Name)'" ).GUID }
        if (-not $guid) { continue }
        $path = "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid"
        Set-RegistryValueSafe $path 'TcpAckFrequency' 1
        Set-RegistryValueSafe $path 'TCPNoDelay' 1
    }
}

function Optimize-Wifi {
    Write-Action "Optimizando Wi-Fi (prioridad y sin ahorro de energ?a)..."
    $wifiAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -match 'Wireless|Wi-Fi|802\.11' }
    if (-not $wifiAdapters) { Write-Action "No se detectaron adaptadores Wi-Fi activos, saltando..." "Yellow"; return }
    foreach ($nic in $wifiAdapters) {
        try {
            $pm = Get-NetAdapterPowerManagement -Name $nic.Name -ErrorAction Stop
            Remember 'NICPower' $nic.Name $pm
            Set-NetAdapterPowerManagement -Name $nic.Name -WakeOnMagicPacket Enabled -WakeOnPattern Disabled -DeviceSleepOnDisconnect Disabled -ReduceSpeedOnPowerDown Disabled -ErrorAction SilentlyContinue
        } catch {}
        try {
            $iface = Get-NetIPInterface -InterfaceAlias $nic.InterfaceAlias -AddressFamily IPv4 -ErrorAction Stop
            Remember 'InterfaceMetric' $nic.InterfaceAlias ([pscustomobject]@{ InterfaceMetric = $iface.InterfaceMetric; AutomaticMetric = $iface.AutomaticMetric })
            Set-NetIPInterface -InterfaceAlias $nic.InterfaceAlias -AddressFamily IPv4 -InterfaceMetric 10 -AutomaticMetric Disabled -ErrorAction SilentlyContinue
        } catch {}
        try { netsh wlan set autoconfig enabled=yes interface="$($nic.Name)" | Out-Null } catch {}
    }
}

function Optimize-Network {
    Write-Action "Optimizando TCP global..."
    $tcp = Get-NetTCPSetting -SettingName InternetCustom -ErrorAction SilentlyContinue
    if ($null -eq $tcp) { Write-Action "InternetCustom no disponible, saltando ajustes TCP" "Yellow"; return }
    Remember 'TCPSetting' 'Internet' (Get-NetTCPSetting -SettingName Internet)
    Set-NetTCPSetting -SettingName InternetCustom -AutoTuningLevelLocal Normal -ScalingHeuristics Disabled -EcnCapability Disabled -Timestamps Disabled -MemoryPressureProtection Enabled -InitialCongestionWindow 10 -MinRto 300 | Out-Null
    Set-NetTCPSetting -SettingName Internet -AutoTuningLevelLocal Normal | Out-Null
    Write-Action "Desactivando ahorro de energia de adaptadores..."
    $adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -or $_.Status -eq 'Dormant' }
    foreach ($nic in $adapters) {
        $pm = Get-NetAdapterPowerManagement -Name $nic.Name
        Remember 'NICPower' $nic.Name $pm
        try {
            Set-NetAdapterPowerManagement -Name $nic.Name -WakeOnMagicPacket Enabled -WakeOnPattern Disabled -DeviceSleepOnDisconnect Disabled -ReduceSpeedOnPowerDown Disabled -ErrorAction Stop
        } catch {
            # Si alguna propiedad no existe en el adaptador, lo ignoramos
        }
    }
    Write-Action "Aplicando desactivacion de Nagle por interfaz..."
    $ifaces = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
    foreach ($nic in $ifaces) {
        $guid = ($nic | Get-NetAdapterAdvancedProperty -DisplayName 'Network Address' -ErrorAction SilentlyContinue).RegistryKeyword
        if (-not $guid) { $guid = (Get-WmiObject Win32_NetworkAdapter -Filter "Name='$($nic.Name)'" ).GUID }
        if (-not $guid) { continue }
        $path = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$guid"
        Set-RegistryValueSafe $path 'TcpAckFrequency' 1
        Set-RegistryValueSafe $path 'TCPNoDelay' 1
    }
}

function Optimize-Wifi {
    Write-Action "Optimizando Wi-Fi (prioridad y sin ahorro de energia)..."
    $wifiAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -match 'Wireless|Wi-Fi|802\.11' }
    if (-not $wifiAdapters) { Write-Action "No se detectaron adaptadores Wi-Fi activos, saltando..." "Yellow"; return }
    foreach ($nic in $wifiAdapters) {
        try {
            $pm = Get-NetAdapterPowerManagement -Name $nic.Name -ErrorAction Stop
            Remember 'NICPower' $nic.Name $pm
            Set-NetAdapterPowerManagement -Name $nic.Name -WakeOnMagicPacket Enabled -WakeOnPattern Disabled -DeviceSleepOnDisconnect Disabled -ReduceSpeedOnPowerDown Disabled -ErrorAction SilentlyContinue
        } catch {}
        try {
            $iface = Get-NetIPInterface -InterfaceAlias $nic.InterfaceAlias -AddressFamily IPv4 -ErrorAction Stop
            Remember 'InterfaceMetric' $nic.InterfaceAlias ([pscustomobject]@{ InterfaceMetric = $iface.InterfaceMetric; AutomaticMetric = $iface.AutomaticMetric })
            Set-NetIPInterface -InterfaceAlias $nic.InterfaceAlias -AddressFamily IPv4 -InterfaceMetric 10 -AutomaticMetric Disabled -ErrorAction SilentlyContinue
        } catch {}
        try { netsh wlan set autoconfig enabled=yes interface="$($nic.Name)" | Out-Null } catch {}
    }
}

function Optimize-Services {
    Write-Action "Desactivando servicios no cr?ticos para gaming..."
    $targets = @(
        @{ Name = 'Spooler'; Type = 'Disabled' },
        @{ Name = 'Fax'; Type = 'Disabled' },
        @{ Name = 'DiagTrack'; Type = 'Disabled' },
        @{ Name = 'RetailDemo'; Type = 'Disabled' },
        @{ Name = 'MapsBroker'; Type = 'Disabled' },
        @{ Name = 'WSearch'; Type = 'Disabled' }
    )
    foreach ($svc in $targets) { Set-ServiceSafe -Name $svc.Name -StartupType $svc.Type -StopNow $true }
}

function Clean-Tasks {
    Write-Action "Deshabilitando tareas programadas de telemetr?a..."
    $tasks = @(
        '\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser',
        '\\Microsoft\\Windows\\Application Experience\\ProgramDataUpdater',
        '\\Microsoft\\Windows\\Autochk\\Proxy',
        '\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator',
        '\\Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip',
        '\\Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector',
        '\\Microsoft\\Windows\\Feedback\\Siuf\\DmClient',
        '\\Microsoft\\Windows\\Feedback\\Siuf\\DmClientOnScenarioDownload',
        '\\Microsoft\\Windows\\Windows Error Reporting\\QueueReporting'
    )
    foreach ($t in $tasks) { Disable-TaskSafe -TaskPath $t }
}

function Remove-Bloatware {
    Write-Action "Quitando apps preinstaladas no necesarias (reversible con Restore)..."
    $blockList = @(
        'Microsoft.3DBuilder','Microsoft.BingNews','Microsoft.BingWeather','Microsoft.GetHelp','Microsoft.Getstarted','Microsoft.MicrosoftOfficeHub','Microsoft.MicrosoftSolitaireCollection','Microsoft.MixedReality.Portal','Microsoft.People','Microsoft.SkypeApp','Microsoft.Todos','Microsoft.WindowsAlarms','Microsoft.WindowsCommunicationsApps','Microsoft.WindowsFeedbackHub','Microsoft.ZuneMusic','Microsoft.ZuneVideo','Microsoft.YourPhone','MicrosoftTeams'
    )
    foreach ($pkg in $blockList) {
        $apps = Get-AppxPackage -Name $pkg -AllUsers -ErrorAction SilentlyContinue
        foreach ($app in $apps) {
            Remember 'Appx' $app.PackageFullName $app.InstallLocation
            Remove-AppxPackage -Package $app.PackageFullName -AllUsers -ErrorAction SilentlyContinue
        }
    }
}

function Restore-Appx {
    if (-not $script:Backup.ContainsKey('Appx')) { return }
    foreach ($pkg in $script:Backup['Appx'].Keys) {
        $loc = $script:Backup['Appx'][$pkg]
        if (Test-Path $loc) {
            try { Add-AppxPackage -Register (Join-Path $loc 'AppxManifest.xml') -DisableDevelopmentMode -ErrorAction SilentlyContinue } catch {}
        }
    }
}

function Optimize-ExplorerUI {
    Write-Action "Desactivando animaciones y acelerando men?s..."
    Set-RegistryValueSafe 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' 'VisualFXSetting' 2
    Set-RegistryValueSafe 'HKCU\Control Panel\Desktop' 'UserPreferencesMask' ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) ([Microsoft.Win32.RegistryValueKind]::Binary)
    Set-RegistryValueSafe 'HKCU\Control Panel\Desktop' 'MenuShowDelay' 10 ([Microsoft.Win32.RegistryValueKind]::String)
    Set-RegistryValueSafe 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarAnimations' 0
    Set-RegistryValueSafe 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'DisabledHotkeys' ''
}

function Restore-ExplorerUI { Restore-RegistryValues }

function Apply-FullOptimization {
    New-RestorePointSafe
    Load-Backup
    Optimize-SchedulerAndGPU
    Set-UltimatePlan
    Set-TimerResolution -Milliseconds 0.5
    Optimize-Network
    $wifiChoice = Read-Host "¿Aplicar optimizaci?n Wi-Fi adicional? (S/N)"
    if ($wifiChoice -match '^[sS]') { Optimize-Wifi }
    Optimize-Services
    Clean-Tasks
    Remove-Bloatware
    Optimize-ExplorerUI
    Save-Backup
    Write-Action "Optimizaci?n completa aplicada. Reinicia para que todo surta efecto." 'Green'
}

function Apply-LightOptimization {
    New-RestorePointSafe
    Load-Backup
    Optimize-SchedulerAndGPU
    Set-UltimatePlan
    Set-TimerResolution -Milliseconds 0.5
    Optimize-Network
    $wifiChoice = Read-Host "¿Aplicar optimizaci?n Wi-Fi adicional? (S/N)"
    if ($wifiChoice -match '^[sS]') { Optimize-Wifi }
    Optimize-ExplorerUI
    Save-Backup
    Write-Action "Optimizaci?n ligera aplicada. Reinicia para que todo surta efecto." 'Green'
}

function Restore-Defaults {
    Write-Action "Restaurando valores..."
    Load-Backup
    Restore-RegistryValues
    Restore-Services
    Restore-Tasks
    Restore-Appx
    Restore-PowerPlan
    Restore-TimerResolution
    Restore-NetworkTweaks
    Write-Action "Restauraci?n terminada. Reinicia para asegurar que todo vuelva a estado original." 'Green'
}

function Check-Status {
    Write-Host ""
    Write-Action "Chequeando estado actual..."
    $activePlan = (powercfg /GETACTIVESCHEME) 2>$null
    if ($activePlan -match '\: ([a-f0-9\-]+)\s+\((.+)\)') {
        Write-Host "Plan de energia activo: $($Matches[2]) ($($Matches[1]))"
    } else {
        Write-Host "Plan de energia activo: no detectado"
    }

    $hags = (Get-ItemProperty -Path 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers' -Name 'HwSchMode' -ErrorAction SilentlyContinue).HwSchMode
    $gameDvr = (Get-ItemProperty -Path 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR' -Name 'AllowGameDVR' -ErrorAction SilentlyContinue).AllowGameDVR
    $netThrottle = (Get-ItemProperty -Path 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile' -Name 'NetworkThrottlingIndex' -ErrorAction SilentlyContinue).NetworkThrottlingIndex
    $sysResp = (Get-ItemProperty -Path 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile' -Name 'SystemResponsiveness' -ErrorAction SilentlyContinue).SystemResponsiveness
    $gamesKey = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games'
    $gpuPriority = (Get-ItemProperty -Path $gamesKey -Name 'GPU Priority' -ErrorAction SilentlyContinue).'GPU Priority'
    $priority = (Get-ItemProperty -Path $gamesKey -Name 'Priority' -ErrorAction SilentlyContinue).Priority
    Write-Host ("HAGS (HwSchMode): {0} | GameDVR AllowGameDVR: {1}" -f $(if ($hags -ne $null) { $hags } else { 'no leído' }), $(if ($gameDvr -ne $null) { $gameDvr } else { 'no leído' }))
    Write-Host ("NetworkThrottlingIndex: {0} | SystemResponsiveness: {1} | GPU Priority/Priority: {2}/{3}" -f $(if ($netThrottle -ne $null) { $netThrottle } else { 'no leído' }), $(if ($sysResp -ne $null) { $sysResp } else { 'no leído' }), $(if ($gpuPriority -ne $null) { $gpuPriority } else { 'no leído' }), $(if ($priority -ne $null) { $priority } else { 'no leído' }))

    $tcpInternet = Get-NetTCPSetting -SettingName Internet -ErrorAction SilentlyContinue
    $tcpCustom = Get-NetTCPSetting -SettingName InternetCustom -ErrorAction SilentlyContinue
    if ($tcpInternet -and $tcpCustom) {
        Write-Host ("TCP Internet AutoTuning={0}, InternetCustom AutoTuning={1}, ScalingHeuristics={2}, ECN={3}, Timestamps={4}" -f $tcpInternet.AutoTuningLevelLocal, $tcpCustom.AutoTuningLevelLocal, $tcpCustom.ScalingHeuristics, $tcpCustom.EcnCapability, $tcpCustom.Timestamps)
    } else {
        Write-Host "TCP: no se pudo leer Internet/InternetCustom"
    }

    Write-Host "Servicios esperados en Disabled:"
    $svcTargets = @('Spooler','Fax','DiagTrack','RetailDemo','MapsBroker','WSearch')
    foreach ($svc in $svcTargets) {
        try {
            $info = Get-Service -Name $svc -ErrorAction Stop
            Write-Host (" - {0}: Startup={1}, Estado={2}" -f $svc, $info.StartType, $info.Status)
        } catch {
            Write-Host (" - {0}: no encontrado" -f $svc)
        }
    }

    Write-Host "Tareas de telemetria:"
    $tasks = @(
        '\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser',
        '\\Microsoft\\Windows\\Application Experience\\ProgramDataUpdater',
        '\\Microsoft\\Windows\\Autochk\\Proxy',
        '\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator',
        '\\Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip',
        '\\Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector',
        '\\Microsoft\\Windows\\Feedback\\Siuf\\DmClient',
        '\\Microsoft\\Windows\\Feedback\\Siuf\\DmClientOnScenarioDownload',
        '\\Microsoft\\Windows\\Windows Error Reporting\\QueueReporting'
    )
    foreach ($t in $tasks) {
        try {
            $taskName = $t.Split('\\')[-1]
            $taskPath = $t.Substring(0, $t.LastIndexOf('\\') + 1)
            $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
            Write-Host (" - {0}: {1}" -f $t, $task.State)
        } catch {
            Write-Host (" - {0}: no encontrada" -f $t)
        }
    }

    $wifiAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -match 'Wireless|Wi-Fi|802\.11' }
    if ($wifiAdapters) {
        Write-Host "Wi-Fi activo:"
        foreach ($nic in $wifiAdapters) {
            try {
                $iface = Get-NetIPInterface -InterfaceAlias $nic.InterfaceAlias -AddressFamily IPv4 -ErrorAction Stop
                Write-Host (" - {0}: InterfaceMetric={1}, AutomaticMetric={2}" -f $nic.InterfaceAlias, $iface.InterfaceMetric, $iface.AutomaticMetric)
            } catch {
                Write-Host (" - {0}: sin datos de metrica" -f $nic.InterfaceAlias)
            }
        }
    } else {
        Write-Host "Wi-Fi: no hay adaptadores activos"
    }

    $menuDelay = (Get-ItemProperty -Path 'HKCU\\Control Panel\\Desktop' -Name 'MenuShowDelay' -ErrorAction SilentlyContinue).MenuShowDelay
    $taskbarAnimations = (Get-ItemProperty -Path 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' -Name 'TaskbarAnimations' -ErrorAction SilentlyContinue).TaskbarAnimations
    $visualFX = (Get-ItemProperty -Path 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects' -Name 'VisualFXSetting' -ErrorAction SilentlyContinue).VisualFXSetting
    Write-Host ("UI: MenuShowDelay={0}, TaskbarAnimations={1}, VisualFXSetting={2}" -f $(if ($menuDelay -ne $null) { $menuDelay } else { 'no leído' }), $(if ($taskbarAnimations -ne $null) { $taskbarAnimations } else { 'no leído' }), $(if ($visualFX -ne $null) { $visualFX } else { 'no leído' }))

    $blockList = @(
        'Microsoft.3DBuilder','Microsoft.BingNews','Microsoft.BingWeather','Microsoft.GetHelp','Microsoft.Getstarted','Microsoft.MicrosoftOfficeHub','Microsoft.MicrosoftSolitaireCollection','Microsoft.MixedReality.Portal','Microsoft.People','Microsoft.SkypeApp','Microsoft.Todos','Microsoft.WindowsAlarms','Microsoft.WindowsCommunicationsApps','Microsoft.WindowsFeedbackHub','Microsoft.ZuneMusic','Microsoft.ZuneVideo','Microsoft.YourPhone','MicrosoftTeams'
    )
    $missing = @()
    foreach ($pkg in $blockList) {
        $apps = Get-AppxPackage -Name $pkg -AllUsers -ErrorAction SilentlyContinue
        if (-not $apps) { $missing += $pkg }
    }
    Write-Host ("Apps removidas (esperado si se aplico bloat cleanup): {0}" -f ($(if ($missing) { $missing -join ', ' } else { 'ninguna' })))

    Write-Host ""
    Write-Action "Indicadores clave arriba. Si ves CS2 Ultimate Performance activo, HAGS=2, GameDVR=0, servicios marcados en Disabled y tareas en Disabled, la optimizacion esta aplicada." "Green"
}

function Apply-FullOptimization {
    New-RestorePointSafe
    Load-Backup
    Optimize-SchedulerAndGPU
    Set-UltimatePlan
    Set-TimerResolution -Milliseconds 0.5
    Optimize-Network
    $wifiChoice = Read-Host "Aplicar optimizacion Wi-Fi adicional? (S/N)"
    if ($wifiChoice -match '^[sS]') { Optimize-Wifi }
    Optimize-Services
    Clean-Tasks
    Remove-Bloatware
    Optimize-ExplorerUI
    Save-Backup
    Write-Action "Optimizacion completa aplicada. Reinicia para que todo surta efecto." 'Green'
    Prompt-Restart
}

function Apply-LightOptimization {
    New-RestorePointSafe
    Load-Backup
    Optimize-SchedulerAndGPU
    Set-UltimatePlan
    Set-TimerResolution -Milliseconds 0.5
    Optimize-Network
    $wifiChoice = Read-Host "Aplicar optimizacion Wi-Fi adicional? (S/N)"
    if ($wifiChoice -match '^[sS]') { Optimize-Wifi }
    Optimize-ExplorerUI
    Save-Backup
    Write-Action "Optimizacion ligera aplicada. Reinicia para que todo surta efecto." 'Green'
    Prompt-Restart
}

function Restore-Defaults {
    Write-Action "Restaurando valores..."
    Load-Backup
    Restore-RegistryValues
    Restore-Services
    Restore-Tasks
    Restore-Appx
    Restore-PowerPlan
    Restore-TimerResolution
    Restore-NetworkTweaks
    Write-Action "Restauracion terminada. Reinicia para asegurar que todo vuelva a estado original." 'Green'
    Prompt-Restart
}

function Show-Menu {
    Write-Host ""
    Write-Host "=== Optimizador CS2 / Windows 11 ==="
    Write-Host "1) Aplicar optimizacion completa"
    Write-Host "2) Aplicar optimizacion ligera"
    Write-Host "3) Restaurar valores por defecto"
    Write-Host "4) Chequear estado actual"
    Write-Host "0) Salir"
    $choice = Read-Host "Selecciona una opcion"
    switch ($choice) {
        '1' { Apply-FullOptimization }
        '2' { Apply-LightOptimization }
        '3' { Restore-Defaults }
        '4' { Check-Status }
        default { Write-Action "Saliendo..." }
    }
}

Show-Menu
