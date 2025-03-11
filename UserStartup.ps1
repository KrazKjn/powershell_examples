<#
.SYNOPSIS
This script provides functions to start and modify processes with options for priority, affinity, and elevation.

.DESCRIPTION
Includes two key functions:
1. `Start-Process-Ext` - Starts a process with extended options like priority, affinity, and administrative elevation.
2. `Modify-Process` - Modifies an existing process's priority and affinity dynamically.

Supports dynamic validation, error handling, logging, and works on systems with multiple CPUs/cores.

.PARAMETER StopSqlServices
Stops SQL Services, else Modifies them.

#>

param (
    [switch]$StopSqlServices
)

# Retrieve system processor information and dynamically calculate the max CPU affinity value.
$sysInfo = Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors
$maxCPU = [math]::Pow(2, $sysInfo.NumberOfLogicalProcessors) - 1 # Max affinity bitmask (all processors)
$currentUser = [Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdministrator =$currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Function to modify priority and affinity of a running process.
function Modify-Process {
    <#
    .SYNOPSIS
    Modifies a process's priority and CPU affinity.

    .PARAMETER ProcessName
    The name of the target process.

    .PARAMETER ProcessPriority
    The desired priority class (Idle, BelowNormal, Normal, AboveNormal, High, RealTime).

    .PARAMETER ProcessorAffinity
    The CPU affinity bitmask defining which CPUs the process can run on.

    .EXAMPLE
    Modify-Process -ProcessName "notepad" -ProcessPriority High -ProcessorAffinity 3
    #>
    param (
        [ValidateNotNullOrEmpty()]
        [string]$ProcessName,

        [ValidateSet("Idle", "BelowNormal", "Normal", "AboveNormal", "High", "RealTime")]
        [System.Diagnostics.ProcessPriorityClass]$ProcessPriority,

        [int]$ProcessorAffinity
    )

    if ($ProcessorAffinity -lt 0 -or $ProcessorAffinity -gt $maxCPU) {
        throw "Invalid Processor Affinity Value: $ProcessorAffinity. Valid range is 0 to $maxCPU."
    }
    try {
        $processes = Get-Process -Name $ProcessName -ErrorAction Stop
        foreach ($process in $processes) {
            Write-Host "Target Process Found: $($process.Id) - $($process.ProcessName)"

            if ($isAdministrator) {
                # Modify priority if necessary.
                if ($process.PriorityClass -ne $ProcessPriority) {
                    Write-Host "   Changing Process Priority from: $($process.PriorityClass) to $ProcessPriority"
                    $process.PriorityClass = $ProcessPriority
                }

                # Modify CPU affinity if within valid range.
                if ($process.ProcessorAffinity -ne $ProcessorAffinity) {
                    Write-Host "   Changing Processor Affinity from: $($process.ProcessorAffinity) to $ProcessorAffinity"
                    $process.ProcessorAffinity = $ProcessorAffinity
                }
            }
        }
    } catch {
        Write-Warning "Error modifying process: $($_.Exception.Message)"
    }
}

# Function to start a process with extended options.
function Start-Process-Ext {
    <#
    .SYNOPSIS
    Starts a process with options for priority, CPU affinity, and elevation.

    .PARAMETER ExecutableName
    Full path to the executable to start.

    .PARAMETER ArgumentList
    Arguments to pass to the executable (optional).

    .PARAMETER ProcessPriority
    Desired priority class for the process.

    .PARAMETER ProcessorAffinity
    CPU affinity bitmask defining which CPUs the process can use.

    .PARAMETER AsAdmin
    Starts the process with administrative privileges (UAC prompt).

    .EXAMPLE
    Start-Process-Ext -ExecutableName "notepad.exe" -ProcessPriority High -ProcessorAffinity 3 -AsAdmin
    #>
    param (
        [ValidateNotNullOrEmpty()]
        [string]$ExecutableName,

        [string]$ArgumentList = $null,

        [ValidateSet("Idle", "BelowNormal", "Normal", "AboveNormal", "High", "RealTime")]
        [System.Diagnostics.ProcessPriorityClass]$ProcessPriority = [System.Diagnostics.ProcessPriorityClass]::Normal,

        [int]$ProcessorAffinity = $maxCPU,

        [switch]$AsAdmin
    )

    if ($ProcessorAffinity -lt 0 -or $ProcessorAffinity -gt $maxCPU) {
        throw "Invalid Processor Affinity Value: $ProcessorAffinity. Valid range is 0 to $maxCPU."
    }
    try {
        # Build arguments for Start-Process
        $arguments = @{}
        if ($AsAdmin -and -not $isAdministrator) { $arguments['Verb'] = 'RunAs' }
        if ($ArgumentList) { $arguments['ArgumentList'] = $ArgumentList }

        $ExecutableName = [Environment]::ExpandEnvironmentVariables($ExecutableName)

        # Start the process
        $process = Start-Process -FilePath $ExecutableName -PassThru @arguments
        Write-Host "Process Started: $($process.Id) - $($process.ProcessName)"

        if ($isAdministrator) {
            # Modify process attributes after starting.
            if ($process.PriorityClass -ne $ProcessPriority) {
                Write-Host "   Changing Process Priority to $ProcessPriority"
                $process.PriorityClass = $ProcessPriority
            }

            if ($process.ProcessorAffinity -ne $ProcessorAffinity) {
                Write-Host "   Changing Processor Affinity to $ProcessorAffinity"
                $process.ProcessorAffinity = $ProcessorAffinity
            }
        }
    } catch {
        Write-Warning "Error starting process: $($_.Exception.Message)"
    }
}

# Stop Services
if ($StopSqlServices) {
    Stop-Service -Name "MSSQL$SQLEXPRESS" -ErrorAction SilentlyContinue
    Stop-Service -Name "SQLWriter" -ErrorAction SilentlyContinue
}

# Example calls to Start-Process-Ext and Modify-Process functions
Start-Process-Ext -ExecutableName "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe" -ProcessPriority AboveNormal -ProcessorAffinity 1
Start-Process-Ext -ExecutableName "C:\Users\itworks\AppData\Local\Programs\Microsoft VS Code Insiders\Code - Insiders.exe" -ProcessorAffinity 1
Start-Process-Ext -ExecutableName "C:\Program Files\Notepad++\notepad++.exe" -ProcessPriority BelowNormal
Start-Process-Ext -ExecutableName "C:\Program Files\Beyond Compare 4\BCompare.exe" -ProcessPriority BelowNormal -AsAdmin
Start-Process-Ext -ExecutableName "C:\Users\itworks\AppData\Local\SourceTree\app-3.4.21\SourceTree.exe" -ProcessPriority BelowNormal
Start-Process-Ext -ExecutableName "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ArgumentList "--profile-directory=Default"
Start-Process-Ext -ExecutableName "%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe"
Start-Process-Ext -ExecutableName "%SystemRoot%\system32\cmd.exe"

# Modify the priority and affinity of specific running processes.
Modify-Process -ProcessName "SearchIndexer" -ProcessPriority BelowNormal -ProcessorAffinity 1
if (-not $StopSqlServices) {
    Modify-Process -ProcessName "sqlservr" -ProcessPriority BelowNormal -ProcessorAffinity 1
    Modify-Process -ProcessName "sqlwriter" -ProcessPriority BelowNormal -ProcessorAffinity 1
}