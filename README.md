# WMIShell
 Non-Persistent Remote Command Execution via WMI with NamedPipe or Windows Service

PowerShell tool to facilitate command-execution on remote targets with two methods.

1 - WMI with Windows Services
* Sets up a Windows Service on remote target used as a temporary data container
* Launches command via remote WMI
* Command stdout stored in file -> Windows Service description
* stdout retrieved via remote service read capabilities from WMI

2 - WMI Initialization of NamedPipe
* WMI used to launch NamedPipe server stream on remote target
* Commands sent from client to server and launched with all stdout returned via pipe

TODO
* Additional initialization mechanisms beyond WMI (Service, Task, etc)
* Better error handling
* Fileless Service Mode
* More options
