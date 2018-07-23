mkdir C:\Windows\LTSvc
copy * C:\Windows\LTSvc
reg add HKLM\Software\Labtech
reg add HKLM\Software\Labtech\Probe
reg add HKLM\Software\Labtech\Probe\Config
reg add HKLM\Software\Labtech\Probe\Commands
reg add HKLM\Software\Labtech\Probe\Status
sc create LTProbe binpath= "C:\Windows\LTSvc\LTProbe.exe" start= auto DisplayName= "LabTech Network Probe"