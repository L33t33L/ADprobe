Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Source https://go.microsoft.com/fwlink/?linkid=2125356

DISM /Online /Add-Capability /CapabilityName:Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 /LimitAccess /Source:https://go.microsoft.com/fwlink/?linkid=2125356
