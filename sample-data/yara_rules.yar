rule Suspicious_PowerShell_Encoded_Command
{
    meta:
        severity = "HIGH"
        description = "PowerShell encoded command usage"
        mitre = "T1059.001"
    strings:
        $ps1 = "powershell.exe"
        $enc1 = "EncodedCommand"
        $enc2 = "-EncodedCommand"
    condition:
        $ps1 and any of ($enc*)
}

rule Suspicious_AdminAccess_Policy
{
    meta:
        severity = "HIGH"
        description = "AdministratorAccess policy reference"
        mitre = "T1098"
    strings:
        $admin = "AdministratorAccess"
    condition:
        $admin
}
