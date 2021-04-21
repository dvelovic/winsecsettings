


function main
{

    $finalHash = @()
    $finalHash += Get-SecPolInfo
    $finalHash += Get-SCHANNELInfo
    #$finalHash+= Get-MacAddressTypeInfo

   # $finalHash | convertto-Json -depth 3 | Out-File c:\temp\out.json

}


Function Get-SecPolInfo
{

    Function Parse-SecPol($CfgFile)
    {
        secedit /export /cfg "$CfgFile" | out-null
        $obj = New-Object psobject
        $index = 0
        $contents = Get-Content $CfgFile -raw
        [regex]::Matches($contents, "(?<=\[)(.*)(?=\])") | %{
            $title = $_
            [regex]::Matches($contents, "(?<=\]).*?((?=\[)|(\Z))", [System.Text.RegularExpressions.RegexOptions]::Singleline)[$index] | %{
                $section = new-object psobject
                $_.value -split "\r\n" | ?{ $_.length -gt 0 } | %{
                    $value = [regex]::Match($_, "(?<=\=).*").value
                    $name = [regex]::Match($_, ".*(?=\=)").value
                    $section | add-member -MemberType NoteProperty -Name $name.tostring().trim() -Value $value.tostring().trim() -ErrorAction SilentlyContinue | out-null
                }
                $obj | Add-Member -MemberType NoteProperty -Name $title -Value $section
            }
            $index += 1
        }
        return $obj
    }
    secedit /export /cfg c:\secpol.cfg
    $SecPool = Parse-SecPol -CfgFile C:\secpol.cfg

    $hash = @{
        AuditLogonEvents = ($SecPool."Event Audit").AuditLogonEvents
        EnableGuestAccount = ($SecPool."System Access").EnableGuestAccount
    }

    $hash
}



function Get-MacAddressTypeInfo
{
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $userName,

        [Parameter(Mandatory = $true)]
        [string]
        $userPassword,

        [Parameter(Mandatory = $true)]
        [string]
        $SCVMM
    )

    Begin
    {

        # Convert to SecureString
        [securestring]$secStringPassword = ConvertTo-SecureString $userPassword -AsPlainText -Force
        [pscredential]$cred = New-Object System.Management.Automation.PSCredential ($userName, $secStringPassword)

    }
    Process
    {

        $DynamicVMs = Invoke-Command $SCVMM -Credential $cred -ScriptBlock {
        `

            $AllVMS = Get-SCVirtualMachine -VMMServer localhost
            $DynamicVMs = @()

            # For each VM, check Virtual Network Adapters if Mac = Dynamic.
            foreach ($vm in $AllVMS)
            {

                $vmnics = $vm | Get-SCVirtualNetworkAdapter

                if ($vmnics.MACAddressType -eq "Dynamic")
                {
                    $DynamicVMs += $vm.Name
                }
            }
        }
    }

    End
    {

        $hash = @{ "MAC Address" = if ($env:COMPUTERNAME -in $DynamicVMs)
        {
            "Dynamic"
        }
        else
        {
            "Static"
        } }
        $hash
    }
}


function Get-SCHANNELInfo
{

    $enabled = @()
    $enabled += 4294967295
    $enabled += 1



    $hash = @{

        "OS Version" = (Get-WmiObject Win32_OperatingSystem).Caption
        "RDP Max Idle time" = if ((Get-ItemProperty "HKLM:SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services").MaxIdleTime -eq $null)
        {
            "Disabled"
        }
        else
        {
            (Get-ItemProperty "HKLM:SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services").MaxIdleTime
        }
        "SSL 2.0" = if (-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"))
        {
            "enabled"
        }
        elseif (((get-itemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client").Enabled) -in $enabled )
        {
            "enabled"
        }
        else
        {
            "disabled"
        }
        "SSL 3.0 Client" = if (-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"))
        {
            "enabled"
        }
        elseif (((get-itemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client").Enabled) -in $enabled )
        {
            "enabled"
        }
        else
        {
            "disabled"
        }
        "SSL 3.0 Server" = if (-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"))
        {
            "enabled"
        }
        elseif (((get-itemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\server").Enabled) -in $enabled )
        {
            "enabled"
        }
        else
        {
            "disabled"
        }
        "TLS 1.2 Client" = if (-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"))
        {
            "enabled"
        }
        elseif (((get-itemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client").Enabled) -in $enabled )
        {
            "enabled"
        }
        else
        {
            "disabled"
        }
        "TLS 1.2 Server" = if (-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"))
        {
            "enabled"
        }
        elseif (((get-itemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server").Enabled) -in $enabled )
        {
            "enabled"
        }
        else
        {
            "disabled"
        }
        "TLS 1.1 Client" = if (-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"))
        {
            "enabled"
        }
        elseif (((get-itemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client").Enabled) -in $enabled )
        {
            "enabled"
        }
        else
        {
            "disabled"
        }
        "TLS 1.1 Server" = if (-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"))
        {
            "enabled"
        }
        elseif (((get-itemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server").Enabled) -in $enabled )
        {
            "enabled"
        }
        else
        {
            "disabled"
        }
        "AES-128" = if (-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128"))
        {
            "enabled"
        }
        elseif (((get-itemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128").Enabled) -in $enabled )
        {
            "enabled"
        }
        else
        {
            "disabled"
        }
        "Triple DES" = if (-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168"))
        {
            "enabled"
        }
        elseif (((get-itemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168").Enabled) -in $enabled )
        {
            "enabled"
        }
        else
        {
            "disabled"
        }
        "DES" = if (-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Ciphers\DES 56/56"))
        {
            "enabled"
        }
        elseif (((get-itemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56").Enabled) -in $enabled )
        {
            "enabled"
        }
        else
        {
            "disabled"
        }
        "RC4 128/128" = if (-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Ciphers\RC4 128/128"))
        {
            "enabled"
        }
        elseif (((get-itemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128").Enabled) -in $enabled )
        {
            "enabled"
        }
        else
        {
            "disabled"
        }
        "RC4 40/128" = if (-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Ciphers\RC4 40/12"))
        {
            "enabled"
        }
        elseif (((get-itemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128").Enabled) -in $enabled )
        {
            "enabled"
        }
        else
        {
            "disabled"
        }
        "RC4 56/128" = if (-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Ciphers\RC4 56/128"))
        {
            "enabled"
        }
        elseif (((get-itemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128").Enabled) -in $enabled )
        {
            "enabled"
        }
        else
        {
            "disabled"
        }
        "RC4 64/128" = if (-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Ciphers\RC4 64/128"))
        {
            "enabled"
        }
        elseif (((get-itemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128").Enabled) -in $enabled )
        {
            "enabled"
        }
        else
        {
            "disabled"
        }
        "MD5" = if (-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Hashes\MD5"))
        {
            "enabled"
        }
        elseif (((get-itemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5").Enabled) -in $enabled )
        {
            "enabled"
        }
        else
        {
            "disabled"
        }
        "SHA" = if (-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Hashes\SHA"))
        {
            "enabled"
        }
        elseif (((get-itemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA").Enabled) -in $enabled )
        {
            "enabled"
        }
        else
        {
            "disabled"
        }
        "SHA256" = if (-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Hashes\SHA256"))
        {
            "enabled"
        }
        elseif (((get-itemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256").Enabled) -in $enabled )
        {
            "enabled"
        }
        else
        {
            "disabled"
        }
        "SHA384" = if (-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Hashes\SHA384"))
        {
            "enabled"
        }
        elseif (((get-itemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384").Enabled) -in $enabled )
        {
            "enabled"
        }
        else
        {
            "disabled"
        }
        "SHA512" = if (-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Hashes\SHA512"))
        {
            "enabled"
        }
        elseif (((get-itemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512").Enabled) -in $enabled )
        {
            "enabled"
        }
        else
        {
            "disabled"
        }

    }
    $hash


}
main
