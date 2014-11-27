<#
.SYNOPSIS
  Script to setup federation with AWS management console
  It must be run as Domain Admin and be run on the Windows Server 2012 R2 on Amazon EC2
  Basically, this script is along with the procedure of AWS security blog by Jeff Wierer, please read the blog if you need more details
     "Enabling Federation to AWS using Windows Active Directory, ADFS, and SAML 2.0"
     http://blogs.aws.amazon.com/security/post/Tx71TWXXJ3UI14/Enabling-Federation-to-AWS-using-Windows-Active-Directory-ADFS-and-SAML-2-0

.Options:
   -Init : Install features and create the Domain forest 
   -Config : Configure ADFS farm for federation with AWS management console
       1. Create users and groups on Active Directory
          users:
             awsmaster   : member of AWS-Admin and AWS-RO 
             awsadmin    : member of AWS-Admin 
             awsreadonly : member of AWS-RO 
             ADFSSVC     : service account of ADFS
          groups:
             AWS-Admin : the group will be mapped to the IAM role "ADFS-Admin"   
             AWS-RO    : the group will be mapped to the IAM role "ADFS-RO" 
       2. Install Windows SDK for using makecert.exe 
       3. Create certificate and import it to the machine
       4. Install ADFS farm
       5. Create the relyingPartyTrust and claims

.NOTES   
   Name: Configure-AWSFederation.ps1
   Author: Yuki Chiba (yukichib@amazon.com)
   Version: 1.0
   DateCreated: 2014-11-21
   DateUpdated: 2014-11-21
#>

Param(
    [String]$DomainName,
    [String]$DomainNetbiosName,
    [String]$SafeModeAdministratorPassword,
    [switch]$init,
    [switch]$config
) 

function init{
    Param([String]$WORKDIR,[String]$DomainName,[String]$DomainNetbiosName,[String]$SafeModeAdministratorPassword)
    Start-Transcript -Path ("$WORKDIR\init-log_"+$(Get-Date).ToString("yyyyMMdd_hhmmss")+".txt")
    Write-Output "DomainName: $DomainName"
    Write-Output "DomainNetbiosName: $DomainNetbiosName"
    Write-Output "SafeModeAdministratorPassword: $SafeModeAdministratorPassword"
    Install-WindowsFeature -Name AD-Domain-Services,ADFS-federation,GPMC -ComputerName localhost -IncludeManagementTools
    Import-Module ADDSDeployment
    Install-ADDSForest -DomainName $DomainName -ForestMode "Win2012" -DomainMode "Win2012" -SafeModeAdministratorPassword (convertto-securestring "$SafeModeAdministratorPassword" -asplaintext -force) -InstallDNS:$true -CreateDNSDelegation:$false -DomainNetbiosName $DomainNetbiosName -DatabasePath "C:\windows\NTDS" -LogPath "C:\windows\NTDS" -SysvolPath "C:\windows\Sysvol" -NoRebootOnCompletion -confirm:$false 
}

function auto_runconfig {
    Param([String]$DomainNetbiosName,[String]$AdministratorPassword,[String]$ScriptFile)
    net user Administrator $AdministratorPassword
    $RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    Set-itemproperty $RunOnceKey "ConfigFederation" ("C:\Windows\SysWOW64\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File $ScriptFile")
    $WinLogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-itemproperty $WinLogonKey "DefaultUserName" "Administrator" 
    Set-itemproperty $WinLogonKey "DefaultPassword" $AdministratorPassword
    Set-itemproperty $WinLogonKey "AutoAdminLogon" "1" 
    Set-itemproperty $WinLogonKey "AutoLogonCount" "1" 
    Set-itemproperty $WinLogonKey "DefaultDomainName" $DomainNetbiosName 
}


function config (){
    Param([String]$WORKDIR)
    Start-Transcript -Path ("$WORKDIR\config-log_"+$(Get-Date).ToString("yyyyMMdd_hhmmss")+".txt")

    $DomainName = (Get-ChildItem env: | ? {$_.Name -eq "USERDNSDOMAIN"}).Value
    $DomainNetbiosName =(Get-ChildItem env: | ? {$_.Name -eq "USERDOMAIN"}).Value
    $SAMLProviderName="ADFS"
    $FederationRolePrefix="ADFS-"
    $AdminGroupName="AWS-Admin"
    $ROGroupName="AWS-RO"
    $MasteruserName="awsmaster"
    $MasteruserPass="P@ssW0rd"
    $MasteruserEmail=$MasteruserName+"@"+$DomainName 
    $AdminuserName="awsadmin"
    $AdminuserPass="P@ssW0rd"
    $AdminuserEmail=$AdminuserName+"@"+$DomainName 
    $ROuserName="awsreadonly"
    $ROuserPass="P@ssW0rd"
    $ROuserEmail=$ROuserName+"@"+$DomainName 
    $ADFSUserName="ADFSSVC"
    $ADFSUserPass="P@ssW0rd"
    $ADFSdisplayName="aws-federation"
    $ADFSuser = $DomainNetbiosName +"\"+$ADFSUserName
    $PublicDNSHostname=Invoke-RestMethod http://169.254.169.254/latest/meta-data/public-hostname
    $CertificateADFSsubject=$PublicDNSHostname
    $PfxPassword="P@ssW0rd"
    $AWSAccountID=(Invoke-RestMethod http://169.254.169.254/latest/dynamic/instance-identity/document).accountId

    Write-Output "DomainName: $DomainName"
    Write-Output "DomainNetbiosName: $DomainNetbiosName"
    Write-Output "SAMLProviderName: $SAMLProviderName"
    Write-Output "FederationRolePrefix: $FederationRolePrefix"
    Write-Output "MasteruserName: $MasteruserName"
    Write-Output "MasteruserPass: $MasteruserPass"
    Write-Output "MasteruserEmail: $MasteruserEmail"
    Write-Output "AdminuserName: $AdminuserName"
    Write-Output "AdminuserPass: $AdminuserPass"
    Write-Output "AdminuserEmail: $AdminuserEmail"
    Write-Output "ROuserName: $ROuserName"
    Write-Output "ROuserPass: $ROuserPass"
    Write-Output "ROuserEmail: $ROuserEmail"
    Write-Output "ADFSUserName: $ADFSUserName"
    Write-Output "ADFSUserPass: $ADFSUserPass"
    Write-Output "ADFSdisplayName: $ADFSdisplayName"
    Write-Output "ADFSuser: $ADFSuser"
    Write-Output "CertificateADFSsubject: $CertificateADFSsubject"
    Write-Output "PfxPassword: $PfxPassword"
    Write-Output "AWSAccountID: $AWSAccountID"
    Write-Output "PublicDNSHostname: $PublicDNSHostname"

    #Create users and groups on Active Directory
    Write-Output "##########Create users and groups on Active Directory####################################################"
    Import-Module ActiveDirectory -ErrorAction Ignore
    while (!($?)) {
      Start-Sleep -s 5
      Import-Module ActiveDirectory -ErrorAction Ignore
    }

    Get-ADUser -Server localhost -Filter *  -ErrorAction Ignore
    while (!($?)) {
      Start-Sleep -s 10
      Get-ADUser -Server localhost -Filter *  -ErrorAction Ignore
    }

    New-ADUser -Name $MasteruserName -AccountPassword (convertto-securestring "$MasteruserPass" -asplaintext -force) -EmailAddress $MasteruserEmail -enabled $true -Server localhost -Verbose
    New-ADUser -Name $AdminuserName -AccountPassword (convertto-securestring "$AdminuserPass" -asplaintext -force) -EmailAddress $AdminuserEmail -enabled $true -Server localhost -Verbose
    New-ADUser -Name $ROuserName -AccountPassword (convertto-securestring "$ROuserPass" -asplaintext -force) -EmailAddress $ROuserEmail -enabled $true -Server localhost -Verbose
    New-ADUser -Name $ADFSUserName -AccountPassword (convertto-securestring "$ADFSUserPass" -asplaintext -force) -enabled $true -Server localhost -Verbose
    New-ADGroup -Name $AdminGroupName -GroupScope Global -Server localhost  -Verbose
    Add-ADGroupMember -Identity $AdminGroupName -Members @($MasteruserName,$AdminuserName) -Server localhost -Verbose
    New-ADGroup -Name $ROGroupName -GroupScope Global -Server localhost  -Verbose
    Add-ADGroupMember -Identity $ROGroupName -Members @($MasteruserName,$ROuserName) -Server localhost -Verbose

    #Install Windows SDK for using makecert.exe
    Write-Output "###########Install Windows SDK for using makecert.exe####################################################"
    Invoke-WebRequest http://www.microsoft.com/click/services/Redirect2.ashx?CR_EAC=300135395 -OutFile $WORKDIR\sdksetup.exe -Verbose
    Start-Process -FilePath "$WORKDIR\sdksetup.exe" -ArgumentList "/quiet /features OptionId.WindowsDesktopSoftwareDevelopmentKit /ceip off" -Wait -Verbose

    #Create certificate and import it to the machine
    Write-Output "###########Create certificate and import it to the machine###############################################"
    Start-Process -FilePath "C:\Program Files (x86)\Windows Kits\8.1\bin\x64\makecert.exe" -ArgumentList "-sky exchange -r -n CN=$CertificateADFSsubject -pe -a sha1 -len 2048 -ss My $WORKDIR\$CertificateADFSsubject.cer" -Wait -Verbose
    Import-Certificate -FilePath $WORKDIR\$CertificateADFSsubject.cer -CertStoreLocation cert:\localMachine\my -Verbose
    $SN= (dir Cert:\LocalMachine\My | where {$_.subject -match $CertificateADFSsubject -and $_.PrivateKey -eq $null}).SerialNumber
    Certutil.exe -p $PfxPassword -exportpfx $SN $WORKDIR\$CertificateADFSsubject.pfx NoChain
    Import-PfxCertificate -FilePath $WORKDIR\$CertificateADFSsubject.pfx -CertStoreLocation cert:\localMachine\my -Password  (convertto-securestring $PfxPassword -asplaintext -force) -Verbose 
    $ADFScertificate = dir Cert:\LocalMachine\My | where {$_.subject -match $CertificateADFSsubject -and $_.PrivateKey -ne $null}
    While ($ADFScertificate -eq $null){
      Start-Sleep 5
      Import-PfxCertificate -FilePath $WORKDIR\$CertificateADFSsubject.pfx -CertStoreLocation cert:\localMachine\my -Password  (convertto-securestring $PfxPassword -asplaintext -force) -Verbose 
      $ADFScertificate = dir Cert:\LocalMachine\My | where {$_.subject -match $CertificateADFSsubject -and $_.PrivateKey -ne $null}
    }
    $CertificateThumbprint =$ADFScertificate.Thumbprint
    Write-Output "CertificateThumbprint: $CertificateThumbprint"

    #Install SQL Server Express
    #Write-Output "###########Install SQL Server 2014 Express###############################################################"
    #$MSSQLDLURL="http://download.microsoft.com/download/E/A/E/EAE6F7FC-767A-4038-A954-49B8B05D04EB/Express%2064BIT/SQLEXPR_x64_ENU.exe"
    #Invoke-WebRequest $MSSQLDLURL -OutFile $WORKDIR\SQLEXPR_x64_ENU.exe -Verbose
    #Start-Process -FilePath "$WORKDIR\SQLEXPR_x64_ENU.exe" -ArgumentList "/q /ACTION=Install /FEATURES=SQL /INSTANCENAME=MSSQLSERVER /SQLSVCACCOUNT=$ADFSuser /SQLSVCPASSWORD=$ADFSUserPass /SQLSYSADMINACCOUNTS=$ADFSuser /AGTSVCACCOUNT='NT AUTHORITY\Network Service' /IACCEPTSQLSERVERLICENSETERMS" -Wait -Verbose

    #Install ADFS farm
    Write-Output "###########Install ADFS farm#############################################################################"
    $ADFSuserCredential = New-Object System.Management.Automation.PSCredential("$ADFSuser",(ConvertTo-SecureString -AsPlainText -Force "$ADFSUserPass"))
    Install-AdfsFarm -CertificateThumbprint $CertificateThumbprint -FederationServiceDisplayName $ADFSdisplayName -FederationServiceName $CertificateADFSsubject -ServiceAccountCredential $ADFSuserCredential -Verbose -ErrorAction Ignore
    #Install-AdfsFarm -CertificateThumbprint $CertificateThumbprint -FederationServiceDisplayName $ADFSdisplayName -FederationServiceName $CertificateADFSsubject -ServiceAccountCredential $ADFSuserCredential -SQLConnectionString "Data Source=localhost;Integrated Security=True" -Verbose -ErrorAction Ignore
    while (!($?)) {
        Start-Sleep -s 10
        Install-AdfsFarm -CertificateThumbprint $CertificateThumbprint -FederationServiceDisplayName $ADFSdisplayName -FederationServiceName $CertificateADFSsubject -ServiceAccountCredential $ADFSuserCredential -Verbose -ErrorAction Ignore
        #Install-AdfsFarm -CertificateThumbprint $CertificateThumbprint -FederationServiceDisplayName $ADFSdisplayName -FederationServiceName $CertificateADFSsubject -ServiceAccountCredential $ADFSuserCredential -SQLConnectionString "Data Source=localhost;Integrated Security=True" -Verbose -ErrorAction Ignore
    }

    setspn -a host/localhost adfssvc

    #Create the relyingPartyTrust and claims for federation with AWS management console
    Write-Output ""###########Create the relyingPartyTrust and claims for federation with AWS management console"###########"
    Add-ADFSRelyingPartyTrust -Name 'Amazon Web Services' -MetadataURL 'https://signin.aws.amazon.com/static/saml-metadata.xml' -MonitoringEnabled $true -AutoUpdateEnabled $true -Verbose
    $Claim_Nameid= New-AdfsClaimRuleSet -ClaimRule '@RuleTemplate = "MapClaims" @RuleName = "NameID" c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"] => issue(Type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, Value = c.Value, ValueType = c.ValueType, Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/format"] = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");'
    $Claim_Rolesessionname= New-AdfsClaimRuleSet -ClaimRule '@RuleTemplate = "LdapClaims" @RuleName = "RoleSessionName" c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => issue(store = "Active Directory", types = ("https://aws.amazon.com/SAML/Attributes/RoleSessionName"), query = ";mail;{0}", param = c.Value);'
    $Claim_Adgroup=New-AdfsClaimRuleSet -ClaimRule '@RuleName = "Get AD Group" c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => add(store = "Active Directory", types = ("http://temp/variable"), query = ";tokenGroups;{0}", param = c.Value);'
    $Claim_Iamrole=New-AdfsClaimRuleSet -ClaimRule ('@RuleName = "Roles" c:[Type == "http://temp/variable", Value =~ "(?i)^AWS-"] => issue(Type = "https://aws.amazon.com/SAML/Attributes/Role", Value = RegExReplace(c.Value, "AWS-", "arn:aws:iam::'+$AWSAccountID+':saml-provider/'+$SAMLProviderName+',arn:aws:iam::'+$AWSAccountID+':role/'+$FederationRolePrefix+'"));')
    $All_Claims = New-AdfsClaimRuleSet -ClaimRule  ($Claim_Nameid.ClaimRules + $Claim_Rolesessionname.ClaimRules + $Claim_Adgroup.ClaimRules + $Claim_Iamrole.ClaimRules)
    $Auth_Rule = '@RuleTemplate = "AllowAllAuthzRule" => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");'
    Set-AdfsRelyingPartyTrust -TargetName 'Amazon Web Services' -IssuanceTransformRules $All_Claims.ClaimRulesString -IssuanceAuthorizationRules $Auth_Rule -Verbose
    (Get-AdfsRelyingPartyTrust -Name 'Amazon Web Services').IssuanceTransformRules

}

function cleanup {
    $WinLogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Remove-itemproperty $WinLogonKey "DefaultUserName"
    Remove-itemproperty $WinLogonKey "DefaultPassword"
    Remove-itemproperty $WinLogonKey "AutoAdminLogon"
    Remove-itemproperty $WinLogonKey "AutoLogonCount" 
}

function main{
    Param([String]$WORKDIR,[String]$DomainName,[String]$DomainNetbiosName,[String]$SafeModeAdministratorPassword)
    if($init){
        if($DomainName -eq "" ){$DomainName="example.com"}
        if($DomainNetbiosName -eq ""){$DomainNetbiosName="example"}
        if($SafeModeAdministratorPassword -eq ""){$SafeModeAdministratorPassword="P@ssW0rd"}
        init -WORKDIR $WORKDIR -DomainName $DomainName -DomainNetbiosName $DomainNetbiosName -SafeModeAdministratorPassword $SafeModeAdministratorPassword
        #auto_runconfig ($DomainNetbiosName,$AdministratorPassword,$ScriptFile)
        Restart-Computer -Force
        exit
    }
    elseif ($config){
        config -WORKDIR $WORKDIR
        #cleanup
        exit
    }
    else{
        Write-Output "Usage: Configure-AWSFederation.ps1 [-init] [-config]"
    }
}


$WORKDIR="C:\aws-federation"
if (!(Test-Path $WORKDIR)) {
  mkdir $WORKDIR
}
main -WORKDIR $WORKDIR -DomainName $DomainName -DomainNetbiosName $DomainNetbiosName -SafeModeAdministratorPassword $SafeModeAdministratorPassword