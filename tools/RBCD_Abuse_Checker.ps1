# Simple Script to check if RBCD could potentially be abused.
# For that we check the ms-DS-MachineAccountQuota value which determines how many computer objects can be added.
# We also check who can add computer accounts to the domain by querying the Default Domain Controllers Policy for the SeMachineAccountPrivilege attribute.
# This is not failsafe, especially the latter part.
# If run from a non domain joined system run it using runas:
# runas /netonly /user:DOMAIN.FQDN\USER.NAME powershell

# Proudly brought to you by LuemmelSec

# If in Domain context we can also just use AD PS cmdlets to query for the quota:
# Get-ADDomain | Select-Object -ExpandProperty DistinguishedName | Get-ADObject -Properties 'ms-DS-MachineAccountQuota'

$mySearcher = New-Object System.DirectoryServices.DirectorySearcher
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
 
# it is possible to specify manually a ldap search Path and provide credentials instead:
#$mySearcher.SearchRoot = "LDAP://DC=DOMAIN,DC=LOCAL",”USERNAME”,”PASSWORD”)
 
$mySearcher.SearchRoot = $objDomain
 
# search for object class "domain"
$mySearcher.Filter = "(& (objectClass=domain))"
$mySearcher.SearchScope = "sub"
 
# specifiy the attributes you would like to retrieve
$myAttributes = ("name", "ms-DS-MachineAccountQuota")
$mySearcher.PropertiesToLoad.AddRange($myAttributes)
 
$searchresult = $mySearcher.FindAll()
foreach ($i in $searchresult.Properties.PropertyNames){
    if($i -eq "ms-ds-machineaccountquota"){
    $MAQ= $searchresult.Properties.$i
    }
}

[xml]$GPOXML= Get-GPOReport -Name "Default Domain Controllers Policy" -ReportType Xml
foreach ($p in $GpoXml.GPO.Computer.ExtensionData.Extension.UserRightsAssignment) {
    if($p.name -eq "SeMachineAccountPrivilege"){
    $SeMachineAccountPrivilege = $p.InnerText
    }
}

if(($MAQ -gt 0) -and ($SeMachineAccountPrivilege -match "Authenti")){
    Write-Host "### RBCD abusable ### " -ForegroundColor Green
    Write-Host "Users / Groups: $($SeMachineAccountPrivilege -Split("SeMachineAccountPrivilege"))"
    Write-Host "Quota: $($MAQ)"
    }

if(($MAQ -lt 1) -or ($SeMachineAccountPrivilege -notmatch "Authenti")){
    Write-Host "### RBCD NOT abusable ### " -ForegroundColor Red
    Write-Host "Users / Groups: $($SeMachineAccountPrivilege -Split("SeMachineAccountPrivilege"))"
    Write-Host "Quota: $($MAQ)"
    }
