# PowerShell script to check which users and groups have the "DS-Replication-Get-Changes-All" aka DCSync
# Will also check if you are in a forest or not, to retrieve correct user and group names from other domains if needed
# Just specify the domain name as parameter -> Check-DCSync-Principals -domainname YOUR.DOMAIN.COM

# Function to retrieve ACEs
function Get-ACEs($path) {
    $dn = (Get-ADComputer -Identity $path -Server $domainName).DistinguishedName
    $acl = (Get-ADObject -Identity $dn -Server $domainController -Properties nTSecurityDescriptor).nTSecurityDescriptor.Access
    $aces = $acl | Where-Object { $_.ObjectType -eq $extendedRightsCheck -and $_.AccessControlType -eq "Allow" }
    foreach ($ace in $aces) {
        $usersWithExtendedRights += $ace.IdentityReference
    }
}

# Function to determine object type from SID
function Get-ObjectTypeFromSID($sid) {
    if (Get-ADForest -Server $domainName) {
        $forest = Get-ADForest
        $domains = $forest.Domains
    } else {
        $domains = $domainName
    }

    foreach ($domain in $domains) {
        $adUser = Get-ADUser -Filter { Sid -eq $sid } -Server $domain -ErrorAction SilentlyContinue
        if ($adUser) {
            return [PSCustomObject]@{
                ObjectType = "User"
                Domain = $domain
            }
        }

        $adGroup = Get-ADGroup -Filter { Sid -eq $sid } -Server $domain -ErrorAction SilentlyContinue
        if ($adGroup) {
            return [PSCustomObject]@{
                ObjectType = "Group"
                Domain = $domain
            }
        }
    }

    return [PSCustomObject]@{
        ObjectType = "Unknown"
        Domain = "Unknown"
    }
}


function Check-DCSync-Principals ($domainName){ 
    $extendedRightsCheck = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" # This is the GUID used in the ACE for DS-Replication-Get-Changes-All -> https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
    $usersWithExtendedRights = @()
    # Get domain controller name
    $domainController = (Get-ADDomainController -Server $domainName).Name

    # Check default domain path
    $acl = (Get-ADObject -Filter "objectClass -eq 'domain'" -Server $domainController -Properties nTSecurityDescriptor).nTSecurityDescriptor.Access
    $aces = $acl | Where-Object { $_.ObjectType -eq $extendedRightsCheck -and $_.AccessControlType -eq "Allow" }
    foreach ($ace in $aces) {
        $usersWithExtendedRights += $ace.IdentityReference
    }

    # Check domain controller path
    Get-ACEs -Path $domainController

    # Remove duplicates
    $usersWithExtendedRights = $usersWithExtendedRights | Select-Object -Unique

    # Convert SIDs to usernames and determine object type
    $usersWithNames = foreach ($user in $usersWithExtendedRights) {
        #$sid = $user.SID
        $sidValue = $user.Value
        $objectType = Get-ObjectTypeFromSID $sidValue

        $name = "Unknown"
        $foundDomain = "Unknown"

        if ($objectType.ObjectType -eq "User") {
            $foundDomain = $objectType.Domain
            $name = (Get-ADUser -Identity $sidValue -Server $foundDomain).SamAccountName
        } elseif ($objectType.ObjectType -eq "Group") {
            $foundDomain = $objectType.Domain
            $name = (Get-ADGroup -Identity $sidValue -Server $foundDomain).Name
        }

        [PSCustomObject]@{
            SID = $sidValue
            Name = $name
            ObjectType = $objectType.ObjectType
            Domain = $foundDomain
        }
    }


    # Output the users and groups with extended rights
    $usersWithNames | Format-Table
}
