################################################################################################
# Convert-UserAccountControlValues.ps1
# 
# AUTHOR: Fabian Müller, Microsoft Deutschland GmbH
# VERSION: 0.1.1
# DATE: 23.11.2012
#
# THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
# FITNESS FOR A PARTICULAR PURPOSE.
#
# This sample is not supported under any Microsoft standard support program or service. 
# The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
# implied warranties including, without limitation, any implied warranties of merchantability
# or of fitness for a particular purpose. The entire risk arising out of the use or performance
# of the sample and documentation remains with you. In no event shall Microsoft, its authors,
# or anyone else involved in the creation, production, or delivery of the script be liable for 
# any damages whatsoever (including, without limitation, damages for loss of business profits, 
# business interruption, loss of business information, or other pecuniary loss) arising out of 
# the use of or inability to use the sample or documentation, even if Microsoft has been advised 
# of the possibility of such damages.
################################################################################################
# Simply as a proof-of-concept, I have modified the script from https://gallery.technet.microsoft.com/Convert-userAccountControl-629eed01 to search for accounts that are configured for 
# settings such as:
# 
# •	Unconstrained Delegation
# •	Constrained Delegation (S4U2S)
# •	Password Never Expires
# •	Store Pwd Using Reversible Encryption
# •	Account is Sensitive and Cannot Be Delegated (this is a good setting for any privileged account)
# •	Use Only Kerberos DES Encryption Types for This Account
# •	Do Not Require Kerberos PreAuthentication
# 
# Does not require any elevated privileges.
# 
# THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
# FITNESS FOR A PARTICULAR PURPOSE.
# 
################################################################################################

Function Set-UserAccountControlValueTable
{
	# see http://support.microsoft.com/kb/305144/en-us
	
    $userAccountControlHashTable = New-Object HashTable
    $userAccountControlHashTable.Add("SCRIPT",1)
    $userAccountControlHashTable.Add("ACCOUNTDISABLE",2)
    $userAccountControlHashTable.Add("HOMEDIR_REQUIRED",8) 
    $userAccountControlHashTable.Add("LOCKOUT",16)
    $userAccountControlHashTable.Add("PASSWD_NOTREQD",32)
    $userAccountControlHashTable.Add("ENCRYPTED_TEXT_PWD_ALLOWED",128)
    $userAccountControlHashTable.Add("TEMP_DUPLICATE_ACCOUNT",256)
    $userAccountControlHashTable.Add("NORMAL_ACCOUNT",512)
    $userAccountControlHashTable.Add("INTERDOMAIN_TRUST_ACCOUNT",2048)
    $userAccountControlHashTable.Add("WORKSTATION_TRUST_ACCOUNT",4096)
    $userAccountControlHashTable.Add("SERVER_TRUST_ACCOUNT",8192)
    $userAccountControlHashTable.Add("DONT_EXPIRE_PASSWORD",65536) 
    $userAccountControlHashTable.Add("MNS_LOGON_ACCOUNT",131072)
    $userAccountControlHashTable.Add("SMARTCARD_REQUIRED",262144)
    $userAccountControlHashTable.Add("TRUSTED_FOR_DELEGATION",524288) 
    $userAccountControlHashTable.Add("NOT_DELEGATED",1048576)
    $userAccountControlHashTable.Add("USE_DES_KEY_ONLY",2097152) 
    $userAccountControlHashTable.Add("DONT_REQ_PREAUTH",4194304) 
    $userAccountControlHashTable.Add("PASSWORD_EXPIRED",8388608) 
    $userAccountControlHashTable.Add("TRUSTED_TO_AUTH_FOR_DELEGATION",16777216) 
    $userAccountControlHashTable.Add("PARTIAL_SECRETS_ACCOUNT",67108864)

    $userAccountControlHashTable = $userAccountControlHashTable.GetEnumerator() | Sort-Object -Property Value 
    return $userAccountControlHashTable
}

Function Get-UserAccountControlFlags($UACValue)
{    
        Set-UserAccountControlValueTable | foreach {
	    $binaryAnd = $_.value -band $UACValue
	    if ($binaryAnd -ne "0") { write $_ }
    }
}

#$UACValueUserAccountControl = Read-Host "Please provide the userAccountControl value: "
#Get-UserAccountControlFlags($UACValueUserAccountControl)

Clear-Host

$UsersAndComputers = Get-ADObject `
                -Filter {(objectSid -like "*") -and (userAccountControl -like "*") -and (PrimaryGroupID -ne 516) -and (PrimaryGroupID -ne 521)} `
                -Properties CanonicalName, Name, DistinguishedName, ObjectClass, userAccountControl, msDS-AllowedToDelegateTo `
                    | Select-Object CanonicalName, Name, DistinguishedName, ObjectClass, userAccountControl, @{n='UACDecoded'; e={(Get-UserAccountControlFlags($_.userAccountControl)).Name}}, msDS-AllowedToDelegateTo

Write-Host "========================================================================" -ForegroundColor Green
Write-Host "Unconstrained Delegation:" -ForegroundColor Green
$UsersAndComputers | Where-Object {$_.UACDecoded -contains "TRUSTED_FOR_DELEGATION"}
Write-Host "------------------------------------------------------------------------" -ForegroundColor Green
Write-Host "Constrained Delegation (S4U2S):" -ForegroundColor Green
$UsersAndComputers | Where-Object {$_.UACDecoded -contains "TRUSTED_TO_AUTH_FOR_DELEGATION"}
Write-Host "------------------------------------------------------------------------" -ForegroundColor Green
Write-Host "Password Never Expires:" -ForegroundColor Green
$UsersAndComputers | Where-Object {$_.UACDecoded -contains "DONT_EXPIRE_PASSWORD"}
Write-Host "------------------------------------------------------------------------" -ForegroundColor Green
Write-Host "Store Pwd Using Reversible Encryption:" -ForegroundColor Green
$UsersAndComputers | Where-Object {$_.UACDecoded -contains "ENCRYPTED_TEXT_PWD_ALLOWED"}
Write-Host "------------------------------------------------------------------------" -ForegroundColor Green
Write-Host "Account is Sensitive and Cannot Be Delegated:" -ForegroundColor Green
$UsersAndComputers | Where-Object {$_.UACDecoded -contains "NOT_DELEGATED"}
Write-Host "------------------------------------------------------------------------" -ForegroundColor Green
Write-Host "Use Only Kerberos DES Encryption Types for This Account:" -ForegroundColor Green
$UsersAndComputers | Where-Object {$_.UACDecoded -contains "USE_DES_KEY_ONLY"}
Write-Host "------------------------------------------------------------------------" -ForegroundColor Green
Write-Host "Do Not Require Kerberos PreAuthentication:" -ForegroundColor Green
$UsersAndComputers | Where-Object {$_.UACDecoded -contains "DONT_REQ_PREAUTH"}
Write-Host "------------------------------------------------------------------------" -ForegroundColor Green
Write-Host "Service Accounts AT RISK!" -ForegroundColor Green
$UsersAndComputers | Where-Object {($_.UACDecoded -contains "DONT_EXPIRE_PASSWORD") -and ($_.UACDecoded -contains "DONT_REQ_PREAUTH")}
Write-Host "------------------------------------------------------------------------" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green