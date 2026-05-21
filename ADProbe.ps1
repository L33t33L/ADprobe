<#
ADProbe - PowerShell Script
Copyright (c) 2025 Horizon Secured

Licensed under the MIT License, modified by the Commons Clause License Condition v1.0.

"Commons Clause" License Condition v1.0

The Software is provided to you by the Licensor under the License, as defined below, subject to the following condition.

Without limiting other conditions in the License, the grant of rights under the License will not include, and the License does not grant to you, the right to Sell the Software.

For purposes of the foregoing, "Sell" means practicing any or all of the rights granted to you under the License to provide to third parties, for a fee or other consideration (including without limitation fees for hosting or consulting/support services related to the Software), a product or service whose value derives, entirely or substantially, from the functionality of the Software. Any license notice or attribution required by the License must also include this Commons Clause License Condition notice.

Software: ADProbe
License: MIT License, modified by Commons Clause
Licensor: Horizon Secured
#>
<#
Requirements:
For Windows Servers: Install-WindowsFeature
    RSAT-AD-Powershell
    RSAT-DNS-Server

For Windows Clients: Add-WindowsCapability -Online 
    Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
    Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
    Rsat.Dns.Tools~~~~0.0.1.0

Most of the controls are possible with just Domain User account. These controls requires Domain Admin:
 - SMB1
 - HiddenObjectNoAccess
 - HiddenObjectDenyList
 - HiddenAccount
 - ADObjects30
 - DNSDynUpdate
#>

Write-Host "Starting Script" -ForegroundColor white -BackgroundColor DarkCyan



## File Title Declaration ## Option to edit in the future ##
## fileTitle - name of the file in the HTML title/tab name in the browser ##
## mainTitle - Main title for the entire page ##

$ErrorActionPreference = "SilentlyContinue"
$FileDate=Get-Date -Format "MM_dd_yyyy"
$fileTitle = "ADProbe_$FileDate"
$mainTitle = "Active Directory Vulnerability Scan"

## Global Variables ###
$global:ACLDate = Get-Date -Date ((Get-ADObject $("CN=AdminSDHolder,CN=System,"+"$(Get-ADDomain | Select-Object -ExpandProperty DistinguishedName)") -Properties msDS-ReplAttributeMetaData | select -ExpandProperty msDS-ReplAttributeMetaData) -split "`n`n" | Where-Object { $_.Replace("`n","") -match "nTSecurityDescriptor" } | % { $_ -split "`n" } | Where-Object { $_ -match "ftimeLastOriginatingChange" } | % { [regex]::matches($_, "\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z") | Select-Object -ExpandProperty Value })
$global:ADroot=Get-ADObject (Get-ADDomain | Select-Object -ExpandProperty DistinguishedName)

########################

## Main title always first because of position 0, followed by an enter after each title ##
## When creating a new chapter, a variable name is created and the main title is placed at position 0, then the titles are added ##

$firstChapter = @"
Active Directory - Vulnerabilities
 Account Lockout and Password Policy
 Accounts with Old Passwords
 Active Directory Certification Services - ESC1
 Active Directory Certification Services - ESC2
 Active Directory Certification Services - ESC3
 Active Directory Certification Services - ESC4
 Active Directory Certification Services - ESC6
 Active Directory Certification Services - ESC8
 Azure Active Directory SSO Account
 Computers with Default Password
 Constrained Delegation
 DNS Dynamic Updates
 Domain Join Computer Owner
 Editable GPOs
 GPO Link Premission
 Inactive but Enabled Users
 Kerberos Encryption
 LAPS
 LDAP Signing
 Machines Out of Date
 NTLM
 Passwords in Policies
 Pre-Windows 2000 Compatible Access Group
 Protected Users
 Read-Only Domain Controller Groups
 Resource Based Constrained Delegation
 Service accounts with AdminCount attribute
 SMB
 Trusts
 Unconstrained Delegation
 AdminCount attribute
 Bad Password Count
 Disabled Kerberos Preauthentication
 Do Not Require a Password
 Kerberos DES Enabled
 Password in Description
 Password Never Expires
 Password Stored Using Reversible Encryption	
 Service Principal Name
"@

$secondChapter = @"
Active Directory - Persistent Methods
 Active Directory Recent Objects
 AdminSDHolder
 DCShadow Computer
 DCShadow Privilege
 DCSync Privilege
 Domain Controllers
 Hidden Objects
 KRBTGT Account
 Privileged groups
 Shadow Principals
 SIDHistory
 User Accounts with Modified Primary Group
"@

## Each added chapter must also be added here ##

$chapterList = "firstChapter", "secondChapter"

## Descriptions for titles, to add just add another string to the array and at least one paragraph (<p></p>) for the title and text, insert the text into the paragraph || if bold text is needed, use (<b></b>) ##
## For descriptions of a new chapter, do the same as for titles ##

$descriptionFirstChap = "
<p>Password and account policy is a critical part of securing Windows Infrastructure. A properly configured policy protects us primarily against various brute-force attacks, which involve cracking/guessing the password of the target account. We recommend configuring the password and account policy according to <b>CIS Benchmarks and general Best Practices.</b> These include the following parameters:
<br> - Password with a minimum of 14 characters, ideally in passphrases
<br> - Enforced password complexity
<br> - Maximum password age of 365 days
<br> - Minimum password age of 1 day
<br> - Enforced password history and prohibition of using the last 24 passwords
<br> - Account lockout after 5 unsuccessful attempts
<br> - Minimum account lockout duration of 15 minutes
<br> - Reset account lockout after minimally 15 minutes
</p>",
"<p>Historical passwords in the environment pose a high risk, especially in the absence of multi-factor authentication. Below are the accounts with passwords older than 18 months.</p>",
"<p>ESC1 indicates a misconfiguration/vulnerability within Microsoft Certification Services at the level of certificate templates. An attacker can exploit this misconfiguration to issue a new certificate, which can then be used to escalate their privileges. ESC1 consists of the following configuration requirements:
<br> - Enrollment permissions for non-privileged users. A non-privileged user can request a certificate.
<br> - 'Manager Approval' function disabled. No approval is required when requesting a certificate.
<br> - No authorized signature required for certificate requests.
<br> - Extended Key Usage (EKU) allows the certificate to be used for authentication purposes (Client Authentication, PKINIT Client Authentication, Smart Card Logon).
<br> - The certificate template allows the requester to configure the Subject Alternative Name (SAN) field.</p>",
"<p>ESC2 indicates a misconfiguration/vulnerability within Microsoft Certification Services at the level of certificate templates. An attacker can exploit this misconfiguration to issue a new certificate, which can then be used to escalate their privileges. ESC2 consists of the following configuration requirements:
<br> - Enrollment permissions for non-privileged users. A non-privileged user can request a certificate.
<br> - 'Manager Approval' function disabled. No approval is required when requesting a certificate.
<br> - No authorized signature required for certificate requests.
<br> - Extended Key Usage (EKU) is set to 'Any Purpose' or is empty. If EKU is empty, it is equivalent to a subordinate certification authority certificate.</p>",
"<p>ESC3 indicates a misconfiguration/vulnerability within Microsoft Certification Services at the level of certificate templates. An attacker can exploit this misconfiguration to issue a new certificate, which can then be used to escalate their privileges. ESC3 consists of the following configuration requirements:
<br> - Enrollment permissions for non-privileged users. A non-privileged user can request a certificate.
<br> - 'Manager Approval' function disabled. No approval is required when requesting a certificate.
<br> - No authorized signature required for certificate requests.
<br> - Extended Key Usage (EKU) is set to 'Certificate Request Agent EKU'. This EKU allows the individual to issue certificates on behalf of other entities.
<br> - Absence of 'Enrollment Agent' restrictions. This setting needs to be manually checked: Certification Authority console (certsrv.msc) > right-click on the specified certification authority > Properties > Enrollment Agents. Here, we recommend applying restrictions as per Microsoft's recommendations.</p>",
"<p>ESC4 indicates a misconfiguration/vulnerability within Microsoft Certification Services at the level of certificate templates. This misconfiguration involves an Access Control List (ACL) that allows unwanted/non-privileged entities to modify the certificate template.</p>",
"<p>ESC6 indicates a specific 'flag' within the certification authority policy. This is the 'EDITF_ATTRIBUTESUBJECTALTNAME2' setting within the 'policy\EditFlags' policy. This setting means that any certificate request can specify any SAN value.</p>",
"<p>ESC8 indicates a configuration that allows 'NTLM Relay' attacks within the 'Certificate Enrollment Web Services'. This service allows users to request certificates through a web interface. This web interface may be vulnerable to 'NTLM Relay' attacks. The vulnerability consists of the following items:
<br> - Installed 'Certificate Enrollment Web Services'.
<br> - NTLM enabled within IIS/domain.
<br> - 'Extended Protection' function disabled within IIS.</p>",
"<p>AZUREADSSOACC is a computer account used for Single-Sign-On functionality within the connection to Microsoft Azure Active Directory and its services. The password for this account is used in the process of encrypting Kerberos tickets. Therefore, it is necessary to regularly change the password for this account. Microsoft's recommendation is every 30 days. Due to encryption issues, it is also necessary to enforce only modern Kerberos encryption algorithms AES128 and AES256 for this account.</p>",
"<p>When pre-creating a computer account for connecting a device to the domain, you can check the option 'Assign this computer account as a pre-Windows 2000 computer'. This causes the computer account to have a default password based on the computer account name itself. The disadvantage is that this state occurs in most cases when creating computer accounts via script. This state can also be achieved by using the 'Reset Account' action. Therefore, if there is such an account in the environment with the name PC01$, the password for it is pc01. We recommend not intentionally creating such accounts, and if using scripts, we recommend checking such accounts to ensure they do not have a default password after creation.</p>",
"<p>A more restricted type of delegation of user login to a backend service. If we have a service on the server that uses an account with the above attribute, the service is authorized to delegate the user's Ticket Granting Service ticket or request it on its own. An attacker can exploit Constrained Delegation to obtain Ticket Granting Service tickets of other users. Delegation must be used with caution and with security in mind.</p>",
"<p>To ensure scalability of operations and data relevance, the DNS system supports so-called Dynamic Updates, where the client device on its own initiative notifies the DNS server of its address change so that the DNS server can always provide the current translation. If the type of DNS zone is Active Directory-integrated, the Secure Dynamic Updates feature is automatically used, which is available only for this type of zone and allows requiring client authentication before making this change. This enforces that only the corresponding devices or adequately authorized administrators can change the records. In addition to Secure Dynamic Updates, NonSecure Dynamic Updates can also be enabled. This feature allows unauthorized entities to modify DNS records.</p>",
"<p>When a delegated join account (e.g. djoinacc, guy from helpdesk, ..., ) creates a computer object, it becomes that object’s owner. Ownership grants implicit full control — the account can always modify permissions or attributes, even if Write All Properties isn’t granted. This means the account could change sensitive attributes such as RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) or LAPS (ms-Mcs-AdmPwd), leading to privilege escalation.
<br>To prevent this, it’s recommended to:
<br> - Move joined computers out of the delegated OU (to remove inherited rights).
<br> - Regularly transfer ownership of those objects to a protected group (e.g. Domain Admins) using a cleanup script.
<br> - And potentially remove any ACEs left for the delegated account
<br>Until ownership is changed and ACEs are removed, the owner of the computer object can escalate privileges.</p>",
"<p>Permission to modify policies can allow an attacker to distribute malicious code in the environment. The attacker can also use this function to persist in the Active Directory environment. Delegation of permissions on policies must be used with caution and with security in mind.</p>",
"<p>The permission to assign policies can be exploited by an attacker to escalate and distribute malicious code in the environment. Additionally, an attacker can use this function to persist in the Active Directory environment. Delegation of permissions on policies must be used with caution and with security in mind.</p>",
"<p>Inactive but not disabled accounts in Active Directory can facilitate an attacker's access to the environment. Passwords for such accounts are often historically older and therefore weaker. The longer such an account is kept in the environment, the higher the probability that the password may be in databases of leaked passwords. Unused accounts should be disabled in Active Directory according to a defined process. The script searches for accounts that have been inactive for more than a year and are not disabled.</p>",
"<p>The chosen encryption algorithms within the Kerberos protocol are an essential part of securing the Active Directory domain. In the case of weak ciphers, an attacker can perform so-called Kerberoasting attacks against the Kerberos protocol. Within the Kerberos protocol, we can request a Ticket Granting Service ticket for access to a service, which is encrypted with a hash derived from the password of the account used to run the service. An attacker can request any Ticket Granting Service ticket with a regular user account, save it, and then attempt to crack it offline to obtain the service account password (Kerberoasting). It is essential that the encryption algorithms within the Kerberos protocol are defined at the GPO level.</p>",
"<p>Local Administrator Password Solution (LAPS) is a Microsoft solution that allows automatic rotation of local administrator passwords on Windows devices. Local administrator passwords are then stored in the attributes of computer accounts within Active Directory. This attribute is protected only by ACL, which defines access to the attribute. Permission to read this attribute can be exploited by an attacker for persistence, or it may simply be a misconfiguration of delegation by administrators. Below are the computer accounts, containers, and organizational units to which non-standard read permissions are delegated for the attribute containing the local administrator password.</p>",
"<p>The LDAP protocol is used in Active Directory to read and modify objects in the directory services database. The LDAP Signing function ensures that communication within the LDAP protocol is signed with a cryptographic signature, ensuring the authenticity and integrity of the message. This primarily protects against Man in the Middle attacks. We recommend enforcing LDAP Signing across the entire Active Directory domain using GPO.</p>",
"<p>Unsupported operating systems are not protected by the manufacturer in the event of new security vulnerabilities. Therefore, it is necessary to both update and upgrade systems to new versions of operating systems.</p>",
"<p>In an Active Directory domain, the Kerberos and NTLM protocols are used for user and computer authentication. The less secure of these is the NTLM protocol, which must be properly secured. In the absence of NTLM protocol security, there is a risk of Man in the Middle attacks or successful cracking of the outdated LM Hash, thereby obtaining the password in plain text. Therefore, it is necessary to enforce the newer version of the NTLMv2 protocol across the domain and disable the storage of LM hashes.</p>",
"<p>In an Active Directory domain, it was previously possible to store passwords associated with creating/modifying users, services, scheduled tasks, etc., within Group Policy objects. These passwords were stored encrypted in the GPO. However, the encryption key used to encrypt these passwords was leaked to the public. Microsoft responded by releasing an update that prevents passwords from being stored in Group Policy objects in this way. However, this update does not remove already existing policies with stored passwords created before this update. It is necessary to review the environment and eliminate these policies.</p>",
"<p>The 'Pre-Windows 2000 Compatible Access' group in Active Directory by default may include the following groups: Authenticated Users, Anonymous logon, Everyone. This results in a larger number of permissions over Active Directory objects for all users/computers. One of the significant added permissions is 'Read all properties' on user account objects, allowing an attacker to gather all necessary information about target accounts during the reconnaissance phase. We recommend keeping only the 'Authenticated Users' group in the 'Pre-Windows 2000 Compatible Access' group and removing the rest after proper testing. A higher level of security is achieved by also removing the 'Authenticated Users' group. In this case, you remove the read permissions for many attributes even for regular authenticated users, which can significantly hinder an attacker's movement. This action can lead to various errors, so it is essential to test it thoroughly.</p>",
"<p>The Protected Users group protects its members against various types of abuse. Protections include: disallowing NTLM authentication, disallowing delegation, DES and RC4 encryption algorithms within Kerberos authentication, disallowing caching of plain-text passwords in the case of WDigest or CredSSP. It is essential that privileged accounts are part of this group, at least members of the 'Domain Admins' and 'Enterprise Admins' groups. Do not add computer and service accounts to the group.</p>",
"<p>Read-Only Domain Controller groups in Active Directory determine which user/administrator passwords may or may not be replicated to the RODC. In Active Directory, there are the 'Allowed RODC Password Replication Group' and 'Denied RODC Password Replication Group'. The 'Denied RODC Password Replication Group' must be kept in its default state, as it explicitly prohibits the replication of privileged account passwords. Ideally, no administrator accounts should be placed in the 'Allowed RODC Password Replication Group'.</p>",
"<p>This is a type of Constrained Delegation, where the setting is applied to the target account to which the delegation is made. This type of delegation again poses a risk of abuse of Ticket Granting Service tickets of other users. Delegation must be used with caution and with security in mind.</p>",
"<p>Accounts with the Service Principal Name attribute combined with the AdminCount attribute set to 1 indicate privileged service accounts. In an Active Directory domain, it is possible to request a Ticket Granting Service ticket for any service, regardless of whether we are authorized for the target service. The problem is that part of the Ticket Granting Service ticket is encrypted with a hash derived from the password of the account used to run the service. An attacker can request any Ticket Granting Service ticket with a regular user account, save it, and then attempt to crack it offline to obtain the service account password (Kerberoasting). Service accounts should not be part of privileged groups. In necessary cases, such an account must be additionally secured.</p>",
"<p>The SMB protocol is widely used within Windows Infrastructure. However, its settings and old versions can compromise the security of the entire infrastructure and help an attacker compromise the environment. The outdated version of the SMB protocol (SMBv1) is often exploited in Windows operating systems. We recommend disabling SMBv1 protocol across the board using Group Policy. SMB Signing ensures the integrity and authenticity of SMB messages using a cryptographic signature, preventing Man in the Middle attacks. We again recommend defining this setting across the board at the Group Policy level. Below are the domain controllers and their settings.</p>",
"<p>Trusts are trusted relationships established with other forests/domains. An attacker can exploit these relationships to abuse the remote forest/domain and vice versa. Therefore, trusts must be used with caution.</p>",
"<p>These are typically service accounts that need to be able to delegate user login to a backend service. If we have a service on the server that uses an account with the above attribute, the Ticket Granting Ticket of any user authenticating to this service is stored in memory on the server. An attacker can easily obtain Ticket Granting Tickets of privileged accounts. Delegation must be used with caution and with security in mind.</p>",
"<p>The AdminCount attribute set to 1 on accounts in Active Directory indicates that the account is currently or has been in a privileged group. If found, we recommend reviewing the accounts in this list.</p>",
"<p>Frequently mistyped passwords can be a sign of a Password Spray attack or a Brute Force attack. Therefore, this state must be constantly monitored and evaluated using a SIEM tool. This state can be monitored using event 4625.</p>",
"<p>By default, every Active Directory account must perform Kerberos pre-authentication, where it must prove its identity when requesting a Ticket Granting Ticket by encrypting a timestamp with its password hash. This behavior can be intentionally disabled. An attacker could then request a Ticket Granting Ticket for any account and attempt to crack the password offline (Kerberoasting technique). We recommend not using this attribute.</p>",
"<p>This attribute allows setting an empty password for an account under certain conditions. This attribute can be used to bypass the password policy. We recommend not using this attribute.</p>",
"<p>Kerberos allows the use of DES, RC4, and AES encryption algorithms for ticket encryption. DES is the oldest and easiest to break of these encryption algorithms. For compatibility reasons, DES encryption for Kerberos can be enabled directly on the Active Directory account. We recommend not using this attribute.</p>",
"<p>As part of the script execution, the customer searched the descriptions of Active Directory accounts for the possible presence of plain text passwords. Descriptions of accounts should not contain hints or the actual passwords for accounts.</p>",
"<p>Never-expiring passwords are the biggest problem in combination with a weak password policy. As a rule, historical accounts with historical passwords remain in the environment, which an attacker can easily crack. We recommend not using this attribute.</p>",
"<p>This attribute allows the password to be stored in a way that makes it possible to decrypt the password. Normally, passwords are encrypted so that decryption is mathematically impossible (One Way Encryption). For compatibility reasons, this attribute can be set directly on the Active Directory account. We recommend not using this attribute.</p>",
"<p>User accounts with the Service Principal Name attribute are typically service accounts used to run services on target devices. In an Active Directory domain, it is possible to request a Ticket Granting Service ticket for any service, regardless of whether we are authorized for the target service. The problem is that part of the Ticket Granting Service ticket is encrypted with a hash derived from the password of the account used to run the service. An attacker can request any Ticket Granting Service ticket with a regular user account, save it, and then attempt to crack it offline to obtain the service account password (Kerberoasting). If found, we recommend reviewing the accounts in this list.</p>"

$descriptionSecondChap = "
<p>During an attack, an attacker may attempt to create various types of objects in Active Directory, for example, for hidden persistence. This check lists Active Directory objects created in the last 30 days. Carefully read the list and investigate suspicious/unknown objects.</p>",
"<p>This is a container in Active Directory whose ACL serves as a template for privileged accounts and groups. An attacker can modify the permissions on this container to achieve high privileges without membership in privileged groups. We recommend reviewing the accounts in this list. The last ACL change occurred on: <b>$ACLDate</b></p>",
"<p>In a DCShadow attack, the attacker must have a compromised domain device that will act as a 'Rogue Domain Controller' and from which changes will be replicated to Active Directory. At that moment, such a device acquires a new value in the Service Principal Name attribute E3514235-4B06-11D1-AB04-00C04FC2DCD2/*. If found, the account must be investigated.</p>",
"<p>DCShadow privileges are privileges that allow the target account to replicate changes to Active Directory from a compromised domain device 'Rogue Domain Controller'. These are the privileges Add/Remove Replica In Domain, DS-Replication-Synchronize, DS-Replication-Manage-Topology. These privileges are found on the root object of the domain and must be monitored. We recommend reviewing the accounts in this list.</p>",
"<p>DCSync privileges are privileges that allow the target account to replicate the Active Directory database. These are the privileges Directory Replicating Changes and Directory Replicating Changes All. These privileges are found on the root object of the domain and must be monitored. We recommend reviewing the accounts in this list.</p>",
"<p>In extreme cases, an attacker could connect their own Rogue Domain Controller to the environment to ensure persistent access to Active Directory data. We recommend reviewing the accounts in this list.</p>",
"<p>As part of persistence, attackers try to hide their presence from administrators using various techniques. These techniques often involve operations that remove permissions to target objects. A domain administrator should have permissions on all objects in Active Directory, and based on this, a check can be performed. The check includes the following:
<br>1) Objects with denied access
<br>2) Objects with Deny List permissions
<br>3) Accounts with denied access
<br>If found, the objects must be investigated.</p>",
"<p>The krbtgt account is the default account in Active Directory, whose password hash is used to encrypt Ticket Granting Tickets within the Kerberos authentication mechanism. This account must be monitored for its login and password changes within its Active Directory object. The password change must be performed at least after 2008 to generate AES encryption keys for the Kerberos authentication protocol.</p>",
"<p>Membership in privileged groups. We recommend monitoring the status of privileged groups.</p>",
"<p>Shadow Principals is a feature of the Red Forest concept that allows the management of the productive forest from the administrative forest. An attacker can exploit this feature to gain privileges without membership in privileged groups. If found, the objects must be investigated.</p>",
"<p>SIDHistory is a user attribute containing the SID of a user/group, for example, after migration from another domain to retain 'old' access. An attacker can exploit this attribute to gain privileges without membership in privileged groups. If found, the accounts must be investigated.</p>",
"<p>Historically, the Primary Group feature (exposed as the primaryGroupID attribute) was used for scenarios like network access from macOS. An attacker can abuse this setting to hide or disguise membership in a target group. By default, a user’s primaryGroupID points to Domain Users (RID 513). If an account’s Primary Group is set to anything else, the account should be investigated and verified.</p>"


## When adding another chapter, the chapter must also be added here ##

$descriptionChapters = "descriptionFirstChap", "descriptionSecondChap"

## Main Code ##
## Adding new scripts is always done using functions, follow the structure of other functions ##
## Then you need to write the main link to the script, if there are multiple scripts for one title, write all scripts into the link ##
## Then write the link into the chapter manager and the management variable into the main variable ##

function PwdLastSet {
	#Accounts with passwords older than 578 days ZKB
	$neededNames = "Name", "PwdLastSet", "LastLogonTimestamp"
    $PwdLastSetUsers=Get-ADUser -Filter 'enabled -eq $true' -Properties Name, PwdLastSet,lastlogonTimestamp | select name, @{N='pwdlastset' ; E={[DateTime]::FromFileTime($_.PwdLastSet)}}, @{N='LastLogonTimestamp' ; E={[DateTime]::FromFileTime($_.lastlogonTimestamp)}} | Where-Object {$_.PwdLastSet -le $(Get-Date -date $(get-date).AddDays(-578))} | Sort-Object -Property PwdLastSet
    $PwdLastSetComps=Get-ADComputer -Filter * -Properties Name, PWDLastSet, LastLogonTimestamp | select name, @{N='pwdlastset' ; E={[DateTime]::FromFileTime($_.PwdLastSet)}}, @{N='LastLogonTimestamp' ; E={[DateTime]::FromFileTime($_.lastlogonTimestamp)}} | Where-Object {$_.PwdLastSet -le $(Get-Date -date $(get-date).AddDays(-578))} | Sort-Object -Property PwdLastSet
	    $results=foreach ($User in $PwdLastSetUsers){
        $array= @(); $array +=[pscustomobject]@{
                      Name = $User.Name
                      PWDLastSet = $User.PWDLastSet
                      LastLogonTimestamp = $User.LastLogonTimestamp
                     }
                     $array}
                    $results+= foreach ($Comp in $PwdLastSetComps){
                    $array= @();  $array +=[pscustomobject]@{
                    Name = $Comp.Name
                    PWDLastSet = $Comp.PWDLastSet
                    LastLogonTimestamp = $Comp.LastLogonTimestamp
                     }
                     $array}
    $selectionNames = "Name", "PwdLastSet", "LastLogonTimestamp"
	return $neededNames, $PwdLastSetUsers, $selectionNames
}
    
$PwdLastSet = "PwdLastSet"

function UnconstrainedDelegation {
	#Accounts with unconstrained delegation excluding the DCs
	$neededNames = "Name", "ObjectClass"
	$UnconstrainedDelegation=Get-ADObject -LDAPFilter '(&(!(primaryGroupID=516)(userAccountControl:1.2.840.113556.1.4.803:=524288)))' -Properties Name, UserAccountControl, ObjectClass | Select-Object Name, ObjectClass
	$selectionNames = "Name", "ObjectClass"
	return $neededNames, $UnconstrainedDelegation, $selectionNames
}
$UnconstrainedDelegation = "UnconstrainedDelegation"

function ConstrainedDelegation {
	#Accounts with constrained delegation
	$neededNames = "Name", "ObjectClass", "MSDS allowed to delegate to"
	$ConstrainedDelegation=Get-ADObject -LDAPFilter "(&(msDS-AllowedToDelegateTo=*))" -Properties Name, UserAccountControl, ObjectClass, msDS-AllowedToDelegateTo | Select-Object Name, ObjectClass, @{N="msDS-AllowedToDelegateTo";E={$_."msDS-AllowedToDelegateTo" -join ", "}}
	$selectionNames = "Name", "ObjectClass", "msDS-AllowedToDelegateTo"
	return $neededNames, $ConstrainedDelegation, $selectionNames
}
$ConstrainedDelegation = "ConstrainedDelegation"

function RBConstrainedDelegation {
	#Accounts with constrained delegation
	$neededNames = "Name", "ObjectClass", "MSDS allowed to act on behalf of other identity"
	$RBConstrainedDelegation=Get-ADObject -LDAPFilter "(&(msDS-AllowedToActOnBehalfOfOtherIdentity=*))" -Properties Name, UserAccountControl, ObjectClass, msDS-AllowedToActOnBehalfOfOtherIdentity | Select-Object Name, ObjectClass, @{N="msDS-AllowedToActOnBehalfOfOtherIdentity";E={$_."msDS-AllowedToActOnBehalfOfOtherIdentity".Access.IdentityReference -join ", "}}
	$selectionNames = "Name", "ObjectClass", "msDS-AllowedToActOnBehalfOfOtherIdentity"
	return $neededNames, $RBConstrainedDelegation, $selectionNames
}
$RbConstrainedDelegation = "RBConstrainedDelegation"


function SPN {
	#user accounts with SPN but no the TGT accounts
	$neededNames = "Name", "User Principal Name", "Service Principal Name"
	$SPN=Get-ADUser -LDAPFilter '(&(objectCategory=user)(!(samAccountName=krbtgt)(servicePrincipalName=*)))' -Properties Name, UserPrincipalName, ServicePrincipalName | Select-Object Name, UserPrincipalName, @{N="ServicePrincipalName";E={$_.ServicePrincipalName -join ", "}}
	$selectionNames = "Name", "UserPrincipalName", "ServicePrincipalName"
	return $neededNames, $SPN, $selectionNames
}
$spn = "SPN"


function AdminCount {
	#all Accounts with AdminCount 1
	$neededNames = "Name", "User Principal Name"
	$AdminCount=Get-ADUser -LDAPFilter '(adminCount=1)' -Properties Name, UserPrincipalName | Select-Object Name, UserPrincipalName
	$selectionNames = "Name", "UserPrincipalName"
	return $neededNames, $AdminCount, $selectionNames
}
$adminNum = "AdminCount"


function PrivServiceAccounts {
	#all service accounts with AdminCount 1
	$neededNames = "Name", "User Principal Name", "Service Principal Name"
	$PrivServiceAccounts=Get-ADUser -LDAPFilter '(&(objectClass=user)(!(samAccountName=krbtgt)(servicePrincipalName=*)(adminCount=1)))' -Properties Name, UserPrincipalName, ServicePrincipalName | Select-Object Name, UserPrincipalName, @{N="ServicePrincipalName";E={$_.ServicePrincipalName -join ", "}}
	$selectionNames = "Name", "UserPrincipalName", "ServicePrincipalName"
	return $neededNames, $PrivServiceAccounts, $selectionNames
}
$privAccounts = "PrivServiceAccounts"


function BadPasswordCount {
	#Users where bad password count is greater than or equal to 3
	$neededNames = "Name", "User Principal Name", "Bad Password Count", "Account Lockout Time", "Locked Out"
	$PDC=Get-ADForest |Select-Object -ExpandProperty RootDomain |Get-ADDomain |Select-Object -ExpandProperty PDCEmulator
	$BadPasswordCount=Get-ADUser -LDAPFilter '(&(objectCategory=user)(badpwdcount>=3))' -Server $PDC -Properties Name, UserPrincipalName, BadPWDCount, AccountLockoutTime, LockedOut | Select-Object Name, UserPrincipalName, BadPWDCount, AccountLockoutTime, LockedOut | Sort-Object -Descending -Property BadPWDCount
	$selectionNames = "Name", "UserPrincipalName", "BadPWDCount", "AccountLockoutTime", "LockedOut"
	return $neededNames, $BadPasswordCount, $selectionNames
}
$badPwdNum = "BadPasswordCount"

function DoNotRequirePassword {
	#all accounts that do not require a password
	$neededNames = "Name", "User Principal Name"
	$DoNotRequirePassword=Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))' -Properties Name, UserPrincipalName | Select-Object Name, UserPrincipalName
	$selectionNames = "Name", "UserPrincipalName"
	return $neededNames, $DoNotRequirePassword, $selectionNames
}
$accWithoutPwd = "DoNotRequirePassword"


function PasswordNeverExpires {
	#Password never expires
	$neededNames = "Name", "User Principal Name", "Date Of The Last Password Change"
	$PasswordNeverExpires=Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=66048))' -Properties Name, UserPrincipalName, PWDLastSet | Select-Object Name, UserPrincipalName, @{N='pwdlastset' ; E={[DateTime]::FromFileTime($_.PwdLastSet)}} | Sort-Object -Descending PwdLastSet
	$selectionNames = "Name", "UserPrincipalName", "pwdlastset"
	return $neededNames, $PasswordNeverExpires, $selectionNames
}
$endlessPwd = "PasswordNeverExpires"


function PwdDesc {
	#Section: Password in description
	$neededNames = "Name", "UserPrincipalName", "Description"
	$PwdDesc=Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(|(description=*hesl*)(description=*pwd*)(description=*pass*)(description=*word*)(description=*p4$$*)(description=*pa$$*)(description=*p4ss*)(description=*w0rd*)))' -Properties Name, UserPrincipalName, Description | Select-Object Name, UserPrincipalName, Description
	$selectionNames = "Name", "UserPrincipalName", "Description"
	return $neededNames, $PwdDesc, $selectionNames
}
$pwdDesc = "PwdDesc"


function ReversibleEncryption {
	#Section: Reversible Encryption
	$neededNames = "Name", "User Principal Name"
	$ReversibleEncryption=Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))' -Properties Name, UserPrincipalName | Select-Object Name, UserPrincipalName
	$selectionNames = "Name", "UserPrincipalName"
	return $neededNames, $ReversibleEncryption, $selectionNames
}
$weakEnc = "ReversibleEncryption"


function KerberosDES {
	#accounts that have Kerberos DES enabled
	$neededNames = "Name", "User Principal Name"
	$KerberosDES=Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152))' -Properties Name, UserPrincipalName | Select-Object Name, UserPrincipalName
	$selectionNames = "Name", "UserPrincipalName"
	return $neededNames, $KerberosDES, $selectionNames
}
$kerberos = "KerberosDES"


function ASREPUsers {
	#Disabled kerberos preauth
	$neededNames = "Name", "User Principal Name"
	$ASREPUsers=Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' -Properties Name, UserPrincipalName, UserAccountControl | Select-Object Name, UserPrincipalName
	$selectionNames = "Name", "UserPrincipalName"
	return $neededNames, $ASREPUsers, $selectionNames
}
$kerberosPreAuth = "ASREPUsers"


function Trusts {
	#all trusts
	#Get-ADObject -LDAPFilter '(objectClass=trustedDomain)'
	$neededNames = "DIRECTION", "DISALLOW TRANSITIVITY", "DISTINGUISHED NAME", "FOREST TRANSITIVE", "INTRA FOREST", "IS TREE PARENT", "IS TREE ROOT", "NAME", "OBJECT CLASS", "OBJECT GUID", "SELECTIVE AUTHENTICATION", "SID FILTERING FOREST AWARE", "SID FILTERING QUARANTINED", "SOURCE", "TARGET", "TGTDELEGATION", "TRUSTATTRIBUTES", "TRUSTED POLICY", "TRUSTING POLICY", "TRUST TYPE", "IS UP-LEVEL ONLY", "USES AES KEYS", "USES RC4 ENCRYPTION"
	$Trusts=Get-ADTrust -Filter * -Properties Direction,DisallowTransivity,DistinguishedName,ForestTransitive,IntraForest,Name,ObjectClass,ObjectGUID,SelectiveAuthentication,SIDFilteringForestAware,SIDFilteringQuarantined,Source,Target,TGTDelegation,TrustAttributes,UsesAESKeys,UsesRC4Encryption | Select-Object Direction,DisallowTransivity,DistinguishedName,ForestTransitive,IntraForest,Name,ObjectClass,ObjectGUID,SelectiveAuthentication,SIDFilteringForestAware,SIDFilteringQuarantined,Source,Target,TGTDelegation,TrustAttributes,UsesAESKeys,UsesRC4Encryption
	$selectionNames = "Direction", "DisallowTransivity", "DistinguishedName", "ForestTransitive", "IntraForest", "IsTreeParent", "IsTreeRoot", "Name", "ObjectClass", "ObjectGUID", "SelectiveAuthentication", "SIDFilteringForestAware", "SIDFilteringQuarantined", "Source", "Target", "TGTDelegation", "TrustAttributes", "TrustedPolicy", "TrustingPolicy", "TrustType", "UplevelOnly", "UsesAESKeys", "UsesRC4Encryption"
	return $neededNames, $Trusts, $selectionNames
}
$trust = "Trusts"

function GPOs {
	#Editable GPOs
    $GPOs = get-gpo -All | select -ExpandProperty DisplayName | ForEach-Object {$Permission=Get-GPPermission -Name $_ -All | `
		    ?{($_.Permission -like "*GpoEdit*")} | select -ExpandProperty Trustee |?{($_.Name -ne "Enterprise Admins") -and ($_.Name -ne "Domain Admins") -and ($_.Name -ne "System")}; `
			if ($Permission -ne $null) { $array= @(); $array +=[pscustomobject]@{
    																				Permission = $Permission.Name
    																				Policy = $_ 
    																			} 
			$array}}	
	$neededNames = "Permission", "Policy"
	$selectionNames = "Permission", "Policy"
	return $neededNames, $GPOs, $selectionNames
}
$GPO = "GPOs"

function DefPol {
	#Editable GPOs
       $neededNames = "DN", "Length","Max Age","Complexity", "Password History","Lockout Treshold","Lockout Duration","Lockout Reset","FGPP Target"
       $PassUsers = Get-ADDefaultDomainPasswordPolicy
           $array= @(); $array +=[pscustomobject]@{
                          DN = $PassUsers.DistinguishedName
                          Length = $PassUsers.MinPasswordLength
                          MaxAge = $PassUsers.MaxPasswordAge
                          Complexity = $PassUsers.ComplexityEnabled
                          PasswordHistory = $PassUsers.PasswordHistoryCount
                          LockoutTreshold = $PassUsers.LockoutThreshold
                          LockoutDuration = $PassUsers.LockoutDuration
                          LockoutReset = $PassUsers.LockoutObservationWindow
                          FGPPTarget = "This is not FGPP"
                            }                                                       
$PassAdmins = Get-ADFineGrainedPasswordPolicy -Filter *
            foreach ($FGPP in $PassAdmins){
                         $array +=[pscustomobject]@{
                          DN = "[FGPP]"+$FGPP.DistinguishedName
                          Length = $FGPP.MinPasswordLength
                          MaxAge = $FGPP.MaxPasswordAge
                          Complexity = $FGPP.ComplexityEnabled
                          PasswordHistory = $FGPP.PasswordHistoryCount
                          LockoutTreshold = $FGPP.LockoutThreshold
                          LockoutDuration = $FGPP.LockoutDuration
                          LockoutReset = $FGPP.LockoutObservationWindow
                          FGPPTarget = $FGPP.AppliesTo
                        }                                                   
 }
    $selectionNames = "DN", "Length","MaxAge","Complexity", "PasswordHistory", "LockoutTreshold","LockoutDuration","LockoutReset","FGPPTarget"
	return $neededNames, $Array, $selectionNames
}
$DefPol = "DefPol"

function GPLink {
	#Permissions to link GPO on AD Root
    $neededNames = "Object", "IdentityReference", "AccessControlType"
        $DN=Get-ADDomain | Select-Object -ExpandProperty DistinguishedName	
        $RootACL=(Get-Acl -path $("AD:$ADRoot")).access | Where-Object{$_.ObjectType -like "*f30e3bbf-9ff0-11d1-b603-0000f80367c1*" -or $_.ObjectType -like "*f30e3bbe-9ff0-11d1-b603-0000f80367c1*"}
    	$results=foreach ($ACL in $RootACL){
        $array= @(); $array +=[pscustomobject]@{
                Object = $ADroot
                IdentityReference = $ACL.IdentityReference
                AccessControlType = $ACL.AccessControlType
                }
                $array}
                    $OUs = Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName
                        $results+=foreach ($OU in $OUs){
                        $OUsACL = (Get-Acl -path $("AD:\$OU")).access | Where-Object{$_.ObjectType -like "*f30e3bbf-9ff0-11d1-b603-0000f80367c1*" -or $_.ObjectType -like "*f30e3bbe-9ff0-11d1-b603-0000f80367c1*"}
                        foreach ($ACL in $OUsACL){
                        if ($ACL.IsInherited -eq $false){
                        $array= @(); $array +=[pscustomobject]@{
                        Object = $OU
                        IdentityReference = $ACL.IdentityReference
                        AccessControlType = $ACL.AccessControlType
                        }
                        $array}
                        }
                        }
                                $Sites = Get-ADObject -Filter 'objectclass -eq "Site"' -SearchBase "CN=Configuration,$DN" | Select-Object -ExpandProperty DistinguishedName
                                    $results+=foreach ($Site in $Sites) {
                                    $SitesACL = (Get-Acl -path $("AD:\$Site")).access | Where-Object{$_.ObjectType -like "*f30e3bbf-9ff0-11d1-b603-0000f80367c1*" -or $_.ObjectType -like "*f30e3bbe-9ff0-11d1-b603-0000f80367c1*"}
                                     foreach ($ACL in $SitesACL){
                                     if ($ACL.IsInherited -eq $false){
                                     $array= @(); $array +=[pscustomobject]@{
                                     Object = $Site
                                     IdentityReference = $ACL.IdentityReference
                                     AccessControlType = $ACL.AccessControlType
                                     }
                                     $array}
                                     }
                                     }
                                     
    $selectionNames = "Object", "IdentityReference", "AccessControlType"
	return $neededNames, $Results, $selectionNames
}

$GPLink = "GPLink"

function MachinesOutOfDate {
    # Devices that are no longer supported
    [string[]]$ServersOutOfDate = 'Windows Server 2000*', 'Windows Server 2003*', 'Windows Server 2008*', 'Windows Server 1709*', `
    'Windows Server 1709*', 'Windows Server 1803*', 'Windows Server 1903*', 'Windows Server 1903*', `
    'Windows Server 1809*', 'Windows Server 1909*', 'Windows Server 2004*', 'Windows Server 20H2*'                                      

    [string]$ServerLDAPFilter = "(|" + ($ServersOutOfDate | foreach {$_.Insert(0,"(operatingSystem=") + ")"}) + ")"

    
    $ret1 = Get-ADComputer -LDAPFilter "(&(objectCategory=computer)$ServerLDAPFilter)" -Properties Name, OperatingSystem, OperatingSystemVersion | Select-Object Name, OperatingSystem, OperatingSystemVersion
    
    #https://endoflife.date/windows
    [string[]]$DesktopsOutOfDate = 'Windows XP*', 'Windows Vista*', 'Windows 7*', 'Windows 8*'
    [string]$DesktopsLDAPFilter = "(|" + ($DesktopsOutOfDate | foreach {$_.Insert(0,"(operatingSystem=") + ")"}) + ")"
    $ret2 = Get-ADComputer -LDAPFilter "(&(objectCategory=computer)$DesktopsLDAPFilter)" -Properties Name, OperatingSystem, OperatingSystemVersion | Select-Object Name, OperatingSystem, OperatingSystemVersion

#--------------------------------------------------------------------------------------------------------------------------------------------------------------------

    [string[]]$DesktopsPossiblyOutOfDate = 'Windows 10*Enterprise*', 'Windows 10*Education*', 'Windows 10 Home*', 'Windows 10 Pro*'
    #https://learn.microsoft.com/en-us/windows/release-health/release-information
    [string[]]$BuildsOutOfDate =   '*10240*', '*10586*', '*14393*', '*17763*', '*14393*', '*14393*', '*15063*', '*16299*', `
                                   '*15063*', '*17134*', '*15063*', '*17763*', '*18362*', '*18363*', '*19041*', '*19042*', '*19043*', '*19045*'
    [string]$DesktopsLDAPFilter2 = "(|" + ($DesktopsPossiblyOutOfDate | foreach {$_.Insert(0,"(operatingSystem=") + ")"}) + ")" + `
                                   "(|" + ($BuildsOutOfDate           | foreach {$_.Insert(0, "(operatingSystemVersion=") + ")"}) + ")"
    
    $ret3 = Get-ADComputer -LDAPFilter "(&(objectCategory=computer)$DesktopsLDAPFilter2)" -Properties Name, OperatingSystem, OperatingSystemVersion | Select-Object Name, OperatingSystem, OperatingSystemVersion
    
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------

    $ret = @()
    foreach($i in $ret1){
        $i | foreach {$ret += [PSCustomObject]@{Name = $_.Name 
                                                OperatingSystem = $_.OperatingSystem
                                                OperatingSystemVersion = $_.OperatingSystemVersion
                                                MachineType = "Server"}}
    }

    foreach($i in $ret2){
        $i | foreach {$ret += [PSCustomObject]@{Name = $_.Name 
                                                OperatingSystem = $_.OperatingSystem
                                                OperatingSystemVersion = $_.OperatingSystemVersion
                                                MachineType = "Desktop"}}
    }

    foreach($i in $ret3){
        $i | foreach {$ret += [PSCustomObject]@{Name = $_.Name 
                                                OperatingSystem = $_.OperatingSystem
                                                OperatingSystemVersion = $_.OperatingSystemVersion
                                                MachineType = "Desktop"}}
    }

    $neededNames = "Name", "Operating system", "Operating system version", "Machine Type"
    $selectionNames = "Name", "OperatingSystem", "OperatingSystemVersion", "MachineType"

    return $neededNames, $ret, $selectionNames
}
$MachinesOutOfDate = "MachinesOutOfDate"

function InactiveEnabledUsers {
	# Inactive and non-disabled accounts
    $neededNames = "Name", "Last logon date"
    $ret = Get-ADUser -Filter 'enabled -eq $true' -Properties name, lastlogondate | select name, lastlogondate | Where-Object {$_.lastlogondate -le $(Get-Date -date $(get-date).AddDays(-365)) -and $null -ne $_.LastLogonDate}
	$selectionNames = "Name", "LastLogonDate"
	return $neededNames, $ret, $selectionNames
}
$InactiveEnabledUsers = "InactiveEnabledUsers"

function CompDefaultPass {
        # Computer Accounts with default known passwords
        $selectionNames = "ComputersWithDefaultPasswords"
                $ret = Get-ADComputer -Filter * | select -ExpandProperty samaccountname | foreach {$_ = $_ -replace '[$]' ; $pass = $_.ToLower() ; $Password = ConvertTo-SecureString $pass -AsPlainText -Force ; $CompName= (Get-ADDomain | select -ExpandProperty netbiosname) + "\" + $_ ; $cred = New-Object System.Management.Automation.PSCredential ($compName,$Password); $ErrorActionPreference = "SilentlyContinue"; Get-ADDomain -Credential $cred | Out-Null ;if ($?) { $array= @(); $array +=[pscustomobject]@{
    		    ComputersWithDefaultPasswords = $_ } 
                $array}}      
        $neededNames = "Computers With Default Passwords"
	return $neededNames, $ret, $selectionNames
}
$CompDefaultPass = "CompDefaultPass"

function Pre2000Group {
	# List of members from the AD group Pre-Windows 2000 Compatible Access
    $selectionNames = "PreWindows2000CompatibleAccessGroupMembers"
	            $ret = Get-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" | Select-Object -ExpandProperty SAMAccountName | foreach { $array= @(); $array +=[pscustomobject]@{
    		    PreWindows2000CompatibleAccessGroupMembers = $_ } 
                $array} 
 	$neededNames = "Pre-Windows 2000 Compatible Access Group Members"
	return $neededNames, $ret, $selectionNames
}
$Pre2000Group = "Pre2000Group"

 function AzureADSSO {
	# Last password change for AZUREADSSOACC and used encryption algorithms, the script currently expects a vulnerable state in case of an existing AzureADSSO account. It is necessary to check the password age and configured ciphers.
    $neededNames = "ObjectName", "PasswordLastSet", "EncryptionType"
    $AzureADSSOPWD = try { Get-ADComputer AZUREADSSOACC -Properties PasswordLastSet | select -ExpandProperty PasswordLastSet } catch {}
    $AzureADSSOPWD = try { New-TimeSpan -Start $AzureADSSOPWD -end (Get-Date) | select -ExpandProperty Days } catch {}
        $AzureADSSOENC = try {Get-ADComputer AZUREADSSOACC -Properties msDS-SupportedEncryptionTypes | select -ExpandProperty msDS-SupportedEncryptionTypes} catch {}
        if ($AzureADSSOENC -eq $null) { $resultenc = "Supported Encryption Type is not defined - defaults to RC4_HMAC_MD5"}
            elseif ($AzureADSSOENC -eq 1) { $resultenc = "Supported Encryption Type is DES_CBC_CRC"}
            elseif ($AzureADSSOENC -eq 2) { $resultenc = "Supported Encryption Type is DES_CBC_MD5"}
            elseif ($AzureADSSOENC -eq 3) { $resultenc = "Supported Encryption Types are DES_CBC_CRC, DES_CBC_MD5"}
            elseif ($AzureADSSOENC -eq 4) { $resultenc = "Supported Encryption Type is RC4"}
            elseif ($AzureADSSOENC -eq 5) { $resultenc = "Supported Encryption Types are DES_CBC_CRC, RC4"}
            elseif ($AzureADSSOENC -eq 6) { $resultenc = "Supported Encryption Types are DES_CBC_MD5, RC4"}
            elseif ($AzureADSSOENC -eq 7) { $resultenc = "Supported Encryption Types are DES_CBC_CRC, DES_CBC_MD5, RC45"}
            elseif ($AzureADSSOENC -eq 8) { $resultenc = "Supported Encryption Type is AES 128"}
            elseif ($AzureADSSOENC -eq 9) { $resultenc = "Supported Encryption Types are DES_CBC_CRC, AES 128"}
            elseif ($AzureADSSOENC -eq 10) { $resultenc = "Supported Encryption Types are DES_CBC_MD5, AES 128"}
            elseif ($AzureADSSOENC -eq 11) { $resultenc = "Supported Encryption Types are DES_CBC_CRC, DES_CBC_MD5, AES 128"}
            elseif ($AzureADSSOENC -eq 12) { $resultenc = "Supported Encryption Types are RC4, AES 128"}
            elseif ($AzureADSSOENC -eq 13) { $resultenc = "Supported Encryption Types are DES_CBC_CRC, RC4, AES 1285"}
            elseif ($AzureADSSOENC -eq 14) { $resultenc = "Supported Encryption Types are DES_CBC_MD5, RC4, AES 128"}
            elseif ($AzureADSSOENC -eq 15) { $resultenc = "Supported Encryption Types are DES_CBC_CBC, DES_CBC_MD5, RC4, AES 128"}
            elseif ($AzureADSSOENC -eq 16) { $resultenc = "Supported Encryption Type is AES 256"}
            elseif ($AzureADSSOENC -eq 17) { $resultenc = "Supported Encryption Types are DES_CBC_CRC, AES 256"}
            elseif ($AzureADSSOENC -eq 18) { $resultenc = "Supported Encryption Types are DES_CBC_MD5, AES 256"}
            elseif ($AzureADSSOENC -eq 19) { $resultenc = "Supported Encryption Types are DES_CBC_CRC, DES_CBC_MD5, AES 256"}
            elseif ($AzureADSSOENC -eq 20) { $resultenc = "Supported Encryption Types are RC4, AES 256"}
            elseif ($AzureADSSOENC -eq 21) { $resultenc = "Supported Encryption Types are DES_CBC_CRC, RC4, AES 256"}
            elseif ($AzureADSSOENC -eq 22) { $resultenc = "Supported Encryption Types are DES_CBC_MD5, RC4, AES 256"}
            elseif ($AzureADSSOENC -eq 23) { $resultenc = "Supported Encryption Types are DES_CBC_CRC, DES_CBC_MD5, RC4, AES 256"}
            elseif ($AzureADSSOENC -eq 24) { $resultenc = "Supported Encryption Types are AES 128, AES 256"}
            elseif ($AzureADSSOENC -eq 25) { $resultenc = "Supported Encryption Types are DES_CBC_CRC, AES 128, AES 256"}
            elseif ($AzureADSSOENC -eq 26) { $resultenc = "Supported Encryption Types are DES_CBC_MD5, AES 128, AES 256"}
            elseif ($AzureADSSOENC -eq 27) { $resultenc = "Supported Encryption Types are ES_CBC_MD5, DES_CBC_MD5, AES 128, AES 256"}
            elseif ($AzureADSSOENC -eq 28) { $resultenc = "Supported Encryption Types are RC4, AES 128, AES 256"}
            elseif ($AzureADSSOENC -eq 29) { $resultenc = "Supported Encryption Types are DES_CBC_CRC, RC4, AES 128, AES 256"}
            elseif ($AzureADSSOENC -eq 30) { $resultenc = "Supported Encryption Types are DES_CBC_MD5, RC4, AES 128, AES 256"}
            elseif ($AzureADSSOENC -eq 31) { $resultenc = "Supported Encryption Types are DES_CBC_CRC, DES_CBC_MD5, RC4-HMAC, AES128-CTS-HMAC-SHA1-96, AES256-CTS-HMAC-SHA1-96"}

        $AzureADSSO = try {Get-ADComputer AZUREADSSOACC -Properties Name, PasswordLastSet, msDS-SupportedEncryptionTypes | select Name, PasswordLastSet, msDS-SupportedEncryptionTypes} catch {}
        $array= @(); $array +=[pscustomobject]@{                   
                              ObjectName = $AzureADSSO.Name 
                              PasswordLastSet = $AzureADSSO.PasswordLastSet
                              EncryptionType = $resultenc
                              }
    if ($array.ObjectName){
     } else { 
     $array=""
     }
    $selectionNames = "ObjectName", "PasswordLastSet", "EncryptionType"
	return $neededNames, $Array, $selectionNames
}
$AzureADSSO = "AzureADSSO"

 function ProtectedUsers {
	# Group protecting privileged accounts from, for example, NTLM authentication, delegation, ...
    $neededNames = "Name", "AdminCount"
        $ret = Get-ADGroupMember "Protected Users" | Get-ADUser -Properties Name, AdminCount | select Name, AdminCount
	$selectionNames = "Name", "AdminCount"
	return $neededNames, $ret, $selectionNames
}
$ProtectedUsers = "ProtectedUsers"

 function SMB1 {
	# Function to detect SMB protocol settings (directly from DC) - privileges needed
    $selectionNames = "DomainController", "SMBv1Enabled", "SMBSigningEnabled", "SMBSigningRequired"
        $ret= try {Get-ADDomainController -filter * | select -ExpandProperty Hostname | foreach { $array= @(); $array +=[pscustomobject]@{
                                                                   DomainController = $_
                                                                   SMBv1Enabled = (invoke-command -ComputerName $_ -ScriptBlock {Get-SmbServerConfiguration | select -ExpandProperty EnableSMB1Protocol})
                                                                   SMBSigningEnabled = (invoke-command -ComputerName $_ -ScriptBlock {Get-SmbServerConfiguration | select -ExpandProperty EnableSecuritySignature})
                                                                   SMBSigningRequired = (invoke-command -ComputerName $_ -ScriptBlock {Get-SmbServerConfiguration | select -ExpandProperty RequireSecuritySignature})
                                                                   }                                                       
                                                                    $array}} catch {}
    $neededNames = "Domain Controller", "SMBv1 Enabled", "SMB Signing Enabled", "SMB Signing Required"
	return $neededNames, $ret, $selectionNames
}

function SMB2 {
	# Function to detect SMB protocol settings from GPO
    $selectionNames = "GPO", "Setting", "Option"
      [xml]$XML=Get-GPOReport -All -ReportType Xml
      $XML2 = ($XML | Select-Xml -XPath '/GPOS' -Namespace @{gpo = "http://www.microsoft.com/GroupPolicy/Settings"}).Node | select -ExpandProperty GPO
        $results=foreach ($GPO in $XML2){
            $array= @(); $array +=[pscustomobject]@{
                      GPO = $GPO.Name
                      Setting = $GPO.Computer.ExtensionData.Extension.SecurityOptions.Display | ?{$_.Name -like "*Client: Digitally sign communications*(always)*"} | select -ExpandProperty Name
                      Option = $GPO.Computer.ExtensionData.Extension.SecurityOptions.Display | ?{$_.Name -like "*Client: Digitally sign communications*(always)*"} | select -ExpandProperty DisplayBoolean
              
                        }
                        $array +=[pscustomobject]@{
                      GPO = $GPO.Name
                      Setting = $GPO.Computer.ExtensionData.Extension.SecurityOptions.Display | ?{$_.Name -like "*Server: Digitally sign communications*(always)*"} | select -ExpandProperty Name
                      Option = $GPO.Computer.ExtensionData.Extension.SecurityOptions.Display | ?{$_.Name -like "*Server: Digitally sign communications*(always)*"} | select -ExpandProperty DisplayBoolean
              
                        }                                                        
                 $array}

         $ret = $results | ?{$_.Setting -like "*"}
 
    $neededNames = "GPO", "Setting", "Option"
	return $neededNames, $ret, $selectionNames
}

$SMB = "SMB1", "SMB2"

 function KerberosEncryption {
	# Function to detect encryption settings of the Kerberos protocol
    $selectionNames = "GPO", "Setting", "Option"
        [xml]$XML=Get-GPOReport -All -ReportType Xml
        $XML2 = ($XML | Select-Xml -XPath '/GPOS' -Namespace @{gpo = "http://www.microsoft.com/GroupPolicy/Settings"}).Node | select -ExpandProperty GPO



        $results=foreach ($GPO in $XML2){
        $array= @(); $array +=[pscustomobject]@{
                      GPO = $GPO.Name
                      Setting = $GPO.Computer.ExtensionData.Extension.SecurityOptions.Display | ?{$_.Name -like "*Network security: Configure encryption types allowed for Kerberos*"} | select -ExpandProperty Name
                      Option = $GPO.Computer.ExtensionData.Extension.SecurityOptions.Display | ?{$_.Name -like "*Network security: Configure encryption types allowed for Kerberos*"} | select -ExpandProperty DisplayFields | select -ExpandProperty Field | ?{$_.Value -eq "true"} | Select -ExpandProperty Name   
                        }                                                       
                 $array}

        $ret = $results | ?{$_.Setting -like "*"}
    $neededNames = "GPO", "Setting", "Option"
	return $neededNames, $ret, $selectionNames
}

$KerberosEncryption = "KerberosEncryption"function NTLM {
	# Function to detect NTLM settings
    $selectionNames = "GPO", "Setting", "Option"
        [xml]$XML=Get-GPOReport -All -ReportType Xml
        $XML2 = ($XML | Select-Xml -XPath '/GPOS' -Namespace @{gpo = "http://www.microsoft.com/GroupPolicy/Settings"}).Node | select -ExpandProperty GPO



        $results=foreach ($GPO in $XML2){
        $array= @(); $array +=[pscustomobject]@{
                      GPO = $GPO.Name
                      Setting = $GPO.Computer.ExtensionData.Extension.SecurityOptions.Display | ?{$_.Name -like "*Lan Manager Authentication level*"} | select -ExpandProperty Name
                      Option = $GPO.Computer.ExtensionData.Extension.SecurityOptions.Display | ?{$_.Name -like "*Lan Manager Authentication level*"} | select -ExpandProperty DisplayString
                        }                                                       
                 $array}
        $results+=foreach ($GPO in $XML2){
        $array= @(); $array +=[pscustomobject]@{
                      GPO = $GPO.Name
                      Setting = $GPO.Computer.ExtensionData.Extension.SecurityOptions.Display | ?{$_.Name -like "*NTLM SSP Based*clients*"} | select -ExpandProperty Name
                      Option = $GPO.Computer.ExtensionData.Extension.SecurityOptions.Display | ?{$_.Name -like "*NTLM SSP Based*clients*"} | select -ExpandProperty DisplayFields | select -ExpandProperty Field | ?{$_.Value -eq "true"} | Select -ExpandProperty Name
                        }                                                       
                 $array}
        $results+=foreach ($GPO in $XML2){
        $array= @(); $array +=[pscustomobject]@{
                      GPO = $GPO.Name
                      Setting = $GPO.Computer.ExtensionData.Extension.SecurityOptions.Display | ?{$_.Name -like "*NTLM SSP Based*servers*"} | select -ExpandProperty Name
                      Option = $GPO.Computer.ExtensionData.Extension.SecurityOptions.Display | ?{$_.Name -like "*NTLM SSP Based*servers*"} | select -ExpandProperty DisplayFields | select -ExpandProperty Field | ?{$_.Value -eq "true"} | Select -ExpandProperty Name
                        }                                                       
                 $array}
        $results+=foreach ($GPO in $XML2){
        $array= @(); $array +=[pscustomobject]@{
                      GPO = $GPO.Name
                      Setting = $GPO.Computer.ExtensionData.Extension.SecurityOptions.Display | ?{$_.Name -like "*Lan Manager hash*"}  | select -ExpandProperty Name
                      Option = $GPO.Computer.ExtensionData.Extension.SecurityOptions.Display | ?{$_.Name -like "*Lan Manager hash*"} | select -ExpandProperty DisplayBoolean
                        }                                                       
                 $array}

        $ret = $results | ?{$_.Setting -like "*"}
    $neededNames = "GPO", "Setting", "Option"
	return $neededNames, $ret, $selectionNames
}

$NTLM = "NTLM"
 function LDAP {
	# Function to detect LDAP protocol settings
    $selectionNames = "GPO", "Setting", "Option"
        [xml]$XML=Get-GPOReport -All -ReportType Xml
        $XML2 = ($XML | Select-Xml -XPath '/GPOS' -Namespace @{gpo = "http://www.microsoft.com/GroupPolicy/Settings"}).Node | select -ExpandProperty GPO

        $results=foreach ($GPO in $XML2){
        $array= @(); $array +=[pscustomobject]@{
                        GPO = $GPO.Name
                        Setting = $GPO.Computer.ExtensionData.Extension.SecurityOptions.Display | ?{$_.Name -like "*Domain controller: LDAP*"} | select -ExpandProperty Name
                        Option = $GPO.Computer.ExtensionData.Extension.SecurityOptions.Display | ?{$_.Name -like "*Domain controller: LDAP*"} | select -ExpandProperty DisplayString
              
                        }                                                       
                     $array +=[pscustomobject]@{
                      GPO = $GPO.Name
                      Setting = $GPO.Computer.ExtensionData.Extension.SecurityOptions.Display | ?{$_.Name -like "*Network security: LDAP*"} | select -ExpandProperty Name
                      Option = $GPO.Computer.ExtensionData.Extension.SecurityOptions.Display | ?{$_.Name -like "*Network security: LDAP*"} | select -ExpandProperty DisplayString
              
                        }                                                       
                 $array}

        $ret = $results | ?{$_.Setting -like "*"}
    $neededNames = "GPO", "Setting", "Option"
	return $neededNames, $ret, $selectionNames
}

$LDAP = "LDAP"

function RODCGroups {
	#Searching for RODC Group members
	$neededNames = "Name", "Desc"
	$AllowRODC=Get-ADGroupMember "Allowed RODC Password Replication Group" | foreach { if($_.ObjectClass -eq "group") { Get-ADGroupMember $_ | foreach { Get-ADUser $_ -Properties Name,AdminCount | ?{$_.AdminCount -eq "1" }}  } else { Get-ADUser $_ -Properties Name,AdminCount | ?{$_.AdminCount -eq "1" }}} | select Name,AdminCount
    $results=foreach ($User in $AllowRODC){
        $array= @(); $array +=[pscustomobject]@{
                      Name = $User.Name
                      Desc = "Administrator Account is allowed to be cached!"
                        }                                                       
                 $array}
    $DefaultRODC=@(
    "Cert Publishers",             
    "Domain Admins",             
    "Domain Controllers",     
    "Enterprise Admins",  
    "Group Policy Creator Owners",
    "krbtgt",                   
    "Read-only Domain Controllers",
    "Schema Admins"
    )
	$DenyRODC=Get-ADGroupMember "Denied RODC Password Replication Group" | select -ExpandProperty name | sort -Property Name
    $DiffRODC=Compare-Object -ReferenceObject $DefaultRODC -DifferenceObject $DenyRODC | select -ExpandProperty InputObject
        $results+=foreach ($object in $DiffRODC){
        $array= @(); $array +=[pscustomobject]@{
                      Name = $object
                      Desc = "Deny group is not in default state!"
                        }                                                       
                 $array}
    $selectionNames = "Name", "Desc"
	return $neededNames, $results, $selectionNames
}

$RODCGroups="RODCGroups"

function LAPS {
	#Searching for LAPS permissions
	$selectionNames = "Object", "Type", "IdentityReference", "Attribute", "ActiveDirectoryRights"
            #read property / readproperty specificky atribut
            $results= try {Get-ADComputer -Filter * | foreach {$ACL= (Get-Acl -Path "AD:$_").Access | ?{$_.ObjectType -like "8f76d561-facd-4b6c-9606-3216035d899e" -and $_.IdentityReference -notlike "NT AUTHORITY\SELF"}
                          $array= @(); $array +=[pscustomobject]@{
                                      Object = $_.Name
                                      Type = "Computer"
                                      IdentityReference = $ACL.IdentityReference
                                      Attribute = if ($ACL.ObjectType -eq "8f76d561-facd-4b6c-9606-3216035d899e") {"ms-Mcs-AdmPwd"} else {"ms-Mcs-AdmPwdExpirationTime"}
                                      ActiveDirectoryRights = $ACL.ActiveDirectoryRights
                                          }
                                        $array} } catch {}
            #read all / ReadProperty
            $MSOL=(Get-ADUser -Filter 'Name -like "*MSOL_*"' -Properties Name,Description | ?{$_.Description -like "Account created by Microsoft Azure Active*"}).Name
            $results+= try {Get-ADComputer -Filter * | foreach {$ACL= (Get-Acl -Path "AD:$_").Access | ?{$_.ActiveDirectoryRights -like "ReadProperty" -and $_.ObjectType -like "00000000-0000-0000-0000-000000000000" -and $_.IdentityReference -notlike "*$MSOL*"}
                          $array= @(); $array +=[pscustomobject]@{
                                      Object = $_.Name
                                      Type = "Computer"
                                      IdentityReference = $ACL.IdentityReference
                                      Attribute = ""
                                      ActiveDirectoryRights = $ACL.ActiveDirectoryRights
                                          }
                                        $array}} catch {}
            #full / genericall
            $results+= try {Get-ADComputer -Filter * | foreach {$ACL= (Get-Acl -Path "AD:$_").Access | ?{$_.ActiveDirectoryRights -like "GenericAll" -and $_.ObjectType -like "00000000-0000-0000-0000-000000000000" -and $_.AccessControlType -like "Allow" -and $_.IdentityReference -notlike "*\Domain Admins" -and $_.IdentityReference -notlike "NT AUTHORITY\SYSTEM" -and $_.IdentityReference -notlike "*\Exchange Trusted Subsystem" -and $_.IdentityReference -notlike "*\Enterprise Admins" -and $_.IdentityReference -notlike "S-1-5-32-548" -and $_.IdentityReference -notlike "*Account Operators*"  }
                          $array= @(); $array +=[pscustomobject]@{
                                      Object = $_.Name
                                      Type = "Computer"
                                      IdentityReference = $ACL.IdentityReference
                                      Attribute = ""
                                      ActiveDirectoryRights = $ACL.ActiveDirectoryRights
                                          }
                                        $array}} catch {}
            #extended / extendedright
            $results+= try {Get-ADObject -Filter * | ?{$_.ObjectClass -like "Container" -or $_.ObjectClass -like "OrganizationalUnit" -and $_.DistinguishedName -notlike "*CN=System,*" -and $_.DistinguishedName -notlike "*CN=Program Data,*"} | foreach {$ACL=(Get-Acl -Path "AD:$_").Access | ?{$_.ActiveDirectoryRights -like "*ExtendedRight*" -and $_.IsInherited -like "False" -and $_.IdentityReference -notlike "*\Domain Admins" -and $_.IdentityReference -notlike "NT AUTHORITY\SELF" -and $_.IdentityReference -notlike "*RAS and IAS Servers*" -and $_.IdentityReference -notlike "*NT AUTHORITY\Enterprise Domain Controllers*"}
                          $array= @(); $array +=[pscustomobject]@{
                                      Object = $_.Name
                                      Type = $_.ObjectClass
                                      IdentityReference = $ACL.IdentityReference
                                      Attribute = ""
                                      ActiveDirectoryRights = "Extended Right"
                                          }
                                        $array}} catch {}
            $Ret = $Results | ?{$_.IdentityReference -notlike $null} | Sort-Object -Property IdentityReference
            $neededNames = "Object", "Type", "IdentityReference", "Attribute", "ActiveDirectoryRights"
	return $neededNames, $ret, $selectionNames
}

$LAPS="LAPS"

function CPassword {
    #Searching SYSVOL for passwords in GPOs - Deprecated function in AD - https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30
    $selectionNames = "GPO", "File"
    $domain = Get-ADDomain | select -ExpandProperty Forest
    $XMLs = findstr /S /I cpassword \\$domain\SYSVOL\$domain\Policies\*.xml
        $results = foreach ($xml in $XMLs) {
        $filePath = $xml -split ':' | Select-Object -First 1
        $pattern = '(?<=\{)[0-9A-Fa-f\-]{36}(?=\})'
        $GUID = [regex]::Match($filePath, $pattern).Value
        $GPO = Get-GPO -Guid $GUID
        $Array = @()
            $Array += [pscustomobject]@{
            GPO  = $GPO.DisplayName
            File = $filePath
    }
    $Array
}

$neededNames = "GPO", "File"
return $neededNames, $results, $selectionNames
}

$CPassword="CPassword"

function DNSDynUpdate {
    #Searching for DNS Dynamic Updates Zone's configuration - looking for nonsecure
    $selectionNames = "ZoneName", "DynamicUpdate"
    $DC=Get-ADDomainController | select -First 1 | select -ExpandProperty Name
    $DNSZones=Get-DnsServerZone -ComputerName $DC
    $results= try { foreach ($DNSZone in $DNSZones) {
        if ($DNSZone.DynamicUpdate -like "*nonsec*"){
        $DNSZone | select Zonename, DynamicUpdate
        }
        }} catch {}
    $neededNames = "ZoneName", "DynamicUpdate"
	return $neededNames, $results, $selectionNames
}

$DNSDynUpdate="DNSDynUpdate"

function ADCSESC1 {
    #Searching for vulnerability/misconfiguration in AD CS - ESC1 - https://m365internals.com/2022/11/07/investigating-certificate-template-enrollment-attacks-adcs/, https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation
    $selectionNames = "Object", "Type", "IdentityReference", "ActiveDirectoryRights", "ObjectType"
    $results = try {Get-ADObject -LDAPFilter '(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2) (pkiextendedkeyusage=1.3.6.1.5.2.3.4))(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1))' -SearchBase "CN=Configuration,$ADroot" | foreach { $ACL=(Get-Acl -Path AD:$_).Access | ?{($_.IdentityReference -notlike "*Enterprise Admins*" -and $_.IdentityReference -notlike "*Domain Admins*") -and ($_.ActiveDirectoryRights -like "GenericAll" -or $_.ObjectType -like "0e10c968-78fb-11d2-90d4-00c04f79dc55")}
                        $array= @(); $array +=[pscustomobject]@{
                                      Object = $_.Name
                                      Type = $_.ObjectClass
                                      IdentityReference = $ACL.IdentityReference
                                      ActiveDirectoryRights = $ACL.ActiveDirectoryRights
                                      ObjectType = $ACL.ObjectType
                                          }
                                      $array}} catch {}
    $results = $results | ?{$_.IdentityReference -notlike ""}
    $neededNames = "Object", "Type", "IdentityReference", "ActiveDirectoryRights", "ObjectType"
	return $neededNames, $results, $selectionNames
}

$ADCSESC1="ADCSESC1"

function ADCSESC2 {
    #Searching for vulnerability/misconfiguration in AD CS - ESC2 - https://github.com/GhostPack/PSPKIAudit#esc1---misconfigured-certificate-templates
    $selectionNames = "Object", "Type", "IdentityReference", "ActiveDirectoryRights", "ObjectType"
    $results = try {Get-ADObject -LDAPFilter '(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1))' -SearchBase "CN=Configuration,$ADroot" | foreach {$ACL=(Get-Acl -Path AD:$_).Access | ?{($_.IdentityReference -notlike "*Enterprise Admins*" -and $_.IdentityReference -notlike "*Domain Admins*") -and ($_.ActiveDirectoryRights -like "GenericAll" -or $_.ObjectType -like "0e10c968-78fb-11d2-90d4-00c04f79dc55")}
                        $array= @(); $array +=[pscustomobject]@{
                                      Object =$_.Name
                                      Type = $_.ObjectClass
                                      IdentityReference = $ACL.IdentityReference
                                      ActiveDirectoryRights = $ACL.ActiveDirectoryRights
                                      ObjectType = $ACL.ObjectType
                                          }
                                      $array}} catch {}
    $results = $results | ?{$_.IdentityReference -notlike ""}
    $neededNames = "Object", "Type", "IdentityReference", "ActiveDirectoryRights", "ObjectType"
	return $neededNames, $results, $selectionNames
}

$ADCSESC2="ADCSESC2"

function ADCSESC3 {
    #Searching for vulnerability/misconfiguration in AD CS - ESC3 - https://github.com/GhostPack/PSPKIAudit#esc1---misconfigured-certificate-templates
    $selectionNames = "Object", "Type", "IdentityReference", "ActiveDirectoryRights", "ObjectType"
    $results = try {Get-ADObject -LDAPFilter '(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.1))(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1))' -SearchBase "CN=Configuration,$ADroot" | foreach {$ACL=(Get-Acl -Path AD:$_).Access | ?{($_.IdentityReference -notlike "*Enterprise Admins*" -and $_.IdentityReference -notlike "*Domain Admins*") -and ($_.ActiveDirectoryRights -like "GenericAll" -or $_.ObjectType -like "0e10c968-78fb-11d2-90d4-00c04f79dc55")}
                        $array= @(); $array +=[pscustomobject]@{
                                      Object =$_.Name
                                      Type = $_.ObjectClass
                                      IdentityReference = $ACL.IdentityReference
                                      ActiveDirectoryRights = $ACL.ActiveDirectoryRights
                                      ObjectType = $ACL.ObjectType
                                          }
                                      $array}} catch {}
    $results = $results | ?{$_.IdentityReference -notlike ""}
    $neededNames = "Object", "Type", "IdentityReference", "ActiveDirectoryRights", "ObjectType"
	return $neededNames, $results, $selectionNames
}

$ADCSESC3="ADCSESC3"

function ADCSESC4 {
    #Searching for vulnerability/misconfiguration in AD CS - ESC4 - https://github.com/GhostPack/PSPKIAudit#esc1---misconfigured-certificate-templates
    $selectionNames = "Object", "Type", "IdentityReference", "ActiveDirectoryRights"
    $results = try {Get-ADObject -LDAPFilter '(objectclass=pkicertificatetemplate)' -SearchBase "CN=Configuration,$ADroot" | foreach {$ACL=(Get-Acl -Path AD:$_).Access | ?{$_.IdentityReference -notlike "*Domain Admins" -and $_.IdentityReference -notlike "*Enterprise Admins" -and $_.IdentityReference -notlike "*Domain Controllers*" -and $_.ActiveDirectoryRights -ne "GenericRead" -and $_.ActiveDirectoryRights -ne "ReadProperty, GenericExecute" -and $_.ActiveDirectoryRights -ne "ReadProperty, WriteProperty, ExtendedRight"}
                        $array= @(); $array +=[pscustomobject]@{
                                      Object =$_.Name
                                      Type = $_.ObjectClass
                                      IdentityReference = $ACL.IdentityReference
                                      ActiveDirectoryRights = $ACL.ActiveDirectoryRights
                                          }
                                      $array}} catch {}
    $results = $results | ?{$_.IdentityReference -notlike ""}
    $neededNames = "Object", "Type", "IdentityReference", "ActiveDirectoryRights"
	return $neededNames, $results, $selectionNames
}

$ADCSESC4="ADCSESC4"

function ADCSESC6 {
    #Searching for vulnerability/misconfiguration in AD CS - ESC6 - https://github.com/GhostPack/PSPKIAudit#esc1---misconfigured-certificate-templates
    $selectionNames = "CA", "EditFlags"
    $CAs=Get-ADObject -LDAPFilter '(objectclass=pkienrollmentservice)' -SearchBase "CN=Configuration,$ADroot" -Properties DNSHostname,CN
    $CAs=$CAs.DNSHostname+"\"+$CAs.CN
    $results =  try {foreach ($CA in $CAs) {if ((certutil -config $CA -getreg "policy\EditFlags") -like "*EDITF_ATTRIBUTESUBJECTALTNAME2*"){$flag=certutil -config $CA -getreg "policy\EditFlags" | select-string "EDITF_ATTRIBUTESUBJECTALTNAME2"} else {$flag=""}
                        $array= @(); $array +=[pscustomobject]@{
                                      CA =$CA
                                      EditFlags = $flag
                                          }
                                      $array}} catch {}
    $results = $results | ?{$_.EditFlags -notlike ""}
    $neededNames = "CA", "EditFlags"
	return $neededNames, $results , $selectionNames
}

$ADCSESC6="ADCSESC6"

function ADCSESC8 {
    #Searching for vulnerability/misconfiguration in AD CS - ESC8 - https://github.com/GhostPack/PSPKIAudit#esc1---misconfigured-certificate-templates
    $selectionNames = "CA", "HTTP", "HTTPS"
    $results = (Get-ADObject -LDAPFilter '(objectclass=pkienrollmentservice)' -SearchBase "CN=Configuration,$ADroot" -Properties DNSHostname).DNSHostname | ForEach-Object {invoke-WebRequest -Uri "http://$_/certsrv" -DisableKeepAlive -UseBasicParsing -Method Head -ErrorVariable Error0
                        $array= @(); $array +=[pscustomobject]@{
                                          CA = $_
                                          HTTP = $(if (($Error0 -notlike '*404*') -and ($Error0 -notlike "*unable to connect to the remote server*")) {'Web Enrollment running'} else {''})
                                          HTTPS = ""
                                              }
                                          $array}

    $results += (Get-ADObject -LDAPFilter '(objectclass=pkienrollmentservice)' -SearchBase "CN=Configuration,$ADroot" -Properties DNSHostname).DNSHostname | ForEach-Object {invoke-WebRequest -Uri "https://$_/certsrv" -DisableKeepAlive -UseBasicParsing -Method Head -ErrorVariable Error0
                        $array= @(); $array +=[pscustomobject]@{
                                          CA = $_
                                          HTTP = ""
                                          HTTPS = $(if (($Error0 -notlike '*404*') -and ($Error0 -notlike "*unable to connect to the remote server*")) {'Web Enrollment running'} else {''})
                                              }
                                          $array}
    $results = $results | ?{$_.HTTP -notlike "" -or $_.HTTPS -notlike ""}
    $neededNames = "CA", "HTTP", "HTTPS"
	return $neededNames, $results , $selectionNames
}

$ADCSESC8="ADCSESC8"

function ComputerOwner {
	#AD Objects created for last 30 days
	$neededNames = "DN", "Owner", "Created"
    $Computers=Get-ADComputer -Filter * -Properties DistinguishedName,whenCreated
    $results= foreach ($Computer in $Computers){
        $ObjectOwner=(Get-ADComputer $Computer -Properties NTSecurityDescriptor).NTSecurityDescriptor.owner
        if ($ObjectOwner -notlike "*\Domain Admins"){
        $Array = @() ; $array +=[pscustomobject]@{
        DN = $Computer.DistinguishedName
        Owner = $ObjectOwner
        Created = $Computer.whenCreated
        }
        $Array}
        }
	$selectionNames = "DN", "Owner", "Created"
	return $neededNames, $results, $selectionNames
}
$ComputerOwner = "ComputerOwner"

$firstChapterScripts = "DefPol", "PwdLastSet","ADCSESC1","ADCSESC2", "ADCSESC3","ADCSESC4", "ADCSESC6", "ADCSESC8", "AzureADSSO", "CompDefaultPass", "ConstrainedDelegation", "DNSDynUpdate", "ComputerOwner", "GPO","GPLink", "InactiveEnabledUsers", "KerberosEncryption", "LAPS", "LDAP", "MachinesOutOfDate", "NTLM","CPassword","Pre2000Group", "ProtectedUsers", "RODCGroups", "RBConstrainedDelegation", "privAccounts", "SMB", "trust", "UnconstrainedDelegation", "adminNum", "badPwdNum", "kerberosPreAuth", "accWithoutPwd", "kerberos", "pwdDesc", "endlessPwd", "weakEnc", "spn"           

## Chapter 1 scripts - end

function AdminSDHolder {
	#AdminSDHolder, Generic All, Reset Passwords, Member
	$neededNames = "Identity Reference", "Active Directory Rights", "Object Type", "Inherited Object Type", "Access Control Type"
	$DN=Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
	$AdminSDHolderCN="CN=AdminSDHolder,CN=System,$DN"
	$AdminSDHolder=(Get-Acl -path $("AD:$AdminSDHolderCN")).access | Where-Object{$_.AccessControlType -eq "Allow" -and $_.ActiveDirectoryRights -eq "GenericAll" -or $_.ObjectType -eq "00299570-246d-11d0-a768-00aa006e0529" -or $_.ObjectType -eq "bf9679c0-0de6-11d0-a285-00aa003049e2"} | Select-Object ActiveDirectoryRights, ObjectType, InheritedObjectType, AccessControlType, IdentityReference
	$selectionNames = "IdentityReference", "ActiveDirectoryRights", "ObjectType", "InheritedObjectType", "AccessControlType"
	return $result = $neededNames, $AdminSDHolder, $selectionNames
}
$adminHolder = "AdminSDHolder"


function KRBTGT {
	#krbtgt account
	$neededNames = "Name", "Password Last Set", "Last Logon"
	$KRBTGT=Get-ADUser krbtgt -Properties Name, pwdLastSet, lastlogon | select name, @{N='pwdlastset' ; E={[DateTime]::FromFileTime($_.PwdLastSet)}}, @{N='LastLogon' ; E={[DateTime]::FromFileTime($_.LastLogon)}}
	$selectionNames = "Name", "pwdLastSet", "lastlogon"
	return $result = $neededNames, $KRBTGT, $selectionNames
}
$krbtgt = "KRBTGT"


function PrivilegedGroups {
	#Privileged groups
	$neededNames = "Group", "Members"
	$Groups=@("Account Operators","Server Operators", "Print Operators", "Backup Operators", "Replicator", "Key Admins", "Enterprise Key Admins", "Domain Controllers", "Enterprise Read-Only Domain Controllers", "Administrators", "Domain Admins", "Enterprise Admins", "Schema Admins","DNSAdmins")
	$PrivilegedGroups = New-Object System.Collections.ArrayList
	foreach ($group in $groups) {
		$Members= try { ((Get-ADGroupMember -Identity $group | Select-Object -ExpandProperty SAMAccountName) -Join ", ") } catch { continue }
		$PrivilegedGroups.Add( [PsCustomObject]@{ "Group" = $group; "Members" = $Members } ) >> $null
	}
	$selectionNames = "Group", "Members"
	return $neededNames, $PrivilegedGroups, $selectionNames
}
$privilegedGroups = "PrivilegedGroups"


function ShadowsPrincipals {
	#Searching for shadow principals
	$neededNames = "Distinguished Name", "ObjectClass", "ObjectGUID"
	$DN=Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
	$ShadowsPrincipals=Get-ADObject -SearchBase "CN=Shadow Principal Configuration,CN=Services,CN=Configuration,$DN" -Filter * -Properties DistinguishedName, ObjectClass, ObjectGUID |Select-Object DistinguishedName, ObjectClass, ObjectGUID | ?{$_.DistinguishedName -notlike "CN=Shadow Principal Configuration,CN=Services,*"}
	$selectionNames = "DistinguishedName", "ObjectClass", "ObjectGUID"
	return $neededNames, $ShadowsPrincipals, $selectionNames
}
$shadowsPrincipals = "ShadowsPrincipals"


function SIDHistory {
	#Searching for SIDHistory values
	$neededNames = "Name", "User Principal Name", "SID History"
	$SIDHistory=Get-ADObject -LDAPFilter "(sidhistory=*)" -Properties Name, UserPrincipalName, SIDHistory | Select-Object Name, UserPrincipalName, @{N="SIDHistory";E={$_.SIDHistory -join ", "}}
	$selectionNames = "Name", "UserPrincipalName", "SIDHistory"
	return $neededNames, $SIDHistory, $selectionNames
}
$sidHistory = "SIDHistory"


function PrimaryGroup1 {
	#users where primary group isn't 'domain users'
	$neededNames = "Name", "User Principal Name", "Primary Group"
	$PrimaryGroup1=Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(!(primaryGroupID=513))(!(Name=Guest)))' -Properties Name, UserPrincipalName, PrimaryGroup | Select-Object Name, UserPrincipalName, PrimaryGroup
	$selectionNames = "Name", "UserPrincipalName", "PrimaryGroup"
	return $neededNames, $PrimaryGroup1, $selectionNames
}
$primaryGroup = "PrimaryGroup1"


function DomainControllers {
	#computers with primary group of domain controllers
	$neededNames = "Name", "Primary Group"
	$DomainControllers=Get-ADComputer -LDAPFilter '(&(objectCategory=computer)(primaryGroupID=516))' -Properties Name, PrimaryGroup | Select-Object Name, PrimaryGroup
	$selectionNames = "Name", "PrimaryGroup"
	return $neededNames, $DomainControllers, $selectionNames
}
$domainCont = "DomainControllers"


function DCSync {
	#Account with DCSync right - Directory Replicating Changes / ALL / filtered set
	$neededNames = "Identity Reference", "Access Control Type"
	$ADroot=Get-ADObject (Get-ADDomain | Select-Object -ExpandProperty DistinguishedName)
	$DCSync=(Get-Acl -path $("AD:$ADRoot")).access | Where-Object{$_.ObjectType -like "*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" -or $_.ObjectType -like "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" -or $_.ObjectType -like "*89e95b76-444d-4c62-991a-0facbeda640c*"}| Select-Object IdentityReference, AccessControlType
	$selectionNames = "IdentityReference", "AccessControlType"
	return $neededNames, $DCSync, $selectionNames
}
$dcSync = "DCSync"


function DCShadow1 {
	#Account with DCShadow right - Add/Remove Replica In Domain, DS-Replication-Synchronize, DS-Replication-Manage-Topology
	$neededNames = "Identity Reference", "Access Control Type" 
	$ADroot=Get-ADObject (Get-ADDomain | Select-Object -ExpandProperty DistinguishedName)
	$DCShadow1=(Get-Acl -path $("AD:$ADRoot")).access |  Where-Object{$_.ObjectType -like "*1131f6ac-9c07-11d1-f79f-00c04fc2dcd2*" -or $_.ObjectType -like "*1131f6ab-9c07-11d1-f79f-00c04fc2dcd2*" -or $_.ObjectType -like "*9923a32a-3607-11d2-b9be-0000f87a36b2*"}| Select-Object IdentityReference, AccessControlType
	$selectionNames = "IdentityReference", "AccessControlType"
	return $neededNames, $DCShadow1, $selectionNames
}
$shadowA = "DCShadow1"


function DCShadow2 {
	#DCShadow Computer SPN
	$neededNames = "Distinguished Name", "Name" 
	$DCShadow2=Get-ADComputer -LDAPFilter "(&(objectClass=computer)(servicePrincipalName=E3514235-4B06-11D1-AB04-00C04FC2DCD2*)(!(servicePrincipalName=ldap*)))" | Select-Object DistinguishedName, Name
	$selectionNames = "DistinguishedName", "Name"
	return $neededNames, $DCShadow2, $selectionNames
}
$shadowB = "DCShadow2"


function HiddenObjectNoAccess {
	#Hidden Object No Access
	$neededNames = "Distinguished Name"
	$HiddenObjectNoAccess=Get-ADObject -Filter * -Properties DistinguishedName | Where-Object{$_.ObjectClass -eq $null} | Select-Object DistinguishedName
	$selectionNames = "DistinguishedName"
	return $neededNames, $HiddenObjectNoAccess, $selectionNames
}


function HiddenObjectDenyList {
	#Hidden Object Deny List
	$neededNames = "OUName", "Active Directory Rights", "Inheritance Type", "Object Type", "Inherited Object Type", "Object Flags", "Access Control Type", "Identity Reference", "Is Inherited", "Inheritance Flags", "Propagation Flags"
	$HiddenObjectDenyList= @()
	$ADObjects=Get-ADObject -Filter *
	foreach ($object in $ADObjects){
	$ACL=(Get-ACL -ErrorAction SilentlyContinue -Path $("AD:$object")).access | Where-Object {$_.AccessControlType -eq "Deny" -and $_.ActiveDirectoryRights -like "ListChildren"}
		if ($ACL -ne $null)  {
			Add-Member -InputObject $ACL -Name OUName -Value $object -MemberType NoteProperty
			$HiddenObjectDenyList += $ACL
		}
	}
	$selectionNames = "OUName", "ActiveDirectoryRights", "InheritanceType", "ObjectType", "InheritedObjectType", "ObjectFlags", "AccessControlType", "IdentityReference", "IsInherited", "InheritanceFlags", "PropagationFlags"
	return $neededNames, $HiddenObjectDenyList, $selectionNames
}

function HiddenAccount {
	#Hidden Accounts
	$neededNames = "Value"
	function Get-RIDsRemaining
	{
		param ($domainDN)
		$de = [ADSI]"LDAP://CN=RID Manager$,CN=System,$domainDN"
		$return = new-object system.DirectoryServices.DirectorySearcher($de)
		$property= ($return.FindOne()).properties.ridavailablepool
		[int32]$totalSIDS = $($property) / ([math]::Pow(2,32))
		[int64]$temp64val = $totalSIDS * ([math]::Pow(2,32))
		[int32]$currentRIDPoolCount = $($property) - $temp64val
		$ridsremaining = $totalSIDS - $currentRIDPoolCount
		return $currentRIDPoolCount
	}

	$ErrorActionPreference = "SilentlyContinue"
	$HiddenAccount=@()
	$DomainDN = ([adsi]"LDAP://RootDSE").defaultNamingContext
	$Domain=[adsi]"LDAP://$DomainDN"
	$DomainName = $Domain.name.ToString().ToLower()
	$DomainSIDBytes = $Domain.Properties.ObjectSID.Value
	$DomainStringSID = (New-Object System.Security.Principal.SecurityIdentifier($DomainSIDBytes,0)).Value

	$LastRID = Get-RIDsRemaining($DomainDN)

	for ($CurrentRID=500;$CurrentRID -lt $LastRID;$CurrentRID++)
	{
		$CurrentSid="$DomainStringSID-$CurrentRID"
		$objSID = New-Object System.Security.Principal.SecurityIdentifier($CurrentSid)

		$objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
		if ($objUser)
		{
			# Validate the object returned is not from another domain (due to SidHistory)
			if ($objUser.ToString().Split('\')[0].ToLower() -eq $DomainName)
			{
				$LDAPObj = [adsi]"LDAP://<SID=$CurrentSid>"
				if ($LDAPObj.Path -eq $null)
				{
				# Validate if not SIDHistory of current domain scenario - generating FPs
					$objValidatedUser = New-Object System.Security.Principal.NTAccount($objUser)
					$objValidatedSID = $objValidatedUser.Translate( [System.Security.Principal.SecurityIdentifier])
					if ($objValidatedSID.Value -eq $objSID)
					{$HiddenAccount += $objUser}
				}
			}
		}
		$objUser = $null
		$LDAPObj = $null
	}
	$selectionNames = "Value"
	return $neededNames, $HiddenAccount, $selectionNames
}
$hidddenObj = "HiddenObjectNoAccess", "HiddenObjectDenyList", "HiddenAccount"

function ADObjects30 {
	#AD Objects created for last 30 days
	$neededNames = "DN", "Class", "Created", "Owner"
    $CreatedDate = (Get-Date) - (New-TimeSpan -Days 30)
    $Objects30=Get-ADObject -Filter 'whenCreated -gt $CreatedDate' -Properties DistinguishedName,ObjectClass,whenCreated
    $results= foreach ($objects in $Objects30){
        $ObjectOwner=(Get-ADObject $Objects -Properties NTSecurityDescriptor).NTSecurityDescriptor.owner
        $Array = @() ; $array +=[pscustomobject]@{
        DN = $objects.DistinguishedName
        Class = $objects.ObjectClass
        Created = $objects.whenCreated
        Owner = $ObjectOwner
        }
        $Array}
	$selectionNames = "DN", "Class", "Created", "Owner"
	return $neededNames, $results, $selectionNames
}
$ADObjects30 = "ADObjects30"


## Variable for the entire chapter ##

$secondChapterScripts = "ADObjects30","adminHolder", "shadowB", "shadowA", "dcSync", "domainCont", "hidddenObj", "krbtgt", "privilegedGroups", "shadowsPrincipals", "sidHistory", "primaryGroup"

## Variable designated for chapter management ##
$chapterScripts = "firstChapterScripts", "secondChapterScripts"

## Parts of HTML code ##########
## generation of chapter titles ##

function Big-Head($num, $line) {
	$result = @"
				<div class="bigHead">
					<h2 id=`"$num`">$num<span style=`"margin-left: 33px`">$line</h2>
					<span>$(Graph-Maker)</span>
				</div>
"@
	return $result	
}

# Graph variables

$global:gGraphValue_vulnerable = 0
$global:gGraphValue_warning = 0
$global:gGraphValue_safe = 0

# Graph values

$global:gGlobalGraphValue_vulnerable = 0
$global:gGlobalGraphValue_warning = 0
$global:gGlobalGraphValue_safe = 0

# Graph functions

function Graph-Maker{
	Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Windows.Forms.DataVisualization

    $Chart = New-object System.Windows.Forms.DataVisualization.Charting.Chart
    $ChartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea
    $Series = New-Object -TypeName System.Windows.Forms.DataVisualization.Charting.Series
    $ChartTypes = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]

	$Series.ChartType = $ChartTypes::Pie
    $Chart.Series.Add($Series)

    #3D Graf

	$ChartArea.Area3DStyle.Enable3D = $True
    $ChartArea.Area3DStyle.Inclination = 50

    $Chart.ChartAreas.Add($ChartArea)
    $ChartArea.BackColor = [System.Drawing.ColorTranslator]::FromHtml('#'+"f5f5f8")

    #Hodnoty v grafu

	[string[]] $names = "Vulnerable", "Warning", "Safe"
	[int[]] $values = $global:gGraphValue_vulnerable, $global:gGraphValue_warning, $global:gGraphValue_safe
    
	$Chart.Palette = [System.Windows.Forms.DataVisualization.Charting.ChartColorPalette]::None
    $Chart.PaletteCustomColors = @( [System.Drawing.Color]::FireBrick,  [System.Drawing.Color]::DarkOrange, [System.Drawing.Color]::FromArgb(0, 95, 172))
    
    $Chart.Series['Series1'].Points.DataBindXY($names, $values)

    $Chart.Width = 300
    $Chart.Height = 250
    $Chart.BackColor = [System.Drawing.ColorTranslator]::FromHtml('#'+"f5f5f8")
    
    $ChartTitle = New-Object System.Windows.Forms.DataVisualization.Charting.Title
    $ChartTitle.Text = 'Summary'
    $ChartFont = New-Object System.Drawing.Font @('Microsoft Sans Serif','12', [System.Drawing.FontStyle]::Bold)
    $ChartTitle.Font =$ChartFont
    $Chart.Titles.Add($ChartTitle)

    $Chart.Series['Series1']['PieLineColor'] = 'Black'
    $Chart.Series['Series1']['PieLabelStyle'] = 'Inside'
    $Chart.Series['Series1'].Label = "#VALX (#VALY)"
    $chartseriesfont = New-Object System.Drawing.Font @('Microsoft Sans Serif','8', [System.Drawing.FontStyle]::Regular)
    $chart.Series['Series1'].Font = $chartseriesfont
    $chart.Series['Series1'].LabelForeColor = [System.Drawing.Color]::White
    
	$Chart.SaveImage("$ENV:USERPROFILE\Desktop\chart.png", "png")
	$var = Get-Content "$ENV:USERPROFILE\Desktop\chart.png" -Encoding Byte -ReadCount 0
	$encodedText =[Convert]::ToBase64String($var)
	Remove-Item "$ENV:USERPROFILE\Desktop\chart.png"

	return "<img src=`"data:image/png;base64,$encodedText`" style=`"margin:left; display:block`">"
}

function MainGraph-Maker{
	Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Windows.Forms.DataVisualization

    $Chart = New-object System.Windows.Forms.DataVisualization.Charting.Chart
    $ChartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea
    $Series = New-Object -TypeName System.Windows.Forms.DataVisualization.Charting.Series
    $ChartTypes = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]

	$Series.ChartType = $ChartTypes::Pie
    $Chart.Series.Add($Series)

	#3D graph

	$ChartArea.Area3DStyle.Enable3D = $True
    $ChartArea.Area3DStyle.Inclination = 50

    $Chart.ChartAreas.Add($ChartArea)
    $ChartArea.BackColor = [System.Drawing.ColorTranslator]::FromHtml('#'+"f5f5f8")
      
    #Graph Values

	[string[]] $names = "Vulnerable", "Warning", "Safe"
	[int[]] $values = $global:gGlobalGraphValue_vulnerable, $global:gGlobalGraphValue_warning, $global:gGlobalGraphValue_safe
    
    $Chart.Palette = [System.Windows.Forms.DataVisualization.Charting.ChartColorPalette]::None
    $Chart.PaletteCustomColors = @( [System.Drawing.Color]::FireBrick,  [System.Drawing.Color]::DarkOrange, [System.Drawing.Color]::FromArgb(0, 95, 172))

    $Chart.Series['Series1'].Points.DataBindXY($names, $values)

    $Chart.Width = 350
    $Chart.Height = 350
    $Chart.BackColor = [System.Drawing.ColorTranslator]::FromHtml('#'+"f5f5f8")
    
    $ChartTitle = New-Object System.Windows.Forms.DataVisualization.Charting.Title
    $ChartTitle.Text = 'Summary'
    $ChartFont = New-Object System.Drawing.Font @('Microsoft Sans Serif','14', [System.Drawing.FontStyle]::Bold)
    $ChartTitle.Font =$ChartFont
    $Chart.Titles.Add($ChartTitle)


    $Chart.Series['Series1']['PieLineColor'] = 'Black'
    $Chart.Series['Series1']['PieLabelStyle'] = 'Inside'
    $Chart.Series['Series1'].Label = "#VALX (#VALY)"
    $chartseriesfont = New-Object System.Drawing.Font @('Microsoft Sans Serif','10', [System.Drawing.FontStyle]::Regular)
    $chart.Series['Series1'].Font = $chartseriesfont
    $chart.Series['Series1'].LabelForeColor = [System.Drawing.Color]::White

	$Chart.SaveImage("$ENV:USERPROFILE\Desktop\chart.png", "png")
	$var = Get-Content "$ENV:USERPROFILE\Desktop\chart.png" -Encoding Byte -ReadCount 0
	$encodedText =[Convert]::ToBase64String($var)
	Remove-Item "$ENV:USERPROFILE\Desktop\chart.png"

	return "<img src=`"data:image/png;base64,$encodedText`" style=`"margin:auto; display:block`">"
}

$warnChapters = @("Active Directory Certification Services - ESC4","NTLM","LDAP","SMB","Protected Users","AdminSDHolder","Domain Controllers","DCShadow Privilege","DCSync","Privileged Groups","KRBTGT","Kerberos Encryption","Account Lockout and Password Policy","Active Directory Recent Objects"," Azure Active Directory SSO Account") #...
$warnRegex = [string]::Join('|', $warnChapters)

## Generation of chapter subtitles ##

function Text-Content($num, $numB, $line, $descriptionChapter, $connect) {
	$helpStr = Table-Maker($connect)s
	$descriptionChap = $descriptionChapters[$num-1]
	$desc = $(Get-Variable "$descriptionChap" -ValueOnly)[$numB-1]

	if($line -match $warnRegex) {
		$secClass = "warn"
		$secinfo = "warning"
		$global:gGraphValue_warning ++
		$global:gGlobalGraphValue_warning ++         
	}

	elseif ($helpStr.Contains("The following data was found:")) {
		$secClass = "vun"
		$secinfo = "vulnerable"
		$global:gGraphValue_vulnerable ++
		$global:gGlobalGraphValue_vulnerable ++                    
	}
	else {
		$secClass = "safe"
		$secinfo = "safe"
		$global:gGraphValue_safe ++
		$global:gGlobalGraphValue_safe ++
	}

	if ($numB -gt 9) {
		$margin = 25
	} else {
		$margin = 33
		$HelpNum = "&nbsp;&nbsp;"
	}

	$result = @"
	<div class="showenContent" id="$num$numB">
	<div class="clickBox" onclick="HideShow(this);">
		<h3>$num.$numB$HelpNum<span style=`"margin-left: $($margin)px`"></span>$line<span class="$secClass">$secinfo</span></h3>
	</div>
	<div class="hideAll">
		<div>
			$desc
		</div>
		<div class="mainPrintOut">
			<ul>
				$helpStr
			</ul>
		</div>
	</div>
</div>
"@
	return $result
}

## Generation of tables ##

function Table-Maker($com) {
	foreach ($itemM in $com) {
		$data = $(&"$itemM")
		if(($($data.count -eq 3)) -and ($data[1])){ 
			$numTable = 0
			$result += "<li><label>The following data was found:</label>`r`n"
			$result += "<div class=`"scrollable`"><table class=`"CElementTable`"><thead><tr>"
			foreach ($name in $data[0]) {
				$result += "<th>$name</th>"
			}
			$result += "</tr></thead><tbody>"
			$numHelp = 0
			foreach ($item in $data[1]) {
				foreach ($nameA in ($data[2] -split " ")) {
					$result += "<td>$($item.($nameA))</td>"
					$numTable ++
				}
				$result += "</tr>"
			}
			$result += "</tbody></table></div></li>`r`n"
		} 
		else {$result += "<li><label>No data was found.</label></li>`r`n"}
	}

	return $result
}

Write-Host "Start of Main Code" -ForegroundColor white -BackgroundColor fr

## Declaration of the HTML page head ##

$header = @"
    <meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>$fileTitle</title>
	<script>
		document.addEventListener("DOMContentLoaded", function(){
			var allText = document.getElementsByClassName("hideAll");
			if (allText) {
				for (let index = 0; index < allText.length; index++) {
					allText[index].setAttribute("hidden", "hidden");
				}
			}
			var tableNums = document.getElementsByClassName("num");
			var safeNum = 0;
			if (document.getElementsByClassName("safe")) {
				safeNum = document.getElementsByClassName("safe").length;
			};
			var vunNum = 0;
			if (document.getElementsByClassName("vun")) {
				vunNum = document.getElementsByClassName("vun").length;
			};
            var warnNum = 0;
			if (document.getElementsByClassName("warn")) {
				warnNum = document.getElementsByClassName("warn").length;
			};
			tableNums[0].textContent = safeNum;
			tableNums[1].textContent = vunNum;
            tableNums[2].textContent = warnNum;
		});
		function HideShow(elem) {
			var element = elem.nextElementSibling;
			if(element.getAttribute("hidden")) {element.removeAttribute("hidden");}
			else element.setAttribute("hidden", "hidden");
		};
	</script>
	<style>
		* {
			font-family: Arial, Helvetica, sans-serif;
			scroll-behavior: smooth;
		}
		body{
			margin: 0;
			padding: 0;
			width: 100%;
			height: 100%;
			background: #212237;
			border-color: #005fac;
		}
		.main {
			
			width: 90%;
			min-height: 95%;
			margin: 0 auto 5px auto;
			background-color: #f5f5f8;
			border-radius: 7px;
		}
        .logo-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            margin-top: 20px;
            position: relative;
        }
        .logo {
            width: 150px;
            height: 150px;
            fill: #212237;
        }
		.head {
			width: 90%;
			min-height: 100px;
            margin: 0 auto 0 auto;
            text-align: center;
		}
		.head h1 {
			font-size: 55px;
            color: #212237;
            font-weight: bold;
		}
        .head h4 {
			padding-top: -10px;
			font-size: 30px;
            color: #000000;
            font-weight: bold;
        }
		.mainTable {
			width: 80%;
			margin: auto;
			margin-top: 15px;
		}
		.mainTable table {
			border-collapse: collapse;
			width: 100%;
			text-align: center;
		}
		.mainTable td {
			border: 1px solid black;
		}
		.mainTable td:first-child {
			width: 80%;
		}
		.head h1 {
			margin-top: 0;
			text-align: center;
        }
		.head h4 {
			margin-top: 0;
			text-align: center;
        }
        .mainListContainer {
            display: flex;
            justify-content: center;
        }
		.mainList {
            max-width: 1450px;
            margin: auto;
            margin: 0 auto;
            padding: 0;
        }
        .mainList ul {
            list-style: none;
            columns: 2;
            column-gap: 100px;
            padding: 0;
            margin: 0;
        }
        .mainList li {
            line-height: 25px;
            text-align: left;
            padding: 9px;
            margin-bottom: 7px;
            border: 1px solid #000000;
			width: 100%;
			background-color: rgba(33, 34, 55, 0.9);
			border-color: #cccccc;
			cursor: pointer;
			border-radius: 5px;
            transition: color 0.1s, background-color 0.1s, border-color 0.1s;
        }

        .mainList a {
            color: #FFFFFF;
            text-decoration: none;
        }
        .mainList li:hover {
			background-color: #cccccc;
			border-color: #b7b7b7;
            color: #000000;            
		}
        .mainList li:hover a {
            color: #000000;
        }        
		.mainContent {
			width: 90%;
			margin: auto;
		}
		.mainContent > .showenContent {
			margin-top: 15px;
			margin-bottom: 15px;
		}
		.bigHead {
			margin-top: 20px;
		}
		.bigHead h2 {
			margin-top: 0;
		}
		.bigHead span {
			width: 90%;
			margin-left: 20px;
		}
		.showenContent {
			width: 100%;
		}
		.showenContent p {
			margin-left: 15px;
			margin-right: 15px;
			text-align: justify;
			text-justify: inter-word;
		}
		.showenContent span {
			font-weight: 700;
			float: right;
		}
		.showenContent h3 {
			margin-left: 15px;
			margin-right: 15px;
		}
		.clickBox {
			border: 1px solid #000000;
			width: 100%;
			background-color: rgba(33, 34, 55, 0.9);
			border-color: #cccccc;
			cursor: pointer;
			border-radius: 5px;
            color: #FFFFFF;
            transition: color 0.1s, background-color 0.1s, border-color 0.1s;
		}
        .clickBox a {
            color: #FFFFFF;
            text-decoration: none;
        }
		.hideAll {
			margin: 0;
			cursor: default;
		}
		.mainPrintOut {
			width: 90%;
			margin: auto;
		}
		.mainPrintOut ul {
			list-style: none;
		}
		.mainPrintOut li {
			line-height: 35px;
			font-weight: 700;
		}
		.mainPrintOut table {
			width: 100%;
			height: 100%;
			font-weight: 500;
			font-size: 12px;
			background-color: #f5f5f8;
		}
		.mainPrintOut td, th {
			padding: 6px;
			padding-top: 4px;
			padding-bottom: 4px;
		}
		.toTop {
			position: fixed;
			border-radius: 50%;
			bottom: 15px;
			right: 15px;
			background-color: #FFFFFF;
			border-color: #005fac;
			width: 50px;
			height: 50px;
			margin: 0;
			padding: 0;
			align-items: center;
			justify-content: center;
		}
		.toTop:hover {
			background-color: #CCCCCC;
		}
		.toTop svg {
			position: relative;
			top: 50%;
			left: 50%;
			transform: translate(-50%, -50%);
		}
		.CElementTable td {
			padding: 8px;
			margin: 0px;
			border: 0px;
			height: 35px !important;
		}
		.CElementTable th {
			background: #005fac;
			font-size: 11px;
			text-transform: uppercase;
			padding: 10px 15px;
			vertical-align: middle;
			color: #ffffff;
		}
		.CElementTable tr:nth-of-type(odd) {
			background: #dedede;
		}
		.CElementTable tr:nth-of-type(even) {
			background: #dedede;
		}
		.CElementTable tr:first-child th:first-child {
			border-top-left-radius: 5px;
		}
		.CElementTable tr:first-child th:last-child {
			border-top-right-radius: 5px;
		}
		.CElementTable tr:last-child td:first-child {
			border-bottom-left-radius: 5px;
		}
		.CElementTable tr:last-child td:last-child {
			border-bottom-right-radius: 5px;
		}
		.showenContent:last-child {
			padding-bottom: 25px;
		}
        .clickBox:hover {
			background-color: #cccccc;
			border-color: #b7b7b7;
            color: #000000;            
		}
        .clickBox:hover a {
            color: #000000;
        }
        .whiteSpace {
            margin-left: 25px;
        }
		.scrollable {
			max-height: 400px;
			width: 90%;
			overflow: auto;
		}
		.scrollable tbody {
			max-height: 400px;
			width: 90%;
			overflow: scroll;
		}
		.scrollable thead {
			overflow: auto;
			width: 100%;
		}
		.scrollable thead tr {
			position: relative;
		}
		.scrollable table {
			overflow: hidden;
		}
		.safe {
			color: #005fac;
		}
		.vun {
			color: #C70000;
		}
		.warn {
			color: #FFA500;
		}
	</style>
"@

## Loop for creating content and chapter subtitles ##

$mainContentPS = ""
$mainContentPSData = ""
$menu = ""
$num = 1
foreach ($item in $chapterList) {
	$numB = 0
    $LargeTitle = ""
	$mainContentPS += '<div class="mainContent">'
	$helpLevel = $chapterScripts[$num-1]
	$connect = $(Get-Variable "$helpLevel" -ValueOnly)
    foreach ($line in $($(Get-Variable "$item" -ValueOnly) -split "`r`n")) {
		if ($line -eq "") {
			break
		}
		if ($numB -eq 0) {
			$menu += "<li><a href=`"#$num`">$num<span style=`"margin-left: 33px`"><b><u>$line</u></b></a></li>"
            $LargeTitle = $line
		}
		else {
			if ($numB -gt 9) {
				$margin = 25
			} else {
				$margin = 33
			}
			$menu += "<li><a href=`"#$num$numB`">$num.$numB<span style=`"margin-left: $($margin)px`">$line</a></li>"
			$helpLevelB = $connect[$numB-1]
			$mainContentPSData += Text-Content $num $numB $line $descriptionChapter $(Get-Variable "$helpLevelB" -ValueOnly)
		}
        $numB ++
    }
    $mainContentPS += Big-Head $num $LargeTitle
    $mainContentPS += $mainContentPSData
	$mainContentPSData = ""
	$mainContentPS += '</div>'
    $global:gGraphValue_vulnerable = 0
	$global:gGraphValue_warning = 0
	$global:gGraphValue_safe = 0
    $num ++
}
Write-Host "Main generation completed" -ForegroundColor Black -BackgroundColor White

## Declaration of the main body ##

$bodyMain = @"
<content>
		<div class="main">
        <div class="logo-container">
			<svg class="logo" version="1.0" xmlns="http://www.w3.org/2000/svg"
            width="150.000000pt" height="150.000000pt" viewBox="0 0 300.000000 300.000000"
            preserveAspectRatio="xMidYMid meet">
			<g transform="translate(0.000000,300.000000) scale(0.100000,-0.100000)"
            fill="#212237" fill-opacity="0.75" stroke="none">
            <path d="M1460 2270 c-42 -33 -164 -79 -235 -89 -37 -6 -70 -13 -74 -16 -15
            -15 -12 -231 3 -299 34 -145 134 -270 274 -340 l73 -37 72 38 c90 46 193 147
            230 223 41 85 60 188 55 308 -3 56 -7 105 -10 108 -3 3 -35 9 -71 14 -79 12
            -157 40 -220 80 -56 35 -64 36 -97 10z m110 -68 c36 -17 105 -42 153 -54 l89
            -22 -4 -136 c-3 -134 -4 -137 -41 -212 -43 -87 -104 -148 -203 -204 l-63 -35
            -71 37 c-84 44 -166 127 -206 211 -26 54 -29 69 -32 199 l-4 141 89 22 c48 13
            117 38 153 56 36 19 67 33 70 32 3 -1 34 -17 70 -35z"/>
            <path d="M1444 2104 c-37 -18 -64 -62 -64 -103 0 -24 -4 -31 -20 -31 -26 0
            -32 -26 -28 -135 l3 -90 163 -3 162 -2 0 111 c0 102 -2 111 -20 116 -11 3 -20
            14 -20 24 0 10 -7 36 -16 58 -25 63 -95 87 -160 55z m119 -42 c10 -10 20 -35
            24 -55 l6 -37 -92 0 -91 0 0 28 c0 33 24 70 54 82 29 13 77 3 99 -18z m-20
            -112 c37 3 74 2 81 -2 13 -7 17 -160 4 -173 -3 -3 -58 -7 -123 -9 -88 -2 -120
            1 -130 11 -17 16 -13 162 4 173 6 3 30 4 53 1 24 -3 73 -4 111 -1z"/>
            <path d="M1468 1897 c-31 -24 -32 -60 -3 -87 24 -23 28 -24 53 -9 33 18 41 62
            16 90 -20 22 -42 24 -66 6z m50 -16 c8 -4 12 -19 10 -32 -2 -18 -9 -24 -28
            -24 -19 0 -26 6 -28 24 -3 20 11 41 28 41 3 0 11 -4 18 -9z"/>
            <path d="M450 1220 l0 -150 45 0 45 0 0 60 0 60 60 0 60 0 0 -60 0 -60 45 0
            45 0 0 150 0 150 -45 0 -45 0 0 -60 0 -60 -60 0 -60 0 0 60 0 60 -45 0 -45 0
            0 -150z m68 73 c2 -26 8 -53 14 -61 8 -9 8 -16 0 -24 -7 -7 -12 -34 -12 -60 0
            -41 -3 -48 -20 -48 -19 0 -20 7 -20 120 0 108 2 120 18 120 13 0 18 -10 20
            -47z m201 -73 c2 -115 1 -120 -19 -120 -17 0 -20 6 -20 49 0 45 -18 80 -33 65
            -3 -3 -14 -1 -24 6 -17 11 -17 11 0 6 32 -10 57 11 57 49 0 42 9 65 25 65 10
            0 13 -30 14 -120z"/>
            <path d="M871 1352 c-55 -27 -76 -64 -76 -132 0 -96 58 -150 161 -150 95 0
            159 69 151 163 -7 84 -68 137 -157 137 -25 0 -60 -8 -79 -18z m53 -22 c-41
            -16 -64 -59 -64 -116 0 -56 18 -85 65 -104 17 -8 16 -9 -8 -9 -20 -1 -40 10
            -63 33 -29 29 -34 41 -34 83 0 29 7 58 16 72 17 24 67 50 94 50 9 0 6 -4 -6
            -9z m86 -1 c46 -14 70 -52 70 -109 0 -44 -32 -109 -53 -111 -7 0 -25 -2 -42
            -5 -25 -3 -26 -2 -9 5 12 5 31 22 43 37 43 55 19 159 -43 184 -31 13 -9 12 34
            -1z m-6 -51 c22 -30 20 -91 -2 -119 -26 -31 -78 -31 -105 2 -24 30 -19 106 9
            126 29 21 81 16 98 -9z"/>
            <path d="M1150 1220 l0 -150 45 0 45 0 0 50 c0 68 25 68 62 0 28 -50 28 -50
            80 -50 48 0 50 1 36 18 -8 9 -25 34 -37 54 l-22 38 26 23 c20 17 27 32 27 60
            0 80 -47 107 -184 107 l-78 0 0 -150z m90 111 c0 -6 -4 -13 -10 -16 -16 -10
            -12 -91 5 -105 23 -19 86 0 104 32 13 23 13 29 -4 54 -20 31 -19 41 5 36 52
            -12 66 -74 25 -118 -30 -32 -31 -40 -5 -81 19 -32 19 -33 1 -33 -11 0 -30 18
            -47 45 -22 35 -34 45 -55 45 -29 0 -39 -15 -39 -61 0 -22 -5 -29 -20 -29 -19
            0 -20 7 -20 120 l0 120 30 0 c17 0 30 -4 30 -9z m54 -27 c50 -19 31 -74 -25
            -74 -27 0 -29 2 -29 40 0 41 13 50 54 34z"/>
            <path d="M1460 1220 l0 -150 40 0 40 0 0 150 0 150 -40 0 -40 0 0 -150z m58 6
            c2 -77 0 -116 -8 -121 -20 -12 -24 4 -25 103 -2 108 2 132 19 132 8 0 12 -36
            14 -114z"/>
            <path d="M1590 1334 l0 -36 75 4 c41 2 75 2 75 0 0 -3 -34 -46 -75 -97 -41
            -51 -75 -102 -75 -113 0 -21 4 -22 135 -22 l135 0 0 30 0 29 -79 3 -80 3 79
            95 c47 56 80 104 80 118 0 22 -2 22 -135 22 l-135 0 0 -36z m240 1 c0 -3 -30
            -43 -67 -88 -36 -45 -71 -88 -76 -94 -12 -17 7 -40 36 -46 12 -2 -6 -5 -41 -6
            -35 0 -62 3 -60 7 4 11 64 86 101 125 31 35 46 79 29 85 -28 9 -8 22 33 22 25
            0 45 -2 45 -5z"/>
            <path d="M1981 1352 c-55 -27 -76 -64 -76 -132 0 -96 58 -150 161 -150 95 0
            159 69 151 163 -7 84 -68 137 -157 137 -25 0 -60 -8 -79 -18z m155 -30 c39
            -18 54 -49 54 -108 0 -39 -5 -51 -34 -80 -24 -24 -43 -34 -62 -33 l-29 1 33
            14 c89 39 61 214 -35 214 -53 0 -93 -45 -93 -105 0 -55 24 -101 60 -114 l25
            -9 -27 -1 c-65 -2 -121 98 -93 166 32 75 114 97 201 55z m-22 -44 c22 -30 20
            -91 -2 -119 -26 -31 -78 -31 -104 0 -25 32 -24 95 2 121 28 28 84 27 104 -2z"/>
            <path d="M2260 1220 l0 -150 45 0 45 0 0 82 0 82 61 -82 c58 -78 63 -82 100
            -82 l39 0 0 150 0 150 -45 0 -44 0 -3 -81 -3 -81 -59 81 c-57 77 -62 81 -98
            81 l-38 0 0 -150z m100 73 c18 -25 47 -59 64 -75 40 -38 55 -23 58 60 2 52 5
            62 20 62 17 0 18 -10 16 -117 -4 -142 -14 -152 -75 -71 -66 86 -83 101 -99 87
            -9 -8 -14 -32 -14 -75 0 -57 -2 -64 -20 -64 -19 0 -20 7 -20 120 0 110 2 120
            18 120 11 0 33 -20 52 -47z"/>
            <path d="M802 904 c-25 -17 -29 -56 -8 -73 7 -6 37 -18 65 -27 52 -15 65 -36
            39 -62 -14 -14 -74 -16 -83 -2 -3 5 -15 15 -26 20 -26 14 -25 -4 1 -30 39 -39
            150 -17 150 31 0 28 -25 50 -74 64 -56 16 -75 37 -55 61 16 19 68 18 90 -2 28
            -25 47 -12 21 14 -26 26 -87 30 -120 6z"/>
            <path d="M985 815 l0 -105 73 0 c41 0 72 4 72 10 0 6 -27 10 -60 10 l-60 0 0
            41 0 41 55 -4 c39 -2 55 1 55 10 0 8 -18 12 -55 12 l-55 0 0 35 0 35 60 0 c33
            0 60 4 60 10 0 6 -31 10 -72 10 l-73 0 0 -105z"/>
            <path d="M1199 891 c-24 -24 -29 -38 -29 -76 0 -63 39 -105 98 -105 42 0 92
            30 92 56 0 20 -10 17 -36 -11 -39 -42 -101 -30 -124 24 -36 88 58 159 127 95
            18 -17 29 -21 32 -13 2 7 -8 23 -23 36 -40 34 -99 32 -137 -6z"/>
            <path d="M1410 840 c0 -73 3 -83 25 -105 31 -32 91 -34 129 -4 24 19 26 26 26
            105 0 60 -3 84 -12 84 -10 0 -12 -20 -10 -74 3 -65 1 -77 -17 -95 -25 -25 -73
            -27 -95 -5 -12 11 -16 36 -16 95 0 64 -3 79 -15 79 -12 0 -15 -16 -15 -80z"/>
            <path d="M1650 815 c0 -90 2 -105 16 -105 14 0 16 7 11 40 -5 40 -5 40 28 40
            29 0 37 -6 56 -40 13 -22 29 -40 36 -40 18 0 16 9 -11 49 l-22 34 23 23 c29
            30 29 49 -2 79 -20 21 -34 25 -80 25 l-55 0 0 -105z m118 73 c7 -7 12 -22 12
            -35 0 -26 -37 -46 -78 -41 -21 3 -25 9 -26 46 l-2 42 41 0 c22 0 46 -5 53 -12z"/>
            <path d="M1850 815 l0 -105 75 0 c43 0 75 4 75 10 0 6 -27 10 -60 10 l-60 0 0
            41 0 40 52 -2 c35 -2 53 1 56 10 3 10 -9 12 -52 9 l-56 -3 0 38 0 37 55 0 c30
            0 55 5 55 10 0 6 -30 10 -70 10 l-70 0 0 -105z"/>
            <path d="M2045 814 l0 -106 62 4 c48 3 68 9 87 27 32 30 41 71 26 116 -15 45
            -53 65 -122 65 l-53 0 0 -106z m129 65 c20 -16 26 -29 26 -60 0 -55 -34 -89
            -90 -89 l-40 0 0 85 0 85 39 0 c24 0 48 -8 65 -21z"/>
            <path d="M450 820 c0 -6 48 -10 125 -10 77 0 125 4 125 10 0 6 -48 10 -125 10
            -77 0 -125 -4 -125 -10z"/>
            <path d="M2310 818 c0 -10 29 -12 120 -10 66 2 120 7 120 13 0 5 -52 9 -120 9
            -89 0 -120 -3 -120 -12z"/>
            </g>
            </svg>
		</div>
			<div class="head">
				<h1>$mainTitle</h1>
				<h4>$(Get-Date -Format "dd.MM.yyyy  HH:mm")</h4>
			</div>
    		<div class="mainListContainer">
                <div class="mainList">
				    <ul>
                        $menu
				    </ul>
                </div>
			</div>
            <div class="mainTable">
				$(MainGraph-Maker)
			</div>
			$mainContentPS
		</div>
	</content>
"@

## Declaration of the scroll-to-top button ##

$bodyFastBtn = @"
	<a href="#">
    	<div class="toTop">
			<svg width="24" height="24" xmlns="http://www.w3.org/2000/svg" fill-rule="evenodd" clip-rule="evenodd"><g fill="none" stroke="black" stroke-width="4"><path d="M23.245 20l-11.245-14.374-11.219 14.374-.781-.619 12-15.381 12 15.391-.755.609z"/></g></svg>
		</div>
	</a>
"@


## Script completing + HTML page creation##

ConvertTo-Html -Head $header -Body $(($bodyMain + $bodyFastBtn) -join " ") | Out-File -Encoding UTF8 -FilePath ".\ADProbe_$FileDate.html"
Write-Host "`r`nScript completed" -ForegroundColor Black -BackgroundColor White
