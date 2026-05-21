Get-DomainUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=65536)' | Select-Object samaccountname, passwordlastset, useraccountcontrol


([adsisearcher]"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))").FindAll() | ForEach-Object {
    $_.Properties['samaccountname']
}
