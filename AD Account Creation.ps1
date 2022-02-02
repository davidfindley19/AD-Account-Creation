<#
.SYNOPSIS
    Scripted account and mailbox creation for new users.
.DESCRIPTION
    This is accomplished by prompting with a form for the new user's information. The script will truncate the full name to create the username based off company IT standards. After the username
    is created, based off the role, groups/permissions will be assigned to the user. The final step of this script is to create the mailbox on our Exchange server.
.NOTES
    Author: David Findley
    Date: June 8, 2018
    Version: 1.4
#>

Param(
    [Parameter(Mandatory = $true)]
    [string]$FirstName,
    [Parameter(Mandatory = $true)]
    [string]$LastName,
    [Parameter(Mandatory = $true)]
    [string]$Title

)

Write-Host "Manual Account and Mailbox Creation"

# Setting the ActiveDirectory module as required. If this causes an error, the script will break. 
#Requires -Modules ActiveDirectory

# Just grabbing current user credentials. This is assuming user executing script has privileges to modify domain users.
$UserCredential = Read-Host "Enter a username: "
$UserPass = Read-Host -AsSecureString "Enter your password: "
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserCredential , $UserPass 


# Creating full name from the variables. 
$FullName = "$FirstName " + "$LastName"
$UserName = $($FirstName.Substring(0, 1) + $LastName).ToLower()

# Creating username based off of first initial and last name standard.
$Surname = $LastName
$EmailAddress = $UserName + "@business.com"
$StreetAddress = "12345 S. Road"
$City = "City"
$Company = "Business Name"
$PhoneNumber = "555-555-5555"
$Account = (dsquery user -samid $UserName)
$Seed = "abcdefghijkmnpqrstuvwxyz0192837465)!(@*#&$^" # Pool of characters for password generation.
$Random8 = $seed.ToCharArray() | get-random -count 8 # Set to whatever count you want, but I defaulted to 8.
$RandomString = $Random8 -join "" # Creates a string of characters for the password. 
[regex]$rx = "[a-z]" # Expression to match any character from a-z.
$firstalpha = $rx.match($randomstring).value # Get the first matching alphabet character
$plaintext = $randomstring.Replace($firstalpha, $firstalpha.toUpper()) # Force first character to uppercase.
$password = ConvertTo-SecureString -String $plaintext -AsPlainText -Force # Converts to secure string for the New-ADUser cmdlet.

#Creates a new user hashtable for splatting later in the script.
$NewUser = @{
    Name                    = $FullName
    SamAccountName          = $UserName
    GivenName               = $Surname
    Surname                 = $LastName 
    Enable                  = $true
    AccountPassword         = $password 
    EmailAddress            = $EmailAddress 
    Company                 = $Company 
    DisplayName             = "$FirstName $LastName" 
    UserPrincipalName       = "$UserName@company.com" 
    ChangePasswordAtLogon   = $false 
    PasswordNeverExpires    = $true 
    Title                   = $JobTitle 
}

# Sanity check on username creation. 
if ($Account -eq $null) {
    Write-Host "The following username is available: $UserName. Would you like to continue? "
    $Readhost = Read-Host "[Y]es or [N]o"
    switch ($Readhost) {
        Y {Write-Host "Great! Continuing with this username. "; $Create = $true } # Much easier than a bunch of if/else statements
        N {Write-Warning "Let's try that again."; $Create = $false }
        Default {"Invalid response. Exiting script"; exit}
    }
}
else {
    Write-Warning "This username, $UserName, is not available. Please try again." # Right now this exits the script, but it will eventually allow manual entry of a username.
    exit
}
if ($Create -eq $true) {
    try {
        New-ADUser  @NewUser
        Write-Host "$FullName : Account created successfully."
        }
        
    catch {
        $wsh = New-Object -com wscript.shell
        $msg = "Failed to create new user, $FullName. $_"
        $wsh.Popup($msg, -1, "New User", 0 + 48)
        exit

    }
}
else {
    Write-Host "Exiting Script"
    exit
}

# Adding user to group(s) based off of the team they will be joining.
$TeamName = Read-Host "What group will $FirstName $LastName be a part of? Please enter one: Executive, Accounting, IT "
    if ($TeamName -eq "Executive") {
        Add-ADPrincipalGroupMembership -Identity:"CN=$FirstName $LastName,CN=Users,DC=servername,DC=local" -MemberOf:"CN=Full Gropu Name,CN=Users,DC=servername,DC=local", "CN=GIS Portal Publishers,CN=Users,DC=servername,DC=local", `
        "CN=GIS Map Services,CN=Users,DC=servername,DC=local", "CN=GIS Map Publishers,CN=Users,DC=servername,DC=local", "CN=GIS Internal Portal Users,CN=Users,DC=servername,DC=local", `
        "CN=GIS Foreign User Map Services,CN=Users,DC=servername,DC=local" -Server:"servername.domainname.local"
        Write-Host "Setting $FirstName $LastName's manager." # Added here since it adds manager based on role/team you select. 
        Set-ADUser -Identity:"CN=$FirstName $LastName,CN=Users,DC=servername,DC=local" -Manager:"CN=First Name,CN=Users,DC=servername,DC=local" -Department:"Deparment Name for user" -Server:"servername.domainname.local" #Full path for manager account.
        Write-Host "User, $FirstName $LastName, successfully added to group."
        }
            elseif ($TeamName -eq "Accounting"){
            Add-ADPrincipalGroupMembership -Identity:"CN=$FirstName $LastName,CN=Users,DC=servername,DC=local" -MemberOf:"CN=Full Group Name,CN=Users,DC=servername,DC=local", "CN=Full Group Name,CN=Users,DC=servername,DC=local", `
            "CN=Full Group Name,CN=Users,DC=servername,DC=local", "CN=Full Group Name,CN=Users,DC=servername,DC=local", "CN=Full Group Name,CN=Users,DC=servername,DC=local", `
            "CN=Full Group Name,CN=Users,DC=servername,DC=local" -Server:"servername.domainname.local"
            Write-Host "User, $FirstName $LastName, successfully added to Accounting Groups."
            }
                elseif ($TeamName -eq "IT") {
                Add-ADPrincipalGroupMembership -Identity:"CN=$FirstName $LastName,CN=Users,DC=servername,DC=local" -MemberOf:"CN=Full Group Name,CN=Users,DC=servername,DC=local", "CN=Full Group Name,CN=Users,DC=servername,DC=local", `
                "CN=Full Group Name,CN=Users,DC=servername,DC=local", "CN=Full Group Name,CN=Users,DC=servername,DC=local", "CN=Full Group Name,CN=Users,DC=servername,DC=local", `
                "CN=Full Group Name,CN=Users,DC=servername,DC=local" -Server:"servername.domainname.local"
                Write-Host "User, $FirstName $LastName, successfully added to IT Groups."
                }
        
    else {
    Write-Host "User not added to any groups."
    exit
    }

# Enabling new user's mailbox.
Write-Host "Does the user, $UserName, need an Exchange Mailbox enabled? "
    $MailResponse = Read-Host "[Y]es or [N]o"
    switch ($MailResponse) {
        Y {Write-Host "Enabling Mailbox for user, $UserName. " -ForegroundColor Green; $MailResponse = $true } 
        N {Write-Host "Mailbox not required. Exiting. " -ForegroundColor Green; $MailResponse = $false }
        Default {"Invalid response. Exiting script"; exit}
    }

if ($MailResponse -eq $true){
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://adtestexch/powershell -Authentication Kerberos -Credential $Credential # Connecting to remote powershell session on exchange server
    Import-PSSession $Session
    New-Mailbox -name $FullName -UserPrincipalName "$UserName@domain.com" -SamAccountName $SamAccountName -FirstName $FirstName -LastName $LastName # Enabling the account
    Remove-PSSession $Session # Closed. This wraps up the account creation script.   
}

else {

}
