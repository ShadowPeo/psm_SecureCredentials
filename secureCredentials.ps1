<# 

Require Root Store
Script Specific Creds
CredName

Create Creds
    Local w/ AES (DPAPI then AES)
    Shared (AES)

    Save credential as (credIdentifier-?)(DeviceName-(if DPAPI))Username
#>

function New-CredentialKey
{
    Param 
    (
        [string]$keyStore = "$HOME\.Keys",            # Allows oferriding of the default keystore location
        [string]$keyFile                              # If there is either a / or a \ in the file it will assume that its a full path, if there are no slashes it will assume its a reletive path to the keystore. If this is not specified it will be assumed that the file matches the username or if not matches the device name
    )        
}

function New-secureCredential
{
    Param 
    (
        [switch]$aesOnly,                             # Use AES Only, do not use DPAPI
        [string(Mandatory=$true)]$username,           # Username for the credential
        [string]$rootStore = "$HOME\.PSCreds",        # Allows overriding of the default credential root location
        [string]$keyStore = "$HOME\.Keys",            # Allows oferriding of the default keystore location
        [string]$credIdentifer,                 # Used to identify a unique credential where the credential is unique for a given script/task, if not set generic credentials for username will be used. Recommended input is the script name
        [string]$credFile,                      # Credential File, this needs to be the full path to the file
        [string]$keyFile                              # If there is either a / or a \ in the file it will assume that its a full path, if there are no slashes it will assume its a reletive path to the keystore
    )

    #Test Paths, Create if do not exist
    if (-not (Test-Path($rootStore)))
    {
        New-Item -Path $rootStore -ItemType Directory
    }

    if (-not (Test-Path((Join-Path -Path $rootStore -ChildPath $keyStore))))
    {
        New-Item -Path (Join-Path -Path $rootStore -ChildPath $keyStore) -ItemType Directory

    }

    # Calculate Credential File Name if not specified in the $credFile Option

    if ([string]::IsNullOrEmpty($credFile))
    {
        $credFile = "$(if(-not [string]::IsNullOrEmpty("$credIdentifer-")){$credIdentifer})$(if(-not $shared){"$($ENV:COMPUTERNAME)-"})$username.crd"
    }
}

# Retrieves secure credential and applying the correct decryption, returns a credential object
function Get-secureCredential
{
    Param 
    (
        [switch]$aesOnly,                             # Use AES Only, do not use DPAPI
        [string(Mandatory=$true)]$username,           # Username for the credential
        [string]$rootStore = "$HOME\.PSCreds",        # Allows overriding of the default credential root location
        [string]$keyStore = "$HOME\.Keys",            # Allows oferriding of the default keystore location
        [string]$credIdentifer,                 # Used to identify a unique credential where the credential is unique for a given script/task, if not set generic credentials for username will be used. Recommended input is the script name
        [string]$credFile,                      # Credential File, this needs to be the full path to the file
        [string]$keyFile,                             # If there is either a / or a \ in the file it will assume that its a full path, if there are no slashes it will assume its a reletive path to the keystore
        [switch]$createOnNotFound                     # Ask to create the credential if not found
    )


}