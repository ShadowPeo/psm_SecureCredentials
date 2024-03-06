<# 

Require Root Store
Script Specific Creds
CredName

Create Creds
    Local w/ AES (DPAPI then AES)
    Shared (AES)

    Save credential as (credIdentifier-?)(DeviceName-(if DPAPI))Username
#>

function New-secureCredential
{
    Param 
    (
        [switch]$aesOnly,                                           # Use AES Only, do not use DPAPI
        [string(Mandatory=$true)]$username,                         # Username for the credential
        [string]$rootStore = "$($ENV:USERPROFILE)\.PSCreds",        # Allows overriding of the default credential root location
        [string]$keyStore = "$($ENV:USERPROFILE)\.Keys",            # Allows oferriding of the default keystore location
        [string]$credentialIdentifer,                               # Used to identify a unique credential where the credential is unique for a given script/task, if not set generic credentials for username will be used. Recommended input is the script name
        [string]$credentialFile,                                    # Credential File, this needs to be the full path to the file
        [string]$keyFile                                            # Full path to a specifc Keyfile, if this does not exist it will be created and used to encrypt the data, if it does exist, this key will be used
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

    # Calculate Credential File Name if not specified in the $credentialFile Option

    if ([string]::IsNullOrEmpty($credentialFile))
    {
        $credentialFile = "$(if(-not [string]::IsNullOrEmpty("$credentialIdentifer-")){$credentialIdentifer})$(if(-not $shared){"$($ENV:COMPUTERNAME)-"})$username.crd"
    }
}

# Retrieves secure credential and applying the correct decryption, returns a credential object
function Get-secureCredential
{
    Param 
    (
        [switch]$aesOnly,                                           # Use AES Only, do not use DPAPI
        [string(Mandatory=$true)]$username,                         # Username for the credential
        [string]$rootStore = "$($ENV:USERPROFILE)\.PSCreds",        # Allows overriding of the default credential root location
        [string]$keyStore = "$($ENV:USERPROFILE)\.Keys",            # Allows oferriding of the default keystore location
        [string]$credentialIdentifer,                               # Used to identify a unique credential where the credential is unique for a given script/task, if not set generic credentials for username will be used. Recommended input is the script name
        [string]$credentialFile,                                    # Credential File, this needs to be the full path to the file
        [string]$keyFile,                                           # Full path to a specifc Keyfile, if this does not exist it will be created and used to encrypt the data, if it does exist, this key will be used
        [switch]$createOnNotFound                                   # Ask to create the credential if not found
    )


}