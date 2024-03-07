<# 

Require Root Store
Script Specific Creds
CredName

Create Creds
    Local w/ AES (DPAPI then AES)
    Shared (AES)

    Save credential as (credIdentifier-?)(DeviceName-(if DPAPI))Username
#>

$script:defaultKeyStore = "$HOME\.keys"

#SecureCredential Type
class secureCredential
{
                                [string]$credentialName
    [ValidateNotNullOrEmpty()]  [string]$lastModifiedBy
    [ValidateNotNullOrEmpty()]  [string]$lastModifiedByComputerName
    [ValidateNotNullOrEmpty()]  [string]$lastModifiedByComputerUUID
    [ValidateNotNullOrEmpty()]  [datetime]$lastModifiedDate
    [ValidateNotNullOrEmpty()]  [boolean]$dpapi
    [ValidateNotNullOrEmpty()]  [boolean]$aes
                                [string]$username
                                [string]$encryptedPassword

    secureCredential()
    {
        $this.credentialName                = ""
        $this.lastModifiedBy                = $env:USERNAME
        $this.lastModifiedByComputerName    = $env:COMPUTERNAME
        $this.lastModifiedByComputerUUID    = (Get-CIMInstance Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID)
        $this.lastModifiedDate              = (Get-Date -UFormat "%F %T")
        $this.dpapi                         = $true
        $this.aes                           = $true
        $this.username                      = ""
        $this.encryptedPassword             = ""
    }
}

function Confirm-keyPath
{
    Param 
    (
        [string]$keyStore = $script:defaultKeyStore,  # Allows oferriding of the default keystore location
        [string]$keyFile,                             # If there is either a / or a \ in the file it will assume that its a full path, if there are no slashes it will assume its a reletive path to the keystore. If this is not specified it will be assumed that the file matches the username or if not matches the device guid
        [switch]$createPath                           # If the path does not exist, create it
    )

    $returnResult = [PSCustomObject]@{
        keyStore         = $keyStore
        keyStoreState    = "Invalid"
        keyFile         = $keyFile
        keyFileState    = "Invalid"
    }

    if (![string]::IsNullOrEmpty($keyFile))
    {
                #Check if keyfile contains a slash, if it does check if its a valid path to both the folder and the file
        
        if ($keyFile -match "[\\\/]")
        {
            # Overriding the default keystore location with the one calculated from the keyfile
            $keyStore = (Split-Path -Path $keyFile -Parent)

            #Test the keyfile as a whole
            if (Test-Path($keyFile))
            {
                $returnResult.keyStore = $keyStore
                $returnResult.keyStoreState = "Valid"
                $returnResult.keyFile = Split-Path -Path $keyFile -Leaf
                $returnResult.keyFileState = "Valid"
                return $returnResult
            }
            else
            {
                $returnResult.keyFile = Split-Path -Path $keyFile -Leaf
                
                Write-Information "Key File does not exist at $keyFile"
                Write-Verbose "Attempting to create keystore at $keystore if enabled"

                if (!(Test-Path($keyStore) -PathType Container) -and $createPath)
                {
                    try {

                        Write-Verbose "Keystore creation is enabled, attempting to create keystore at $keystore"

                        New-Item -Path $keyStore -ItemType Directory | Out-Null
                        
                        $returnResult.keyStore = $keyStore
                        $returnResult.keyStoreState = "Created"

                        Write-Information "Key Store Created at $keyStore"

                        return $returnResult
                    }
                    catch {
                        throw "Key Store does not exist and could not be created at $keyStore"
                    }
                }
                elseif (!(Test-Path($keyStore) -PathType Container) -and !$createPath)
                {
                    throw "Keystore creation is disabled, and keystore does not exist at $keyStore"
                }
                else
                {
                    Write-Information "Key file exists at $keyFile"
                    
                    $returnResult.keyStore = $keyStore
                    $returnResult.keyStoreState = "Valid"

                    return $returnResult
                }
            }
        }
        # If the keyfile does not contain a slash treat it as a reletive path to the keystore, validate the keystore path (create if needed) and return the full path to the keyfile
        elseif (![string]::IsNullOrEmpty($keyStore)) 
        {

            #If the joined path of the keystore and keyfile exists, then the result is valid
            if ((Test-Path((Join-Path -Path $keyStore -ChildPath $keyFile))))
            {
                $returnResult.keyStore = $keyStore
                $returnResult.keyStoreState = "Valid"
                $returnResult.keyFile = $keyFile
                $returnResult.keyFileState = "Valid"
                Write-Information "Key File exists at $(Join-Path -Path $keyStore -ChildPath $keyFile)"
                return $returnResult
            }
            elseif (!(Test-Path($keyStore) -PathType Container) -and $createPath)
            {
                try {

                    Write-Verbose "Keystore creation is enabled, attempting to create keystore at $keystore"

                    New-Item -Path $keyStore -ItemType Directory | Out-Null
                    
                    $returnResult.keyStore = $keyStore
                    $returnResult.keyStoreState = "Created"

                    Write-Information "Key Store Created at $keyStore, keyfile cannot exist as the keystore didn't"

                    return $returnResult
                }
                catch {
                    throw "Key Store does not exist and could not be created at $keyStore"
                }
            }
            else
            {
                throw "Keystore creation is disabled, and keystore does not exist at $keyStore, keyfile cannot exist"
            }
        }
    }
    
    ##Check Keystore Path, if it does not exist and createPath is enabled, create the keystore
    if (![string]::IsNullOrEmpty($keyStore))
    {
        if (!(Test-Path($keyStore) -PathType Container) -and $createPath)
        {
            try {
                New-Item -Path $keyStore -ItemType Directory | Out-Null
                Write-Verbose "Key Store Created at $keyStore"
                $returnResult.keyStoreState = "Created"
            }
            catch {
                throw "Key Store does not exist and could not be created at $keyStore"
            }
        }
        elseif (!(Test-Path($keyStore) -PathType Container) -and !$createPath)
        {
            throw "Keystore creation is disabled, and keystore does not exist at $keyStore"
        }
        #If the Path does exist, check to see if it contains a keyfile with either the username or computer guid in that order
        elseif (Test-Path -Path $keyStore -PathType Container)
        {
            #Set the return objects keystore to the validated path and mark as valid
            $returnResult.keyStoreState = "Valid"
            $returnResult.keyStore = $keyStore
            
            #Set returnResult File name to the username as that is the preferred identity
            $returnResult.keyFile = "$env:USERNAME.key"

            #Check for Username Keyfile
            if (Test-Path -Path (Join-Path -Path $keyStore -ChildPath "$env:USERNAME.key"))
            {
                $returnResult.keyFileState = "Valid"
                return $returnResult
            }

            #Check for Computer GUID
            $GUID = Get-CIMInstance Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID
            
            #Check for UUID
            if (Test-Path -Path (Join-Path -Path $keyStore -ChildPath "$GUID.key"))
            {
                $returnResult.keyFile = "$GUID.key"
                $returnResult.keyFileState = "Valid"
                return $returnResult
            }
            return $returnResult
        }
    }
    else {
        throw "Key Store is blank, please specify a valid path to the key store"
    }
}

function New-encryptionKey
{
    Param 
    (
        [string]$keyStore = $script:defaultKeyStore,  # Allows oferriding of the default keystore location
        [string]$keyFile                              # If there is either a / or a \ in the file it will assume that its a full path, if there are no slashes it will assume its a reletive path to the keystore. If this is not specified it will be assumed that the file matches the username or if not matches the device guid
    )

    $keyPath = Confirm-keyPath -keyStore $keyStore -keyFile $keyFile -createPath

}

#Generates a new secure credential and saves it to the root store
function New-secureCredential
{
    
    Param 
    (
        [Parameter(Mandatory=$true)][string]$username,           # Username for the credential
        [string]$rootStore = "$HOME\.pscreds",                   # Allows overriding of the default credential root location
        [string]$keyStore = $script:defaultKeyStore,             # Allows oferriding of the default keystore location
        [string]$credIdentifer,                                  # Used to identify a unique credential where the credential is unique for a given script/task, if not set generic credentials for username will be used. Recommended input is the script name
        [string]$credFile,                                       # Credential File, this needs to be the full path to the file
        [string]$keyFile,                                        # If there is either a / or a \ in the file it will assume that its a full path, if there are no slashes it will assume its a reletive path to the keystore
        [switch][Alias('Shared')]$aesOnly,                       # Use AES Only, do not use DPAPI, can also be Aliased to Shared for clarity when using in a shared environment
        [switch][Alias('Shared')]$force                          # Will force the write of the credential even if it already exists
    )
}

# Retrieves secure credential and applying the correct decryption, returns a credential object
function Get-secureCredential
{
    Param 
    (
        [Parameter(Mandatory=$true)][string]$username,           # Username for the credential
        [string]$rootStore = "$HOME\.pscreds",                   # Allows overriding of the default credential root location
        [string]$keyStore = $script:defaultKeyStore,             # Allows oferriding of the default keystore location
        [string]$credIdentifer,                                  # Used to identify a unique credential where the credential is unique for a given script/task, if not set generic credentials for username will be used. Recommended input is the script name
        [string]$credFile,                                       # Credential File, this needs to be the full path to the file
        [string]$keyFile,                                        # If there is either a / or a \ in the file it will assume that its a full path, if there are no slashes it will assume its a reletive path to the keystore
        [switch][Alias('Shared')]$aesOnly                        # Use AES Only, do not use DPAPI, can also be Aliased to Shared for clarity when using in a shared environment
    )
}

function Update-secureCredential
{
    Param 
    (
        [Parameter(Mandatory=$true)][string]$username,           # Username for the credential
        [string]$rootStore = "$HOME\.pscreds",                   # Allows overriding of the default credential root location
        [string]$keyStore = $script:defaultKeyStore,             # Allows oferriding of the default keystore location
        [string]$credIdentifer,                                  # Used to identify a unique credential where the credential is unique for a given script/task, if not set generic credentials for username will be used. Recommended input is the script name
        [string]$credFile,                                       # Credential File, this needs to be the full path to the file
        [string]$keyFile,                                        # If there is either a / or a \ in the file it will assume that its a full path, if there are no slashes it will assume its a reletive path to the keystore
        [switch][Alias('Shared')]$aesOnly                        # Use AES Only, do not use DPAPI, can also be Aliased to Shared for clarity when using in a shared environment
    )
}

# TODO|?: Decrypt the credential on the fly and return as plain-text, PSCredential or SecureString so that it can be used in the script but not held in an actively decrypted state

