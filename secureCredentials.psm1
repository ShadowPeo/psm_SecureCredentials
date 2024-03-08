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
$script:defaultCredStore = "$HOME\.pscreds"

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
                                [string]$initVector    
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
        $this.initVector                    = ""
        $this.username                      = ""
        $this.encryptedPassword             = ""
    }
}

function Confirm-filePath
{
    Param 
    (
        [Parameter (HelpMessage="This is the file path to check, if it does not exist and permitted it will create the path.")]
            [PSDefaultValue(Help="Default as set in this script")]
            [string]$filePath = "$($script:defaultCredStore)",
        [Parameter (HelpMessage="Full path or filename only, if there is a / or a \ in the file it will assume that its a full path, if there are no slashes it will assume its a file name relative to the file path. If this is not specified it will be assumed that the file matches the username for a key or script name for a credential if there is not a username file and it is a key it will also check for a key utlising the UUID for the device")]
            [PSDefaultValue(Help='scriptName.cred')]
            [string]$fileName,
        [Parameter (HelpMessage="The type of file your validating a Cred(ential) or a Key. Default is cred. Only used if no filename is provided")]
            [ValidateSet('cred','credential','key')]
            [PSDefaultValue(Help='cred')]
            [string]$type = "cred",
        [Parameter (HelpMessage="If the file path does not exist it will create it.")]
            [switch]$createPath
    )
    
    $returnResult = [PSCustomObject]@{
        filePath         = $filePath
        filePathState    = "Invalid"
        fileName         = $fileName
        fileNameState    = "Invalid"
    }
    
    #This is here as setting the defaults above in the Params does not seem to work for some reason
    if ([string]::IsNullOrEmpty($filePath) -and ($type -eq "cred" -or $type -eq "credential"))
    {
        $filePath = $script:defaultCredStore
    }
    elseif (([string]::IsNullOrEmpty($filePath) -and $type -eq "key"))
    {
        $filePath = $script:defaultKeyStore
    }

    if (![string]::IsNullOrEmpty($fileName))
    {
                #Check if fileName contains a slash, if it does check if its a valid path to both the folder and the file
        
        if ($fileName -match "[\\\/]")
        {
            # Overriding the default filePath location with the one calculated from the fileName
            $filePath = (Split-Path -Path $fileName -Parent)

            #Test the fileName as a whole
            if (Test-Path($fileName))
            {
                $returnResult.filePath = $filePath
                $returnResult.filePathState = "Valid"
                $returnResult.fileName = Split-Path -Path $fileName -Leaf
                $returnResult.fileNameState = "Valid"
                return $returnResult
            }
            else
            {
                $returnResult.fileName = Split-Path -Path $fileName -Leaf
                
                Write-Information "File does not exist at $fileName"
                Write-Verbose "Attempting to create File path at $filePath if enabled"

                if (!(Test-Path($filePath) -PathType Container) -and $createPath)
                {
                    try {

                        Write-Verbose "File path creation is enabled, attempting to create file path at $filePath"

                        New-Item -Path $filePath -ItemType Directory | Out-Null
                        
                        $returnResult.filePath = $filePath
                        $returnResult.filePathState = "Created"

                        Write-Information "File path Created at $filePath"

                        return $returnResult
                    }
                    catch {
                        throw "File path does not exist and could not be created at $filePath"
                    }
                }
                elseif (!(Test-Path($filePath) -PathType Container) -and !$createPath)
                {
                    throw "File path creation is disabled, and file path does not exist at $filePath"
                }
                else
                {
                    Write-Information "Key file exists at $fileName"
                    
                    $returnResult.filePath = $filePath
                    $returnResult.filePathState = "Valid"

                    return $returnResult
                }
            }
        }
        # If the fileName does not contain a slash treat it as a reletive path to the filePath, validate the filePath path (create if needed) and return the full path to the fileName
        elseif (![string]::IsNullOrEmpty($filePath)) 
        {

            #If the joined path of the filePath and fileName exists, then the result is valid
            if ((Test-Path((Join-Path -Path $filePath -ChildPath $fileName))))
            {
                $returnResult.filePath = $filePath
                $returnResult.filePathState = "Valid"
                $returnResult.fileName = $fileName
                $returnResult.fileNameState = "Valid"
                Write-Information "File exists at $(Join-Path -Path $filePath -ChildPath $fileName)"
                return $returnResult
            }
            elseif (!(Test-Path($filePath) -PathType Container) -and $createPath)
            {
                try {

                    Write-Verbose "File path creation is enabled, attempting to create file path at $filePath"

                    New-Item -Path $filePath -ItemType Directory | Out-Null
                    
                    $returnResult.filePath = $filePath
                    $returnResult.filePathState = "Created"

                    Write-Information "File path Created at $filePath, fileName cannot exist as the file path didn't"

                    return $returnResult
                }
                catch {
                    throw "File path does not exist and could not be created at $filePath"
                }
            }
            else
            {
                throw "File path creation is disabled, and file path does not exist at $filePath, filename cannot exist"
            }
        }
    }
    ##Check filePath Path, if it does not exist and createPath is enabled, create the filePath
    if (![string]::IsNullOrEmpty($filePath))
    {
        if (!(Test-Path($filePath) -PathType Container) -and $createPath)
        {
            try {
                New-Item -Path $filePath -ItemType Directory | Out-Null
                Write-Verbose "File path created at $filePath"
                $returnResult.filePath = $filePath
                $returnResult.filePathState = "Created"

                #Set returnResult File name to the username as that is the preferred identity and we are working with a key, else if we are working with a credential use the script name
                if ($type -eq "key")
                {
                    $returnResult.fileName = "$env:USERNAME.key"
                }
                elseif (($type -eq "cred" -or $type -eq "credential") -and (![string]::IsNullOrEmpty($MyInvocation.MyCommand.Name)))
                {
                    $returnResult.fileName = "$($MyInvocation.MyCommand.Name).cred"
                }
                elseif (($type -eq "cred" -or $type -eq "credential") -and ([string]::IsNullOrEmpty($MyInvocation.MyCommand.Name)))
                {
                    throw "Check type is credential but no filename is provided and no script name is available"
                }
                
                return $returnResult
            }
            catch {
                throw "File path does not exist and could not be created at $filePath"
            }
        }
        elseif (!(Test-Path($filePath) -PathType Container) -and !$createPath)
        {
            throw "File path creation is disabled, and file path does not exist at $filePath"
        }
        #If the Path does exist, check to see if it contains a fileName with either the username or computer guid in that order
        elseif (Test-Path -Path $filePath -PathType Container)
        {
            #Set the return objects filePath to the validated path and mark as valid
            $returnResult.filePathState = "Valid"
            $returnResult.filePath = $filePath
            
            #Set returnResult File name to the username as that is the preferred identity and we are working with a key, else if we are working with a credential use the script name
            if ($type -eq "key")
            {
                $returnResult.fileName = "$env:USERNAME.key"
            }
            elseif (($type -eq "cred" -or $type -eq "credential") -and (![string]::IsNullOrEmpty($MyInvocation.MyCommand.Name)))
            {
                $returnResult.fileName = "$($MyInvocation.MyCommand.Name).cred"
            }
            elseif (($type -eq "cred" -or $type -eq "credential") -and ([string]::IsNullOrEmpty($MyInvocation.MyCommand.Name)))
            {
                throw "Check type is credential but no filename is provided and no script name is available"
            }
            

            #Check for Username fileName
            if (Test-Path -Path (Join-Path -Path $filePath -ChildPath $returnResult.fileName))
            {
                $returnResult.fileNameState = "Valid"
                return $returnResult
            }
            elseif ($type -eq "key")
            {
                #Check for Computer GUID
                $GUID = Get-CIMInstance Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID
                
                #Check for UUID
                if (Test-Path -Path (Join-Path -Path $filePath -ChildPath "$GUID.key"))
                {
                    $returnResult.fileName = "$GUID.key"
                    $returnResult.fileNameState = "Valid"
                    return $returnResult
                }
                return $returnResult
            }
            else {
                return $returnResult
            }
        }
        return $returnResult
    }
    else {
        throw "Key Store is blank, please specify a valid path to the key store"
    }
}
function New-aesManagedObject {
    
    Param 
    (
        [Parameter (HelpMessage="The AES Key for the object if not provided it will be generated.")]
            $aesKey,
        [Parameter (HelpMessage="The size of the AES Key the default is 256 as it is the greatest, but 128 and 192 are also valid options")]
            [ValidateSet(128,192,256)]
            [PSDefaultValue(Help='256')]
            [int]$aesKeySize = 256,
        [Parameter (HelpMessage="The initilization vector of the AES encryption, this is a 16 byte array. If not provided it will be generated.")]
            $initVector
    )
    
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = $aesKeySize

    if ($initVector) {
        if ($initVector.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($initVector)
        }
        else {
            $aesManaged.IV = $initVector
        }
    }

    if ($aesKey) {
        if ($aesKey.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($aesKey)
        }
        else {
            $aesManaged.Key = $aesKey
        }
    }

    return $aesManaged
}

function New-encryptionKey
{
    Param 
    (
        [Parameter (HelpMessage="This is the file path to check, if it does not exist it will create the path.")]
            [string]$keyStore = $script:defaultkeyPath,  # Allows oferriding of the default filePath location
        [Parameter (HelpMessage="Full path or filename only, if there is a / or a \ in the file it will assume that its a full path, if there are no slashes it will assume its a file name relative to the file path. If this is not specified it will be assumed that the file matches the username if there is not a username file and it will also check for a key utlising the UUID for the device, if neither exists, it will return a value of username")]
            [string]$keyFile,
        [Parameter (HelpMessage="Output of the generation, it can either store the AES key as is or as a Base64 encoded string. If you want the raw key set this to 'Raw'. Default is Raw. ")]
            [ValidateSet("Raw","Base64")]
            [PSDefaultValue(Help='Raw')]
            [string]$OutputEncoding = "Raw",
        [Parameter (HelpMessage="Forces the output of the key overwriting any existing key. Default is false.")]
            [switch]$force
    )

    $keyPath = Confirm-filePath -filePath $keyStore -fileName $keyFile -createPath -type key
    $aesManaged = New-aesManagedObject
    $aesManaged.GenerateKey()

    #Set the output type to either Base64 or Raw
    if ($OutputEncoding -eq "Base64")
    {
        Write-Information "Outputing the AES Key as a Base64 encoded string"
        $aesKey = [System.Convert]::ToBase64String($aesManaged.Key)
    }
    else
    {
        Write-Information "Outputing the AES Key as a raw byte array"
        $aesKey = $aesManaged.Key
    }

    #Handle the output of the keyfile (if possible)
    if (($keyPath.filePathState -eq "Valid" -and $keyPath.fileNameState -eq "Valid") -and $force)
    {
        Set-Content (Join-Path -Path $keyPath.filePath -ChildPath $keyPath.fileName) $aesKey
    }
    elseif (($keyPath.filePathState -eq "Valid" -and $keyPath.fileNameState -eq "Valid") -and !$force)
    {
        throw "Key already exists and cannot overwrite, please change the name or use -force to overwrite"
    }
    elseif (($keyPath.filePathState -eq "Created" -or $keyPath.filePathState -eq "Valid") -and $keyPath.fileNameState -eq "Invalid")
    {
        Set-Content (Join-Path -Path $keyPath.filePath -ChildPath $keyPath.fileName) $aesKey
    }
    else
    {
        throw "Key file path does not exist and could not be created at $($keyPath.filePath)"
    }

}

#Generates a new secure credential and saves it to the root store
function New-secureCredential
{
    
    Param 
    (
        [Parameter(Mandatory=$true)]
            [string]$username,           # Username for the credential
        [string]$rootStore = $script:defaultCredStore,           # Allows overriding of the default credential root location
        [string]$keyStore = $script:defaultKeyStore,             # Allows oferriding of the default keystore location
        [string]$credIdentifer,                                  # Used to identify a unique credential where the credential is unique for a given script/task, if not set generic credentials for username will be used. Recommended input is the script name
        [string]$credFile,                                       # Credential File, this needs to be the full path to the file
        [string]$keyFile,                                        # If there is either a / or a \ in the file it will assume that its a full path, if there are no slashes it will assume its a reletive path to the keystore
        [switch][Alias('Shared')]$aesOnly,                       # Use AES Only, do not use DPAPI, can also be Aliased to Shared for clarity when using in a shared environment
        [switch]$force                                           # Will force the write of the credential even if it already exists
    )
}

# Retrieves secure credential and applying the correct decryption, returns a credential object
function Get-secureCredential
{
    Param 
    (
        [Parameter(Mandatory=$true)]
            [string]$username,           # Username for the credential
        [string]$rootStore = $script:defaultCredStore,                   # Allows overriding of the default credential root location
        [string]$keyStore = $script:defaultKeyStore,             # Allows oferriding of the default keystore location
        [string]$credIdentifer,                                  # Used to identify a unique credential where the credential is unique for a given script/task, if not set generic credentials for username will be used. Recommended input is the script name
        [string]$credFile,                                       # Credential File, this needs to be the full path to the file
        [string]$keyFile,                                        # If there is either a / or a \ in the file it will assume that its a full path, if there are no slashes it will assume its a reletive path to the keystore
        [Parameter (HelpMessage="Object Type you want to return, secureCredential (from this module) and PSCredential both return username and password, SecureString returns the password as a SecureString, and PlainText returns the password as a string, both will return as a custom object with username and password. Default is PSCredential.")]
            [ValidateSet('secureCred','PSCred','PSCredential','SecureString','PlainText')]
            [PSDefaultValue(Help='PSCredential')]
            [string]$OutputEncoding = "PSCredential"
    )
}

function Update-secureCredential
{
    Param 
    (
        [Parameter(Mandatory=$true)]
            [string]$username,           # Username for the credential
        [string]$rootStore = $script:defaultCredStore,           # Allows overriding of the default credential root location
        [string]$keyStore = $script:defaultKeyStore,             # Allows oferriding of the default keystore location
        [string]$credIdentifer,                                  # Used to identify a unique credential where the credential is unique for a given script/task, if not set generic credentials for username will be used. Recommended input is the script name
        [string]$credFile,                                       # Credential File, this needs to be the full path to the file
        [string]$keyFile,                                        # If there is either a / or a \ in the file it will assume that its a full path, if there are no slashes it will assume its a reletive path to the keystore
        [switch][Alias('Shared')]$aesOnly                        # Use AES Only, do not use DPAPI, can also be Aliased to Shared for clarity when using in a shared environment
    )
}

# TODO|?: Decrypt the credential on the fly and return as plain-text, PSCredential or SecureString so that it can be used in the script but not held in an actively decrypted state

