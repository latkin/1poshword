#Requires -Version 3
Set-StrictMode -Version 2
$errorActionPreference = 'Stop'
$home = if($env:USERPROFILE){ $env:USERPROFILE } else { $env:HOME }
$DefaultVaultPath =
    if (Test-Path "$home/Dropbox/1Password/1Password.agilekeychain"){ "$home/Dropbox/1Password/1Password.agilekeychain" }
    elseif (Test-Path "$home/Dropbox/1Password/1Password.opvault") { "$home/Dropbox/1Password/1Password.opvault" }
    else { Write-Warning "Unable to auto-detect a 1Password vault location" }

Add-Type -TypeDefinition ((Get-Content $psScriptRoot/pbkdf2.cs) -join "`n") -ReferencedAssemblies 'System.Security.Cryptography.Primitives.dll','System.IO'

if($PSVersionTable.PSVersion -lt '5.0.0') {
    Add-Type -ea 0 @'
    public class Entry {
        public string Name;
        public string Id;
        public string VaultPath;
        public string SecurityLevel;
        public string KeyId;
        public string KeyData;
        public string Location;
        public string Type;
        public System.DateTime CreatedAt;
        public System.DateTime LastUpdated;
        public string EncryptedData;
        public override string ToString() {
            return Name;
        }
    }
'@
} else {
    class Entry {
        [string] $Name
        [string] $Id
        [string] $VaultPath
        [string] $SecurityLevel
        [string] $KeyId
        [string] $KeyData
        [string] $Location
        [string] $Type
        [DateTime] $CreatedAt
        [DateTime] $LastUpdated
        [string] $EncryptedData
        [string] ToString() { return $this.Name }
    }
}

function epoch([uint64] $Seconds) {
    (New-Object DateTime @(1970,1,1,0,0,0,0,'Utc')).AddSeconds($seconds).ToLocalTime()
}

function SecureString2String([SecureString] $ss) {
    (New-Object PSCredential @('xyz', $ss)).GetNetworkCredential().Password
}

function NormalizeEntryType([string] $Type) {
    switch -regex ($type) {
        '001|WebForm' { 'Login' }
        '003|SecureNote' { 'SecureNote' }
        '005|Password' { 'Password' }
        default { $type }
    }
}

function DecodeSaltedString([string] $EncodedString) {
    $bytes = [System.Convert]::FromBase64String($encodedString)
    [PSCustomObject] @{
        Salt = $bytes[8 .. 15]
        Data = $bytes[16 .. ($bytes.Length - 1)]
    }
}

function DeriveKeyPbkdf2([string] $Password, [byte[]] $Salt, [int] $Iterations, [int] $byteCount, [string] $HashName) {
    $passBytes = [System.Text.UTF8Encoding]::UTF8.GetBytes($password)
    $hashAlg = Invoke-Expression "New-Object System.Security.Cryptography.HMAC$hashName"
    $deriveBytes = New-Object Medo.Security.Cryptography.Pbkdf2 @($hashAlg, $passBytes, $salt, $iterations)
    $keyData = $deriveBytes.GetBytes($byteCount)
    [PSCustomObject] @{
        Key = $keyData | Select-Object -First ($byteCount / 2)
        Aux = $keyData | Select-Object -Last ($byteCount / 2)
    }
}

function DeriveKeyMD5([byte[]] $Key, [byte[]] $Salt) {
    $key = $key[0 .. ($key.length - 17)]
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $prev = @()
    $keyData = @()
    while ($keyData.Length -lt 32) {
        $prev = $md5.ComputeHash($prev + $key + $salt)
        $keyData += $prev
    }

    [PSCustomObject] @{
         Key = $keyData[0 .. 15]
         IV = $keyData[16 .. 31]
    }
}

function AESDecrypt([byte[]] $Data, [byte[]] $Key, [byte[]] $IV) {
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Padding = 'None'
    $decryptor = $aes.CreateDecryptor($key, $iv)
    $memStream = New-Object System.IO.MemoryStream @(,$data)
    $cryptStream = New-Object System.Security.Cryptography.CryptoStream $memStream,$decryptor,'Read'
    $result = $(
        $b = $cryptStream.ReadByte()
        while ($b -ne -1) {
            $b
            $b = $cryptStream.ReadByte()
        }
    )

    $cryptStream.Dispose()
    $memStream.Dispose()
    $decryptor.Dispose()
    $aes.Dispose()

    $result
}

function DecryptOPVaulOPData([string] $Data, [PSObject] $Key) {
    $dataBytes = [Convert]::FromBase64String($data) 
    $dataLen = 0
    $mul = 1
    $dataBytes[8..15] |% { $dataLen += $mul * $_; $mul *= 256 }
    $padLength = 16 - ($dataLen % 16)
    $computedHash = (New-Object System.Security.Cryptography.HMACSHA256 @(,$key.Aux)).ComputeHash(($dataBytes | Select-Object -First (32 + $padLength + $dataLen)))
    $declaredHash = $dataBytes | Select-Object -Skip (32 + $padLength + $dataLen)
    if (Compare-Object $computedHash $declaredHash) {
        Write-Error "Hash verification failed"
    }
    $iv = $dataBytes[16..31]
    $encryptedBytes = $dataBytes | Select-Object -Skip 32 | Select-Object -First ($dataLen + $padLength)
    AESDecrypt $encryptedBytes $key.Key $iv | Select-Object -Skip $padLength
}

function DecryptOPVaultItemKey([string] $Data, [PSObject] $Key) {
    $dataBytes = [Convert]::FromBase64String($data)
    $iv = $dataBytes[0..15]
    $encryptedKey = $dataBytes[16..79]
    $computedHash = (New-Object System.Security.Cryptography.HMACSHA256 @(,$key.Aux)).ComputeHash(($dataBytes | Select-Object -First 80))
    $declaredHash = $dataBytes | Select-Object -Last 32
    if (Compare-Object $computedHash $declaredHash) {
        Write-Error "Hash verification failed"
    }

    AESDecrypt $encryptedKey $key.Key $iv
}

function GetOPVaultKeyFromBytes([byte[]] $Bytes) {
    $keyHash = [System.Security.Cryptography.SHA512]::Create().ComputeHash($bytes)
    [PSCustomObject] @{
        Key = $keyHash | Select-Object -First 32
        Aux = $keyHash | Select-Object -Last 32
    }
}

function PickDecryptionKey([Entry] $Entry) {
    $keys = Get-Content "$($entry.VaultPath)/encryptionKeys.js" | ConvertFrom-Json |% List
    if ($entry.KeyId) { $keys |? Identifier -eq $entry.KeyId }
    else { $keys |? Level -eq $entry.SecurityLevel }
}

function GetPayloadFromDecryptedEntry([string] $DecryptedJson, [Entry] $Entry) {
    $decryptedEntry = $decryptedJson | ConvertFrom-Json
    $username = $null
    $password = $null
    $text = $null

    switch($entry.Type) {
        'Login' {
            Set-StrictMode -Off
            $password = $decryptedEntry.fields |? Designation -eq 'password' |% Value
            $username = $decryptedEntry.fields |? Designation -eq 'username' |% Value
            Set-StrictMode -Version 2
        }
        'Password' {
            $password = $decryptedEntry.password
        }
        'SecureNote' {
            $text = $decryptedEntry.notesPlain
        }
        default {
            Write-Error "Entry type $typeName is not supported"
        }
    }

    [PSCustomObject] @{
        Username = $username
        Password = $password
        SecureNote = $text
    }
}

function Decrypt([string] $Data, [object] $Key, [int] $Iterations, [switch] $MD5, [switch] $Pbkdf2) {
    $decoded = DecodeSaltedString $data
    $finalKey = 
        if ($md5) {
            DeriveKeyMD5 ([byte[]] $key) $decoded.Salt
        } elseif ($pbkdf2) {
            $plainPass = SecureString2String $password
            DeriveKeyPbkdf2 $plainPass $decoded.Salt $iterations 32 'SHA1'
        }

    AESDecrypt $decoded.Data $finalKey.Key $finalKey.Aux
}

function DecryptEntry([Entry] $Entry, [securestring] $Password) {
    $decryptionKey = PickDecryptionKey $entry

    $dataKey = Decrypt -Pbkdf2 $decryptionKey.Data $password $decryptionKey.Iterations
    $dataKeyCheck = Decrypt -MD5 $decryptionkey.Validation $dataKey
    if (Compare-Object $dataKey $dataKeyCheck) {
        Write-Error "Unable to validate master password"
    }

    $entryBytes = Decrypt -MD5 $entry.EncryptedData $dataKey
    $entryString = [System.Text.Encoding]::UTF8.GetString($entryBytes).Trim() -replace '\p{C}+$'
    GetPayloadFromDecryptedEntry $entryString $entry
}

function GetAgileKeychainEntries([string] $VaultPath, [string] $name) {
    $contents = Get-Content "$vaultPath/data/default/contents.js" | ConvertFrom-Json
    $entryIds = $contents |? { $_[2] -like $name } |% { $_[0] }
    Set-StrictMode -Off
    $entryIds |%{ Get-ChildItem "$vaultPath/data/default/$_.1password" } | Get-Content | ConvertFrom-Json |% {
        [Entry] @{
            Name = $_.Title
            Id = $_.Uuid
            VaultPath = $vaultPath
            SecurityLevel = $_.SecurityLevel
            KeyId = $_.KeyId
            Location = $_.Location
            CreatedAt = (epoch $_.CreatedAt)
            Type = (NormalizeEntryType $_.TypeName)
            LastUpdated = (epoch $_.UpdatedAt)
            EncryptedData = $_.Encrypted
        }
    }
    Set-StrictMode -Version 2
}

function GetOPVaultEntries([string] $VaultPath, [string] $Name, [securestring] $Password) {
    $vaultProfile = ((Get-Content "$vaultPath/default/profile.js") -replace '^var profile=(.+);$','$1') | ConvertFrom-Json
    $plainPass = SecureString2String $password
    $derivedKey = DeriveKeyPbkdf2 $plainPass ([Convert]::FromBase64String($vaultProfile.Salt)) $vaultProfile.Iterations 64 'SHA512'
    $overviewKeyData = DecryptOPVaulOPData $vaultProfile.OverviewKey $derivedKey
    $overviewKey = GetOPVaultKeyFromBytes $overviewKeyData

    $entries = Get-ChildItem "$vaultPath/default/band_*.js" | Get-Content |% { $_ -replace '^[^:]+:(.+)}\);$', '$1' } | ConvertFrom-Json
    Set-StrictMode -Off
    $entries |%{
        $entryBytes = DecryptOPVaulOPData $_.o $overviewKey
        $entryData = [System.Text.Encoding]::UTF8.GetString($entryBytes) | ConvertFrom-Json
        [Entry] @{
            Name = $entryData.Title
            Id = $_.Uuid
            VaultPath = $vaultPath
            Location = $entryData.Url
            CreatedAt = (epoch $_.Created)
            Type = (NormalizeEntryType $_.Category)
            LastUpdated = (epoch $_.Updated)
            EncryptedData = $_.D
            KeyData = $_.K
        }
    } |? Name -like $name
    Set-StrictMode -Version 2
}

<#
.SYNOPSIS
Sets the default 1Password vault directory to a new value.

.DESCRIPTION
Sets the default 1Password vault directory to a new value. The 1Password vault at this location
will be used by other 1Poshword cmdlets unless otherwise specified.

.PARAMETER Path
Specifies the root directory of the default 1Password vault. This directory
should contain the file encryptionKeys.js.

.EXAMPLE
PS ~$ Set-1PDefaultVaultPath '/Users/calvin/1p/1Password.agilekeychain/data/default'
#>
function Set-1PDefaultVaultPath {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({(Test-Path $_ -PathType Container) -and (Test-Path "$_/encryptionKeys.js")})]
        [string] $Path
    )

    if ($psCmdlet.ShouldProcess($path)) {
        $script:DefaultVaultPath = $path
    }
}

<#
.SYNOPSIS
Gets the default 1Password root directory to a new value.

.DESCRIPTION
Gets the default 1Password root directory. The 1Password vault at this location
will be used by Unprotect-1PEntry unless otherwise specified.

.EXAMPLE
PS ~$ Get-1PDefaultVaultPath
#>
function Get-1PDefaultVaultPath {
    $script:DefaultVaultPath
}

function Get-1PEntry {
    param(
        [Parameter(Position = 0)]
        [string] $Name,

        [Parameter(Position = 1)]
        [SecureString] $Password,

        [string] $VaultPath = ($script:DefaultVaultPath)
    )

    if(-not $name){ $name = '*' }

    $result = $null
    if ($vaultPath -like '*.agilekeychain') {
        $result = GetAgileKeychainEntries $vaultPath $name
    } elseif ($vaultPath -like '*.opvault') {
        if (-not $password) {
            $password = Read-Host -AsSecureString -Prompt "1Password master password"
        }
        $result = GetOPVaultEntries $vaultPath $name $password
    }
    if((-not $result) -and ($name -notmatch '\*')) {
        Write-Error "No 1Password entries found with name $name"
    }
    $result
}

<#
.SYNOPSIS
Decrypts a 1Password Login, Password, or Secure Note into various forms.

.DESCRIPTION
Decrypts a 1Password Login, Password, or Secure Note.
The alias 1p is provided by default.
Supported output formats are
  - Plaintext to pipeline (username + password or password only)
  - Plaintext to clipboard (username + password or password only)
  - PSCredential

.PARAMETER Name
Specifies the name of the 1Password entry.
A case-insensitive wildcard match is used.
An error is thrown if no entries, or more than one entry, match the specified name.

.PARAMETER Credential
Specifies the 1Password master password.
If no value is specified, user will be prompted to enter password interactively.
If passing a PSCredential object, only the password field is considered.

.PARAMETER AsCredential
If specified, the resulting entry is returned as a PSCredential.
'Login' entries will have username and password fields populated.
'Password' entries will have the password field populated and 'none' as the username.
'Secure Note' entries are not supported with this option and will result in an error.

.PARAMETER PasswordOnly
If specified, only the password is returned from the resulting entry.
'Secure Note' entries are not supported with this option and will result in an error.

.PARAMETER ToClipboard
If specified, the resulting entry will be copied to the clipboard instead of returned to the pipeline.

.PARAMETER VaultPath
Specifies the root directory of the 1Password vault from which to read.
The default root directory can be read via Get-1PDefaultVaultPath, and changed via Set-1PDefaultVaultPath.

.EXAMPLE
Copies GMail username and password to the clipboard.

PS ~$ Unprotect-1PEntry gmail -ToClipboard
1Password master password: **********
PS ~$

.EXAMPLE
Pipes the system password into another command which normally prompts for a password.

PS ~$ Unprotect-1PEntry system -PasswordOnly | sudo -Sk echo "`ndude, sweet"
1Password master password: **********
Password:
dude, sweet
PS ~$

.EXAMPLE
Uses a bound PSCredential object to specify the 1Password master password.

PS ~$ $cred = Get-Credential
cmdlet Get-Credential at command pipeline position 1
Supply values for the following parameters:
Credential
User: dummy
Password for user dummy: **********

PS ~$ Unprotect-1PEntry myaccount -Credential $cred
myusername
myp@ssw0rd
PS ~$
#>
function Unprotect-1PEntry {
    [CmdletBinding(DefaultParameterSetName = 'Name/Secure')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Name/Secure')]
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Name/Plain')]
        [string] $Name,

        [Parameter(ParameterSetName = 'Name/Secure')]
        [Parameter(ParameterSetName = 'Name/Plain')]
        [string] $VaultPath = ($script:DefaultVaultPath),

        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = 'Entry/Secure')]
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = 'Entry/Plain')]
        [Entry] $Entry,

        [Parameter(Position = 1)]
        [SecureString] $Password,

        [Parameter(ParameterSetName = 'Name/Plain')]
        [Parameter(ParameterSetName = 'Entry/Plain')]
        [switch] $Plaintext,

        [Parameter(ParameterSetName = 'Name/Plain')]
        [Parameter(ParameterSetName = 'Entry/Plain')]
        [Alias('po')]
        [switch] $PasswordOnly
    )

    $paramSet = $psCmdlet.ParameterSetName
    $entries = $null
    if ($name) {
        $entries = Get-1PEntry -Name $name -VaultPath $vaultPath
    }
    if (-not $entries) {
        Write-Error "No 1Password entries found with name $name"
    }
    if (@($entries).Length -gt 1) {
        Write-Error "More than one entry matches ${name}: $($entries -join ', ')"
    }

    $entry = $entries
    if ($entry.Type -match 'SecureNote' -and $passwordOnly) {
        Write-Error "PasswordOnly not supported for Secure Notes"
    }
    if(-not $password){
        $password = Read-Host -AsSecureString -Prompt "1Password master password"
    }

    $decrypted = DecryptEntry $entry $password
    switch -regex ($paramSet) {
        'Secure' {
            if ($decrypted.SecureNote) {
                ConvertTo-SecureString $decrypted.SecureNote -AsPlainText -Force
            } else {
                $securePass = ConvertTo-SecureString $decrypted.Password -AsPlainText -Force
                $username = if ($decrypted.Username) { $decrypted.Username } else { '<none>' }
                New-Object PSCredential @($username, $securePass)
            }
        }
        'Plain' {
            if(-not $passwordOnly) {
                $decrypted.SecureNote
                $decrypted.Username
            }
            $decrypted.Password
        }
    }
}

New-Alias 1p Unprotect-1PEntry

Export-ModuleMember -Function 'Get-1PDefaultVaultPath','Set-1PDefaultVaultPath','Get-1PEntry','Unprotect-1PEntry' -Alias 1p
