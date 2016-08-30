#Requires -Version 3
Set-StrictMode -Version 2
$errorActionPreference = 'Stop'
$home = if($env:USERPROFILE){ $env:USERPROFILE } else { $env:HOME }
$DefaultVaultPath = "$home/Dropbox/1Password/1Password.agilekeychain/data/default"

if($PSVersionTable.PSVersion -lt '5.0.0') {
    Add-Type -ea 0 @'
    public class Entry {
        public string Name;
        public string Id;
        public string VaultPath;
        public string LocationKey;
        public string SecurityLevel;
        public string KeyId;
        public string Location;
        public string Type;
        public System.DateTime CreatedAt;
        public System.DateTime LastUpdated;
        public System.DateTime? LastUsed;
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
        [string] $LocationKey
        [string] $SecurityLevel
        [string] $KeyId
        [string] $Location
        [string] $Type
        [DateTime] $CreatedAt
        [DateTime] $LastUpdated
        [Nullable[DateTime]] $LastUsed
        [string] $EncryptedData
        [string] ToString() { return $this.Name }
    }
}

function epoch([uint64] $Seconds) {
    (New-Object DateTime @(1970,1,1,0,0,0,0,'Utc')).AddSeconds($seconds).ToLocalTime()
}

function DecodeSaltedString([string] $EncodedString) {
    $bytes = [System.Convert]::FromBase64String($encodedString)
    [PSCustomObject] @{
        Salt = $bytes[8 .. 15]
        Data = $bytes[16 .. ($bytes.Length - 1)]
    }
}

function DeriveKeyPbkdf2([string] $Password, [byte[]] $Salt, [int] $Iterations) {
    $deriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes $password,$salt,$iterations
    $keyData = $deriveBytes.GetBytes(32)
    [PSCustomObject] @{
        Key = $keyData[0 .. 15]
        IV = $keyData[16 .. 31]
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

    $paddingSize = $result[-1]
    if ($paddingSize -ge 16) {
        $result
    } else {
        $result[0 .. ($result.Length - $paddingSize - 1)]
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
        'webforms.WebForm' {
            Set-StrictMode -Off
            $password = $decryptedEntry.fields |? Designation -eq 'password' |% Value
            $username = $decryptedEntry.fields |? Designation -eq 'username' |% Value
            Set-StrictMode -Version 2
        }
        'passwords.Password' {
            $password = $decryptedEntry.password
        }
        'securenotes.SecureNote' {
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
            $plainPass = (New-Object PSCredential @('1Poshword', $password)).GetNetworkCredential().Password
            DeriveKeyPbkdf2 $plainPass $decoded.Salt $iterations
        }

    AESDecrypt $decoded.Data $finalKey.Key $finalKey.IV
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

function GetEntries([string] $VaultPath, [string] $name) {
    $contents = Get-Content "$vaultPath/contents.js" | ConvertFrom-Json
    $entryIds = $contents |? { $_[2] -like $name } |% { $_[0] }
    Set-StrictMode -Off
    $entryIds |%{ Get-ChildItem "$vaultPath/$_.1password" } | Get-Content | ConvertFrom-Json |% {
        [Entry] @{
            Name = $_.Title
            Id = $_.Uuid
            VaultPath = $vaultPath
            LocationKey = $_.LocationKey
            SecurityLevel = $_.SecurityLevel
            KeyId = $_.KeyId
            Location = $_.Location
            CreatedAt = (epoch $_.CreatedAt)
            Type = $_.TypeName
            LastUpdated = (epoch $_.UpdatedAt)
            EncryptedData = $_.Encrypted
            LastUsed = if($_.TxTimestamp){ epoch $_.TxTimestamp } else { $null }
        }
    }
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
        [Parameter(Position = 1)]
        [string] $Name,

        [string] $VaultPath = ($script:DefaultVaultPath)
    )

    if(-not $name){ $name = '*' }

    $result = GetEntries $vaultPath $name
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
