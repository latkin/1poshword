#Requires -Version 3
Set-StrictMode -Version 2
$errorActionPreference = 'Stop'
$isWindows,$isOSX,$isLinux = 
    if ($psVersionTable.PSVersion.Major -ge 6) { $isWindows,$isOSX,$isLinux }
    else { $true,$false,$false }

$1passwordRoot =
    if($isWindows) { "${env:userprofile}\Dropbox\1Password\1Password.agilekeychain\data\default" }
    elseif($isOSX) { "${env:HOME}/Dropbox/1Password/1Password.agilekeychain/data/default"}

function ClipboardCopy([string[]] $Data) {
    if ($isWindows) { $data | clip.exe }
    elseif ($isOSX) { $data | pbcopy }
    elseif ($isLinux -and (Get-Command xclip)) { $data | xclip }
    else { Write-Error "Unable to locate clipboard utility" }
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
    $aes.Key = $key
    $aes.IV = $iv
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

function GetDecryptionKey([string] $KeyId, [string] $SecurityLevel, [string] $RootDir) {
    $keysJson = Get-Content "$rootDir/encryptionKeys.js" | ConvertFrom-Json
    if ($keyId) {
        $keysJson.list |? identifier -eq $keyId
    } else {
        $keysJson.list |? level -eq $securityLevel
    }
}

function GetEntries([string] $RootDir) {
    foreach($item in (Get-Content "$rootDir/contents.js" | ConvertFrom-Json)) {
        [PSCustomObject] @{
            Id = $item[0]
            Name = $item[2]
        }
    }
}

function GetPayloadFromDecryptedEntry([string] $EntryJson, [string] $TypeName) {
    $entry = $entryJson | ConvertFrom-Json
    $username = $null
    $password = $null
    $text = $null

    switch($typeName) {
        'webforms.WebForm' {
            Set-StrictMode -Off
            $password = $entry.fields |? designation -eq 'password' |% value
            $username = $entry.fields |? designation -eq 'username' |% value
            Set-StrictMode -Version 2
        }
        'passwords.Password' {
            $password = $entry.password
        }
        'securenotes.SecureNote' {
            $text = $entry.notesPlain
        }
        default {
            Write-Error "Entry type $typeName is not supported"
        }
    }

    [PSCustomObject] @{
        Type = $typeName
        Username = $username
        Password = $password
        Text = $text
    }
}

function Decrypt([string] $Data, [object] $Key, [int] $Iterations, [switch] $MD5, [switch] $Pbkdf2) {
    $decoded = DecodeSaltedString $data
    $finalKey = 
        if ($md5) {
            DeriveKeyMD5 ([byte[]] $key) $decoded.Salt
        } elseif ($pbkdf2) {
            DeriveKeyPbkdf2 ([string] $key) $decoded.Salt $iterations
        }

    AESDecrypt $decoded.Data $finalKey.Key $finalKey.IV
}

function DecryptEntry([PSObject] $Entry, [string] $MasterPassword, [string] $RootDir) {
    Set-StrictMode -Off
    $keyId = $entry.KeyId
    $securityLevel = $entry.securityLevel
    Set-StrictMode -Version 2

    $decryptionKey = GetDecryptionKey $keyId $securityLevel $rootDir

    $dataKey = Decrypt -Pbkdf2 $decryptionKey.data $masterPassword $decryptionKey.Iterations
    $dataKeyCheck = Decrypt -MD5 $decryptionkey.validation $dataKey
    if (Compare-Object $dataKey $dataKeyCheck) {
        Write-Error "Unable to validate master password"
    }

    $entryBytes = Decrypt -MD5 $entry.encrypted $dataKey
    $entryString = [System.Text.Encoding]::UTF8.GetString($entryBytes).Trim() -replace '\p{C}+$'
    GetPayloadFromDecryptedEntry $entryString $entry.typeName
}

function Set-1PDefaultDirectory {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [string] $Path
    )

    if ($psCmdlet.ShouldProcess($path)) {
        $script:1PasswordRoot = $path
    }
}

function Get-1PDefaultDirectory {
    $script:1PasswordRoot
}

function Unprotect-1PEntry {
    [CmdletBinding(DefaultParameterSetName = 'Plain')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $Name,

        [PSCredential] [System.Management.Automation.Credential()] $Credential = ($null),

        [Parameter(ParameterSetName = 'AsCredential')]
        [switch] $AsCredential,

        [Parameter(ParameterSetName = 'PasswordOnly')]
        [switch] $PasswordOnly,

        [Parameter(ParameterSetName = 'Plain')]
        [Parameter(ParameterSetName = 'PasswordOnly')]
        [switch] $ToClipboard,

        [ValidateScript({Test-Path $_ -PathType Container})]
        [string] $1PasswordRoot = ($script:1PasswordRoot)
    )

    $paramSet = $psCmdlet.ParameterSetName
    $entryInfo = GetEntries $1PasswordRoot |? Name -like $name

    if (-not $entryInfo) {
        Write-Error "Unable to find entry matching $name"
    }

    if (@($entryInfo).Length -gt 1) {
        Write-Error "More than one entry matches ${name}: $(($entryInfo |% Name) -join ',')"
    }

    $entry = Get-Content "$1PasswordRoot/$($entryInfo.Id).1password" | ConvertFrom-Json

    if ($paramSet -match 'PasswordOnly|AsCredential' -and $entry.typeName -match 'SecureNote') {
        Write-Error "$paramSet not supported for $($entry.typeName)"
    }

    $plainPass =
        if ($null -eq $credential) {
            $securePass = Read-Host "1Password master password" -AsSecureString
            (New-Object PSCredential @('1poshword', $securePass)).GetNetworkCredential().Password
        } else {
            $credential.GetNetworkCredential().Password
        }

    $decrypted = DecryptEntry $entry $plainPass $1passwordRoot

    $result =
        switch($paramSet) {
            'Plain' {
                $decrypted.Username
                $decrypted.Password
                $decrypted.Text
            }
            'PasswordOnly' {
                $decrypted.Password
            }
            'AsCredential' {
                $securePass = New-Object SecureString
                $decrypted.Password.ToCharArray() |%{ $securePass.AppendChar($_) }
                New-Object PSCredential @($decrypted.Username, $securePass)
            }
        }

    if ($toClipboard) { ClipboardCopy $result }
    else { $result }
}

New-Alias -Name 1p -Value Unprotect-1PEntry

Export-ModuleMember -Function 'Unprotect-1PEntry','Get-1PDefaultDirectory','Set-1PDefaultDirectory' -Alias '1p'