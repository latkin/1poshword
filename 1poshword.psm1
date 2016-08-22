#Requires -Version 3
Set-StrictMode -Version 2
$errorActionPreference = 'Stop'
$isWindows,$isOSX,$isLinux = 
    if ($psVersionTable.PSVersion.Major -ge 6) { $isWindows,$isOSX,$isLinux }
    else { $true,$false,$false }

$1passwordRoot = "${env:userprofile}\Dropbox\1Password\1Password.agilekeychain\data\default"

function ClipboardCopy([string[]] $Data) {
    if ($isWindows) { $data | clip.exe }
    elseif ($isOSX) { $data | pbcopy }
    elseif ($isLinux -and (gcm xclip)) { $data | xclip }
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
    $keysJson = cat "$rootDir\encryptionKeys.js" | ConvertFrom-Json
    if ($keyId) {
        $keysJson.list |? identifier -eq $keyId
    } else {
        $keysJson.list |? level -eq $securityLevel
    }
}

function GetEntries([string] $RootDir) {
    foreach($item in (cat "$rootDir\contents.js" | ConvertFrom-Json)) {
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

function DecryptEntry([string] $EntryId, [string] $MasterPassword, [string] $RootDir) {
    $entry = cat "$rootDir\$entryId.1password" | ConvertFrom-Json

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

    $data = Decrypt -MD5 $entry.encrypted $dataKey

    GetPayloadFromDecryptedEntry ([system.text.encoding]::UTF8.GetString($data).Trim() -replace '\p{C}+$','') $entry.typeName
}

function Set-1PDefaultDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [string] $Path
    )

    $script:1PasswordRoot = $Path
}

function Get-1PDefaultDirectory {
    $script:1PasswordRoot
}

function Unprotect-1PEntry {
    [CmdletBinding(DefaultParameterSetName = 'plain')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $Name,

        [PSCredential] $Credential = ($null),

        [Parameter(ParameterSetName = 'ascredential')]
        [switch] $AsCredential,

        [Parameter(ParameterSetName = 'passwordonly')]
        [switch] $PasswordOnly,

        [Parameter(ParameterSetName = 'plain')]
        [Parameter(ParameterSetName = 'passwordonly')]
        [switch] $ToClipboard,

        [ValidateScript({Test-Path $_ -PathType Container})]
        [string] $1PasswordRoot = ($script:1PasswordRoot)
    )

    $entries = GetEntries $1PasswordRoot

    $entry = $entries |? Name -like $name

    if (-not $entry) {
        Write-Error "Unable to find entry matching $name"
    }

    if (@($entry).Length -gt 1) {
        Write-Error "More than one entry matches ${name}: $(($entry |% Name) -join ',')"
    }

    $plainPass =
        if ($credential -eq $null) {
            $securePass = Read-Host "1Password master password" -AsSecureString
            (New-Object PSCredential @('1poshword', $securePass)).GetNetworkCredential().Password
        } else {
            $credential.GetNetworkCredential().Password
        }

    $decrypted = DecryptEntry $entry.Id $plainPass $1passwordRoot

    $result =
        switch($psCmdlet.ParameterSetName) {
            'plain' {
                $decrypted.Username
                $decrypted.Password
                $decrypted.Text
            }
            'passwordonly' {
                if ($decrypted.Password -eq $null) {
                    Write-Error "'PasswordOnly' not supported for $($decrypted.Type)"
                }

                $decrypted.Password
            }
            'ascredential' {
                if ($decrypted.Password -eq $null) {
                    Write-Error "'AsCredential' not supported for $($decrypted.Type)"
                }

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