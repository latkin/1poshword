#Requires -Version 3
Set-StrictMode -Version 2
$errorActionPreference = 'Stop'
$isWindows,$isOSX,$isLinux = 
    if($psVersionTable.PSVersion.Major -ge 6){ $isWindows,$isOSX,$isLinux }
    else { $true,$false,$false }

$1passwordRoot = "${env:userprofile}\Dropbox\1Password\1Password.agilekeychain\data\default"

function ClipboardCopy
{
    param(
        [string[]] $data
    )

    if($isWindows) {
        $data | clip.exe
    } elseif($isOSX) {
        $data | pbcopy
    } elseif($isLinux -and (gcm xclip)) {
        $data | xclip
    } else {
        Write-Error "Unable to locate clipboard utility"
    }
}

function DecodeSaltedString
{
    param(
        [string] $encodedString
    )
    
    $bytes = [System.Convert]::FromBase64String($encodedString)
    
    [PSCustomObject]@{
        Salt = $bytes[8..15]
        Data = $bytes[16..($bytes.Length - 1)]
    }
}

function DeriveKeyPbkdf2
{
    param(
       [string] $password,
       [byte[]] $salt,
       [int] $iters
    )
    
    $deriveBytes = new-object System.Security.Cryptography.Rfc2898DeriveBytes $password,$salt,$iters
    $keyData = $deriveBytes.GetBytes(32)
    
    [PSCustomObject]@{
        Key = $keyData[0..15]
        IV = $keyData[16..31]
    }
}

function DeriveKeyOpenSSL
{
    param(
       [byte[]] $key,
       [byte[]] $salt
    )
    
    $key = $key[0..($key.length - 17)]
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $prev = @()
    $keyData = @()
    while($keyData.Length -lt 32)
    {
        $prev = $md5.ComputeHash($prev + $key + $salt)
        $keyData += $prev
    }
    
    [PSCustomObject]@{
         Key = $keyData[0..15]
         IV = $keyData[16..31]
    }
}

function AESDecrypt
{
    param(
        [byte[]] $data,
        [byte[]] $key,
        [byte[]] $iv
    )
    
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.IV = $iv
    $aes.Padding = 'None'
    $decryptor = $aes.CreateDecryptor($key, $iv)
    $memStream = new-object System.IO.MemoryStream @(,$data)
    $cryptStream = new-object System.Security.Cryptography.CryptoStream $memStream, $decryptor, 'Read'

    $result = $(
        $b = $cryptStream.ReadByte()
        while($b -ne -1){
            $b
            $b = $cryptStream.ReadByte()
        }
    )    
    $cryptStream.Dispose()
    $memStream.Dispose()
    $decryptor.Dispose()
    $aes.Dispose()
    
    $paddingSize = $result[-1]
    if($paddingSize -ge 16){
        $result
    } else {
        $result[0..($result.Length - $paddingSize - 1)]
    }
}

function GetDecryptionKey
{
    param(
        [string] $KeyId,
        [string] $SecurityLevel,
        [string] $RootDir
    )

    $keysJson = cat "$rootDir\encryptionKeys.js" | ConvertFrom-Json
    if($keyId)
    {
        $keysJson.list |?{ $_.identifier -eq $keyId }
    }
    else
    {
        $keysJson.list |?{ $_.level -eq $securityLevel }
    }
}

function GetContents
{
    param(
        [string] $RootDir
    )

    foreach($item in (cat "$rootDir\contents.js" | ConvertFrom-Json))
    {
        [PSCustomObject]@{
            ID = $item[0]
            Name = $item[2]
        }
    }
}

function GetLoginFromDecryptedJson
{
    param(
        [string] $Json,
        [string] $TypeName
    )
    
    $item = $json | ConvertFrom-Json
    
    if($typeName -eq 'webforms.WebForm'){
        Set-StrictMode -Off
        $password = $item.fields |?{ $_.designation -eq 'password' } |%{ $_.value }
        $username = $item.fields |?{ $_.designation -eq 'username' } |%{ $_.value }
        [PSCustomObject]@{
            Username = $username
            Password = $password
        }
        Set-StrictMode -Version 2
    } elseif($typeName -eq 'passwords.Password') {
        [PSCustomObject]@{
            UserName = $null
            Password = $item.password
        }
    }
}

function DecryptItem
{
    param(
        [string] $ItemID,
        [string] $MasterPassword,
        [string] $RootDir
    )
    
    $itemJson = cat "$rootDir\$itemID.1password" | ConvertFrom-Json
    
    Set-StrictMode -Off
    $keyId = $itemJson.KeyID
    $securityLevel = $itemJson.securityLevel
    Set-StrictMode -Version 2
    
    $decryptionKey = GetDecryptionKey $keyId $securityLevel $rootDir
    
    $decoded = DecodeSaltedString $decryptionKey.data
    $keyKey = DeriveKeyPbkdf2 $masterPassword $decoded.Salt 100000
    $dataKey = AESDecrypt $decoded.Data $keyKey.Key $keyKey.IV

    $dataDecoded = DecodeSaltedString $itemJson.encrypted
    $finalKey = DeriveKeyOpenSSL $dataKey $dataDecoded.Salt
    $finalData = AESDecrypt $dataDecoded.Data $finalKey.Key $finalKey.IV

    $login = GetLoginFromDecryptedJson ([system.text.encoding]::UTF8.GetString($finalData).Trim() -replace '\p{C}+$','') $itemJson.typeName
    
    [PSCustomObject]@{
        Username = $login.Username
        Password = $login.Password
    }
}

function Set-1PDefaultDirectory
{
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [string] $Path
    )

    $script:1PasswordRoot = $Path
}

function Get-1PDefaultDirectory
{
    $script:1PasswordRoot
}

function Unprotect-1PEntry
{
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

    $contents = GetContents $1PasswordRoot

    $item = $contents |?{ $_.Name -like $name }

    if(-not $item)
    {
        Write-Error "Unable to find entry matching $name"
        return
    }

    if(@($item).Length -gt 1)
    {
        Write-Error "More than one entry matches ${name}: $(($item |% Name) -join ',')"
        return
    }

    $plainPass =
        if($credential -eq $null) {
            $securePass = Read-Host "1Password master password" -AsSecureString
            (New-Object PSCredential @('1poshword', $securePass)).GetNetworkCredential().Password
        } else {
            $credential.GetNetworkCredential().Password
        }

    $decrypted = DecryptItem $item.ID $plainPass $1passwordRoot

    $result =
        switch($psCmdlet.ParameterSetName) {
            'plain' {
                $decrypted.Username
                $decrypted.Password
            }
            'passwordonly' {
                $decrypted.Password
            }
            'ascredential' {
                $securePass = New-Object SecureString
                $decrypted.Password.ToCharArray() |%{ $securePass.AppendChar($_) }
                New-Object PSCredential @($decrypted.Username, $securePass)
            }
        }
    
    if($toClipboard) { ClipboardCopy $result }
    else { $result }
}

New-Alias -Name 1p -Value Unprotect-1PEntry

Export-ModuleMember -Function 'Unprotect-1PEntry','Get-1PDefaultDirectory','Set-1PDefaultDirectory' -Alias '1p'