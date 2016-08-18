#Requires -Version 3
Set-StrictMode -Version 2
$errorActionPreference = 'Stop'

$1passwordRoot = $null

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
       [SecureString] $password,
       [byte[]] $salt,
       [int] $iters
    )
    
    $unsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
    $deriveBytes = new-object System.Security.Cryptography.Rfc2898DeriveBytes $unsecurePassword,$salt,$iters
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
    
    $aes = New-Object System.Security.Cryptography.AesManaged
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
        [string] $SecurityLevel
    )
    $keysJson = cat "$1PasswordRoot\encryptionKeys.js" | ConvertFrom-Json
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
    foreach($item in (cat "$1PasswordRoot\contents.js" | ConvertFrom-Json))
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
        [SecureString] $MasterPassword,
        [switch] $PassOnly
    )
    
    $itemJson = cat "$1PasswordRoot\$itemID.1password" | ConvertFrom-Json
    
    Set-StrictMode -Off
    $keyId = $itemJson.KeyID
    $securityLevel = $itemJson.securityLevel
    Set-StrictMode -Version 2
    
    $decryptionKey = GetDecryptionKey $keyId $securityLevel
    
    $decoded = DecodeSaltedString $decryptionKey.data
    $keyKey = DeriveKeyPbkdf2 $masterPassword $decoded.Salt 100000
    $dataKey = AESDecrypt $decoded.Data $keyKey.Key $keyKey.IV

    $dataDecoded = DecodeSaltedString $itemJson.encrypted
    $finalKey = DeriveKeyOpenSSL $dataKey $dataDecoded.Salt
    $finalData = AESDecrypt $dataDecoded.Data $finalKey.Key $finalKey.IV

    $login = GetLoginFromDecryptedJson ([system.text.encoding]::UTF8.GetString($finalData).Trim() -replace '\p{C}+$','') $itemJson.typeName
    
    if(-not $passOnly){
        $login.Username
    }
    $login.Password
}

function Unprotect-1PEntry
{
    param(
        [string] $Name,
        [switch] $PassOnly,
        [string] $1PasswordRoot = ("${env:userprofile}\Dropbox\1Password\1Password.agilekeychain\data\default")
    )

    $contents = GetContents

    $item = $contents |?{ $_.Name -like $name }

    if(-not $item)
    {
        Write-Error "Unable to find entry matching $name"
        return
    }

    if(@($item).Length -gt 1)
    {
        Write-Error "More than one entry matches ${name}: $(($item |% Name) -join ',')"
    }

    $pass = Read-Host "1Password master password" -AsSecureString

    $script:1PasswordRoot = $1PasswordRoot

    DecryptItem $item.ID $pass -PassOnly:$passOnly.IsPresent
}

New-Alias -Name 1p -Value Unprotect-1PEntry

Export-ModuleMember -Function 'Unprotect-1PEntry' -Alias '1p'