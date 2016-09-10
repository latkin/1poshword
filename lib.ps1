################
# Shared helpers
################
function epoch([uint64] $Seconds) {
    (New-Object DateTime @(1970,1,1,0,0,0,0,'Utc')).AddSeconds($seconds).ToLocalTime()
}

function SecureString2String([SecureString] $ss) {
    (New-Object PSCredential @('xyz', $ss)).GetNetworkCredential().Password
}

function ClipboardCopy([string[]] $Data) {
    # turbo h4x to get stuff working cross-plat, with support for
    # copying w/o trailing newline
    $clipTemplate = 
        if (Get-Command 'clip.exe' -CommandType Application -ea 0) { 'cmd.exe /c "type {0} | clip.exe"' }
        elseif (Get-Command 'pbcopy' -CommandType Application -ea 0) { "bash --noprofile --norc -c `"cat {0} | pbcopy`"" }
        elseif (Get-Command 'xclip' -CommandType Application -ea 0) { "bash --noprofile --norc -c `"cat {0} | xclip -selection clipboard`"" }
        else { Write-Error "Unable to locate clipboard utility" }

    $tmp = New-TemporaryFile
    try {
        [IO.File]::WriteAllText($tmp.FullName, $data -join "`n")
        Invoke-Expression ($clipTemplate -f $tmp.FullName)
    } finally {
        Remove-Item $tmp
    }
}

function NormalizeEntryType([string] $Type) {
    switch -regex ($type) {
        '001|WebForm' { 'Login' }
        '003|SecureNote' { 'SecureNote' }
        '005|Password' { 'Password' }
        'GenericAccount' { 'GenericAccount' }
        default { $type }
    }
}

function DeriveKeyPbkdf2([string] $Password, [byte[]] $Salt, [int] $Iterations, [int] $byteCount, [string] $HashName) {
    $passBytes = [System.Text.UTF8Encoding]::UTF8.GetBytes($password)
    $derivation =
        # if hash algorithm is SHA1, can use built-in Rfc2898DeriveBytes
        # otherwise, need to use custom code
        if ($hashName -eq 'SHA1') {
            New-Object System.Security.Cryptography.Rfc2898DeriveBytes @($passBytes, $salt, $iterations)
        } else {
            $hashAlg = Invoke-Expression "New-Object System.Security.Cryptography.HMAC$hashName"
            Add-Type -TypeDefinition ((Get-Content "$psScriptRoot/pbkdf2.cs") -join "`n") `
                -ReferencedAssemblies ([System.Security.Cryptography.HMAC].Assembly.Location),'System.IO'
            New-Object Medo.Security.Cryptography.Pbkdf2 @($hashAlg, $passBytes, $salt, $iterations)
        }
    $keyData = $derivation.GetBytes($byteCount)
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
         Aux = $keyData[16 .. 31]
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

function PickDecryptionKey([Entry] $Entry) {
    $keys = Get-Content "$($entry.VaultPath)/data/default/encryptionKeys.js" | ConvertFrom-Json |% List
    if ($entry.KeyId) { $keys |? Identifier -eq $entry.KeyId }
    else { $keys |? Level -eq $entry.SecurityLevel }
}

function GetPayloadFromDecryptedEntry([string] $DecryptedJson, [Entry] $Entry) {
    $decryptedEntry = $decryptedJson | ConvertFrom-Json
    $username = $null
    $password = $null
    $text = $null

    Set-StrictMode -Off
    switch($entry.Type) {
        'Login' {
            $password = $decryptedEntry.fields |? Designation -eq 'password' |% Value
            $username = $decryptedEntry.fields |? Designation -eq 'username' |% Value
        }
        'Password' {
            $password = $decryptedEntry.password
        }
        'GenericAccount' {
            $username = $decryptedEntry.username
            $password = $decryptedEntry.password
        }
        'SecureNote' {
            $text = $decryptedEntry.notesPlain
        }
        default {
            Write-Error "Entry type $($entry.Type) is not supported"
        }
    }
    Set-StrictMode -Version 2

    [PSCustomObject] @{
        Username = $username
        Password = $password
        SecureNote = $text
    }
}

#######################
# AgileKeychain helpers
#######################
function DecodeAgileKeychainSaltedString([string] $EncodedString) {
    $bytes = [System.Convert]::FromBase64String($encodedString.Trim(0))
    [PSCustomObject] @{
        Salt = $bytes[8 .. 15]
        Data = $bytes[16 .. ($bytes.Length - 1)]
    }
}

function DecryptAgileKeychainData([string] $Data, [object] $Key, [int] $Iterations, [switch] $MD5, [switch] $Pbkdf2) {
    $decoded = DecodeAgileKeychainSaltedString $data
    $finalKey =
        if ($md5) {
            DeriveKeyMD5 ([byte[]] $key) $decoded.Salt
        } elseif ($pbkdf2) {
            $plainPass = SecureString2String $password
            DeriveKeyPbkdf2 $plainPass $decoded.Salt $iterations 32 'SHA1'
        }

    AESDecrypt $decoded.Data $finalKey.Key $finalKey.Aux
}

function DecryptAgileKeychainEntry([Entry] $Entry, [securestring] $Password) {
    $decryptionKey = PickDecryptionKey $entry

    $dataKey = DecryptAgileKeychainData -Pbkdf2 $decryptionKey.Data $password $decryptionKey.Iterations
    $dataKeyCheck = DecryptAgileKeychainData -MD5 $decryptionkey.Validation $dataKey
    if (Compare-Object $dataKey $dataKeyCheck) {
        Write-Error "Unable to validate master password"
    }

    $entryBytes = DecryptAgileKeychainData -MD5 $entry.EncryptedData $dataKey
    $entryString = [System.Text.Encoding]::UTF8.GetString($entryBytes).Trim() -replace '\p{C}+$'
    GetPayloadFromDecryptedEntry $entryString $entry
}

function GetAgileKeychainEntries([string] $VaultPath, [string] $name) {
    $contents = Get-Content "$vaultPath/data/default/contents.js" | ConvertFrom-Json
    $entryIds = $contents |? { $_[2] -like $name } |% { $_[0] }
    Set-StrictMode -Off
    $entryIds |%{ Get-ChildItem "$vaultPath/data/default/$_.1password" } | Get-Content | ConvertFrom-Json `
        |? { $_.Uuid -and ($_.Trashed -ne 'true') } |% {
        [Entry] @{
            Name = $_.Title
            Id = $_.Uuid
            VaultPath = (Resolve-Path $vaultPath).Path
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

function 1PTabExpansion($lastBlock, $vaultPath) {
    $entryStub = $lastBlock -replace '^[^\s]+\s+'
    $quote = "'"
    if ($entryStub -match "^(`"|')") {
        $quote = $matches[1]
        $entryStub = $entryStub -replace "^(`"|')"
    }
    GetAgileKeychainEntries $vaultPath "$entryStub*" |% {
        if ($_ -match '\s') { "$quote$_$quote"}
        else { $_ }
    }
}

#################
# OPVault helpers
#################
function DecryptOPVaulOPData([string] $Data, [PSObject] $Key) {
    $dataBytes = [Convert]::FromBase64String($data)
    $dataLen = 0
    $mul = 1
    $dataBytes[8..15] |% { $dataLen += $mul * $_; $mul *= 256 }
    $padLength = 16 - ($dataLen % 16)
    $computedHash = (New-Object System.Security.Cryptography.HMACSHA256 @(,$key.Aux)).ComputeHash(($dataBytes | Select-Object -First (32 + $padLength + $dataLen)))
    $declaredHash = $dataBytes | Select-Object -Skip (32 + $padLength + $dataLen)
    if (Compare-Object $computedHash $declaredHash) {
        Write-Error "Unable to validate master password"
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
        Write-Error "Unable to validate master password"
    }

    AESDecrypt $encryptedKey $key.Key $iv
}

function GetOPVaultKeyFromBytes([byte[]] $Bytes, [switch] $NoHash) {
    $resultBytes = if ($noHash) { $bytes }
                   else { [System.Security.Cryptography.SHA512]::Create().ComputeHash($bytes) }
    [PSCustomObject] @{
        Key = $resultBytes | Select-Object -First 32
        Aux = $resultBytes | Select-Object -Last 32
    }
}

function DecryptOPVaultEntry([Entry] $Entry, [securestring] $Password) {
    $vaultProfile = ((Get-Content "$($entry.VaultPath)/default/profile.js") -replace '^var profile=(.+);$','$1') | ConvertFrom-Json
    $plainPass = SecureString2String $password
    $derivedKey = DeriveKeyPbkdf2 $plainPass ([Convert]::FromBase64String($vaultProfile.Salt)) $vaultProfile.Iterations 64 'SHA512'

    $encryptionKeyData = DecryptOPVaulOPData $vaultProfile.MasterKey $derivedKey
    $encryptionKey = GetOPVaultKeyFromBytes $encryptionKeyData

    $itemKeyBytes = DecryptOPVaultItemKey $entry.KeyData $encryptionKey
    $itemKey = GetOPVaultKeyFromBytes $itemKeyBytes -NoHash

    $entryBytes = DecryptOPVaulOPData $entry.EncryptedData $itemKey
    $entryString = [System.Text.Encoding]::UTF8.GetString($entryBytes)

    GetPayloadFromDecryptedEntry $entryString $entry
}

function GetOPVaultEntries([string] $VaultPath, [string] $Name, [securestring] $Password) {
    $vaultProfile = ((Get-Content "$vaultPath/default/profile.js") -replace '^var profile=(.+);$','$1') | ConvertFrom-Json
    $plainPass = SecureString2String $password
    $derivedKey = DeriveKeyPbkdf2 $plainPass ([Convert]::FromBase64String($vaultProfile.Salt)) $vaultProfile.Iterations 64 'SHA512'
    $overviewKeyData = DecryptOPVaulOPData $vaultProfile.OverviewKey $derivedKey
    $overviewKey = GetOPVaultKeyFromBytes $overviewKeyData

    $entries = Get-ChildItem "$vaultPath/default/band_*.js" | Get-Content |% {
        $bandEntries = $_ -replace '^ld\((.+)\);$', '$1' | ConvertFrom-Json
        $bandEntries | Get-Member -MemberType NoteProperty |% Name |% { $bandEntries.$_ }
    }

    Set-StrictMode -Off
    $entries |? Category -ne '099' |%{
        $entryBytes = DecryptOPVaulOPData $_.o $overviewKey
        $entryData = [System.Text.Encoding]::UTF8.GetString($entryBytes) | ConvertFrom-Json
        [Entry] @{
            Name = $entryData.Title
            Id = $_.Uuid
            VaultPath = (Resolve-Path $vaultPath).Path
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