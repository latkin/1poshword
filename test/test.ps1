param ([switch] $test)

if(-not $test) {
    powershell -noprofile -file $psScriptRoot/test.ps1 -test
    return
}

$password = ConvertTo-SecureString 'p@ssw0rd' -AsPlainText -Force
$badPassword = ConvertTo-SecureString 'p@ssw0rd1' -AsPlainText -Force
$agileVaultPath = (Resolve-Path "$psScriptRoot/TestVault.agilekeychain").Path
$opVaultPath = (Resolve-Path "$psScriptRoot/TestVault.opvault").Path

function SecureString2String([SecureString] $ss) {
    (New-Object PSCredential @('xyz', $ss)).GetNetworkCredential().Password
}

function log([string] $Msg, [ConsoleColor] $Color = [Console]::ForegroundColor) {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $args = @{Object = $msg}
    if($color -ge 0){ $args.Add('ForegroundColor', $color) }
    Write-Host "$ts - " -nonew
    Write-Host @args
}

function test($name, [ScriptBlock] $action, $errPattern) {
    $err = $null
    log "Running test [$name]" -Color Cyan
    $errorActionPreference = 'Stop'
    try {
        $null = & $action
        if ($errPattern) {
            $err = "Expected error not thrown"
        }
    } catch {
        if ((-not $errPattern) -or ($_ -notmatch $errPattern)){
            $err = $_
        }
    }

    if(-not $err){ log "OK" -Color Green }
    else {
        log "FAIL" -Color Red
        log $err -Color Red
    }
}

log 'Uninstalling module'
Get-Module 1poshword -ea 0 | Uninstall-Module

log 'Importing module'
Import-Module $psScriptRoot/../1poshword.psm1

# Get/Set-1PDefaultVaultPath cases
test 'Set/get default agilekeychain' {
    Set-1PDefaultVaultPath $agileVaultPath
    $v = Get-1PDefaultVaultPath
    if ($v -cne $agileVaultPath){ throw "$v not expected" }
}
test 'Set/get default opvault' {
    Set-1PDefaultVaultPath $opVaultPath
    $v = Get-1PDefaultVaultPath
    if ($v -cne $opVaultPath){ throw "$v not expected" }
}
test 'Set bogus vault' -err . {
    Set-1PDefaultVaultPath $psScriptRoot
}

# Get-1PEntry cases specific to agilekeychain
test "Get all entries from agile" {
    $entries = g1p -vaultpath $agileVaultPath
    if($entries.Length -ne 5) { throw "Expected 5 entries, got $($entries.length)" }

    $entries = g1p test* -vaultpath $agileVaultPath
    if($entries.Length -ne 5) { throw "Expected 5 entries, got $($entries.length)" }
}
test "Get generic account from agile" {
    $entry = g1p TestGenericAccount -vaultpath $agileVaultPath
    if($entry.Name -cne 'TestGenericAccount' -or
       $entry.Type -cne 'GenericAccount' -or
       $entry.VaultPath -cne $agileVaultPath) { throw "Unexpected entry" }
}

# Get-1PEntry cases specific to opvault
test "Get all entries from opvault" {
    $entries = g1p -vaultpath $opVaultPath -password $password
    if($entries.Length -ne 4) { throw "Expected 4 entries, got $($entries.length)" }

    $entries = g1p test* -vaultpath $opVaultPath -password $password
    if($entries.Length -ne 4) { throw "Expected 4 entries, got $($entries.length)" }
}

# Unprotect-1PEntry cases specific to agilekeychain
test "Decrypt generic account from agile" {
    $data = 1p TestLogin $password -vaultpath $agileVaultPath -plain
    if('calvin' -cne $data[0]) { throw "Wrong username $data" }
    if('p@ssw0rd' -cne $data[1]) { throw "Wrong password $data" }

    $data = 1p TestLogin $password -vaultpath $agileVaultPath -plain -po
    if('p@ssw0rd' -cne $data) { throw "Wrong password $data" }

    $cred = 1p TestLogin $password -vaultpath $agileVaultPath
    if('calvin' -cne $cred.Username) { throw "Wrong username $data" }
    if('p@ssw0rd' -cne $cred.GetNetworkCredential().Password) { throw "Wrong password $cred" }
}

# Unprotect-1PEntry cases specific to opvault
test "Wrong password getting entries from OPVault" -err 'Unable to validate master password' {
    g1p -vaultpath $opVaultPath -password $badPassword
}

# cases that apply to both vault formats
foreach($vaultPath in $agileVaultPath, $opVaultPath) {
    # Get-1PEntry positive cases
    test "Get login from $vaultPath" {
        $entry = g1p TestLogin -vaultpath $vaultPath -password $password
        if($entry.Name -cne 'TestLogin' -or
           $entry.Type -cne 'Login' -or
           $entry.Location -cne 'http://mysite.xyz' -or
           $entry.VaultPath -cne $vaultPath) { throw "Unexpected entry" }
    }
    test "Get password from $vaultPath" {
        $entry = g1p TestPassword -vaultpath $vaultPath -password $password
        if($entry.Name -cne 'TestPassword' -or
           $entry.Type -cne 'Password' -or
           $entry.VaultPath -cne $vaultPath) { throw "Unexpected entry" }
    }
    test "Get secure note from $vaultPath" {
        $entry = g1p TestSecureNote -vaultpath $vaultPath -password $password
        if($entry.Name -cne 'TestSecureNote' -or
           $entry.Type -cne 'SecureNote' -or
           $entry.VaultPath -cne $vaultPath) { throw "Unexpected entry" }
    }

    # Get-1PEntry negative cases
    test "Get bogus entry from $vaultPath" -err 'No 1Password entries found' {
        g1p FooBar -vaultpath $vaultPath -password $password
    }
    test "Get bogus entry with wildcard" {
        g1p FooBar* -vaultpath $vaultPath -password $password
    }

    # Unprotect-1PEntry positive cases
    test "Decrypt login from $vaultPath" {
        $data = 1p TestLogin $password -vaultpath $vaultPath -plain
        if('calvin' -cne $data[0]) { throw "Wrong username $data" }
        if('p@ssw0rd' -cne $data[1]) { throw "Wrong password $data" }

        $data = g1p TestLogin $password -vaultpath $vaultPath | 1p -password $password -plain
        if('calvin' -cne $data[0]) { throw "Wrong username $data" }
        if('p@ssw0rd' -cne $data[1]) { throw "Wrong password $data" }

        $data = 1p TestLogin $password -vaultpath $vaultPath -plain -po
        if('p@ssw0rd' -cne $data) { throw "Wrong password $data" }

        $cred = 1p TestLogin $password -vaultpath $vaultPath
        if('calvin' -cne $cred.Username) { throw "Wrong username $data" }
        if('p@ssw0rd' -cne $cred.GetNetworkCredential().Password) { throw "Wrong password $cred" }
    }

    test "Decrypt password from $vaultPath" {
        $data = 1p TestPassword $password -vaultpath $vaultPath -plain
        if('p@ssw0rd' -cne $data) { throw "Wrong password $data" }

        $data = g1p TestPassword $password -vaultpath $vaultPath | 1p -password $password -plain
        if('p@ssw0rd' -cne $data) { throw "Wrong password $data" }

        $data = 1p TestPassword $password -vaultpath $vaultPath -plain -po
        if('p@ssw0rd' -cne $data) { throw "Wrong password $data" }

        $cred = 1p TestPassword $password -vaultpath $vaultPath
        if('<none>' -cne $cred.Username) { throw "Wrong username $data" }
        if('p@ssw0rd' -cne $cred.GetNetworkCredential().Password) { throw "Wrong password $cred" }
    }
    test "Decrypt secure note from $vaultPath" {
        $data = 1p TestSecureNote $password -vaultpath $vaultPath -plain
        if('Hello there!' -cne $data) { throw "Wrong note $data" }

        $data = g1p TestSecureNote $password -vaultpath $vaultPath | 1p -password $password -plain
        if('Hello there!' -cne $data) { throw "Wrong note $data" }

        $data = 1p TestSecureNote $password -vaultpath $vaultPath
        $plainData = (New-Object PSCredential @('x', $data)).GetNetworkCredential().Password
        if('Hello there!' -cne $plainData) { throw "Wrong note $plainData" }
    }

    # Unprotect-1PEntry negative cases
    test "Wrong password decrypting from $vaultPath" -err 'Unable to validate master password' {
        1p TestSecureNote $badPassword -vaultpath $vaultPath -plain
    }
    test "Bogus entry name decrypting from $vaultPath" -err 'No 1Password entries found' {
        1p FooBar $password -vaultpath $vaultPath -plain
    }
    test "Bogus entry name with wildcard decrypting from $vaultPath" -err 'No 1Password entries found' {
        1p FooBar* $password -vaultpath $vaultPath -plain
    }
    test "Multiple entries decrypting" -err 'More than one entry matches' {
        1p * $password -vaultpath $vaultPath
    }
    test "PasswordOnly with secure note" -err 'Password-only operations are not available' {
        1p TestSecureNote $password -vaultpath $vaultPath -po -plaintext
    }
    test "CopyPass with secure note" -err 'Password-only operations are not available' {
        1p TestSecureNote $password -vaultpath $vaultPath -copypass
    }
    test "Unsupported entry type" -err 'Entry type (002|wallet.financial.CreditCard) is not supported' {
        1p TestCreditCard $password -vaultpath $vaultPath
    }
}