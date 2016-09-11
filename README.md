# 1Poshword
PowerShell client for 1Password

![demo](demo.gif)

  - Cross-platform (Windows/OSX/Linux, PowerShell v3.0+)
  - `agilekeychain` and `opvault` support
  - Login, Password, Secure Note, and Generic Account decryption
  - Metadata for all entries
  - Tab completion (`agilekeychain` only)
  - Output formats
    - `PSCredential`
    - `SecureString`
    - Plaintext
    - Clipboard
  - Complete `Get-Help` documentation

## Quickstart

```
'1poshword.psm1','lib.ps1','pbkdf2.cs' |% {
    Invoke-WebRequest https://raw.githubusercontent.com/latkin/1poshword/master/$_ -OutFile ./$_
}

Import-Module ./1poshword.psm1
```

### `Get-1PEntry`

Lists 1Password entries. Alias `g1p`.

```
PS> g1p

Name               Type       LastUpdated          Location
----               ----       -----------          --------
Twitter            Login      11/29/15 11:53:44 PM https://twitter.com/
Github             Login      11/29/15 11:58:12 PM https://github.com/login
Gmail - Personal   Login      11/30/15 12:11:50 AM https://accounts.google.com/ServiceLogin
Gmail - Work       Login      2/8/16 4:23:38 PM    https://accounts.google.com/ServiceLogin
SSH                Password   2/10/16 1:30:34 PM
Gmail Backup Codes SecureNote 6/8/16 8:41:44 AM
...
```

Details

```
PS> g1p twitter | fl *

Name          : Twitter
Id            : E61537A747044159BE8F2A412614C83F
VaultPath     : /Users/lincoln/Dropbox/1Password/1Password.agilekeychain
SecurityLevel : SL5
KeyId         : 
KeyData       : 
Location      : https://twitter.com/
Type          : Login
CreatedAt     : 10/27/15 8:53:36 PM
LastUpdated   : 11/29/15 11:53:44 PM
EncryptedData : U2FsdGVkX198K5razrhlihDvUrIC2FTp29PcqQpmO48MApG758vljLe+z...
```

### `Unprotect-1PEntry`

Derypts a particular 1Password entry to a variety of formats. Alias `1p`.

Add flag `-PasswordOnly` (alias `-po`) to output only an entry's password field.

(Yes, "unprotect" is weird, but that's the [approved verb](https://msdn.microsoft.com/en-us/library/ms714428(v=vs.85).aspx)
for decryption so we're going with it.)

<table>
  <tr>
    <th>Output</th>
    <th>Note</th>
    <th/>
  </tr>
  <tr>
    <td>PSCredential</td>
    <td>Default for<ul><li>Login</li><li>Generic Account</li></td>
    <td><pre>PS> 1p twitter
1Password vault password: ***************

UserName                            Password
--------                            --------
LincolnAtkinson System.Security.SecureString</pre>
    </td>
  </tr>
  <tr>
    <td>SecureString</td>
    <td>Default for<ul><li>Secure Note</li><li>Password</li></td>
    <td><pre>PS> 1p ssh
1Password vault password: ***************

System.Security.SecureString</pre>
    </td>
  </tr>
  <tr>
    <td>Plaintext</td>
    <td/>
    <td><pre>
PS> 1p github -plain
1Password vault password: ***************

latkin
p@ssw0rd1</pre>
    </td>
  </tr>
  <tr>
    <td>Clipboard</td>
    <td/>
    <td><pre>PS> 1p 'Gmail - Personal' -clip
1Password vault password: ***************</pre>
    </td>
  </tr>

</table>

## Tips

<table>
  <tr>
    <td>Password-only output</td>
    <td><pre># output password as SecureString
PS> 1p twitter -po

# output password as plaintext
PS> 1p twitter -plain -po

# copy password to clipboard
PS> 1p twitter -clip -po</pre>
    </td>
  </tr>
  <tr>
    <td>Custom vault path</td>
    <td><pre># at import
PS> Import-Module 1poshword.psm1 -args <.agilekeychain or .opvault path>

# per-command
PS> 1p entryname -VaultPath <.agilekeychain or .opvault path>

# change default
PS> Set-1PDefaultVaultPath <.agilekeychain or .opvault path></pre>
    </td>
  </tr>
  <tr>
    <td>Specify password programmatically</td>
    <td><pre>PS> $p = Read-Host -AsSecureString 'Speak, friend, and enter'
Speak, friend, and enter: ***************

PS> 1p github $p -plain

latkin
p@ssw0rd1</pre>
    </td>
  </tr>
  <tr>
    <td>Piping</td>
    <td><pre>PS> g1p twitter | 1p</pre></td>
  </tr>
  <tr>
    <td>"Reveal" behavior</td>
    <td><pre>PS> 1p 'gmail backup codes' -plain | less</pre></td>
  </tr>
</table>

## Thanks

[1Pass](https://github.com/georgebrock/1pass), as the original inspiration for this. The first draft of 1Poshword
was mostly just a transcription of 1Pass.

[Medo](https://www.medo64.com/), for the C# Pbkdf2-with-arbitrary-HMAC [implementation](https://www.medo64.com/2012/04/pbkdf2-with-sha-256-and-others/).

[AgileBits](https://agilebits.com/), for the excellent [docs](https://support.1password.com/opvault-design/) describing the `opvault` data format.

_This project is not supported or endorsed by AgileBits.
"1Password" is a registered trademark of Agile Web Solutions, Inc._