@{
    # Script module or binary module file associated with this manifest.
    RootModule = '1Poshword'

    # Version number of this module.
    ModuleVersion = '1.0.0'

    # ID used to uniquely identify this module
    GUID = '36a94a72-beaf-431f-aaaf-b102b1e37f8a'

    # Author of this module
    Author = 'Lincoln Atkinson'

    # Copyright statement for this module
    Copyright = 'Lincoln Atkinson, 2016'

    # Description of the functionality provided by this module
    Description = 'PowerShell client for the 1Password password manager'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '4.0'

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = 'Get-1PDefaultVaultPath','Set-1PDefaultVaultPath','Get-1PEntry','Unprotect-1PEntry','Connect-1PAccount'

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = $null

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport = 'g1p','1p'

    # List of all files packaged with this module
    FileList = @('1poshword.psd1', '1poshword.psm1', 'lib.ps1', 'pbkdf2.cs')

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('1Poshword', '1Password', 'password', 'cryptography', 'crypto')

            # A URL to the license for this module.
            LicenseUri = 'https://raw.githubusercontent.com/latkin/1poshword/master/LICENSE'

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/latkin/1poshword'

            # ReleaseNotes of this module
            ReleaseNotes = 'Initial release'
        }
    }
}

