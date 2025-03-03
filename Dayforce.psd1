@{
    RootModule           = 'Dayforce.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = 'a3cc54c8-3a82-4668-a4bb-9164e0d312b8'
    Author               = 'Darren J Robinson'
    CompanyName          = 'Community'
    Copyright            = '(c) 2025 Darren J Robinson. All rights reserved.'
    Description          = "Dayforce PowerShell Module"
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = 'Desktop', 'Core'
    RequiredModules      = ''
    FunctionsToExport    = @('Connect-Dayforce', 'Get-DayForceEmployees', 'Get-DayForceEmployee', 'Build-UserProfile', 'Start-EmployeeBulkExport', 'Get-EmployeeBulkExportStatus', 'Get-EmployeeBulkExport', 'Update-DayForceEmployee', 'Update-DayForceEmployeeSSOAccount', 'Update-DayForceEmployeeContact', 'Invoke-DayForceRequest')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            ProjectUri = 'https://github.com/darrenjrobinson/Dayforce'
        } 
    } 
}

