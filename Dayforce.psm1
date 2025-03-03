Function Connect-Dayforce {

    <#
    .SYNOPSIS
Authenticate to Dayforce and get an Access Token.

.DESCRIPTION
Authenticate to Dayforce and get an Access Token. Set the Global variables $dfAccessToken,  $dfAPIURI and $dfcompanID for use in subsequent calls to Dayforce.

.PARAMETER companyId 
string
Dayforce CompanyId

.PARAMETER credential 
PScredential
Username and Password (as SecureString in the Credential object) for the Dayforce user dedicated to Web service calls.

.PARAMETER environment 
string
Dayforce Environment. Defaults to Stage. Valid values are Production, Touch, Config, Test, Stage, Train.

.EXAMPLE
Get-DayForceEmployees 

.LINK
http://darrenjrobinson.com/

    https://developers.dayforce.com/Build/Dayforce-Security-Framework/Token-based-authentication.aspx
    
    An authentication token can be retrieved with an API call to Dayforce Identity servers.

The call is a POST call on the following URLs:
Production: https://dfid.dayforcehcm.com/connect/token
Touch: https://dfid.dayforcehcm.com/connect/token
Config: https://dfidconfig.np.dayforcehcm.com/connect/token
Test: https://dfidtst.np.dayforcehcm.com/connect/token
Stage: https://dfidtst.np.dayforcehcm.com/connect/token
Train: https://dfidconfig.np.dayforcehcm.com/connect/token
 

You will need to join the following form body to your call:

Grant_type: value is always: password
CompanyId: Client namespace, used to connect to Dayforce UI or APIs
Username: Name of the Dayforce user dedicated to Web service calls
Password: Password of the specified user
Client_Id: Scope of the token, the value is always: Dayforce.HCMAnywhere.Client

The content type of this body should be application/x-www-form-urlencoded.

    #>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]    
        [string]$companyId,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [pscredential]$credential,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateSet("Production", "Touch", "Config", "Test", "Stage", "Train")]
        [string]$environment = "Stage"
    )

 
    $headers = @{
        "Content-Type" = "application/x-www-form-urlencoded"
    }

    switch ($environment) {
        "Production" {
            $Global:dfAPIURI = 'https://dfid.dayforcehcm.com'
        }
        "Touch" {
            $Global:dfAPIURI = 'https://dfid.dayforcehcm.com'
        }
        "Test" {
            $Global:dfAPIURI = 'https://dfidtst.np.dayforcehcm.com'
        }
        "Stage" {
            $Global:dfAPIURI = 'https://dfidtst.np.dayforcehcm.com'
        }
        "Config" {
            $Global:dfAPIURI = 'https://dfidconfig.np.dayforcehcm.com'
        }
        "Train" {
            $Global:dfAPIURI = 'https://dfidconfig.np.dayforcehcm.com'
        }
    }

    $body = @{
        grant_type = "password"
        companyId  = $companyId
        username   = $credential.UserName
        password   = $credential.Password | ConvertFrom-SecureString -AsPlainText 
        client_id  = "Dayforce.HCMAnywhere.Client"
    }

    try {
        $response = Invoke-RestMethod -Uri "$($dfAPIURI)/connect/token" -Method Post -Headers $headers -Body $body -verbose -debug 
        if ($null -ne $response.access_token) {

            # $Global:dfCompanyId = $companyId
            return $Global:dfAccessToken = $response.access_token
        } 
    }
    catch {
        Write-Host "Error: $_"
    }
}



Function Get-DayForceEmployees {
    <#
.SYNOPSIS
Get Employees from Dayforce 

.DESCRIPTION
Get a list of Employees xRefCodes from Dayforce

.PARAMETER companyId 
string
Dayforce CompanyId. Defaults to reading the Global variable $dfCompanyId that was set during the Connect-Dayforce function.

.EXAMPLE
Get-DayForceEmployees 

.LINK
http://darrenjrobinson.com/

#>   

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]    
        [string]$companyId = $dfCompanyId
    )

    try {
        $response = Invoke-RestMethod -Uri "https://$($dfTenantId).dayforcehcm.com/api/$($companyId)/V1/Employees" -Method Get -Headers @{authorization = "Bearer $Global:dfAccessToken" }  
        if ($null -ne $response.data) {
            return $response.data.XRefCode # | ConvertFrom-Json -Depth 10
        }
    } 
    catch {
        Write-Host "Error: $_"
    }
}


Function Get-DayForceEmployee {
   
    <#
.SYNOPSIS
Get an Employee from Dayforce 

.DESCRIPTION
Get an Employee from Dayforce by passing the xRefCode. Use Get-DayForceEmployees to get a list of employees and their xRefCode.

.PARAMETER xRefCode 
string (path)
The unique identifier (external reference code) of the employee to be retrieved. The value provided must be the exact match for an employee; otherwise, a bad request (400) error will be returned.

.PARAMETER contextDate
string (date)
The Context Date value is an “as-of” date used to determine which employee data to search when records have specific start and end dates. The service defaults to the current datetime if the requester does not specify a value. Example: 2017-01-01T13:24:56

.PARAMETER expand
string (query)
This parameter accepts a comma-separated list of top-level entities that contain the data elements needed for downstream processing. When this parameter is not used, only data elements from the employee master record will be included. For more information, please refer to the Introduction to Dayforce Web Services document.

.PARAMETER contextDateRangeFrom
string (date)
The Context Date Range From value is the start of the range of dates used to determine which employee data to search when records have specific start and end dates. The service defaults to null if the requester does not specify a value. Example: 2017-01-01T13:24:56

.PARAMETER contextDateRangeTo
string (date)
The Context Date Range To value is end of the range of dates to determine which employee data to search when records have specific start and end dates. The service defaults to null if the requester does not specify a value. Example: 2017-01-01T13:24:56

.EXAMPLE
Get-DayForceEmployee -xRefCode "123456" -expand "EmployeeManagers,EmployeeProperties,GlobalProperties,Locations,EmploymentTypes,OrgUnitInfos,WorkAssignments,EmploymentStatuses,Contacts,SSOAccounts"

.LINK
http://darrenjrobinson.com/

#>
   
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]    
        [string]$companyId = $dfCompanyId,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]    
        [string]$xRefCode,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]    
        [string]$contextDate,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]    
        [string]$expand,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]    
        [string]$contextDateRangeFrom,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]    
        [string]$contextDateRangeTo
    )

    try {
        
        $query = $null 

        if ($null -ne $expand) {
            $query = "expand=$($expand)"
        }

        if ($null -ne $query) {
            $response = Invoke-RestMethod -Uri "https://$($dfTenantId).dayforcehcm.com/api/$($companyId)/V1/Employees/$($xRefCode)?$($query)" -Method Get -Headers @{authorization = "Bearer $Global:dfAccessToken" }  
        }
        
        if ($null -ne $response.data) {
            return $response.data
        }
    } 
    catch {
        Write-Host "Error: $_"
    }
}


function Get-EmployeeBulkExport {
    <#
.SYNOPSIS
Get a Bulk Export of Employees from Dayforce 

.DESCRIPTION
Get a Bulk Export of Employees from Dayforce 

.PARAMETER companyId
string
The Dayforce CompanyId. Defaults to reading the Global variable $dfCompanyId that was set during the Connect-Dayforce function.  

.PARAMETER bulkExportURI  
URI 
The URI returned after the bulk request has been completed. 

.EXAMPLE
Get-EmployeeBulkExport -backgroundJobQueueItemId "6a86bd80-ba88-4698-afbc-dba2e52b7164"

.LINK
http://darrenjrobinson.com/

#>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]    
        [string]$companyId = $dfCompanyId,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]    
        [string]$bulkExportURI
    )

    try {
        $response = $null 
        $results = $null 
        $response = Invoke-RestMethod -Uri "$($bulkExportURI)" -Method Get -Headers @{authorization = "Bearer $Global:dfAccessToken"; "Content-Type" = "application/json" }
        if ($null -ne $response) {
            $results += $response.data
            if ($null -ne $response.Paging.Next) {
                do {
                    # if ($null -ne $response.Paging.Next) {
                    $response = Invoke-RestMethod -Uri "$($response.Paging.Next)" -Method Get -Headers @{authorization = "Bearer $Global:dfAccessToken"; "Content-Type" = "application/json" }
                    $results += $response.data
                    # }
                } while (
                    $response.Paging.Next.Length -gt 0
                )
            }
            return $results
        }
    }
    catch {
        Write-Host "Error: $_"
    }
}

Function Start-EmployeeBulkExport {
    <#
.SYNOPSIS
Request a Bulk Export of Employees from Dayforce 

.DESCRIPTION
Request a Bulk Export of Employees from Dayforce 

.PARAMETER companyId
string
The Dayforce CompanyId. Defaults to reading the Global variable $dfCompanyId that was set during the Connect-Dayforce function.  

.PARAMETER request
json
The request body for the Bulk Export request.

Ref https://developers.dayforce.com/Build/API-Explorer/Employee-Export-Job/POST-Bulk-Employees-Data.aspx
$request = '{
  "PayGroupXRefCode": "string",
  "EmployeeXRefCode": "string",
  "EmployeeNumber": "string",
  "Expand": "string",
  "PageSize": 0,
  "ContextDate": "2025-01-13T01:32:55.423Z",
  "ContextDateRangeFrom": "2025-01-13T01:32:55.423Z",
  "ContextDateRangeTo": "2025-01-13T01:32:55.423Z",
  "ContextDateOption": "string",
  "DeltaOption": "string",
  "DeltaDate": "2025-01-13T01:32:55.423Z",
  "AmfEntity": "string",
  "AmfLevel": "string",
  "AmfLevelValue": "string",
  "ExportAllEmployeeDetailOnDelta": true,
  "ExcludeTerminatedEmployeesOlderThanXDays": 0,
  "DisplayName": "string",
  "SocialSecurityNumber": "string",
  "EmploymentStatusXRefCode": "string",
  "OrgUnitXRefCode": "string",
  "DepartmentXRefCode": "string",
  "JobXRefCode": "string",
  "PositionXRefCode": "string",
  "PayClassXRefCode": "string",
  "PayPolicyXRefCode": "string",
  "PayTypeXRefCode": "string",
  "PayrollPolicyXRefCode": "string",
  "FilterHireStartDate": "2025-01-13T01:32:55.423Z",
  "FilterHireEndDate": "2025-01-13T01:32:55.423Z",
  "FilterTerminationStartDate": "2025-01-13T01:32:55.423Z",
  "FilterTerminationEndDate": "2025-01-13T01:32:55.423Z",
  "FilterOriginalHireStartDate": "2025-01-13T01:32:55.423Z",
  "FilterOriginalHireEndDate": "2025-01-13T01:32:55.423Z",
  "FilterSeniorityStartDate": "2025-01-13T01:32:55.423Z",
  "FilterSeniorityEndDate": "2025-01-13T01:32:55.423Z",
  "FilterBaseSalaryFrom": 0,
  "FilterBaseSalaryTo": 0,
  "FilterBaseRateFrom": 0,
  "FilterBaseRateTo": 0,
  "FilterTerminatedSinceStartDate": "2025-01-13T01:32:55.423Z",
  "FilterTerminatedSinceEndDate": "2025-01-13T01:32:55.423Z",
  "FilterBirthStartDate": "2025-01-13T01:32:55.423Z",
  "FilterBirthEndDate": "2025-01-13T01:32:55.423Z",
  "AttendancePolicyXrefCode": "string",
  "EmployeeGroupXrefCode": "string",
  "EntitlementPolicyXrefCode": "string",
  "PayHolidayGroupXrefCode": "string",
  "OvertimeGroupXrefCode": "string",
  "JobStepPolicyXrefCode": "string",
  "ScheduleRulePolicyXrefCode": "string",
  "ShiftRotationXrefCode": "string",
  "ShiftTradePolicyXrefCode": "string",
  "PunchPolicyXrefCode": "string",
  "TimeOffPolicyXrefCode": "string",
  "VacationBidGroupXrefCode": "string"
}'


.EXAMPLE

$request = '{
  "Expand": "EmployeeManagers,EmployeeProperties,GlobalProperties,Locations,EmploymentTypes,OrgUnitInfos,WorkAssignments,EmploymentStatuses,Contacts",
  "PageSize": 100,
}'
Start-EmployeeBulkExport -request $request

.LINK
http://darrenjrobinson.com/

#>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]    
        [string]$companyId = $dfCompanyId,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]    
        [string]$request,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]    
        [bool]$isValidateOnly = $false
    )

    Try {
        $response = $null 
        $response = Invoke-RestMethod -Uri "https://$($dfTenantId).dayforcehcm.com/api/$($companyId)/V1/EmployeeExportJobs?isValidateOnly=$($isValidateOnly)" -Method Post -Body $request -Headers @{authorization = "Bearer $Global:dfAccessToken"; "Content-Type" = "application/json" }  

        if ($null -ne $response) {
            return $response.data
        }
    } 
    catch {
        Write-Host "Error: $_"
    }
}


Function Get-EmployeeBulkExportStatus {
    <#
 .SYNOPSIS
Get a Bulk Export Request Status from Dayforce

.DESCRIPTION
Get a Bulk Export Request Status from Dayforce

.PARAMETER companyId
string
The Dayforce CompanyId. Defaults to reading the Global variable $dfCompanyId that was set during the Connect-Dayforce function.  

.PARAMETER statusURI
URI
The URI of the Bulk Export Request response URI. This is returned from the Start-EmployeeBulkExport function.

.LINK
http://darrenjrobinson.com/

#>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]    
        [string]$companyId = $dfCompanyId,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]    
        [string]$statusURI
    )

    try {
        $status = $null 
        $status = Invoke-RestMethod -Uri "$($statusURI)" -Method Get -Headers @{authorization = "Bearer $Global:dfAccessToken"; "Content-Type" = "application/json" } 

        if ($null -ne $status) {
            return $status.data
        }
    }
    catch {
        Write-Host "Error: $_"
    }
}

Function Build-UserProfile {
    <#
 .SYNOPSIS
Take a Dayforce Employee Object and build a User Profile Object

.DESCRIPTION
Take a Dayforce Employee Object and build a User Profile Object

.PARAMETER dayforceEmployee
PSCustomObject
The PowerShell Object returned from Get-DayForceEmployee

.LINK
http://darrenjrobinson.com/

#>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]    
        [PSCustomObject]$dayforceEmployee
    )

    $userProfileTemplate = [pscustomobject][ordered]@{ 
        employeeId         = $null
        employeeNumber     = $null
        xRefCode           = $null 
        firstName          = $null
        lastName           = $null
        hireDate           = $null
        originalHireDate   = $null
        workAssignments    = @(
            [pscustomobject][ordered]@{
                country     = $null
                legalEntity = $null 
                address1    = $null 
                city        = $null 
                state       = $null 
                postalCode  = $null
                department  = $null
                jobTitle    = $null
            }
        )
        employmentStatuses = @(
            [pscustomobject][ordered]@{
                status    = $null
                startDate = $null
                payClass  = $null
                endDate   = $null
            }
        )
        employeeManagers   = @(
            [pscustomobject][ordered]@{
                managerXRefCode           = $null
                managerFirstName          = $null
                managerLastName           = $null
                managerEffectiveStartDate = $null
            }
        )
    }

    try {
        
        $employeeDetails = $userProfileTemplate.PsObject.Copy()
        $employeeDetails.employeeId = $dayforceEmployee.EmployeeId
        $employeeDetails.employeeNumber = $dayforceEmployee.EmployeeNumber
        $employeeDetails.xRefCode = $dayforceEmployee.XRefCode
        $employeeDetails.firstName = $dayforceEmployee.FirstName
        $employeeDetails.lastName = $dayforceEmployee.LastName
        $employeeDetails.hireDate = $dayforceEmployee.HireDate
        $employeeDetails.originalHireDate = $dayforceEmployee.OriginalHireDate
        $employeeDetails.WorkAssignments = $dayforceEmployee.WorkAssignments.Items | ForEach-Object {
            [pscustomobject][ordered]@{
                country     = $_.Location.LegalEntity.Country.ShortName
                legalEntity = $_.Location.LegalEntity.ShortName
                address1    = $_.Location.LegalEntity.LegalEntityAddress.Address1
                city        = $_.Location.LegalEntity.LegalEntityAddress.City
                state       = $_.Location.LegalEntity.LegalEntityAddress.State.ShortName
                postalCode  = $_.Location.LegalEntity.LegalEntityAddress.PostalCode
                department  = $_.PMPositionAssignment.PMPosition.BusinessUnit.ShortName 
                jobTitle    = $_.PMPositionAssignment.PMPosition.ShortName
            }
        }

        $employeeDetails.employmentStatuses = $dayforceEmployee.EmploymentStatuses.Items | ForEach-Object {
            [pscustomobject][ordered]@{
                status    = $_.EmploymentStatus.ShortName
                startDate = $_.EffectiveStart
                payclass  = $_.PayClass.ShortName
                endDate   = $_.EffectiveEnd
            }
        }
        $employeeDetails.employeeManagers = $dayforceEmployee.EmployeeManagers.Items | ForEach-Object {
            [pscustomobject][ordered]@{
                managerXRefCode           = $_.ManagerXRefCode
                managerFirstName          = $_.ManagerFirstName
                managerLastName           = $_.ManagerLastName
                managerEffectiveStartDate = $_.EffectiveStart
            }
        }

        return $employeeDetails

    }
    catch {
        Write-Host "Error: $_"
    }
}

Function Update-DayForceEmployee {
   
    <#
.SYNOPSIS
Update an Employee in Dayforce 

.DESCRIPTION
Update an Employee in Dayforce by passing the xRefCode. Use Get-DayForceEmployees to get a list of employees and their xRefCode.

.PARAMETER xRefCode 
string (path)
The unique identifier (external reference code) of the employee to be retrieved. The value provided must be the exact match for an employee; otherwise, a bad request (400) error will be returned.

.PARAMETER request
request (json)
The request body for the Employee update request.

.EXAMPLE
Update-DayForceEmployee -xRefCode "123456" -request '{"AllowNativeAuthentication": true}'

.LINK
http://darrenjrobinson.com/

#>
   
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]    
        [string]$companyId = $dfCompanyId,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]    
        [string]$xRefCode,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]    
        [string]$request
    )

    try {
        
        $response = Invoke-RestMethod -Uri "https://$($dfTenantId).dayforcehcm.com/api/$($companyId)/V1/Employees/$($xRefCode)" `
        -Method Patch `
        -Headers @{authorization = "Bearer $Global:dfAccessToken" }  `
        -ContentType "application/json" `
        -Body $request

        
        if ($null -ne $response.data) {
            return $response.data
        }
    } 
    catch {
        Write-Host "Error: $_"
    }
}

Function Update-DayForceEmployeeSSOAccount {
   
    <#
.SYNOPSIS
Update/Add an Employee SSO Account in Dayforce 

.DESCRIPTION
Update/Add an Employee SSO Account in Dayforce by passing the xRefCode. Use Get-DayForceEmployees to get a list of employees and their xRefCode.

.PARAMETER xRefCode 
string (path)
The unique identifier (external reference code) of the employee to be retrieved. The value provided must be the exact match for an employee; otherwise, a bad request (400) error will be returned.

.PARAMETER SSOAccount
SSOAccount (string)
The UPN/Email address of the SSO Account to be added/updated.

.PARAMETER EnableNativeAuthentication
EnableNativeAuthentication (boolean)
Enable Native Authentication for the Employee. $true to enable and $false to disable.

.EXAMPLE
Update-DayForceEmployeeSSOAccount -xRefCode "123456" -SSOAccount "joe.smith@org.com.au" -EnableNativeAuthentication $true

.NOTES
Your user role must be assigned access to the PATCH/POST Employee HR Data subfeature under HCM Anywhere > Web Services in the Features tab of System Admin > Roles.
In addition to feature security, you must enable Can Create for Employee Profile - Security Settings - SSO Logins under the Authorizations tab of System Admin > Roles

.LINK
http://darrenjrobinson.com/

#>
   
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]    
        [string]$companyId = $dfCompanyId,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]    
        [string]$xRefCode,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]    
        [string]$SSOAccount,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]    
        [bool]$EnableNativeAuthentication 
    )

    try {       

        # Get Employee SSOAccount config and set if not already set
        $dayforceRecord = $null 
        $dayforceRecord = Get-DayForceEmployee -xRefCode $xRefCode -expand "SSOAccounts"

        if ($EnableNativeAuthentication -eq $true) {            
            
            if ($null -eq $dayforceRecord.FederatedId) {
                Write-HOST "Setting SSOAccount for $xRefCode"
                Write-HOST "{'LoginName': "`'$($SSOAccount)`'"}" 

                $response = Invoke-RestMethod -Uri "https://$($dfTenantId).dayforcehcm.com/api/$($companyId)/V1/Employees/$($xRefCode)/SSOAccounts" `
                    -Method Post `
                    -Headers @{authorization = "Bearer $Global:dfAccessToken" } `
                    -ContentType "application/json" `
                    -Body (@{LoginName = $SSOAccount } | ConvertTo-Json -Depth 2)
                Write-HOST "SSOAccount set for $xRefCode"
            }
            else {
                if ($dayforceRecord.FederatedId.ToLower() -ne $SSOAccount.ToLower()) {
                    Write-HOST "Updating SSOAccount for $xRefCode"
                    Write-HOST "{'LoginName': "$($SSOAccount)"}" 
                    $response = Invoke-RestMethod -Uri "https://$($dfTenantId).dayforcehcm.com/api/$($companyId)/V1/Employees/$($xRefCode)/SSOAccounts" `
                        -Method Patch `
                        -Headers @{authorization = "Bearer $Global:dfAccessToken" } `
                        -ContentType "application/json" `
                        -Body (@{LoginName = $SSOAccount } | ConvertTo-Json -Depth 2) 
                    Write-HOST "SSOAccount updated for $xRefCode"
                }
            }
           
            if ($dayforceRecord.UserAccount.AllowNativeAuthentication -ne $true ) {
                $response = Invoke-RestMethod -Uri "https://$($dfTenantId).dayforcehcm.com/api/$($companyId)/V1/Employees/$($xRefCode)" `
                    -Method Patch `
                    -Headers @{authorization = "Bearer $Global:dfAccessToken" } `
                    -ContentType "application/json" `
                    -Body '{"UserAccount": {"AllowNativeAuthentication": true}}'
                Write-Host "AllowNativeAuthentication set for $xRefCode"
            }
        }
        else { 

            if ($null -eq $dayforceRecord.FederatedId) {
                $response = Invoke-RestMethod -Uri "https://$($dfTenantId).dayforcehcm.com/api/$($companyId)/V1/Employees/$($xRefCode)/SSOAccounts" `
                    -Method Post `
                    -Headers @{authorization = "Bearer $Global:dfAccessToken" } `
                    -ContentType "application/json" `
                    -Body (@{LoginName = $SSOAccount } | ConvertTo-Json -Depth 2) 
                Write-HOST "SSOAccount set for $xRefCode"
            }
            else {
                $response = Invoke-RestMethod -Uri "https://$($dfTenantId).dayforcehcm.com/api/$($companyId)/V1/Employees/$($xRefCode)/SSOAccounts" `
                    -Method Patch `
                    -Headers @{authorization = "Bearer $Global:dfAccessToken" } `
                    -ContentType "application/json" `
                    -Body (@{LoginName = $SSOAccount } | ConvertTo-Json -Depth 2) 
                Write-HOST "SSOAccount updated for $xRefCode"
            }
             
            if ($dayforceRecord.UserAccount.AllowNativeAuthentication -eq $true ) {
                $response = Invoke-RestMethod -Uri "https://$($dfTenantId).dayforcehcm.com/api/$($companyId)/V1/Employees/$($xRefCode)" `
                    -Method Patch `
                    -Headers @{authorization = "Bearer $Global:dfAccessToken" } `
                    -ContentType "application/json" `
                    -Body '{"UserAccount": {"AllowNativeAuthentication": false}}'
                Write-Host "AllowNativeAuthentication disabled for $xRefCode"
            }
        }
        if ($null -ne $response.data) {
            return $response.data
        }
    } 
    catch {
        Write-Host "Error: $_"
    }
}

Function Update-DayForceEmployeeContact {
   
    <#
.SYNOPSIS
Update an Employees Contact in Dayforce 

.DESCRIPTION
Update an Employee contact phone or email in Dayforce by passing the xRefCode. Use Get-DayForceEmployees to get a list of employees and their xRefCode.

.PARAMETER xRefCode 
string (path)
The unique identifier (external reference code) of the employee to be retrieved. The value provided must be the exact match for an employee; otherwise, a bad request (400) error will be returned.

.PARAMETER request
request (json)
The request body for the Employee update request.

.EXAMPLE
Update-DayForceEmployee -xRefCode "123456" -request '{"AllowNativeAuthentication": true}'

.LINK
http://darrenjrobinson.com/

#>
   
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]    
        [string]$companyId = $dfCompanyId,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]    
        [string]$xRefCode,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]    
        [string]$request
    )

    try {
        
        $response = Invoke-RestMethod -Uri "https://$($dfTenantId).dayforcehcm.com/api/$($companyId)/V1/Employees/$($xRefCode)/Contacts" `
        -Method Patch `
        -Headers @{authorization = "Bearer $Global:dfAccessToken" }  `
        -ContentType "application/json" `
        -Body $request

        if ($null -ne $response.data) {
            return $response.data
        }
    } 
    catch {
        Write-Host "Error: $_"
    }
}

function Invoke-DayForceRequest {
    <#
.SYNOPSIS
Submit a Dayforce API Request.

.DESCRIPTION
Submit a Dayforce API Request.

.PARAMETER uri
(required for Full URI parameter set) API URI

.PARAMETER path
(Required for path parameter set) specify the rest of the api query after the base api url as determined when picking the API variable 

.PARAMETER API
(required for path parameter set) will determine the base url
V1  will use the base url https://{your org}.dayforcehcm.com/api/V1/
V2  will use the base url https://{your org}.dayforcehcm.com/api/V2/

.PARAMETER method
(required) API Method
e.g Post, Get, Patch, Delete

.PARAMETER contentType
(required) Content type of the request
e.g application/json, application/x-www-form-urlencoded

.PARAMETER body
(optional - JSON) Payload for a web request

.PARAMETER json
(optional) Return Dayforce Request response as JSON.

.EXAMPLE
Invoke-DayForceRequest -method Get -uri "https://YOURORG.dayforcehcm.com/api/V1/Employees" -contentType "application/json"

.EXAMPLE
Invoke-DayForceRequest -API V1 -path 'Employees' -method Get -contentType "application/json"

.LINK
http://darrenjrobinson.com/
#>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Full URL')]
        [string]$uri,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Path')]
        [string]$path,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Path')]
        [string][ValidateSet("V1", "V2")]$API,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string][ValidateSet("Get", "Put", "Patch", "Delete", "Post")]$method,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$contentType,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string]$body,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [switch]$json
    )

    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        $uri = "https://$($dfTenantId).dayforcehcm.com/api/$API/$path"
    }

    $headers = @{
        Authorization = "Bearer $Global:dfAccessToken"
    }

    try {
        if ($body) {
            if ($json) {
                $result = (Invoke-WebRequest -Method $method -Uri $uri -Headers $headers -ContentType $contentType -Body $body).content
            }
            else {
                $result = Invoke-RestMethod -Method $method -Uri $uri -Headers $headers -ContentType $contentType -Body $body 
            }
        }
        else {   
            if ($json) {
                $result = (Invoke-WebRequest -Method $method -Uri $uri -Headers $headers -ContentType $contentType).content
            }
            else {      
                $result = Invoke-RestMethod -Method $method -Uri $uri -Headers $headers -ContentType $contentType        
            }
        }
        return $result
    }
    catch {
        Write-Error "Request Failed. Check your request parameters. $($_)" 
    }
}