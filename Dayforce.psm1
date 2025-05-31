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
        password   = "$($credential.GetNetworkCredential().password)"
        client_id  = "Dayforce.HCMAnywhere.Client"
    }

    try {
        $response = Invoke-RestMethod -Uri "$($dfAPIURI)/connect/token" -Method Post -Headers $headers -Body $body -verbose -debug 
        if ($null -ne $response.access_token) {
            # set Global variables for use in subsequent calls in other cmdlets
            $Global:dfTenantId = Get-TenantID -credential $credential -companyId $companyId -environment $environment
            
            return $Global:dfAccessToken = $response.access_token
        } 
    }
    catch {
        Write-Host "Error: $_"
    }
}

Function Get-TenantID {
    <#
.SYNOPSIS
Get the Tenant ID from Dayforce client metadata.

.DESCRIPTION
Get the Tenant ID from Dayforce client metadata by calling the client metadata endpoint. Sets the Global variable $dfTenantId for use in subsequent calls to Dayforce.

.PARAMETER credential 
PScredential
Username and Password (as SecureString in the Credential object) for the Dayforce user dedicated to Web service calls.

.PARAMETER companyId 
string
Dayforce CompanyId

.PARAMETER environment 
string
Dayforce Environment. Defaults to Stage. Valid values are Production, Touch, Config, Test, Stage, Train.

.EXAMPLE
Get-TenantID -credential $cred -companyId "MYCOMPANY" -environment "Production"

.LINK
http://darrenjrobinson.com/

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [pscredential]$credential,    
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]    
        [string]$companyId,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateSet("Production", "Touch", "Config", "Test", "Stage", "Train")]
        [string]$environment = "Stage"
    )
   
    switch ($environment) {
        "Production" {
            $Global:dfMetadataURI = "https://www.dayforcehcm.com/api/$companyId/v1/clientmetadata"
        }
        "Touch" {
            $Global:dfMetadataURI = "https://touch.dayforcehcm.com/api/$companyId/v1/clientmetadata"
        }
        "Test" {
            $Global:dfMetadataURI = "https://test.dayforcehcm.com/api/$companyId/v1/clientmetadata"
        }
        "Stage" {
            $Global:dfMetadataURI = "https://stage.dayforcehcm.com/api/$companyId/v1/clientmetadata"
        }
        "Config" {
            $Global:dfMetadataURI = "https://config.dayforcehcm.com/api/$companyId/v1/clientmetadata"
        }
        "Train" {
            $Global:dfMetadataURI = "https://train.dayforcehcm.com/api/$companyId/v1/clientmetadata"
        }
    }

    $headers = @{
        Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($credential.UserName):$($credential.GetNetworkCredential().Password)")) 
    }
    
    try {
        $response = Invoke-RestMethod -method Get `
            -Uri $Global:dfMetadataURI `
            -MaximumRedirection 5 `
            -Headers $headers `
            -PreserveAuthorizationOnRedirect 
  
        [uri]$envURI = $response.ServiceUri 
        $Global:dfTenantId = $envURI.Host.Split('.')[0]
        return $Global:dfTenantId
    }
    catch {
        Write-Error $_
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
# SIG # Begin signature block
# MIIoJQYJKoZIhvcNAQcCoIIoFjCCKBICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCZM5kmVp1QSRBa
# v4SPMShovobgWjkXtwNOnlWWnBdqb6CCISgwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggauMIIElqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXH
# JQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMf
# UBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w
# 1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRk
# tFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYb
# qMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu9Yemj052FVUm
# cJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP6
# 5x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzK
# QtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo
# 80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjB
# Jgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXche
# MBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB
# /wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU
# 7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDig
# NqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd
# 4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiC
# qBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl
# /Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeC
# RK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYT
# gAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/
# a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37
# xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmL
# NriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0
# YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJ
# RyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MIIG
# sDCCBJigAwIBAgIQCK1AsmDSnEyfXs2pvZOu2TANBgkqhkiG9w0BAQwFADBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# HhcNMjEwNDI5MDAwMDAwWhcNMzYwNDI4MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1bQvQtAorXi3XdU5WRuxiEL1M4zr
# PYGXcMW7xIUmMJ+kjmjYXPXrNCQH4UtP03hD9BfXHtr50tVnGlJPDqFX/IiZwZHM
# gQM+TXAkZLON4gh9NH1MgFcSa0OamfLFOx/y78tHWhOmTLMBICXzENOLsvsI8Irg
# nQnAZaf6mIBJNYc9URnokCF4RS6hnyzhGMIazMXuk0lwQjKP+8bqHPNlaJGiTUyC
# EUhSaN4QvRRXXegYE2XFf7JPhSxIpFaENdb5LpyqABXRN/4aBpTCfMjqGzLmysL0
# p6MDDnSlrzm2q2AS4+jWufcx4dyt5Big2MEjR0ezoQ9uo6ttmAaDG7dqZy3SvUQa
# khCBj7A7CdfHmzJawv9qYFSLScGT7eG0XOBv6yb5jNWy+TgQ5urOkfW+0/tvk2E0
# XLyTRSiDNipmKF+wc86LJiUGsoPUXPYVGUztYuBeM/Lo6OwKp7ADK5GyNnm+960I
# HnWmZcy740hQ83eRGv7bUKJGyGFYmPV8AhY8gyitOYbs1LcNU9D4R+Z1MI3sMJN2
# FKZbS110YU0/EpF23r9Yy3IQKUHw1cVtJnZoEUETWJrcJisB9IlNWdt4z4FKPkBH
# X8mBUHOFECMhWWCKZFTBzCEa6DgZfGYczXg4RTCZT/9jT0y7qg0IU0F8WD1Hs/q2
# 7IwyCQLMbDwMVhECAwEAAaOCAVkwggFVMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
# VR0OBBYEFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB8GA1UdIwQYMBaAFOzX44LScV1k
# TN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcD
# AzB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
# ZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmww
# HAYDVR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwDQYJKoZIhvcNAQEMBQADggIB
# ADojRD2NCHbuj7w6mdNW4AIapfhINPMstuZ0ZveUcrEAyq9sMCcTEp6QRJ9L/Z6j
# fCbVN7w6XUhtldU/SfQnuxaBRVD9nL22heB2fjdxyyL3WqqQz/WTauPrINHVUHmI
# moqKwba9oUgYftzYgBoRGRjNYZmBVvbJ43bnxOQbX0P4PpT/djk9ntSZz0rdKOtf
# JqGVWEjVGv7XJz/9kNF2ht0csGBc8w2o7uCJob054ThO2m67Np375SFTWsPK6Wrx
# oj7bQ7gzyE84FJKZ9d3OVG3ZXQIUH0AzfAPilbLCIXVzUstG2MQ0HKKlS43Nb3Y3
# LIU/Gs4m6Ri+kAewQ3+ViCCCcPDMyu/9KTVcH4k4Vfc3iosJocsL6TEa/y4ZXDlx
# 4b6cpwoG1iZnt5LmTl/eeqxJzy6kdJKt2zyknIYf48FWGysj/4+16oh7cGvmoLr9
# Oj9FpsToFpFSi0HASIRLlk2rREDjjfAVKM7t8RhWByovEMQMCGQ8M4+uKIw8y4+I
# Cw2/O/TOHnuO77Xry7fwdxPm5yg/rBKupS8ibEH5glwVZsxsDsrFhsP2JjMMB0ug
# 0wcCampAMEhLNKhRILutG4UI4lkNbcoFUCvqShyepf2gpx8GdOfy1lKQ/a+FSCH5
# Vzu0nAPthkX0tGFuv2jiJmCG6sivqf6UHedjGzqGVnhOMIIGvDCCBKSgAwIBAgIQ
# C65mvFq6f5WHxvnpBOMzBDANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0
# ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMB4XDTI0MDkyNjAw
# MDAwMFoXDTM1MTEyNTIzNTk1OVowQjELMAkGA1UEBhMCVVMxETAPBgNVBAoTCERp
# Z2lDZXJ0MSAwHgYDVQQDExdEaWdpQ2VydCBUaW1lc3RhbXAgMjAyNDCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAL5qc5/2lSGrljC6W23mWaO16P2RHxjE
# iDtqmeOlwf0KMCBDEr4IxHRGd7+L660x5XltSVhhK64zi9CeC9B6lUdXM0s71EOc
# Re8+CEJp+3R2O8oo76EO7o5tLuslxdr9Qq82aKcpA9O//X6QE+AcaU/byaCagLD/
# GLoUb35SfWHh43rOH3bpLEx7pZ7avVnpUVmPvkxT8c2a2yC0WMp8hMu60tZR0Cha
# V76Nhnj37DEYTX9ReNZ8hIOYe4jl7/r419CvEYVIrH6sN00yx49boUuumF9i2T8U
# uKGn9966fR5X6kgXj3o5WHhHVO+NBikDO0mlUh902wS/Eeh8F/UFaRp1z5SnROHw
# SJ+QQRZ1fisD8UTVDSupWJNstVkiqLq+ISTdEjJKGjVfIcsgA4l9cbk8Smlzddh4
# EfvFrpVNnes4c16Jidj5XiPVdsn5n10jxmGpxoMc6iPkoaDhi6JjHd5ibfdp5uzI
# Xp4P0wXkgNs+CO/CacBqU0R4k+8h6gYldp4FCMgrXdKWfM4N0u25OEAuEa3Jyidx
# W48jwBqIJqImd93NRxvd1aepSeNeREXAu2xUDEW8aqzFQDYmr9ZONuc2MhTMizch
# NULpUEoA6Vva7b1XCB+1rxvbKmLqfY/M/SdV6mwWTyeVy5Z/JkvMFpnQy5wR14GJ
# cv6dQ4aEKOX5AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/
# BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEE
# AjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxqII+eyG8w
# HQYDVR0OBBYEFJ9XLAN3DigVkGalY17uT5IfdqBbMFoGA1UdHwRTMFEwT6BNoEuG
# SWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQw
# OTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYBBQUHMAKG
# TGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJT
# QTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIB
# AD2tHh92mVvjOIQSR9lDkfYR25tOCB3RKE/P09x7gUsmXqt40ouRl3lj+8QioVYq
# 3igpwrPvBmZdrlWBb0HvqT00nFSXgmUrDKNSQqGTdpjHsPy+LaalTW0qVjvUBhcH
# zBMutB6HzeledbDCzFzUy34VarPnvIWrqVogK0qM8gJhh/+qDEAIdO/KkYesLyTV
# OoJ4eTq7gj9UFAL1UruJKlTnCVaM2UeUUW/8z3fvjxhN6hdT98Vr2FYlCS7Mbb4H
# v5swO+aAXxWUm3WpByXtgVQxiBlTVYzqfLDbe9PpBKDBfk+rabTFDZXoUke7zPgt
# d7/fvWTlCs30VAGEsshJmLbJ6ZbQ/xll/HjO9JbNVekBv2Tgem+mLptR7yIrpaid
# RJXrI+UzB6vAlk/8a1u7cIqV0yef4uaZFORNekUgQHTqddmsPCEIYQP7xGxZBIhd
# mm4bhYsVA6G2WgNFYagLDBzpmk9104WQzYuVNsxyoVLObhx3RugaEGru+SojW4dH
# PoWrUhftNpFC5H7QEY7MhKRyrBe7ucykW7eaCuWBsBb4HOKRFVDcrZgdwaSIqMDi
# CLg4D+TPVgKx2EgEdeoHNHT9l3ZDBD+XgbF+23/zBjeCtxz+dL/9NWR6P2eZRi7z
# cEO1xwcdcqJsyz/JceENc2Sg8h3KeFUCS7tpFk7CrDqkMIIHbTCCBVWgAwIBAgIQ
# CcjsXDR9ByBZzKg16Kdv+DANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMB4XDTIz
# MDMyOTAwMDAwMFoXDTI2MDYyMjIzNTk1OVowdTELMAkGA1UEBhMCQVUxGDAWBgNV
# BAgTD05ldyBTb3V0aCBXYWxlczEUMBIGA1UEBxMLQ2hlcnJ5YnJvb2sxGjAYBgNV
# BAoTEURhcnJlbiBKIFJvYmluc29uMRowGAYDVQQDExFEYXJyZW4gSiBSb2JpbnNv
# bjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMesp+e1UZ5doOnpL+ep
# m6Iq6GYiqK8ZNcz1XBe7M7eBXwVy4tYP5ByIa6NORYEselVWI9XmO1M+cPS6jRMr
# pZb9xtUH+NpKZO+eSthgTAtnEO1dWaAK6Y7AH/ZVjmgOTWZXBVibjAE/JQKIfZyx
# 4Hm5FOH6hq3bslA+RUQpo3NQxNv2AuzckKQwbW7AoXINudj0duYCiDYshn/9mHzz
# gL0VpNYRpmgEa7WWgc1JH17V+SYlaf6qMWpYoWuODwuDltSH2p57qAI2/4J6rUYE
# vns7QZ9sgIUdGlUr596fp0Y4juypyVGE7Rr0a8PtByLWUupyV7Z5kKPr/MRjerXA
# mBnf6AdhI3kY6Gjz356fZkPA49UuCIXFgyTZT84Ao6Klw+0RqJ70JDt449Uky7hd
# a+h8h2PiUdf7rXQamV57mY65+lHAmc4+UgTuWsnpwnTuNlkbZxRnCw2D+W3qto2a
# BhDebciKZzivfiAWlWfTcHtCpy96gM5L+OB45ezDpU6KAH1hwRSjORUlW5yoFTXU
# bPUBRflU3O2bZ0wdAJeyUYaHWAayNoyFfuKdrmCLtIx726O06dz9Kg+cJf+1ZdJ7
# KcUvZgR2d8F19FV5G1CVMnOzhMZR2dnIeJ5h0EgcOKNHl3hMKFdVRx4lhW8tcrQQ
# N4ZT2EgGfI9fBc0i3GXTFA0xAgMBAAGjggIDMIIB/zAfBgNVHSMEGDAWgBRoN+Dr
# tjv4XxGG+/5hewiIZfROQjAdBgNVHQ4EFgQUBTFWqXTuYnNp+d03es2KM9JdGUgw
# DgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0w
# gaowU6BRoE+GTWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1o
# dHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2ln
# bmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDA+BgNVHSAENzA1MDMGBmeBDAEE
# ATApMCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwgZQG
# CCsGAQUFBwEBBIGHMIGEMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
# dC5jb20wXAYIKwYBBQUHMAKGUGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEu
# Y3J0MAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggIBAFhACWjPMrcafwDfZ5me
# /nUrkv4yYgIi535cddPAm/2swGDTuzSVBVHIMBp8LWLmzXPA1GbxBOmA4L8vvDgj
# EpQF9I9Ph5MNYgYhg0xSpAIp9/KAoc4OQnwlyRGPN+CjayY40xxTz4/hHohWg4rn
# JMIuVEjkMtKnMdTbpnqU85w78AQlfD79v/gWQ2dL1T3n18HOEjTt8VSurxkEhQ5I
# 3SH8Cr9YhUv94ObWIUbOKUt5SG7m/d+y2mfkKRSOmRluLSoYLPWbx35pArsYkaPp
# jf5Yl5jiJPY3GQzEU/SRVW0rrwDAbtKSN0gKWtZxijPDbs8aQUYCijFfje6OWGF4
# RnmPSQh0Ff8AyzPQcx9LjQ/8W7gUELsE6IFuXP5bj2i6geLy65LRe46QZlYDq/bM
# azUoZQTlje/hs6pkOL4f1Kv7tbJZmMENVVURJNmeDRejvNliHaaGEAv/iF0Zo7pq
# vj4wCCCGG3j/sNR5WSRYnxf5xQ4r9i9gZqk4yjwk/DJCW2rmKNCUoxNIZWh2EIlM
# SDzw3DMKk2ylZdiY/LAi5GmbCyGLt6sTz/IE1w1NYwrp/z6v4I91lDgdXg+fTkhh
# xt47hWmjMOD3ZYVSFzQmg8al1iQ/+6RYKgfsww64tIky8JOOZX/3ss/uhxKUjPJx
# YJkOwQwUyoAYzjcu/AE7By0rMYIGUzCCBk8CAQEwfTBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhAJyOxc
# NH0HIFnMqDXop2/4MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAI
# oAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIB
# CzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIABNdsDMjI2Q54NHIti4
# X0PX0wP6FDkNUEbOcfBufbGmMA0GCSqGSIb3DQEBAQUABIICAAvu5DAsCvb/UXYE
# kNWwMyLR31oLB+tKwkzrkUa5+sq/VyQBUbamSEwiazg76Er82fIeO0rIUdDa4JUw
# BJ9uPhw/2lebFMRqQXA5E+v206Ld+JJt3bUb36sZuIXRIy171RpEXy7z37jBeK0c
# vmsoO+BTMpMffi7DYMtL7mZEoogkL/bgk5cvyyDFFHVBvQKhstaRQhiMnzANsCVr
# 47GZ+0WAiALvU91zm0t1rb1gn6lp+YJlLYsCCjlcam5RInfD03UHVPqeYo+Tw9UM
# Tobc6jQPT429SEy+G9C1axaOyzj5adQiraGuYGYeTTUimOIIgQgiRJwjUNsyPPF4
# kNV/yti5jqeRaPsFSusqTIecGzTOMT9rrd51hpbKGWU7oAvSl5/EJKcIu/ldhlAe
# nUwifGOAULXUs3GBxlnT17EKnUQilM8YAZDtuSZ7pt92yCzoVN8a5+FEU2268hEN
# 6Kxcap6wY7GUdnQXm7BJtnB0/Zkwkarrq/dnAr9M4dcrghUjXfgEtjInNClzFqNb
# ewiJwiw07b67ElwT1lXr0nWqKH7TviX4ZOIrzzgail3u3OTdCS1G2+Bf2Qxvatvd
# 0YeXmqk+lGodD45mDbUbdlTgTi5r7TA21EoxAu+AstKK+fQQNlNo324p9w3RTIid
# mK/mO44RQVLmmAKS9yFx8O7foV4IoYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJ
# AgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTsw
# OQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVT
# dGFtcGluZyBDQQIQC65mvFq6f5WHxvnpBOMzBDANBglghkgBZQMEAgEFAKBpMBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1MDUzMTAy
# NDQyNlowLwYJKoZIhvcNAQkEMSIEIKgfud7xODg5R5tf9sbAprG7y1QHUPOfxhyd
# N2lFBPthMA0GCSqGSIb3DQEBAQUABIICABoJPnn9nsIKb+p7ZkMrbJhWCsBxH1eg
# OYLRA91F0rILe9KxNhv0EqbSyCIn7g2a36rIH8PunLIi377gSMvrITRigo0vMpLD
# noU0/59LGMOyr5r/JlS2GKAsUo7APFNVZAJgXXlP7QdHMk9y63CvFUUKlY36Eqhh
# YXuwY+2vC7AN/0az2sRCzANg4gr0pIzCNTfw/78U0R+BZLwFNzQ8GoYNaGK41ias
# hAetIzKMc1Ghw9uji+Ol159WHcp8ItNy6ATem9duTeiInUUUwvbvGGPPlsUok/lz
# RimnxJSmoVJP5gXxK4y7uHBvxYIfRb2wMXa8wixxWObpz4O7uUMJOVyppTyJkwQO
# Q5sJbSHt584K4pEubM2gLVPm85h5ijA34Ip6voXjKytoKfAB6FJInR3Oxr+IFHuM
# 3Yqwz+FlSjY1zfFJplNlYFIqUHEPNdHSMZGcXgbV0QBaUTLJnmcNbH/CFxpI9amu
# 36nt9FNjbRKqgnXlQZCoiD++MNFTfNp+23DWN/FbyQ+opUs21e92LgNTXjGPpunW
# y+LRuRKZ8pq3IdKxn3DjWAr3bI7ixDJpS8vNPi3sEU+HPlI2imjhlNrTNU6eYgHc
# EbnQHR/7PW15reUVH/MAuxPiSVE2iOEqQ7JvYuWcXjF+AA8giFAU/gvxMIo/ovt1
# dt88RzLFT2b6
# SIG # End signature block
