# Dayforce HCM PowerShell Module 

A foundational PowerShell Module to query Employee data from Dayforce. 
Minimal cmdlets to update Dayforce for business email/contact info and Federated Single Sign On.

Author: Darren Robinson - February 2025


```powershell

get-command -module Dayforce | sort-object Name | Get-Help | FT Name, Synopsis -autosize

Name                              Synopsis
----                              --------
Build-UserProfile                 Take a Dayforce Employee Object and build a User Profile Object
Connect-Dayforce                  Authenticate to Dayforce and get an Access Token.
Get-DayForceEmployee              Get an Employee from Dayforce
Get-DayForceEmployees             Get Employees from Dayforce
Get-EmployeeBulkExport            Get a Bulk Export of Employees from Dayforce
Get-EmployeeBulkExportStatus      Get a Bulk Export Request Status from Dayforce
Invoke-DayForceRequest            Submit a Dayforce API Request.
Start-EmployeeBulkExport          Request a Bulk Export of Employees from Dayforce
Update-DayForceEmployee           Update an Employee in Dayforce
Update-DayForceEmployeeContact    Update an Employees Contact in Dayforce
Update-DayForceEmployeeSSOAccount Update/Add an Employee SSO Account in Dayforce

```


## Dayforce API Enablement

[API Ref](https://developers.dayforce.com/Build/API-Explorer/Employee/GET-Employees.aspx)

**Before You Begin:** Your user role must be assigned access to the Read Data subfeature under HCM Anywhere > Web Services in the Features tab of System Admin > Roles.

In addition to feature security, you must enable XRefCode under RESTful Services > Human Resources > Employee in the Web Services Field-Level Access tab of System Admin > Roles.


## Getting Started



## Create a Credential File 

One Time setup credentials in a local encrypted file

```powershell 
$dfCreds = Get-Credential 
$dfCreds | Export-Clixml -Path ./dfCreds.xml
```

Then moving forward the credential file can be imported and used with the module. 

Set two other Global Variables that will be used by the module. Setting **Global:dfCompanyId** & **Global:dfTenantId** as Global means that they don't need to be provided to each function. 

Finally, the Environment needs to match the Dayforce environment configuration. Different environments have different oAuth Token endpoints. 

Environments names are: **Production, Touch, Config, Test, Stage, Train**

The Connect-Dayforce defaults to the **Stage** environment. 

### Example

```powershell
$dfCreds = Import-Clixml -Path ./dfCreds.xml  
$Global:dfCompanyId = 'companystage'
$Global:dfTenantId = 'globalausstage404'
$environment = "Stage"
```

## Connect to Dayforce and get an Access Token 

The Connect-Dayforce cmdlet will connect to the Dayforce oAuth Token endpoint to get an access token. 

It will also set the **Global:dfAPIURI** and **Global:dfAccessToken** variables that will be used by the other cmdlets. 

```powershell
Connect-Dayforce -CompanyId $dfCompanyId -Credential $dfCreds -environment "Stage"

eyJhbGciOiJSUzI1NiIsImtpZCI6IjRCOTJBNERDODdBRkQ1MDI5MDcyMDY3ODVBMDg2MTYxRjFENURENjdSUzI1NiIsIng1dCI6IlM1S2szSWV2MVFLUWNnWjRXZ2hoWWZIVjNXYyIsInR5cCI6ImF0K2p3dCJ9.eyJpc3MiOiJo.............EI4MDAifQ.gYUAuJ6Rcz8.......vpZJd8JMsVBOA
```

## Decoding the Access Token

Using my [JWTDetails Powershell Module](https://www.powershellgallery.com/packages/JWTDetails/1.0.3) the access token can be decoded. 

```powershell
$Global:dfAccessToken | Get-JWTDetails


iss                  : https://dfidtst.np.dayforcehcm.com
nbf                  : 1736744263
iat                  : 1736744263
exp                  : 1736747863
aud                  : {df.amf.configapi, df.amf.metadataapi, df.amf.runtimeapi, df.hcmanywhere.clientÔÇª}
scope                : {dayforce, df.amf.configapi, df.amf.metadataapi, df.amf.runtimeapiÔÇª}
amr                  : {password}
client_id            : Dayforce.HCMAnywhere.Client
sub                  : 1642@companystage.dayforce.com
auth_time            : 1736744263
idp                  : local
df.ns                : companystage
api_version          : 1.0
df.userid            : 1642
preferred_username   : df_user
df.culture           : {"Id":3081,"Code":"en-AU"}
df.userglobalid      : a5e30c50-a0de-4ed6-95ed-76a8ce97d4e1
df.site_purpose      : Test
df.client_ip_address : 161.160.100.99
jti                  : 7ECF8E309EDF495754CF6205012DB800
sig                  : gYUAuJ6Rcz84KsfTtVLwKudJk1dWv+qEiab.....Jd8JMsVBOA==
expiryDateTime       : 13/01/2025 4:57:43 PM
timeToExpiry         : 00:58:26.4979877
```

## Get DayForce Employees

First you need to get a list of Dayforce Employee XRefCodes

The Get-DayForceEmployees cmdlet will return Employee XRefCodes

```powershell
Get-DayForceEmployees

103989
102197
104174
104383
104379
103987
......
103851
104217
104331
102012
104212
103833
104438
```

## Get a DayForce Employee

The Get-DayForceEmployee cmdlet will return Employee information for a given XRefCode and query.

The query instructs Dayforce to return specific information. 

For the list of Expanders [see here](https://developers.dayforce.com/Build/API-Explorer/Employee/GET-Employee-Details/Expanders.aspx)

```powershell
Get-DayForceEmployee -xRefCode 104438 -expand "EmployeeManagers,EmployeeProperties,GlobalProperties,Locations,EmploymentTypes,OrgUnitInfos,WorkAssignments,EmploymentStatuses,Contacts"


EmployeeId         : 2251
HireDate           : 22/07/2024 12:00:00 AM
OriginalHireDate   : 22/07/2024 12:00:00 AM
EmployeeNumber     : 104438
EmploymentStatuses : @{Items=System.Object[]}
WorkAssignments    : @{Items=System.Object[]}
Contacts           : @{Items=System.Object[]}
EmployeeManagers   : @{Items=System.Object[]}
EmploymentTypes    : @{Items=System.Object[]}
EmployeeProperties : @{Items=System.Object[]}
XRefCode           : 104438
FirstName          : Leah
LastName           : Wright

```

## Get a DayForce Employee Profile

The Build-UserProfile cmdlet takes a returned Employee Object and extracts the value data for a record into a more structured and usable PSObject. 

### Example 1

Get a Dayforce Employee object and pass to the Build-UserProfile cmdlet. 

```powershell
$record104438 = Get-DayForceEmployee -xRefCode 104438 -expand "EmployeeManagers,EmployeeProperties,GlobalProperties,Locations,EmploymentTypes,OrgUnitInfos,WorkAssignments,EmploymentStatuses,Contacts"

Build-UserProfile -dayforceEmployee $record104438 

employeeId         : 2251
employeeNumber     : 104438
xRefCode           : 104438
firstName          : Leah
lastName           : Wright
hireDate           : 22/07/2024 12:00:00 AM
originalHireDate   : 22/07/2024 12:00:00 AM
workAssignments    : @{country=Australia; legalEntity=************; address1=404 One Rd; city=Sydney; state=New South Wales; postalCode=3207; department=Reception; jobTitle=Corporate Receptionist}
employmentStatuses : @{status=Active; startDate=22/07/2024 12:00:00 AM; payclass=PT; endDate=}
employeeManagers   : @{managerXRefCode=101250; managerFirstName=Judy; managerLastName=Ross; managerEffectiveStartDate=22/07/2024 12:00:00 AM}
```

### Example 2

From the pipeline passing a returned Dayforce Employee object. 

```powershell
$record104438 | Build-UserProfile


employeeId         : 2251
employeeNumber     : 104438
xRefCode           : 104438
firstName          : Leah
lastName           : Wright
hireDate           : 22/07/2024 12:00:00 AM
originalHireDate   : 22/07/2024 12:00:00 AM
workAssignments    : @{country=Australia; legalEntity=***************; address1=404 Bar Rd; city=Port Adelaide; state=South Australia; postalCode=5061; department=People & Culture - HR; jobTitle=Corporate Recruiting}
employmentStatuses : @{status=Active; startDate=22/07/2024 12:00:00 AM; payclass=PT; endDate=}
employeeManagers   : @{managerXRefCode=101250; managerFirstName=Ella; managerLastName=McDole; managerEffectiveStartDate=22/07/2024 12:00:00 AM}
```

### Example 3 

Using the output from Get-EmployeeBulkExport contained in a collection named $allEmployees process them all. 

```powershell
$allUserProfiles = @() 
foreach ($employee in $allEmployees) {
    $allUserProfiles += Build-UserProfile $employee
} 
```

## Get Bulk Employee Records

Getting an extract of muliple employee records invovles multiple steps. 

1. Create a bulk record request. The request can include many different filter parameters. At a minimum you want to request the record detail you want, the pagesize for the returned record results and a filter such as FilterHireStartDate. 
2. Query the status of the bulk request. When it has been completed you get the URI of the results
3. Iterate through the results


### Bulk Record Request

**Before You Begin:** Your user role must be assigned access to the PATCH/POST HR Bulk Job subfeature under HCM Anywhere > Web Services in the Features tab of System Admin > Roles.

In addition to field-level access, you must enable EmployeeExportBulkResponse, EmployeeExportBackgroundJobStatus (and relevant child nodes) and EmployeeExportParameters (and relevant child nodes) under RESTful Services > Human Resources in the Web Services Field-Level Access tab of System Admin > Roles.

As detailed above the bulk request needs to include the data you want and a filter as a minimum. 

Filter options are:

- "PayGroupXRefCode": "string",
- "EmployeeXRefCode": "string",
- "EmployeeNumber": "string",
- "Expand": "string",
- "PageSize": 0,
- "ContextDate": "2025-01-13T01:32:55.423Z",
- "ContextDateRangeFrom": "2025-01-13T01:32:55.423Z",
- "ContextDateRangeTo": "2025-01-13T01:32:55.423Z",
- "ContextDateOption": "string",
- "DeltaOption": "string",
- "DeltaDate": "2025-01-13T01:32:55.423Z",
- "AmfEntity": "string",
- "AmfLevel": "string",
- "AmfLevelValue": "string",
- "ExportAllEmployeeDetailOnDelta": true,
- "ExcludeTerminatedEmployeesOlderThanXDays": 0,
- "DisplayName": "string",
- "SocialSecurityNumber": "string",
- "EmploymentStatusXRefCode": "string",
- "OrgUnitXRefCode": "string",
- "DepartmentXRefCode": "string",
- "JobXRefCode": "string",
- "PositionXRefCode": "string",
- "PayClassXRefCode": "string",
- "PayPolicyXRefCode": "string",
- "PayTypeXRefCode": "string",
- "PayrollPolicyXRefCode": "string",
- "FilterHireStartDate": "2025-01-13T01:32:55.423Z",
- "FilterHireEndDate": "2025-01-13T01:32:55.423Z",
- "FilterTerminationStartDate": "2025-01-13T01:32:55.423Z",
- "FilterTerminationEndDate": "2025-01-13T01:32:55.423Z",
- "FilterOriginalHireStartDate": "2025-01-13T01:32:55.423Z",
- "FilterOriginalHireEndDate": "2025-01-13T01:32:55.423Z",
- "FilterSeniorityStartDate": "2025-01-13T01:32:55.423Z",
- "FilterSeniorityEndDate": "2025-01-13T01:32:55.423Z",
- "FilterBaseSalaryFrom": 0,
- "FilterBaseSalaryTo": 0,
- "FilterBaseRateFrom": 0,
- "FilterBaseRateTo": 0,
- "FilterTerminatedSinceStartDate": "2025-01-13T01:32:55.423Z",
- "FilterTerminatedSinceEndDate": "2025-01-13T01:32:55.423Z",
- "FilterBirthStartDate": "2025-01-13T01:32:55.423Z",
- "FilterBirthEndDate": "2025-01-13T01:32:55.423Z",
- "AttendancePolicyXrefCode": "string",
- "EmployeeGroupXrefCode": "string",
- "EntitlementPolicyXrefCode": "string",
- "PayHolidayGroupXrefCode": "string",
- "OvertimeGroupXrefCode": "string",
- "JobStepPolicyXrefCode": "string",
- "ScheduleRulePolicyXrefCode": "string",
- "ShiftRotationXrefCode": "string",
- "ShiftTradePolicyXrefCode": "string",
- "PunchPolicyXrefCode": "string",
- "TimeOffPolicyXrefCode": "string",
- "VacationBidGroupXrefCode": "string"

Other options are:

- **PayGroupXRefCode** - Filters employee based on their current pay group. Use a comma (,) to add multiple pay groups.
- **EmployeeXRefCode** - Filters employee based on exact match of the employee's XrefCode. Use a comma (,) to add multiple employee XRefCodes.
  - One of PayGroupXrefCode and/or EmployeeXrefCode is required.
- **EmployeeNumber** - Filters employee based on exact match of employee's employee number. Use a comma (,) to add multiple employee numbers.
- **Expand** - Add additional employee data in Dayforce. See the list of expand options; note their respective access / authorization requirements.
- **PageSize** - Used to determine maximum number of employees returned per requests. Example if there are 120 employees. A page size of 25 will return the first 25 employees in the first response. A total of 5 calls is needed to retrieve all 120 employees.
- **ContextDate** - Fetches all the recordx having last modified date prior to the context date. If - ContextDateRangeFrom and ContextDateRangeTo is provided  ContextDate is ignored.
- **ContextDateRangeFrom** - Filters records with effective dates (such as workassignments, employmentStatuses, addresses)
- **ContextDateRangeTo** - Filters records with effective dates (such as workassignments, employmentStatuses, addresses)
- **ContextDateOption** - References the export period:
    - **Current** - Selecting this option will return all the selected details, but only the currently effective record.
    - **FullHistory** - Selecting this option will retumnall the selected details including all historical data associated with the employee.
    - **Latest** - Selecting this option will return only the latest effective record for the selected details, this includes future dated records associated to the employee.
    - **​CurrentPayPeriod** - Selecting this option will require PayGroupXrefcode as the reference code. The pay group's pay period range is derived from the pay date. Pay date is the next available pay date from the export run date or current date.  Example, the pay group's pay period from 05/01 to 05/15 has a 05/18 pay date. If the export is run on 05/10, the next pay date is 05/18 and 05/01 to 05/15 will be used as the Current Pay Period. Records that are effective within this period are exported.
    - **​CurrentandFuture** - Selecting this option will return the records for the selected details that are either currently active as of the export date, or have future dated effective starts.
    - **DeltaOption** - 
        - **MODIFIED_SINCE_DELTA_DATE** - This selection allows you to export only employees/details which have changed since the last export date.
        - **EFFECTIVE_SINCE_DELTA_DATE** - This selection allows you to export only employees/details which have become effective since the last export date.
        - **MODIFIED_OR_EFFECTIVE_SINCE_DELTA_DATE** - This combines the logic of both the above options exports records that either been changed or become effective since the last export date.
    - **DeltaDate** - Used as the last export date for the DeltaOption

#### Example Employee Bulk Export Request

Get employee records that started after 31 Dec 2015 with thier Manager, Employee Properties, Types, Work Assignments, Status and Contact info. 

### Example - All Employees since end of December 2015
```powershell

$request = '{
    "Expand": "EmployeeManagers,EmployeeProperties,GlobalProperties,Locations,EmploymentTypes,OrgUnitInfos,WorkAssignments,EmploymentStatuses,Contacts",
    "PageSize": 100,
    "FilterHireStartDate": "2015-12-31T12:00:00.000Z"
  }'
$bulkRequest = Start-EmployeeBulkExport -request $request
$bulkRequest

Message                                            JobStatus
-------                                            ---------
Employee Export Background Job queued successfully https://<tenant>.dayforcehcm.com/api/<environment>/V1/EmployeeExportJobs/Status/3

```

### Example - Terminating Employees
```powershell
$filterEndRequest = '{
    "Expand": "EmployeeManagers,EmployeeProperties,Locations,EmploymentTypes,WorkAssignments,EmploymentStatuses,Contacts",
    "PageSize": 100,
    "FilterTerminationStartDate": "2024-12-31T12:00:00.000Z"
  }'

$bulkEndRequest = Start-EmployeeBulkExport -request $filterEndRequest

do {
    $bulkExportDetails = Get-EmployeeBulkExportStatus -statusURI $bulkEndRequest.JobStatus
    Start-Sleep -Seconds 15
} until (
    $bulkExportDetails.Status.ToLower() -eq "succeeded"
)

```

### Query the status of the bulk request

The request depending on the filters and query can take some time to be fulfilled. 
Check the status periodically. 

#### Example

The following queries the status every 15 seconds waiting until the request has commpleted. 

```powershell
do {
    $bulkExportDetails = Get-EmployeeBulkExportStatus -statusURI $exportURI
    Start-Sleep -Seconds 15
} until (
    $bulkExportDetails.Status.ToLower() -eq "succeeded"
)


Status    Results
------    -------
Succeeded https://globalausstage404.dayforcehcm.com/api/companystage/V1/EmployeeExportJobs/Data/be4b69e5-d485-4d3c-9471-ae85ef1c6d6a

```

### Get the bulk records

The Get-EmployeeBulkExport cmdlet will return all the records from the bulk request (automatically doing pagnation to iterate through each page of results.)

#### Example 1

```powershell
$allEmployees = Get-EmployeeBulkExport -bulkExportURI $bulkExportDetails.Results 
```

#### Example 2

Build the usable PSObject Profile Records

```powershell
$allUserProfiles = @()
foreach ($employee in $allEmployees) {
    $allUserProfiles += Build-UserProfile $employee
} 
$allUserProfiles.count 

446
```

#### Example - Display the first 5 records from the collection 

```powershell
$allUserProfiles[0..4] 

employeeId         : 1648
employeeNumber     : 103989
xRefCode           : 103989
firstName          : Ismail
lastName           : Cruz
hireDate           : 31/07/2023 12:00:00 AM
originalHireDate   : 31/07/2023 12:00:00 AM
workAssignments    : @{country=Australia; legalEntity=***************; address1=461 Williamstown Rd; city=Port Melbourne; state=Victoria; postalCode=3207; department=Cloud - Managed Services; jobTitle=Cloud Engineer}
employmentStatuses : @{status=Active; startDate=31/07/2023 12:00:00 AM; payclass=FT; endDate=}
employeeManagers   : @{managerXRefCode=100396; managerFirstName=Makayla; managerLastName=Lopez; managerEffectiveStartDate=31/07/2023 12:00:00 AM}

employeeId         : 1649
employeeNumber     : 102197
xRefCode           : 102197
firstName          : Nigela
lastName           : Ross
hireDate           : 4/10/2021 12:00:00 AM
originalHireDate   : 26/11/2019 12:00:00 AM
workAssignments    : @{country=Australia; legalEntity=***************; address1=1 Export Park Drive; city=Byron Bay; state=New South Wales; postalCode=2299; department=Technology; jobTitle=Head of Exports}
employmentStatuses : @{status=Active; startDate=4/10/2021 12:00:00 AM; payclass=FT; endDate=}
employeeManagers   : @{managerXRefCode=102989; managerFirstName=Mike; managerLastName=Myers; managerEffectiveStartDate=12/01/2022 12:00:00 AM}

employeeId         : 1650
employeeNumber     : 104174
xRefCode           : 104174
firstName          : Colleen
lastName           : Redmond
hireDate           : 20/11/2023 12:00:00 AM
originalHireDate   : 20/11/2023 12:00:00 AM
workAssignments    : @{country=Australia; legalEntity=***************; address1=404 Bay Rd; city=Melbourne; state=Victoria; postalCode=3201; department=Cyber; jobTitle=Response Services}
employmentStatuses : @{status=Active; startDate=20/11/2023 12:00:00 AM; payclass=FT; endDate=}
employeeManagers   : @{managerXRefCode=100503; managerFirstName=Ingrid; managerLastName=Tooth; managerEffectiveStartDate=20/11/2023 12:00:00 AM}

employeeId         : 1651
employeeNumber     : 104383
xRefCode           : 104383
firstName          : Leon
lastName           : Messi
hireDate           : 3/06/2024 12:00:00 AM
originalHireDate   : 3/06/2024 12:00:00 AM
workAssignments    : @{country=Australia; legalEntity=***************; address1=404 Smart Rd; city=Port Adelaide; state=South Australia; postalCode=5071; department=Technology; jobTitle=Engineer}
employmentStatuses : @{status=Active; startDate=3/06/2024 12:00:00 AM; payclass=FT; endDate=}
employeeManagers   : @{managerXRefCode=102648; managerFirstName=Emily; managerLastName=George; managerEffectiveStartDate=3/06/2024 12:00:00 AM}

employeeId         : 1652
employeeNumber     : 104379
xRefCode           : 104379
firstName          : Penny
lastName           : Silver
hireDate           : 27/05/2024 12:00:00 AM
originalHireDate   : 27/05/2024 12:00:00 AM
workAssignments    : @{country=Australia; legalEntity=***************; address1=404 Day St; city=Brisbane; state=Queensland; postalCode=7071; department=People & Culture - HR; jobTitle=Corporate HR}
employmentStatuses : @{status=Active; startDate=27/05/2024 12:00:00 AM; payclass=FT; endDate=}
employeeManagers   : @{managerXRefCode=101250; managerFirstName=Mark; managerLastName=Field; managerEffectiveStartDate=27/05/2024 12:00:00 AM}
```

## Update Dayforce with SSO Account details for Service Provider SSO to Entra ID

To enable an employee to get Single Sign On to Dayforce using Entra ID, Dayforce must be updated with the employees UPN/Email address and EnableNativeAuthentication enabled on their record. 

To perform this use the Update-DayForceEmployeeSSOAccount cmdlet with the employees xRefCode (obtained through Get-DayforceEmployee) and the boolean parameter -EnableNativeAuthentication

### Example 1

Update Dayforce record 101989 with their email address for Federated SSO and set EnableNativeAuthentication to true

```powershell
Update-DayForceEmployeeSSOAccount -xRefCode 101989 -SSOAccount "Charles.Darwin@customer.com.au" -EnableNativeAuthentication $true 
```

### Example 2

Update Dayforce record 101989 with email address for Federated SSO and disable EnableNativeAuthentication 

```powershell
Update-DayForceEmployeeSSOAccount -xRefCode 101989 -SSOAccount "Charles.Darwin@customer.com.au" -EnableNativeAuthentication $false 
```


## Update Dayforce Employee Business Email Address

Updating an employee record requires an input object that includes the path to the field(s) being updated.

The example below is updating the business email address on the Contact object in Dayforce.

### Example - updating the business email address for a Dayforce Record

**NOTE** the value of PersonContactId changes each time the record is updated.

```powershell 
$empRecord = Get-DayForceEmployee -xRefCode 103989 -expand "Contacts,SSOAccounts"
$businessEmailObj = $empRecord.Contacts.items | Where-Object { $_.contactinformationtype.xRefCode -eq "BusinessEmail" } | Select-Object

$emailAddress = "charles.darwin@company.com.au"
$effectiveStart = get-date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"

$body = @{Contacts = @{Items = @(
    @{
        PersonContactId = $businessEmailObj.PersonContactId
        ContactInformationType = @{
            XRefCode = "BusinessEmail"
        }
        ElectronicAddress = $emailAddress
        EffectiveStart = $effectiveStart
    })}}

Update-DayForceEmployee -xRefCode 103989 -request ($body | convertto-json -Depth 5)
```

## Invoke a Dayforce API Request

The `Invoke-DayForceRequest` cmdlet allows you to make API requests to Dayforce with various methods and headers, reusing the Global AccessToken variable for authentication and supporting API versioning.

### Parameters

- **uri**: (required for Full URI parameter set) API URI
- **path**: (required for path parameter set) specify the rest of the API query after the base API URL as determined when picking the API variable
- **API**: (required for path parameter set) will determine the base URL
  - V1 will use the base URL `https://{your org}.dayforcehcm.com/api/V1/`
  - V2 will use the base URL `https://{your org}.dayforcehcm.com/api/V2/`
- **method**: (required) API Method (e.g., Post, Get, Patch, Delete)
- **contentType**: (required) Content type of the request (e.g., application/json, application/x-www-form-urlencoded)
- **body**: (optional - JSON) Payload for a web request
- **json**: (optional) Return Dayforce Request response as JSON

### Examples

#### Example 1

Invoke a GET request to retrieve employees:

```powershell
Invoke-DayForceRequest -method Get -uri "https://YOURORG.dayforcehcm.com/api/V1/Employees" -contentType "application/json"
```

#### Example 2

Invoke a GET request using API version and path:

```powershell
Invoke-DayForceRequest -API V1 -path 'Employees' -method Get -contentType "application/json"
```

#### Example 3

Invoke a PATCH request to update an employee's contact information:

```powershell
$body = @{
    Contacts = @{
        Items = @(
            @{
                PersonContactId = "12345"
                ContactInformationType = @{
                    XRefCode = "BusinessEmail"
                }
                ElectronicAddress = "new.email@company.com"
                EffectiveStart = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ")
            }
        )
    }
}

Invoke-DayForceRequest -API V1 -path 'Employees/12345/Contacts' -method Patch -contentType "application/json" -body ($body | ConvertTo-Json -Depth 5)
```