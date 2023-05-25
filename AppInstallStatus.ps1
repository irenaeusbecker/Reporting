Install-Module MSAL.PS
Import-Module -name MSAL.PS

#Azure App ID Details
$connectionDetails = @{
    'TenantId'     = 'tenant-id'
    'ClientId'     = 'AzureAppID'
    'ClientSecret' = 'AzureAppSecret' | ConvertTo-SecureString -AsPlainText -Force
}

#LogAnalytics Access Data
$CustomerId = "LogAnalyticsID"
$SharedKey = 'LogAnalyticsSecret'
#Table Name for Custom Log 
$LogType = "AppInfos"


### Functions

$TimeStampField = ""
$authResult = Get-MsalToken @connectionDetails
$Authheader = @{Authorization = "Bearer $($authResult.AccessToken)"}

# Log analytics functions
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}	

# Create the function to create and post the request
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode

}

# Definition of Logfile for Debug Topics
#$logfile = "C:\Temp\Apps_Status_Windows.log"
#If (Test-Path $logfile) {
#	Remove-Item $logfile
#}else{
#}
#New-Item $logfile


# Get all Applications
$URL = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=(isof('microsoft.graph.win32LobApp'))&`$select=id,displayName"
$AppsResponse = Invoke-RestMethod -Method GET -uri $URL -Headers $Authheader

#Looping through MS Graph pages if more then a 100 results
$Apps = $AppsResponse.value
$AppsNextLink = $AppsResponse."@odata.nextLink"
while ($AppsNextLink -ne $null){
    $AppsResponse = (Invoke-RestMethod -Uri $AppsNextLink -Headers $Authheader -Method Get)
    $AppsNextLink = $AppsResponse."@odata.nextLink"
    $Apps += $AppsResponse.value
}

foreach ($item in $Apps){

    # Get all managed apps
	$URL = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/{$($item.id)}/userStatuses"
    $Response = Invoke-RestMethod -Method GET -uri $URL -Headers $Authheader

	if ($Response.value.installedDeviceCount) { $nr_installed=$Response.value.installedDeviceCount} else {$nr_installed="0"}
	if ($Response.value.failedDeviceCount) { $nr_failed=$Response.value.failedDeviceCount} else {$nr_failed="0"}
	if ($Response.value.notInstalledDeviceCount) { $nr_not_installed=$Response.value.notInstalledDeviceCount} else {$nr_not_installed="0"}
    
#	Add-Content $logfile "$($item.id),$($item.displayName),$nr_installed,$nr_failed,$nr_not_installed" 
	
	
	# Create the object
	$Properties = [Ordered] @{
		"AppID"     = $($item.id)
		"AppDisplayName" = $($item.displayName)
		"Install_Successful"     = $nr_installed	
		"Install_Failed"            = $nr_failed
		"Install_No"     = $nr_not_installed	
	}
	$DeviceInfo = New-Object -TypeName "PSObject" -Property $Properties
	$DeviceInfoJson = $DeviceInfo | ConvertTo-Json

	Write $DeviceInfoJson

	$params = @{
		CustomerId = $customerId
		SharedKey  = $sharedKey
		Body       = ([System.Text.Encoding]::UTF8.GetBytes($DeviceInfoJson))
		LogType    = $LogType 
	}

	$LogResponse = Post-LogAnalyticsData @params	
	
}

