 <#
#############################################################################
Script purpose: Apply SDT and OpsNote to Windows device in LogicMonitor on graceful shutdown.

Script must be assigned via a Group Policy, see for example:
https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc770300(v=ws.10)

Script should be saved (most likely) to C:\Windows\System32\GroupPolicy\Machine\Scripts\Shutdown\ - This can be set
 within the Group Policy.

Script Operation:

- Finds own computername from own environment;

- Finds own system IPs for enabled adaptors from WMI;

- Calls LogicMonitor API (using credentials hardcoded in script) to determine the most likely device ID based on the above data;

- Adds 5 minute whole-device SDT, and 65 minute Uptime SDT, to cover restart period and subsequent uptime alerting period;
--- Will only happen if API user has "Acknowledge" rights.

- Adds OpsNote to Device in LogicMonitor to flag the graceful restart occurence.
--- Will only happen if API user has "Manage SDT" rights.

Script can be run manually via Powershell / Powershell ISE on the device to prove
 API connection and operation.

Various 'debug' sections in this script can be commented in (by taking the space
 out ot the relevant leading '<## >' line) to write data out for human visual check.
#############################################################################
#>

<############################################################################
API Permissions
The API key you are using will need "Acknowledge" permissions for the devices to set SDT.
The API key also needs "Manage" permissions for "Ops Notes" under the settings section if you want the script to record an Ops note on reboot.


#>

<#
#############################################################################
#
# SET YOUR API CREDENTIALS BELOW
#
# Replace the access ID, Key, Company name
# Access ID is the 20-character value from a LogicMonitor API Token
# Access Key is the 40-character value from a LogicMonitor API Token
# Company is the first part of the LogicMonitor portal URL, e.g. https://company.logicmonitor.com/
#
#############################################################################
#>

$accessId = '1234567890'
$accessKey = '1234567890-=-0987654321'
$company = 'portalname'


<#
###############################################################################
# We want to add SDT to the device whose system.sysname matches $env:computername
#  **AND** who has at least one IP match with system.ips
# System name for Windows should be unique on a network, **but** there may be multiple
#  networks within LM so there is a **slender** chance that this might not be
#  enough. Adding a check for matching IPs reduces likelihood of having multiple matches.
# 1. Need to call API to find deviceId
# 2a. Need to call API to set all-device SDT using deviceId
# 2b. Need to call API to set uptime SDT using deviceId *AND* WinSystemUptime DataSourceName
# 3. Need to call API to set OpsNote using deviceId
#
###############################################################################
#>
## Set Device downtime for the entire device for $minutes during reboot (requires acknowledge device permissions)
[bool]$SetDeviceSDT = $true
# Set SDT on the Windows Uptime datasource for 1 hour (requires acknowledge device permissions)
[bool]$SetUptimeSDT = $true
# Set an Ops note on the device at reboot time (requires manage ops notes permission)
[bool]$SetOpsNote = $true
####Obtain Environment Variables
# Device systemname:
$computerName = $env:computername

# Device IPs **of enabled adaptors** such that LM would also find.
# CANNOT use simply Get-NetIPAddress as this may include various other IPs.
$ipsquery = "select IPADDRESS from Win32_NetworkAdapterConfiguration where IPENABLED = true"
$wqlips = Get-WmiObject -Query $ipsquery | select-object -expand IPADDRESS

# Get current time of epoch in milliseconds
$epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

# Get device SDT end time in milliseconds (epoch plus 5 * 60 * 1000)
# 5 minutes should be ample to cover the actual restart:
[int]$minutes = 5
$deviceEndTime = $epoch + ($minutes*60*1000)

# Get uptime SDT end time in milliseconds (epoch plus 65 * 60 * 1000)
# 65 minutes should be ample to cover the expected uptime alert which is < 1 hour by default.
$uptimeEndTime = $epoch + (65*60*1000)

<## >
# For Debug:
echo $computerName
echo $wqlips
<##>

#### Functions Here ####
Function Get-LmRestApi {
    [CmdletBinding()]
    Param(
        [string]$epoch,
        [string]$httpVerb,
        [string]$resourcePath,
        [string]$queryParams,
        [string]$data = '',
        [string]$company,
        [string]$accessKey,
        [string]$accessId,
        [bool]$printResponse = $false
    )
    ## Configure security to force TLS 1.2###
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    # If an epoch value was not provided, generate one
    if ([string]::IsNullOrEmpty($epoch)){$epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)}
    #Construct URL
    $url = 'https://' + $company + '.logicmonitor.com/santaba/rest' + $resourcePath + $queryParams
    
    # Concatenate Request Details
    $requestVars = $httpVerb + $epoch + $data + $resourcePath

    #Construct Signature
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes($accessKey)
    $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
    $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
    $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

    # Construct Headers
    $auth = 'LMv1 ' + $accessId + ':' + $signature + ':' + $epoch
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization",$auth)
    $headers.Add("Content-Type",'application/json')

    # Make Request
    if ($httpVerb -like "POST") {$response = Invoke-RestMethod -Uri $url -Method $httpVerb -Body $data -Header $headers}
    if ($httpVerb -like "GET") {$response = Invoke-RestMethod -Uri $url -Method $httpVerb -Header $headers}
    
    #Print the response formatted as JSON for debugging
    if ($printResponse){
        $status = $response.status
        $jsonbody = $response.data | ConvertTo-Json -Depth 5
        Write-Host "Status: $status"
        Write-Host "Response:"
        Write-Host $body

    }
    return $response
}


###############################################################################
# 1. Need to call API to find deviceId
###############################################################################

# request details
$httpVerb = 'GET'
$resourcePath = '/device/devices'

# Need systemProperties - name=system.displayname value=$computerName
$filter = 'systemProperties.name:system.displayname,systemProperties.value:' + $computerName
$fields = 'id,displayName,systemProperties'
$sort = ''
$queryParams = '?filter=' + $filter + '&fields=' + $fields + '&sort=' + $sort
$data = '';
#Retrieve the Response from the LM API
$response = Get-LmRestApi -httpVerb $httpVerb -resourcePath $resourcePath -queryParams $queryParams -accessKey $accessKey -accessId $accessId -company $company -epoch $epoch
# Print status and body of response
$status = $response.status
$body = $response.data | ConvertTo-Json -Depth 5

<## >
# For Debug:
Write-Host "Status: $status"
Write-Host "Response:"
Write-Host $body
<##>

$alldataObj = ConvertFrom-Json -InputObject $body

$allResponse = $body | ConvertFrom-Json

<## >
# For Debug:
Write-Host "alldataObj: $alldataObj"
Write-Host "allResponse: $allResponse"
Write-Host $allResponse.items.length
<##>

# Set some initial zeros:
$thisDeviceHasMyNameCount = 0;
$previousMatchingIPsMax = 0;

for($i = 0; $i -lt $allResponse.items.length; $i++)
{
    $item = $allResponse.items[$i];
    $displayName = $item.displayName;
	$deviceID = $item.id;
    $thisDeviceHasMyName = $false;
    $matchingIPsCount = 0;
    $NonMatchingIPsCount = 0;
	<## >
	# For Debug:
	Write-Host $displayName
	Write-Host $item.systemProperties.length
	<##>
    for($j = 0; $j -lt $item.systemProperties.length; $j++)
    {
        $systemPropertyName = $item.systemProperties[$j].name;
        $systemPropertyValue = $item.systemProperties[$j].value;
		<## >
		# For Debug:
        Write-Host $systemPropertyName"="$systemPropertyValue
		<##>

        if($systemPropertyName -eq 'system.sysname' -And $systemPropertyValue -eq $computerName)
        {
            $thisDeviceHasMyName = $true;
			<## >
			# For Debug:
            Write-Host $systemPropertyName"="$systemPropertyValue
			<##>
        }

        if($systemPropertyName -eq 'system.ips')
        {
            $systemIps = $systemPropertyValue
			<## >
			# For Debug:
            Write-Host "System IPs ="$systemIps
			<##>

			<## >
			# For Debug:
			Write-host "IPs from LogicMonitor as split:"
			Write-host '---'
			<##>

			ForEach ($lmip in $($systemIps -split ","))
			{
				if ($lmip -like '*:*')
				{
					# Parse IPv6 address to contracted form, from the fully expanded format held in LM API response:
					$ip = [System.Net.IPAddress]::Parse($lmip);
					#Write-host $ip
				}
				else
				{
					$ip = $lmip;
					#Write-host $ip
				}

				# Check if the IPs we found from WMI include each IP that LM knows about,
				#  ignoring "127.0.0.1" that the device won't list in the WMI response.
				if ($wqlips -like "*$ip*" -And $ip -ne "127.0.0.1")
				{
					$matchingIPsCount++
					#Write-host "match! of" $ip
				}
			}
			#Write-host '==='
        }
    }
    
    # We have now gone through all the system.properties (0 to j) of the current (i) Device.
	# If the Device has a matching name and at least one matching IP, and more matching IPs than any other name-matched Device,
	#  it's most likely the right Device.
	# If it has the same number of matching IPs as another device of the same system name (hugely unlikely) we can't make a
	#  decision, so we'll have to leave it as ambiguous (and ultimately, can't set SDT).
    if($thisDeviceHasMyName -And $matchingIPsCount -gt 0 -And $matchingIPsCount -ge $previousMatchingIPsMax)
    {
		# Increment count of possible matching devices, and set max matched IPs count to count from this device.
        $thisDeviceHasMyNameCount++;
		$previousMatchingIPsMax = $matchingIPsCount;

		# Don't need an array or the like. If there's more than one possible device we do nothing later on anyway.
        $myDeviceID = $deviceID;

        <## >
		# For Debug:
        Write-Host "This device is me!"
        Write-Host "ID: "$myDeviceID
        Write-Host "Name: "$computerName
        Write-Host "Matching IPs: "$matchingIPsCount
        Write-Host "Device Count: "$thisDeviceHasMyNameCount
        <##>
    }
}

<## >
# For Debug:
Write-Host "Count after loop: "$thisDeviceHasMyNameCount
<##>

if($thisDeviceHasMyNameCount -lt 1)
{
    # No matching device in LM
}

if($thisDeviceHasMyNameCount -gt 1)
{
    # Multiple matching devices in LM
}

if($thisDeviceHasMyNameCount -eq 1)
{
    # Wow. We have exactly one device of this system.sysname, we can proceed...

	<## >
	# For Debug:
    Write-Host "Going ahead for the following Device:"
    Write-Host "ID:" $myDeviceID
    Write-Host "Name:" $computerName
	<##>
	
	###############################################################################
	# 2a. Need to call API to set SDT using deviceId
	###############################################################################

	# request details
    if ($SetDeviceSDT) {
	    $httpVerb = 'POST'
	    $resourcePath = '/sdt/sdts'
	    $queryParams = ''
	    $data = '{"sdtType":1,"type":"DeviceSDT","deviceId":' + $myDeviceID + ',"comment":"SDT for graceful shutdown","startDateTime":' + $epoch + ',"endDateTime":' + $deviceEndTime + '}';

        $SdtResponse = Get-LmRestApi -httpVerb $httpVerb -resourcePath $resourcePath -queryParams $queryParams -data $data -accessKey $accessKey -accessId $accessId -company $company -epoch $epoch
	
	    # Find status and body of response
	    $status = $SdtResponse.status
	    $body = $SdtResponse.data | ConvertTo-Json -Depth 5

	    <## >
	    # For Debug:
	    Write-Host "Status:$status"
	    Write-Host "Response:$body"
	    <##>
    }

	###############################################################################
	# 2b. Need to call API to set uptime SDT using deviceId *AND* WinSystemUptime DataSourceName
	###############################################################################
	
	# Only the $data will need to change, then call the LmRestApi using the function
	if ($SetUptimeSDT) {
	    $data = '{"sdtType":1,"type":"DeviceDataSourceSDT","deviceId":' + $myDeviceID + ',"dataSourceName":"WinSystemUptime","comment":"SDT for graceful shutdown","startDateTime":' + $epoch + ',"endDateTime":' + $uptimeEndTime + '}';
        $Sdt2Response = Get-LmRestApi -httpVerb $httpVerb -resourcePath $resourcePath -queryParams $queryParams -data $data -accessKey $accessKey -accessId $accessId -company $company -epoch $epoch

	    # Find status and body of response
	    $status = $Sdt2Response.status
	    $body = $Sdt2Response.data | ConvertTo-Json -Depth 5

	    <## >
	    # For Debug:
	    Write-Host "Status:$status"
	    Write-Host "Response:$body"
	    <##>
    }	

	###############################################################################
	# 3. Need to call API to set OpsNote using deviceId
	###############################################################################

	# Update the request detaiuls for the opsnotes endpoint.  Note that this requires Manage Ops Notes permission.
    if($SetOpsNote) {
	    $httpVerb = 'POST'
	    $resourcePath = '/setting/opsnotes'
	    $queryParams = ''
	    $data = '{"note":"SDT for graceful shutdown","tags":[{"name":"shutdown"}],"scopes":[{"type":"device","deviceId":' + $myDeviceID + '}]}'
    
        $OpNResponse = Get-LmRestApi -httpVerb $httpVerb -resourcePath $resourcePath -queryParams $queryParams -data $data -accessKey $accessKey -accessId $accessId -company $company -epoch $epoch

	    # Find status and body of response
	    $status = $OpNResponse.status
	    $body = $OpNResponse.data | ConvertTo-Json -Depth 5

	    <##
	    # For Debug:
	    Write-Host "Status:$status"
	    Write-Host "Response:$body"
	    ##>
    }
} 
