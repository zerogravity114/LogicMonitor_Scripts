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
 
