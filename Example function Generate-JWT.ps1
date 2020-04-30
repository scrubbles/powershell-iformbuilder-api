function Generate-JWT (
    <# From u/ping_localhost on https://www.reddit.com/r/PowerShell/comments/8bc3rb/generate_jwt_json_web_token_in_powershell/ #>
    [Parameter(Mandatory = $True)]
    [ValidateSet("HS256", "HS384", "HS512")]
    $Algorithm = $null,
    $type = $null,
    [Parameter(Mandatory = $True)]
    [string]$Issuer = $null,
    [int]$ValidforSeconds = $null,
    [Parameter(Mandatory = $True)]
    $SecretKey = $null
    ){

    $exp = [int][double]::parse((Get-Date -Date $((Get-Date).addseconds($ValidforSeconds).ToUniversalTime()) -UFormat %s)) # Grab Unix Epoch Timestamp and add desired expiration.

    [hashtable]$header = @{alg = $Algorithm; typ = $type}
    [hashtable]$payload = @{iss = $Issuer; exp = $exp}

    $headerjson = $header | ConvertTo-Json -Compress
    $payloadjson = $payload | ConvertTo-Json -Compress
    
    $headerjsonbase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerjson)).Split('=')[0].Replace('+', '-').Replace('/', '_')
    $payloadjsonbase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadjson)).Split('=')[0].Replace('+', '-').Replace('/', '_')

    $ToBeSigned = $headerjsonbase64 + "." + $payloadjsonbase64

    $SigningAlgorithm = switch ($Algorithm) {
        "HS256" {New-Object System.Security.Cryptography.HMACSHA256}
        "HS384" {New-Object System.Security.Cryptography.HMACSHA384}
        "HS512" {New-Object System.Security.Cryptography.HMACSHA512}
    }

    $SigningAlgorithm.Key = [System.Text.Encoding]::UTF8.GetBytes($SecretKey)
    $Signature = [Convert]::ToBase64String($SigningAlgorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ToBeSigned))).Split('=')[0].Replace('+', '-').Replace('/', '_')
    
    $token = "$headerjsonbase64.$payloadjsonbase64.$Signature"
    $token
}

$api_key = ''
$api_secret = ''

Generate-JWT -Algorithm 'HS256' -type 'JWT' -Issuer $api_key -SecretKey $api_secret -ValidforSeconds 3600