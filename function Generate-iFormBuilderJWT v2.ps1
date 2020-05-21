function Generate-iFormBuilderJWT (
    <# From u/ping_localhost on https://www.reddit.com/r/PowerShell/comments/8bc3rb/generate_jwt_json_web_token_in_powershell/ #>
    [Parameter(Mandatory = $True)]
    [ValidateSet("HS256", "HS384", "HS512")]
    $Algorithm = $null,

    $type = $null,

    [Parameter(Mandatory = $True)]
    [string]$Issuer = $null,

    [int]$ValidforSeconds = $null,

    [Parameter(Mandatory = $True)]
    $SecretKey = $null,

    $Audience = $null
) {

    $exp = [int][double]::parse((Get-Date -Date $((Get-Date).addseconds($ValidforSeconds).ToUniversalTime()) -UFormat %s)) # Grab Unix Epoch Timestamp and add desired expiration.
    $iat = [int][double]::parse((Get-Date -Date $((Get-Date).ToUniversalTime()) -UFormat %s)) # Grab Unix Epoch Timestamp and add desired expiration.

    [hashtable]$header = @{alg = $Algorithm; typ = $type }
    [hashtable]$payload = @{
        iss = $Issuer;
        aud = $Audience
        exp = $exp;
        iat = $iat;
    }

    $headerjson = $header | ConvertTo-Json -Compress
    $payloadjson = $payload | ConvertTo-Json -Compress
    
    $headerjsonbase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerjson)).Split('=')[0].Replace('+', '-').Replace('/', '_')
    $payloadjsonbase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadjson)).Split('=')[0].Replace('+', '-').Replace('/', '_')

    $ToBeSigned = $headerjsonbase64 + "." + $payloadjsonbase64

    $SigningAlgorithm = switch ($Algorithm) {
        "HS256" { New-Object System.Security.Cryptography.HMACSHA256 }
        "HS384" { New-Object System.Security.Cryptography.HMACSHA384 }
        "HS512" { New-Object System.Security.Cryptography.HMACSHA512 }
    }

    $SigningAlgorithm.Key = [System.Text.Encoding]::UTF8.GetBytes($SecretKey)
    $Signature = [Convert]::ToBase64String($SigningAlgorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ToBeSigned))).Split('=')[0].Replace('+', '-').Replace('/', '_')
    
    $token = "$headerjsonbase64.$payloadjsonbase64.$Signature"
    $token
}


$ServerName = "csi360"
$uri = "https://$ServerName.iformbuilder.com/exzact/api/oauth/token"
$api_key = 'c6a2394c7aa21fa63df3d78bf85de3e9fa7d1014'
$api_secret = '3cae02759c42053cf17f5e60c8e671b8908d696d'

$JWT = Generate-iFormBuilderJWT -Algorithm 'HS256' -type 'JWT' -Issuer $api_key -SecretKey $api_secret -Audience $uri -ValidforSeconds 3600

$securetoken = Read-Host -AsSecureString
$ServerName = "csi360"
$uri = "https://$ServerName.iformbuilder.com/exzact/api/oauth/token"
$headers = @{
    "grant_type" = "jwt-bearer"#"urn:ietf:params:oauth:grant-type:jwt-bearer"
    "assertion" = $JWT
}

$Response = Invoke-RestMethod -Uri $uri -Method Post -SslProtocol Tls12 -Headers $headers






$type = "JWT"
$Algorithm = "HS256"

[hashtable]$header = @{alg = $Algorithm; typ = $type }
<# 
Name                           Value
----                           -----
alg                            HS256
typ                            JWT 
#>
$headerjson = $header | ConvertTo-Json -Compress
# {"alg":"HS256","typ":"JWT"}
$headerjsonbase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerjson)).Split('=')[0].Replace('+', '-').Replace('/', '_')

<# 
incorrect
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9

correct
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
#>

#first decode base64
$CorrectEnc64 = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
$CorrectEncBytes = [System.Convert]::FromBase64String($correctEnc)

#Conver from UTF8
[System.Text.Encoding]::UTF8.GetString($CorrectEncBytes)
# {"alg":"HS256","typ":"JWT"}
#...this is correct

#first decode base64
$INCorrectEnc64 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9'
$INCorrectEncBytes = [System.Convert]::FromBase64String($INCorrectEnc64)

#Conver from UTF8
[System.Text.Encoding]::UTF8.GetString($INCorrectEncBytes)






function Generate-ExampleJWT (
    <# From u/ping_localhost on https://www.reddit.com/r/PowerShell/comments/8bc3rb/generate_jwt_json_web_token_in_powershell/ #>
    [Parameter(Mandatory = $True)]
    [ValidateSet("HS256", "HS384", "HS512")]
    $Algorithm = $null,

    $type = $null,

    [Parameter(Mandatory = $True)]
    [string]$Issuer = $null,

    [int]$ValidforSeconds = $null,

    [Parameter(Mandatory = $True)]
    $SecretKey = $null,

    $Audience = $null
) {

    $exp = [int][double]::parse((Get-Date -Date $((Get-Date).addseconds($ValidforSeconds).ToUniversalTime()) -UFormat %s)) # Grab Unix Epoch Timestamp and add desired expiration.

    [hashtable]$header = @{alg = $Algorithm; typ = $type }
    [hashtable]$payload = @{
        iss = $Issuer;
        aud = $Audience
        exp = '1384370238';
        iat = '1384370228';
    }

    $headerjson = $header | ConvertTo-Json -Compress
    $payloadjson = $payload | ConvertTo-Json -Compress
    
    $headerjsonbase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerjson)).Split('=')[0].Replace('+', '-').Replace('/', '_')
    $payloadjsonbase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadjson)).Split('=')[0].Replace('+', '-').Replace('/', '_')

    $ToBeSigned = $headerjsonbase64 + "." + $payloadjsonbase64

    $SigningAlgorithm = switch ($Algorithm) {
        "HS256" { New-Object System.Security.Cryptography.HMACSHA256 }
        "HS384" { New-Object System.Security.Cryptography.HMACSHA384 }
        "HS512" { New-Object System.Security.Cryptography.HMACSHA512 }
    }

    $SigningAlgorithm.Key = [System.Text.Encoding]::UTF8.GetBytes($SecretKey)
    $Signature = [Convert]::ToBase64String($SigningAlgorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ToBeSigned))).Split('=')[0].Replace('+', '-').Replace('/', '_')
    
    $token = "$headerjsonbase64.$payloadjsonbase64.$Signature"
    $token
}



$uri = "https://company.iformbuilder.com/exzact/api/oauth/token"
$api_key = '1d38f6a6c89c868b6de90819d9b4e46ee6bfd05a'
$api_secret = '6b19083c7f0889cdb7035a1f845320a298810cb0'
Generate-ExampleJWT -Algorithm 'HS256' -type 'JWT' -Issuer $api_key -SecretKey $api_secret -Audience $uri -ValidforSeconds 3600