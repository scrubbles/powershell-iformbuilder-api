$token1 = (
    [access_token] => 4edb587ff14807031e2d5a373553d223f605253e
    [token_type] => Bearer
    [expires_in] => 3600 #1 hour, what happens when it expires?
)


$ServerName = "csi360"
$uri = "https://$ServerName.iformbuilder.com/exzact/api/v60/token"
$AuthToken = @{
    "Authorization" = "Bearer 6e24b04333a616e128ce8c214e03b3a845ebc000"
}
$Response = Invoke-RestMethod -Uri $uri -Method Get -Headers $AuthToken


[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12



$ServerName = "csi360"
$uri = "https://$ServerName.iformbuilder.com/exzact/api/oauth/token"
$headers = @{
    "assertion" = $JWT2
}
$Response = Invoke-RestMethod -Uri $uri -Method Post -SslProtocol Tls12 -Authentication Bearer -Token $JWT2












# Call Connect-Okta before calling Okta API functions.
function Connect-Okta($token, $baseUrl) {
    $script:headers = @{"Authorization" = "SSWS $token"; "Accept" = "application/json"; "Content-Type" = "application/json"}
    $script:baseUrl = $baseUrl

    $module = Get-Module OktaAPI
    $modVer = $module.Version.ToString()
    $psVer = $PSVersionTable.PSVersion

    $osDesc = [Runtime.InteropServices.RuntimeInformation]::OSDescription
    $osVer = [Environment]::OSVersion.Version.ToString()
    if ($osDesc -match "Windows") {
        $os = "Windows"
    } elseif ($osDesc -match "Linux") {
        $os = "Linux"
    } else { # "Darwin" ?
        $os = "MacOS"
    }

    $script:userAgent = "okta-api-powershell/$modVer powershell/$psVer $os/$osVer"
    # $script:userAgent = "OktaAPIWindowsPowerShell/0.1" # Old user agent.
    # default: "Mozilla/5.0 (Windows NT; Windows NT 6.3; en-US) WindowsPowerShell/5.1.14409.1012"

    # see https://www.codyhosterman.com/2016/06/force-the-invoke-restmethod-powershell-cmdlet-to-use-tls-1-2/
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

#region Core functions

function Invoke-Method($method, $path, $body) {
    $url = $baseUrl + $path
    if ($body) {
        $jsonBody = $body | ConvertTo-Json -compress -depth 100 # max depth is 100. pipe works better than InputObject
        # from https://stackoverflow.com/questions/15290185/invoke-webrequest-issue-with-special-characters-in-json
        # $jsonBody = [System.Text.Encoding]::UTF8.GetBytes($jsonBody)
    }
    Invoke-RestMethod $url -Method $method -Headers $headers -Body $jsonBody -UserAgent $userAgent -UseBasicParsing
}

function Invoke-PagedMethod($url, $convert = $true) {
    if ($url -notMatch '^http') {$url = $baseUrl + $url}
    $response = Invoke-WebRequest $url -Method GET -Headers $headers -UserAgent $userAgent -UseBasicParsing
    $links = @{}
    if ($response.Headers.Link) { # Some searches (eg List Users with Search) do not support pagination.
        foreach ($header in $response.Headers.Link.split(",")) {
            if ($header -match '<(.*)>; rel="(.*)"') {
                $links[$matches[2]] = $matches[1]
            }
        }
    }
    $objects = $null
    if ($convert) {
        $objects = ConvertFrom-Json $response.content
    }
    @{objects = $objects
      nextUrl = $links.next
      response = $response
      limitLimit = [int][string]$response.Headers.'X-Rate-Limit-Limit'
      limitRemaining = [int][string]$response.Headers.'X-Rate-Limit-Remaining' # how many calls are remaining
      limitReset = [int][string]$response.Headers.'X-Rate-Limit-Reset' # when limit will reset, see also [DateTimeOffset]::FromUnixTimeSeconds(limitReset)
    }
}

function Invoke-OktaWebRequest($method, $path, $body) {
    $url = $baseUrl + $path
    if ($body) {
        $jsonBody = $body | ConvertTo-Json -compress -depth 100
    }
    $response = Invoke-WebRequest $url -Method $method -Headers $headers -Body $jsonBody -UserAgent $userAgent -UseBasicParsing
    @{objects = ConvertFrom-Json $response.content
      response = $response
      limitLimit = [int][string]$response.Headers.'X-Rate-Limit-Limit'
      limitRemaining = [int][string]$response.Headers.'X-Rate-Limit-Remaining' # how many calls are remaining
      limitReset = [int][string]$response.Headers.'X-Rate-Limit-Reset' # when limit will reset, see also [DateTimeOffset]::FromUnixTimeSeconds(limitReset)
    }
}

function Get-Error($_) {
    $responseStream = $_.Exception.Response.GetResponseStream()
    $responseReader = New-Object System.IO.StreamReader($responseStream)
    $responseContent = $responseReader.ReadToEnd()
    ConvertFrom-Json $responseContent
}
#endregion