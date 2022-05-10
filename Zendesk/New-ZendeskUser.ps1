function New-ZendeskUser
{
    param(
    [Parameter(Mandatory=$true)]$Name,
    [Parameter(Mandatory=$true)]$EmailAddress,
    [Parameter(Mandatory=$true)]$ZendeskUsername,
    [string]$PhoneNumber,
    [bool]$Verified
    )

    $apiToken = ":)"

    $authUsername = "$($ZendeskUsername.Trim())/token"

    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $authUsername,$apiToken)))
    $httpAuthorizationHeaders = @{Authorization=("Basic {0}" -f $base64AuthInfo)}
    
    $body = @{
    'user' = @{
            'email' = $EmailAddress
            'identities' = @(@{
                'type' = "email"
                'value' = $EmailAddress
            })
            'name' = $Name
            'verified' = $Verified
        }
    }

    if (![string]::IsNullOrEmpty($phonenumber))
    {
    $body.user.identities += @{
            'type' = "phone_number"
            'value' = $PhoneNumber
        }
    }

    $bodyJson = ConvertTo-Json -InputObject $body -depth 3


    $response = Invoke-RestMethod -Method POST -Uri "https://zendeskdomain.zendesk.com/api/v2/users" -Headers $httpAuthorizationHeaders -Body $bodyJson -verbose -ContentType "application/json"
}