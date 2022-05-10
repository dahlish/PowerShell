#REQUIRES -Modules MSOnline

function Add-PhoneNumbersToZendesk
{
    param(
        [Parameter(Mandatory=$true)]$ZendeskUsername,
        [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$TenantAdminCredentials,
        [switch]$UseAuthenticatorPhoneInstead
    )

    $apiToken = ":)"

    $authUsername = "$($ZendeskUsername.Trim())/token"

    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $authUsername,$apiToken)))
    $httpAuthorizationHeaders = @{Authorization=("Basic {0}" -f $base64AuthInfo)}

    Import-Module MSOnline
    Connect-MsolService -Credential $TenantAdminCredentials

    if (!$UseAuthenticatorPhoneInstead)
    {
        $users = Get-MsolUser | where {$_.PhoneNumber -ne $null -or $_.MobilePhone -ne $null -and $_.UserPrincipalName.Contains("#EXT#") -eq $false}
    }
    else
    {
            $users = Get-MsolUser -All | where{
             $_.StrongAuthenticationRequirements.State -ne ""
        } | Select DisplayName,UserprincipalName,@{Name="PhoneNumber";Expression={$_.StrongAuthenticationUserDetails.PhoneNumber}} | where {$_.PhoneNumber -ne $null -and $_.UserPrincipalName.Contains("#EXT#") -eq $false}
    }

    foreach ($user in $users)
    {
        $httpResponse = Invoke-RestMethod -Method GET -Uri "https://zendeskdomain.zendesk.com/api/v2/search.json?query=type:user $($user.UserPrincipalName)" -Headers $httpAuthorizationHeaders


        $zendeskUserId = ($httpResponse.results | where {$_.email -eq $user.UserPrincipalName}).Id

        if (![string]::IsNullOrEmpty($zendeskUserId))
        {

            $zendeskCurrentPhoneNumber = ($httpResponse.results | where {$_.email -eq $user.UserPrincipalName}).phone

            Write-Output "ZENDESK USER ID: $($zendeskUserId)"

            if ([string]::IsNullOrEmpty($zendeskCurrentPhoneNumber))
            {

                if (![string]::IsNullOrEmpty($user.PhoneNumber))
                {
                    $body = @{
                        identity = @{
                            type = "phone_number"
                            value = $user.PhoneNumber
                        }
                    }  

                    $bodyJson = ConvertTo-Json -InputObject $body

                    Write-Output "Adding phone number $($user.PhoneNumber) to user $($user.UserPrincipalName)"
                    $response = Invoke-RestMethod -Method POST -Uri "https://zendeskdomain.zendesk.com/api/v2/users/$($zendeskUserId)/identities.json" -Headers $httpAuthorizationHeaders -Body $bodyJson -verbose -ContentType "application/json"
                }
                elseif (![string]::IsNullOrEmpty($user.MobilePhone))
                {
                    $body = @{
                        identity = @{
                            type = "phone_number"
                            value = $user.PhoneNumber
                        }
                    }  

                    $bodyJson = ConvertTo-Json -InputObject $body

                    Write-Output "Adding phone number $($user.MobilePhone) to user $($user.UserPrincipalName)"
                    $response = Invoke-RestMethod -Method POST -Uri "https://zendeskdomain.zendesk.com/api/v2/users/$($zendeskUserId)/identities.json" -Headers $httpAuthorizationHeaders -Body $bodyJson -verbose -ContentType "application/json"
                }
                else
                {
                    Write-Error "User has no phone numbers. Moving to next user."
                }
            }
            else {
                Write-Output "Skipping $($user.UserPrincipalName) as they already have a phone number added."
            }
        }
        else {
            Import-Module .\New-ZendeskUser.ps1

            Write-Warning "Creating $($user.UserPrincipalName) as they don't have an account in zendesk."

            if (![string]::IsNullOrEmpty($user.PhoneNumber))
            {
                Write-Output "Also Adding phone number $($user.PhoneNumber) to user $($user.UserPrincipalName)"
                New-ZendeskUser -Name $user.DisplayName -EmailAddress $user.UserPrincipalName -ZendeskUsername $ZendeskUsername -PhoneNumber $user.PhoneNumber -Verified $true
            }
            elseif (![string]::IsNullOrEmpty($user.MobilePhone))
            {
                Write-Output "Also Adding phone number $($user.MobilePhone) to user $($user.UserPrincipalName)"
                New-ZendeskUser -Name $user.DisplayName -EmailAddress $user.UserPrincipalName -ZendeskUsername $ZendeskUsername -PhoneNumber $user.MobilePhone -Verified $true
            }
            else {
                Write-Warning "Can't create user for an unknown reason."
            }
        }
    }
}
