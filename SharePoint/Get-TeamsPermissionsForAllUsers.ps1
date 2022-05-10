$TenantAdminCredentials = Get-Credential

Connect-MsolService -Credential $TenantAdminCredentials
Connect-MicrosoftTeams -Credential $TenantAdminCredentials
Connect-SPOService -Url https://<tenantname>-admin.sharepoint.com -Credential $TenantAdminCredentials
Connect-PnPOnline -Credential $TenantAdminCredentials -Url "https://<tenantname>.sharepoint.com"


$licensedUsers = Get-MsolUser | Where-Object { $_.isLicensed -eq "TRUE" } | Select-Object UserPrincipalName, DisplayName, Country, Department
$allTeams = Get-Team
$allSPOSites = Get-SPOSite
$allSPOSitesThatAreTeams = Get-PnPMicrosoft365Group -IncludeSiteUrl | where {$_.SiteUrl -gt 0 -and $_.HasTeam -eq $true}

$exportObject = @()
$exportObjectSPO = @()

for ($i = 0; $i -lt $allTeams.Count; $i++)
{
    $teamMembers = $allTeams[$i] | Get-TeamUser

    $allTeams[$i] | Add-Member -MemberType NoteProperty -Name "TeamMembers" -Value $teamMembers
}

for ($i = 0; $i -lt $allSPOSites.Count; $i++)
{
    Write-Output "Going through members of site: $($allSPOSites[$i].Url)"
    try 
    {
        if (!($allSPOSitesThatAreTeams.SiteUrl -match $allSPOSites[$i].Url))
        {
            $siteMembers = Get-SPOUser -Site $allSPOSites[$i].Url -ErrorAction Stop
            $allSPOSites[$i] | Add-Member -MemberType NoteProperty -Name "SiteMembers" -Value $siteMembers
        }
        else {
            Write-Output "Skipping $($allSPOSites[$i].Url) as it is a team."
        }
    }
    catch [Microsoft.SharePoint.Client.ServerUnauthorizedAccessException]
    {
        Write-Output "Skipping site $($allSPOSites[$i].Title) due to it most likely being a team or you don't have access to it."
    }
}

$allSPOSites = $allSPOSites | where {$_.PSObject.Properties.name -match "SiteMembers"}

foreach ($user in $licensedUsers)
{
    Write-Output "Processing user $($user.UserPrincipalName)"
    $userExportObject = [PSCustomObject]@{
        UPN = $user.UserPrincipalName
    }
    $userExportObjectSPO = [PSCustomObject]@{
        UPN = $user.UserPrincipalName
    }

    foreach ($team in $allTeams)
    {
        Write-Output "Processing team $($team.DisplayName)"
        if ($team.TeamMembers.User-contains $user.UserPrincipalName)
        {
            Write-Output "User $($user.UserPrincipalName) is member of team $($team.DisplayName)"
            $userExportObject | Add-Member -MemberType NoteProperty -Name $team.DisplayName -Value "X"
        }
        else {
            Write-Output "User $($user.UserPrincipalName) is NOT member of team $($team.DisplayName)"
            $userExportObject | Add-Member -MemberType NoteProperty -Name $team.DisplayName -Value ""
        }
    }

    foreach ($spoSite in $allSPOSites)
    {
        Write-Output "Processing site $($spoSite.Title)"
        if ($spoSite.SiteMembers.LoginName -contains $user.UserPrincipalName)
        {
            Write-Output "User $($user.UserPrincipalName) is member of site $($spoSite.DisplayName)"
            $userExportObjectSPO | Add-Member -MemberType NoteProperty -Name $spoSite.Title -Value "X"
        }
        else {
            Write-Output "User $($user.UserPrincipalName) is NOT member of site $($spoSite.DisplayName)"
            $userExportObjectSPO | Add-Member -MemberType NoteProperty -Name $spoSite.Title -Value ""
        }
    }

    Write-Output "Exporting user $($user.UserPrincipalName)"
    $exportObject += $userExportObject
    $exportObjectSPO += $userExportObjectSPO
}


Write-Output "Exporting excel..."
Export-Excel -InputObject $exportObject -Path "C:\Script\teamsreport_test.xlsx" -TableName Light1 -BoldTopRow -AutoSize -WorksheetName "Teams"
Export-Excel -InputObject $exportObjectSPO -Path "C:\Script\teamsreport_test.xlsx" -TableName Light2 -BoldTopRow -AutoSize -WorksheetName "SharePoint" -Append
