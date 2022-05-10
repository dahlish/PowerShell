function Get-Settings
{
    if ((Test-Path "C:\Script\Trapets\sanctionsettings.json"))
    {
        $settings = Get-Content -Path "C:\Script\Trapets\sanctionsettings.json" -Raw | ConvertFrom-Json
        
        if ($null -eq $settings.Authentication.Token -or (Get-Date).ToUniversalTime() -gt $settings.Authentication.ExpiresAt)
        {
            $apiPassword = ConvertTo-SecureString $settings.ApiPassword

            $requestBody = @{
                grant_type = "password"
                username = $settings.ApiUsername
                password = (ConvertFrom-SecureString -SecureString $ApiPassword -AsPlainText)
            }

            $headers = @{
                'Content-Type' = 'application/x-www-form-urlencoded'
                'Cache-Control' = 'no-cache'
                }
        
            $response = Invoke-WebRequest -Method POST -Uri "https://kyc.instantwatch.net/token" -Body $requestBody -Headers $headers

            $responseContent = ConvertFrom-Json $response.Content

            if ($null -ne $responseContent.access_token)
            {
                $settings.Authentication.Token = $responseContent.access_token
                $settings.Authentication.ExpiresAt = (Get-Date).AddSeconds(($responseContent.expires_in) - 180).ToUniversalTime() #3 minute earlier so the token doesn't expire in the middle of a daily run.

                Set-Content -Path "C:\Script\Trapets\sanctionsettings.json" -Value (ConvertTo-Json $settings) -Force
                return $settings
            }
            else {
                Write-Output "($(Get-Date)): No token was obtained." | Out-File "C:\Script\Trapets\sanctionslog.txt" -Force -Append
                return $null
            }
        }
        else {
            return $settings
        }
    }
    else {
        New-Item -ItemType File -Path "C:\Script\Trapets\sanctionsettings.json" -Force
        $defaultSettings = [PSCustomObject]@{
            Authentication = [PSCustomObject]@{
                ExpiresAt = $null
                Token = $null
            }
            SFTPAuthentication = [PSCustomObject]@{
                SFTPUsername = $null
                SFTPPassword = $null
            }
            O365Authentication = [PSCustomObject]@{
                O365Username = $null
                O365Password = $null
            }
            KeywordHitratingFilter = 0.5
            ServiceScope = "SANCTION"
            ApiUsername = $null
            ApiPassword = $null
            ReportTo = "AML-AM@domain.se"
            ReportName = $null
        }

        Set-Content -Path "C:\Script\Trapets\sanctionsettings.json" -Value (ConvertTo-Json $defaultSettings) -Force
        Write-Output "($(Get-Date)): No settings file was seen. New file has been generated. Please enter settings and start the script again." | Out-File "C:\Script\Trapets\sanctionslog.txt" -Force -Append
        return $null
    }
}


function New-TrapetsScreening {

    $settings = Get-Settings
    $exportObject = @()

    if ($settings)
    {
        $SFTPPassword = ConvertTo-SecureString $settings.SFTPAuthentication.SFTPPassword
        $SFTPCredentials = New-Object System.Management.Automation.PSCredential ($settings.SFTPAuthentication.SFTPUsername, $SFTPPassword)
        $SFTPHostname = $settings.SFTPAuthentication.Hostname

        $smtpPassword = ConvertTo-SecureString $settings.O365Authentication.O365Password
        $smtpCredentials = New-Object System.Management.Automation.PSCredential ($settings.O365Authentication.O365Username, $smtpPassword)

        $logDate = (Get-Date).ToShortDateString()

        Import-Module Posh-SSH -UseWindowsPowershell

        try
        {
            Write-Output "Connecting to Client SFTP..."
            $sftpSession = New-SFTPSession -ComputerName $SFTPHostname -Credential $SFTPCredentials -Force -Port 2022
            Set-SFTPLocation -SessionId $sftpSession.SessionId -Path "/ScreeningSFTP"
            Write-Output "Connected."
        }
        catch
        {
            Write-Output "Unable to connect to Client SFTP..." | Out-File -FilePath "C:\Script\Trapets\Logs\$($logDate)_SFTP_log.txt"
            break
        }


        $sftpFiles = Get-SFTPChildItem -SessionId $sftpSession.SessionId

        if ($sftpFiles -ne $null)
        {

            $latestFile = ($sftpFiles | Sort-Object -Property LastWriteTime -Descending)[0]
            $splitFile = $latestFile.FullName.Split("/")
            $splitFileName = $splitFile[$splitFile.Length - 1]

            try
            {
                Write-Output "Downloading $($latestFile.FullName)..."
                Get-SFTPFile $sftpSession.SessionId -RemoteFile $latestFile.FullName -LocalPath "C:\Script\Trapets" -ErrorAction Stop
                Write-Output "Download successful."
            }
            catch
            {
                Write-Output "Unable to download latest file or there is none in the SFTP folder." | Out-File -FilePath "C:\Script\Trapets\Logs\$($logDate)_SFTP_log.txt"
                break
            }
        }

        #Cant try catch due to it always throwing error, even though it deletes?
        Write-Output "Deleting file $($latestFile.FullName)..."
        Remove-SFTPItem -SessionId $sftpSession.SessionId -Path $latestFile.FullName -Force -Verbose -ErrorAction SilentlyContinue
        Remove-SFTPSession -SessionId $sftpSession.SessionId
        Write-Output "Deleted file."

        $csvLocation = "C:\Script\Trapets\$($splitFileName)"
        if (!(Test-Path $csvLocation))
        {
            Write-Error "Csv file not found, please check the correct path."
            break;
        }
        $csvImport = Import-Csv $csvLocation

        

        $requestBody = [PSCustomObject]@{
            KeyWordHitratingFilter = $settings.KeywordHitratingFilter
            ServiceScope = $settings.ServiceScope
            UpdatedAfter = $null
            KeyWordType = "Regular"
            SubQueries = @()
        }
        $currentSubqueryId = 0

        foreach($object in $csvImport)
        {
            $requestBody.SubQueries += [PSCustomObject]@{
                Id = $currentSubqueryId
                Name = $object."Security Issuer Name"
            }

            $currentSubqueryId++
        }

        $headers = @{
            Authorization = "Bearer $($settings.Authentication.Token)"
        }

        $response = Invoke-WebRequest -Headers $headers -Body (ConvertTo-Json $requestBody) -Method POST -Uri "https://kyc.instantwatch.net/api/listlookup/do-query" -ContentType "application/json"
        $responseContent = ConvertFrom-Json $response.Content

        $csvImport | Add-Member -NotePropertyName IsSanctioned -NotePropertyValue "NO"
        $csvImport | Add-Member -NotePropertyName SanctionLists -NotePropertyValue "N/A"
        $csvImport | Add-Member -NotePropertyName SanctionAdded -NotePropertyValue $null
        $csvImport | Add-Member -NotePropertyName MatchedNames -NotePropertyValue $null
        
        $entities = $responseContent.ResponseItems.Entities

        foreach($responseItem in $responseContent.ResponseItems)
        {
            $subQuery = $requestBody.SubQueries | Where-Object {$_.Id -eq $responseItem.SubQueryId}

            foreach($match in $responseItem.Entities)
            {
                $exportedIndividual = [PSCustomObject]@{
                SubQueryId = $responseItem.SubQueryId
                SubQueryName = $subQuery.Name
                Name = $match.Name
                Countries = $match.Countries.CountryCode
                Source = $match.SourceName
                List = $match.ListType
                BirthDate = $match.BirthDate
                AddedAt = $match.Added
                }
                $exportObject += $exportedIndividual
            }
        }

        for ($i = 0; $i -lt $csvImport.Count; $i++)
        {
            $csvImport[$i].Position = $csvImport[$i].Position.Replace(".", ",")
            $csvImport[$i]."Settled Position" = $csvImport[$i]."Settled Position".Replace(".", ",")
            $csvImport[$i]."Market Value Fund" = $csvImport[$i]."Market Value Fund".Replace(".", ",")

            if ($exportObject.SubQueryId.Count -gt 0)
            {
                if ($exportObject.SubQueryName.Contains($csvImport[$i]."Security Issuer Name"))
                {   
                    $csvImport[$i].IsSanctioned = "YES"
                    $csvImport[$i].SanctionLists = ($exportObject | Where-Object {$_.SubQueryName -eq $csvImport[$i]."Security Issuer Name" -and $_.SubQueryId -eq $i}).Source -Join ", "
                    $csvImport[$i].MatchedNames = ($exportObject | Where-Object {$_.SubQueryName -eq $csvImport[$i]."Security Issuer Name" -and $_.SubQueryId -eq $i}).Name -Join ", "
                    $csvImport[$i].SanctionAdded = ($exportObject | Where-Object {$_.SubQueryName -eq $csvImport[$i]."Security Issuer Name" -and $_.SubQueryId -eq $i}).AddedAt -Join ", "
                }
            }
        }

        $filePathAndName = "C:\Script\Trapets\SanctionsList_$(Get-Date -Format "yyyy_MM_dd_HHmm").xlsx"
        #$newFilePathAndName = "C:\Script\Trapets\SanctionsList_$(Get-Date -Format "yyyy_MM_dd_HHmm")_ordered.xlsx"
        $csvImport | Export-Excel -Path $filePathAndName -TableName Light1 -BoldTopRow -AutoSize
        $importedExcel = Import-Excel -Path $filePathAndName
        Remove-Item $filePathAndName
        $importedExcel | select IsSanctioned, "Fund Name", "Security Name", Position, "Settled Position", "Market Value Fund", "Security Currency", "Security Issuer Name", MatchedNames, SanctionLists, SanctionAdded, "Security Issuer Description", "Underlying Issuer Name", "Underlying Issuer Description" | Sort-Object -Property IsSanctioned -Descending | Export-Excel -Path $filePathAndName  -TableName Light1 -BoldTopRow -AutoSize
        Write-Output "($(Get-Date)): $($entities.Count) matches found. Csv has been generated." | Out-File "C:\Script\Trapets\sanctionslog.txt" -Force -Append

        if ($csvImport.IsSanctioned.Contains("YES"))
        {
            Send-MailMessage -From "Trapets Screening <screening@domain.se>" -To "$($settings.ReportTo)", "<email>" -Subject "Trapets Screening - $(Get-Date -Format("yyyy-MM-dd"))" -Body "Hi $($settings.ReportName), <br><br>Attached you will find the daily screening report. <b>This report contains matches.</b><br><br>This report has been saved to: Domain AM - General\AML\Portfolio Sanctions Screening" -BodyAsHtml -Attachments $filePathAndName -SmtpServer "smtp.office365.com" -Credential $smtpCredentials -UseSsL
        }
        else {
            Send-MailMessage -From "Trapets Screening <screening@domain.se>" -To "$($settings.ReportTo)", "<email>" -Subject "Trapets Screening - $(Get-Date -Format("yyyy-MM-dd"))" -Body "Hi $($settings.ReportName), <br><br>Attached you will find the daily screening report. This report contains no matches.<br><br>This report has been saved to: Domain AM - General\AML\Portfolio Sanctions Screening" -BodyAsHtml -Attachments $filePathAndName -SmtpServer "smtp.office365.com" -Credential $smtpCredentials -UseSsL
        }
    }

    
}
