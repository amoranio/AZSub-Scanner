<#
    Name: AzSub-Scanner
    Description: This script it to find non-compliant accounts which have greater access than they should (At the subscription level)
    Author: Ashley Moran
    Social: @amoranio
    Site: https://amoran.io

#>

$logo = @('
      __   ____  ____  _  _  ____       ____   ___   __   __ _  __ _  ____  ____ 
     / _\ (__  )/ ___)/ )( \(  _ \ ___ / ___) / __) / _\ (  ( \(  ( \(  __)(  _ \
    /    \ / _/ \___ \) \/ ( ) _ ((___)\___ \( (__ /    \/    //    / ) _)  )   /
    \_/\_/(____)(____/\____/(____/     (____/ \___)\_/\_/\_)__)\_)__)(____)(__\_)
    @amoranio
')

$logo
Write-Host ""

# Global Variables
$pass = $false
$logged = $false

$noncompliant = @()
$toreview = @()
$getra = @()
$query = "*.onmicrosoft.com" # This needs to be your filter or search query to remove accounts you don't care about. This example will target cloud accounts.

$outfile = "" # Set this for the script to output to a csv. For example: C:\temp\AzSub-Scanner.csv

# To have all subs searched uncomment below
# $subscriptions = @((Get-AzSubscription).Name)
$subscriptions = @("My-sub-name")

# Define which roles to hunt for
$roles = @("Owner", "contributor", "User Access Administrator")



# Pre-reqs
if (Get-InstalledModule AzureAD){ 
    Write-Host "[*] Module: AzureAD Installed" -ForegroundColor Green
    $pass = $true

} else { 
    Write-Host "[!] [*] Module: AzureAD Missing" -ForegroundColor Red
    $pass = $false
}

if (Get-InstalledModule AZ){ 
    Write-Host "[*] Module: AzureAD Installed" -ForegroundColor Green
    $pass = $true

} else { 
    Write-Host "[!] [*] Module: AZ Missing" -ForegroundColor Red
    $pass = $false
}

Write-Host ""

if ($pass){

    try {Get-AzSubscription | Out-Null} catch {Connect-AzAccount}
    try {Get-AzureADUser -Top 1 | Out-Null} catch {Connect-AzureAD}



## Start
foreach ($sub in $subscriptions){
    
    # Set Subscription
    Set-AzContext -SubscriptionName $sub | Out-Null
    Write-Host "[*] Checking Subscription: $sub" -ForegroundColor Yellow
    $scpe = "/subscriptions/" + (Get-AzSubscription -SubscriptionName $sub).Id

    # Build the list
    foreach ($rol in $roles){

        # Removes Resource Group
        $getra += (Get-AzRoleAssignment -RoleDefinitionName $rol -Scope $scpe | Where-Object {$_.Scope -notlike "*resource*"})

    }

    # Filter Types
    $rausers = @($getra | Where-Object {$_.ObjectType -eq "User"})
    $ragroups = @($getra | Where-Object {$_.ObjectType -eq "Group"})


    # Check users directly added
    foreach ($rausr in $rausers){

        if ($rausr.SignInName -notlike $query){

            $nc = New-Object PSObject

            $nc | Add-Member -MemberType NoteProperty -Name 'Subscription' -Value $sub
            $nc | Add-Member -MemberType NoteProperty -Name 'Name' -Value $rausr.SignInName
            $nc | Add-Member -MemberType NoteProperty -Name 'Group' -Value "SubscriptionLevel"
            $nc | Add-Member -MemberType NoteProperty -Name 'GroupID' -Value "NA"
            $nc | Add-Member -MemberType NoteProperty -Name 'Role' -Value $rausr.RoleDefinitionName

            $noncompliant += $nc

        }

    }

    # Check users granted via group/s

    foreach ($ragrp in $ragroups){

        try {$tmp = @(Get-AzureAdGroupMember -ObjectID $ragrp.ObjectID -WarningAction SilentlyContinue)} catch {

             Write-Host "$($ragrp.ObjectID) Failed..."}

                if ($tmp){

                    if (!$ragrp.DisplayName){$ragrp.DisplayName = "Blank"}

                    foreach ($t in $tmp){

                        if ($t.UserPrincipalName -notlike $query){

                            
                            $nc = New-Object PSObject

                            $nc | Add-Member -MemberType NoteProperty -Name 'Subscription' -Value $sub
                            $nc | Add-Member -MemberType NoteProperty -Name 'Name' -Value $t.UserPrincipalName
                            $nc | Add-Member -MemberType NoteProperty -Name 'Group' -Value $ragrp.DisplayName
                            $nc | Add-Member -MemberType NoteProperty -Name 'GroupID' -Value $ragrp.ObjectID
                            $nc | Add-Member -MemberType NoteProperty -Name 'Role' -Value $ragrp.RoleDefinitionName
            
                            if ($ragrp.DisplayName -eq "Blank"){
                                $toreview += $nc
                            } else {
                                $noncompliant += $nc
                            }
                        }
                        

                    }
                    

        }


    }



}

#Output
Write-Host ""
Write-Host "[*] List of users/groups to review" -ForegroundColor Yellow
$noncompliant | format-table    

Write-Host ""
Write-Host "[*] Showing users and groups that may be managed, or applied automatically" -ForegroundColor Yellow
$toreview | format-table

if ($outfile){
    $noncompliant | Export-CSV $outfile
}

} else {

    Write-Host "[!] Please Installed The Required Modules"

}
