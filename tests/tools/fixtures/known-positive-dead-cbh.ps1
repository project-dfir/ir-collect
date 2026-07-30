#requires -Version 3
# VENDORED KNOWN POSITIVE - this file's comment-based help is DEAD ON PURPOSE. Do not "fix" it.
#
# It reproduces the exact shape IR-Collect.ps1 shipped with: a #requires + comment preamble butted
# directly against the <# with no blank line between them. PowerShell then discards the entire help
# block and Get-Help returns an auto-generated syntax stub instead. The failure is silent - the
# script runs fine, the help text is right there in the file, and nobody sees it.
#
# tests/unit/Test-HelpOutput.ps1 calibrates against this file: if it can no longer detect that this
# help is dead, it refuses to certify the real collector as healthy.
<#
.SYNOPSIS
    CALIBRATIONMARKER - a synopsis that Get-Help will never show.

.DESCRIPTION
    If this text ever reaches Get-Help output, the breakage this fixture encodes has stopped
    reproducing on the current PowerShell version, and the guard that reads it must be revisited
    rather than trusted.

.NOTES  Exit codes: 0 clean | 40 fatal.
#>
[CmdletBinding()]
param(
    [string]$CaseId = 'IR',
    [switch]$RapidOnly
)
"body"
