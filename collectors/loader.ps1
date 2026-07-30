# In-guest LOADER (Windows). Use when the kit is delivered on a read-only ISO / share and you
# just want to launch it: it finds IR-Collect.ps1 next to itself, resolves a WRITABLE output
# target, and runs the collector in Lab mode. Extra args pass through (e.g. -Auto -CaseId EX1).
#
#   D:\kit\loader.ps1 -Auto -CaseId EXERCISE1
#
# Output precedence: a volume LABELED 'EVIDENCE'/'IR-EVIDENCE' (an attached evidence disk) ->
# $env:IR_OUT -> C:\ir_evidence. (Never writes onto the read-only delivery media.)
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$col  = Get-ChildItem $here -Recurse -Filter IR-Collect.ps1 -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $col) { $col = Get-ChildItem (Split-Path $here -Parent) -Recurse -Filter IR-Collect.ps1 -ErrorAction SilentlyContinue | Select-Object -First 1 }
if (-not $col) { Write-Error "IR-Collect.ps1 not found under $here"; exit 1 }

$evd = Get-Volume 2>$null | Where-Object { $_.FileSystemLabel -match 'IR.?EVID|EVIDENCE' -and $_.DriveLetter -and $_.DriveType -ne 'CD-ROM' } | Select-Object -First 1
$out = if ($evd)          { "$($evd.DriveLetter):\ir_evidence" }
       elseif ($env:IR_OUT) { $env:IR_OUT }
       else                { Join-Path $env:SystemDrive 'ir_evidence' }

Write-Host "Loader: $($col.FullName)  ->  $out  (Lab mode)" -ForegroundColor Cyan
& $col.FullName -Lab -Dest $out @args
exit $LASTEXITCODE
