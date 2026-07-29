# KNOWN-POSITIVE FIXTURE (Windows) - do not "fix" this file.
#
# Show-VolatileGate exactly as it stood before commit ca32bd9. It contains the two-state collapse
# that shipped, and whose failure mode is an UNREADABLE DISK rather than a merely misleading bundle:
#
#     $encRisk = $false
#     try { $encRisk = ([bool](Get-BitLockerVolume ...)) -and (-not $memOk) } catch {}
#     if ($encRisk) { ...the do-not-power-off banner... }
#
# A safe default, a probe whose failure is discarded, and a decision taken on the result. The
# safe-default detector MUST find exactly one hit here.
#
# The WHOLE function is vendored, not a fragment: the detector parses with the PowerShell AST, so
# the fixture has to be syntactically valid. An unbalanced excerpt fails to parse and the
# calibration reports a tooling error instead of a hit.
#
# Vendored rather than fetched with `git show <sha>~1` because CI checkouts are shallow and that
# would silently yield nothing - a calibration that cannot run is indistinguishable from one that
# passed.

function Show-VolatileGate {
    $n = 0
    try { $n = (Get-ChildItem -LiteralPath $Dirs.volatile,$Dirs.network -File -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count } catch {}
    $memOk = [bool]$script:MemOk
    # is the disk encrypted but we have no verified RAM (where the key lives)?
    $encRisk = $false
    try { $encRisk = ([bool](Get-BitLockerVolume 2>$null | Where-Object { $_.ProtectionStatus -eq 'On' })) -and (-not $memOk) } catch {}
    $memNote = if ($memOk) { "RAM: VERIFIED ({0:N1} GB)" -f ($script:MemBytes/1GB) } else { 'RAM: NOT verified - capture failed/absent (see 03_memory)' }
    Write-Host ""
    if ($encRisk) {
        Write-Host "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
        Write-Host "  !!  VOLATILE: AMBER - ENCRYPTED DISK + NO VERIFIED RAM   !!" -ForegroundColor Red
        Write-Host "  !!  The BitLocker key lives in RAM you did NOT capture.  !!" -ForegroundColor Red
        Write-Host "  !!  Get a recovery key (00_metadata\bitlocker_keys.txt)  !!" -ForegroundColor Red
        Write-Host "  !!  BEFORE powering off, or the disk image is unreadable.!!" -ForegroundColor Red
        Write-Host "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
        Write-Audit "VOLATILE AMBER | encrypted disk + no verified RAM | files=$n"
    } elseif ($n -ge 10 -and $memOk) {
        Write-Host "  ############################################################" -ForegroundColor Green
        Write-Host "  #   VOLATILE CAPTURE: GREEN  ($n artifacts, OK=$script:StepsOk FAIL=$script:StepsFail)" -ForegroundColor Green
        Write-Host "  #   $memNote"                                                 -ForegroundColor Green
        Write-Host "  #   Perishable data secured in order of volatility."          -ForegroundColor Green
        Write-Host "  #   Safe to proceed to the SLOW non-volatile phase."          -ForegroundColor Green
        Write-Host "  ############################################################" -ForegroundColor Green
        Write-Audit "VOLATILE GREEN | files=$n mem=$memOk OK=$script:StepsOk FAIL=$script:StepsFail"
    } else {
        Write-Host "  !!! VOLATILE: AMBER - $memNote ; $n artifacts. Review 99_logs\errors.log before proceeding." -ForegroundColor Yellow
        Write-Audit "VOLATILE AMBER | files=$n memOk=$memOk"
    }
    Write-Host ""
}
