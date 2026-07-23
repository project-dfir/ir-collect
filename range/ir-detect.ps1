# In-guest hypervisor + guest-tools detector (Windows). Prints one line:
#   <hypervisor> [tools...]    e.g.  "vmware VMTools"  |  "hyper-v vmicheartbeat"
# An orchestrator runs this first to pick the right host-side deploy channel.
$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$sig  = "$($cs.Manufacturer) $($cs.Model) $($bios.SMBIOSBIOSVersion)"
$h = switch -Regex ($sig) {
    'VMware'                        { 'vmware'; break }
    'VirtualBox|innotek'            { 'virtualbox'; break }
    'QEMU|KVM|Bochs|SeaBIOS|Red Hat'{ 'qemu-kvm'; break }
    'Microsoft.*Virtual|Virtual Machine' { 'hyper-v'; break }
    default                         { 'unknown' }
}
$t = @()
foreach ($s in 'VMTools','VBoxService','vmicheartbeat','vmicvss','QEMU-GA','GCEAgent','AmazonSSMAgent') {
    if (Get-Service $s -ErrorAction SilentlyContinue) { $t += $s }
}
"$h $($t -join ' ')".Trim()
