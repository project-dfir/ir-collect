#!/bin/sh
# In-guest hypervisor + guest-agent detector (Linux). Prints one line:
#   <hypervisor> [agent flags...]      e.g.  "vmware vmtoolsd"  |  "qemu-kvm qemu-ga qga-channel"
# An orchestrator runs this first to pick the right host-side deploy channel
# (vmware->govc, hyper-v->PSDirect/Copy-VMFile, virtualbox->VBoxManage, qemu-kvm->qm/virsh).
h=unknown
if command -v systemd-detect-virt >/dev/null 2>&1; then h="$(systemd-detect-virt 2>/dev/null)"; fi
if [ -z "$h" ] || [ "$h" = unknown ] || [ "$h" = none ]; then
  pn="$(cat /sys/class/dmi/id/product_name 2>/dev/null) $(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)"
  case "$pn" in
    *VMware*)               h=vmware;;
    *VirtualBox*|*innotek*) h=virtualbox;;
    *Microsoft*|*Hyper-V*)  h=hyper-v;;
    *QEMU*|*KVM*|*"Red Hat"*) h=qemu-kvm;;
  esac
fi
case "$h" in oracle) h=virtualbox;; microsoft) h=hyper-v;; qemu) h=qemu-kvm;; esac
a=""
pgrep -x vmtoolsd    >/dev/null 2>&1 && a="$a vmtoolsd"
pgrep -x qemu-ga     >/dev/null 2>&1 && a="$a qemu-ga"
pgrep -x VBoxService >/dev/null 2>&1 && a="$a VBoxService"
[ -e /dev/virtio-ports/org.qemu.guest_agent.0 ] && a="$a qga-channel"
lsmod 2>/dev/null | grep -q hv_utils && a="$a hyperv-lis"
echo "$h$a"
