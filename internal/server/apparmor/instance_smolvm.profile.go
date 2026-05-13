package apparmor

import (
	"text/template"
)

// smolvmProfileTpl is the per-instance AppArmor profile loaded around
// smolvm-server. Enforce mode. The allow-list was derived from a full
// lifecycle (start → exec → stop → start) run with the profile in
// complain mode, plus mke2fs (forks /usr/sbin/mke2fs to pre-format the
// storage + overlay disks on the host; without it, in-guest mkfs adds
// ~15s to boot).
var smolvmProfileTpl = template.Must(template.New("smolvmProfile").Parse(`#include <tunables/global>
profile "{{ .name }}" flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # Binary + libraries. mr = read + map. ix = inherit-exec for the smolvm
  # child it spawns (the libkrun hypervisor).
  /usr/local/bin/smolvm rmix,
  /usr/local/bin/smolvm-bin rmix,
  /tmp/smolvm-target/release/smolvm rmix,
  /usr/local/lib/** mr,
  /usr/local/lib64/** mr,
  /usr/lib/** mr,
  /lib/** mr,

  # mkfs.ext4 for pre-formatting storage + overlay disks on the host
  # before the guest boots. Without this, the guest has to mkfs at boot
  # which adds 15-20s. mke2fs is the real binary; mkfs.ext4 is a symlink.
  /{usr/,}sbin/mke2fs rmix,
  /{usr/,}sbin/mkfs.ext4 rmix,
  /etc/mke2fs.conf r,
  @{PROC}/swaps r,

  # Per-instance runtime state: socket, pidfile, cache, data, log.
  /run/incus/*/smolvm-server.sock rw,
  /run/incus/*/smolvm-server.pid rw,
  /run/incus/*/cache/** rwk,
  /run/incus/*/data/** rwk,
  /var/log/incus/*/** rw,

  # Per-instance storage volume. Holds the smolvm VM image, smolvm-server's
  # persistent state (smol/ subdir bind-mounted into the per-instance run
  # path) and the agent rootfs (rootfs/ subdir, cloned from a per-pool
  # image volume at create time). smolvm uses VolumeTypeVM so the path
  # lives under virtual-machines/. Write access on rootfs/ is what lets
  # the guest agent post .smolvm-ready through virtio-fs (smolvm-server's
  # fs-worker proxies the mknod on the host); without it, the host falls
  # back to a 5s socket-probe grace period.
  /var/lib/incus/storage-pools/*/virtual-machines/** rwk,
  /var/lib/incus/devices/*/** rwk,

  # KVM + standard /dev nodes.
  /dev/kvm rw,
  /dev/null rw,
  /dev/zero r,
  /dev/random r,
  /dev/urandom r,
  /dev/tty rw,
  /dev/pts/* rw,

  # /proc and /sys reads smolvm-server typically does (cpu count,
  # cgroup limits, kvm caps, etc.).
  @{PROC}/sys/kernel/random/uuid r,
  @{PROC}/sys/kernel/pid_max r,
  @{PROC}/sys/vm/overcommit_memory r,
  @{PROC}/@{pid}/** r,
  @{PROC}/@{pid}/task/@{tid}/** r,
  /sys/devices/system/cpu/** r,
  /sys/kernel/mm/transparent_hugepage/enabled r,

  # AF_UNIX for the listening socket; AF_INET/AF_INET6 for libkrun's TSI
  # outbound proxy; AF_VSOCK for guest/host RPC.
  network unix,
  network inet stream,
  network inet6 stream,
  network inet dgram,
  network inet6 dgram,
  network vsock,
  network netlink raw,

  # Signal: receive from incusd (parent in init pidns), send to the libkrun
  # child (smolvm _boot-vm).
  signal (send,receive),

  # Explicitly deny everything Tier 1 already strips. These rules make
  # the intent visible in the profile and act as a backstop if any future
  # change ever loosens Tier 1.
  deny capability,
  deny mount,
  deny umount,
  deny pivot_root,
  deny ptrace,
  deny dbus,

{{- if .raw }}

  ### Configuration: raw.apparmor
{{ .raw }}
{{- end }}
}
`))
