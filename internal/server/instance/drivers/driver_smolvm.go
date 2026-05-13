package drivers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/sys/unix"

	smolvmsdk "github.com/smol-machines/smolvm-sdk/smolvm-go"

	internalInstance "github.com/lxc/incus/v7/internal/instance"
	"github.com/lxc/incus/v7/internal/linux"
	"github.com/lxc/incus/v7/internal/netutils"
	"github.com/lxc/incus/v7/internal/server/apparmor"
	"github.com/lxc/incus/v7/internal/server/cgroup"
	"github.com/lxc/incus/v7/internal/server/db"
	dbCluster "github.com/lxc/incus/v7/internal/server/db/cluster"
	"github.com/lxc/incus/v7/internal/server/device"
	deviceConfig "github.com/lxc/incus/v7/internal/server/device/config"
	"github.com/lxc/incus/v7/internal/server/instance"
	"github.com/lxc/incus/v7/internal/server/instance/instancetype"
	"github.com/lxc/incus/v7/internal/server/instance/operationlock"
	"github.com/lxc/incus/v7/internal/server/lifecycle"
	"github.com/lxc/incus/v7/internal/server/metrics"
	"github.com/lxc/incus/v7/internal/server/network"
	"github.com/lxc/incus/v7/internal/server/operations"
	"github.com/lxc/incus/v7/internal/server/project"
	"github.com/lxc/incus/v7/internal/server/state"
	storagePools "github.com/lxc/incus/v7/internal/server/storage"
	storageDrivers "github.com/lxc/incus/v7/internal/server/storage/drivers"
	internalUtil "github.com/lxc/incus/v7/internal/util"
	"github.com/lxc/incus/v7/shared/api"
	"github.com/lxc/incus/v7/shared/ioprogress"
	"github.com/lxc/incus/v7/shared/logger"
	"github.com/lxc/incus/v7/shared/osarch"
	"github.com/lxc/incus/v7/shared/revert"
	"github.com/lxc/incus/v7/shared/units"
	"github.com/lxc/incus/v7/shared/util"
)

const smolvmDefaultImage = "alpine:latest"

var errSmolVMNotSupported = errors.New("Operation not supported by smolvm driver")

// smolvm is the smolvm-backed instance driver.
type smolvm struct {
	common

	architectureName string
}

// smolvmInstantiate creates a smolvm struct without expanding config.
func smolvmInstantiate(s *state.State, args db.InstanceArgs, expandedDevices deviceConfig.Devices, p api.Project) *smolvm {
	d := &smolvm{
		common: common{
			state: s,

			architecture: args.Architecture,
			creationDate: args.CreationDate,
			dbType:       args.Type,
			description:  args.Description,
			ephemeral:    args.Ephemeral,
			expiryDate:   args.ExpiryDate,
			id:           args.ID,
			lastUsedDate: args.LastUsedDate,
			localConfig:  args.Config,
			localDevices: args.Devices,
			logger:       logger.AddContext(logger.Ctx{"instanceType": args.Type, "instance": args.Name, "project": args.Project}),
			name:         args.Name,
			node:         args.Node,
			profiles:     args.Profiles,
			project:      p,
			isSnapshot:   args.Snapshot,
			stateful:     args.Stateful,
		},
	}

	archName, err := osarch.ArchitectureName(d.architecture)
	if err == nil {
		d.architectureName = archName
	}

	if d.expiryDate.IsZero() {
		d.expiryDate = time.Time{}
	}

	if d.creationDate.IsZero() {
		d.creationDate = time.Time{}
	}

	if d.lastUsedDate.IsZero() {
		d.lastUsedDate = time.Time{}
	}

	if expandedDevices != nil {
		d.expandedDevices = expandedDevices
	}

	return d
}

// smolvmLoad creates a smolvm instance from supplied InstanceArgs.
func smolvmLoad(s *state.State, args db.InstanceArgs, p api.Project) (instance.Instance, error) {
	d := smolvmInstantiate(s, args, nil, p)

	err := d.expandConfig()
	if err != nil {
		return nil, err
	}

	return d, nil
}

// smolvmCreate creates a new smolvm instance and the associated storage volume metadata.
func smolvmCreate(s *state.State, args db.InstanceArgs, p api.Project, partialDeviceValidation bool, op *operations.Operation) (instance.Instance, revert.Hook, error) {
	reverter := revert.New()
	defer reverter.Fail()

	d := smolvmInstantiate(s, args, nil, p)
	d.op = op

	if args.Snapshot {
		d.logger.Info("Creating instance snapshot", logger.Ctx{"ephemeral": d.ephemeral})
	} else {
		d.logger.Info("Creating instance", logger.Ctx{"ephemeral": d.ephemeral})
	}

	err := d.init()
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to expand config: %w", err)
	}

	if !args.Snapshot {
		err = instance.ValidConfig(s.OS, d.expandedConfig, true, instancetype.Any)
		if err != nil {
			return nil, nil, fmt.Errorf("Invalid config: %w", err)
		}

		err = instance.ValidDevices(s, d.project, d.Type(), d.localDevices, d.expandedDevices)
		if err != nil {
			return nil, nil, fmt.Errorf("Invalid devices: %w", err)
		}
	}

	// Set up the storage pool to track instance metadata. The smolvm backend
	// manages its own disk content, so the volume on the pool is essentially
	// just a metadata directory.
	_, rootDiskDevice, err := d.getRootDiskDevice()
	if err != nil {
		return nil, nil, fmt.Errorf("Failed getting root disk: %w", err)
	}

	if rootDiskDevice["pool"] == "" {
		return nil, nil, errors.New("The instance's root device is missing the pool property")
	}

	d.storagePool, err = storagePools.LoadByName(d.state, rootDiskDevice["pool"])
	if err != nil {
		return nil, nil, fmt.Errorf("Failed loading storage pool: %w", err)
	}

	if !d.IsSnapshot() {
		cleanup, err := d.devicesAdd(d, false, partialDeviceValidation)
		if err != nil {
			return nil, nil, err
		}

		reverter.Add(cleanup)
	}

	if d.isSnapshot {
		d.logger.Info("Created instance snapshot", logger.Ctx{"ephemeral": d.ephemeral})
		d.state.Events.SendLifecycle(d.project.Name, lifecycle.InstanceSnapshotCreated.Event(d, nil))
	} else {
		d.logger.Info("Created instance", logger.Ctx{"ephemeral": d.ephemeral})

		err = d.state.Authorizer.AddInstance(d.state.ShutdownCtx, d.project.Name, d.Name())
		if err != nil {
			logger.Error("Failed to add instance to authorizer", logger.Ctx{"name": d.Name(), "project": d.project.Name, "error": err})
		}

		reverter.Add(func() { _ = d.state.Authorizer.DeleteInstance(d.state.ShutdownCtx, d.project.Name, d.Name()) })

		d.state.Events.SendLifecycle(d.project.Name, lifecycle.InstanceCreated.Event(d, map[string]any{
			"type":         api.InstanceTypeSmolVM,
			"storage-pool": d.storagePool.Name(),
			"location":     d.Location(),
		}))
	}

	cleanup := reverter.Clone().Fail
	reverter.Success()

	return d, cleanup, nil
}

// init prepares the instance struct after construction.
func (d *smolvm) init() error {
	return d.expandConfig()
}

// machineName returns the name used for the machine on the smolvm server.
// It combines project and instance name to ensure uniqueness across projects.
func (d *smolvm) machineName() string {
	return strings.ReplaceAll(project.Instance(d.project.Name, d.name), "_", "-")
}

// smolvmClient returns a smolvm SDK client targeting the per-instance smolvm
// server. The driver spawns one smolvm-server per Incus instance inside a
// per-instance netns and listens on a unix socket under the instance's
// runtime path. The smolvm.server config key remains as an escape hatch for
// pointing at an externally-managed server (e.g. for development).
func (d *smolvm) smolvmClient() *smolvmsdk.Client {
	if override := d.expandedConfig["smolvm.server"]; override != "" {
		return smolvmsdk.NewClient(override)
	}

	return smolvmsdk.NewClient("unix://" + d.smolvmServerSocketPath())
}

// buildCreateRequest converts the instance's expanded config and devices into a smolvm CreateMachineRequest.
func (d *smolvm) buildCreateRequest() smolvmsdk.CreateMachineRequest {
	req := smolvmsdk.CreateMachineRequest{
		Name: d.machineName(),
	}

	// Image: prefer explicit smolvm.image config, fall back to default.
	if image := d.expandedConfig["smolvm.image"]; image != "" {
		req.Image = image
	} else {
		req.Image = smolvmDefaultImage
	}

	// CPU count from limits.cpu (single integer form).
	if cpuStr := d.expandedConfig["limits.cpu"]; cpuStr != "" {
		if cpu, err := strconv.Atoi(cpuStr); err == nil && cpu > 0 {
			req.CPUs = cpu
		}
	}

	// Memory from limits.memory ("1024MiB", "2GiB", etc.).
	if memStr := d.expandedConfig["limits.memory"]; memStr != "" {
		if memBytes, err := units.ParseByteSizeString(memStr); err == nil && memBytes > 0 {
			memMiB := int(memBytes / (1024 * 1024))
			if memMiB > 0 {
				req.MemoryMB = memMiB
			}
		}
	}

	// Root disk size for storage allocation.
	_, rootDisk, err := d.getRootDiskDevice()
	if err == nil {
		if sizeStr := rootDisk["size"]; sizeStr != "" {
			if sizeBytes, err := units.ParseByteSizeString(sizeStr); err == nil && sizeBytes > 0 {
				sizeGB := sizeBytes / (1024 * 1024 * 1024)
				if sizeGB > 0 {
					req.StorageGB = &sizeGB
				}
			}
		}
	}

	// Translate network/proxy devices into smolvm network configuration.
	d.applyNetworkConfig(&req)

	return req
}

// applyNetworkConfig walks the instance's expanded devices and configures
// smolvm's networking knobs:
//   - any "nic" device enables outbound TCP/UDP networking
//   - any "proxy" device with TCP listen/connect translates into a host→guest port forward
//   - allowed CIDRs are taken from the smolvm.allowed_cidrs config key
func (d *smolvm) applyNetworkConfig(req *smolvmsdk.CreateMachineRequest) {
	for _, dev := range d.expandedDevices {
		switch dev["type"] {
		case "nic":
			req.Network = true
		case "proxy":
			ps, ok := parseProxyDevice(dev)
			if ok {
				req.Ports = append(req.Ports, ps)
				req.Network = true
			}
		}
	}

	if cidrs := d.expandedConfig["smolvm.allowed_cidrs"]; cidrs != "" {
		for _, c := range strings.Split(cidrs, ",") {
			c = strings.TrimSpace(c)
			if c != "" {
				req.AllowedCidrs = append(req.AllowedCidrs, c)
			}
		}
	}
}

// parseProxyDevice converts an Incus proxy device's listen/connect addresses
// into a smolvm PortSpec. Returns false if the device cannot be mapped (e.g.
// non-TCP, malformed addresses, or non-numeric ports).
func parseProxyDevice(dev deviceConfig.Device) (smolvmsdk.PortSpec, bool) {
	listen := dev["listen"]
	connect := dev["connect"]
	if listen == "" || connect == "" {
		return smolvmsdk.PortSpec{}, false
	}

	listenProto, _, listenPort, ok := splitProxyAddress(listen)
	if !ok || listenProto != "tcp" {
		return smolvmsdk.PortSpec{}, false
	}

	_, _, connectPort, ok := splitProxyAddress(connect)
	if !ok {
		return smolvmsdk.PortSpec{}, false
	}

	return smolvmsdk.PortSpec{Host: listenPort, Guest: connectPort}, true
}

// splitProxyAddress parses an Incus proxy address of the form "tcp:host:port"
// into its protocol, host, and port components.
func splitProxyAddress(addr string) (proto string, host string, port int, ok bool) {
	parts := strings.SplitN(addr, ":", 3)
	if len(parts) < 3 {
		return "", "", 0, false
	}

	port, err := strconv.Atoi(parts[2])
	if err != nil {
		return "", "", 0, false
	}

	return parts[0], parts[1], port, true
}

//
// SECTION: storage / bind-mount
//

// smolvmDataBase resolves the smolvm server's cache base directory. The
// driver pins XDG_CACHE_HOME for the per-instance smolvm-server to
// d.smolvmServerCacheDir() so the bind mount target is deterministic. The
// smolvm.data_base config key remains as an explicit override (paired with
// the smolvm.server escape hatch for pointing at an externally-managed
// server).
func (d *smolvm) smolvmDataBase() (string, error) {
	if base := d.expandedConfig["smolvm.data_base"]; base != "" {
		return base, nil
	}

	return d.smolvmServerCacheDir(), nil
}

// smolvmMachinePath returns the absolute on-disk directory the smolvm server
// will use for this instance's machine data. This is the path we bind-mount
// the Incus storage volume on top of.
//
// Mirrors smolvm-server's own derivation: sha256(name) truncated to the first
// 16 hex characters, joined under <base>/smolvm/vms/. Must match byte-for-byte
// or the bind mount lands at the wrong target.
func (d *smolvm) smolvmMachinePath() (string, error) {
	base, err := d.smolvmDataBase()
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256([]byte(d.machineName()))
	return filepath.Join(base, "smolvm", "vms", hex.EncodeToString(sum[:8])), nil
}

// smolvmEnsureMounted mounts the Incus storage volume for this instance and
// bind-mounts the `smol/` subdirectory of that volume on top of the smolvm
// server's per-machine data path so any disk files smolvm writes
// (storage.raw, overlay.raw) land on the Incus pool. The subdirectory pattern
// mirrors the container layout: the volume root keeps Incus's mode-0100
// invariant (see drivers/volume.go EnsureMountPath) while user-data lives in
// a subdir that gets chowned/chmodded for the smolvm-server's dropped uid.
// Idempotent: safe to call when already mounted.
func (d *smolvm) smolvmEnsureMounted() error {
	pool, err := d.getStoragePool()
	if err != nil {
		return fmt.Errorf("Failed loading storage pool: %w", err)
	}

	_, err = pool.MountInstance(d, nil)
	if err != nil {
		return fmt.Errorf("Failed mounting instance volume: %w", err)
	}

	dst, err := d.smolvmMachinePath()
	if err != nil {
		_ = pool.UnmountInstance(d, nil)
		return fmt.Errorf("Failed resolving smolvm machine path: %w", err)
	}

	err = os.MkdirAll(dst, 0o700)
	if err != nil {
		_ = pool.UnmountInstance(d, nil)
		return fmt.Errorf("Failed creating smolvm machine path %q: %w", dst, err)
	}

	if linux.IsMountPoint(dst) {
		return nil
	}

	volRoot, err := filepath.EvalSymlinks(d.Path())
	if err != nil {
		_ = pool.UnmountInstance(d, nil)
		return fmt.Errorf("Failed resolving instance path: %w", err)
	}

	// Container-style rootfs ownership. The agent rootfs lives at
	// `<volRoot>/rootfs/`, populated at instance-create time from a per-pool
	// image volume (see storage/backend_smolvm.go::ensureSmolvmBaseImage).
	// smolvm-server's fs-worker thread runs setpriv'd to the dropped uid
	// and must be able to write the guest agent's `.smolvm-ready` marker
	// through virtio-fs - without that, host falls back to a 5s socket
	// probe. Each instance has its own CoW clone, so chowning is safe.
	// Cheap idempotency: if `rootfs/` itself already matches the target
	// uid, the recursive walk ran on a previous mount.
	//
	// Volume root mode: Incus ships volume roots at 0o100 so only root can
	// traverse (container idmap pattern - guest-side uid 0 maps to a
	// distinct host uid that has no business reading volume metadata). For
	// smolvm, the dropped uid is an unmapped host uid and we explicitly
	// want it to traverse `volRoot/` into `rootfs/`, so relax to 0o101 -
	// world-traversable but still no-listing.
	//
	// virtual-machines/ parent dir mode: storage/drivers/volume.go ships
	// VolumeTypeVM's base directory at 0o700 (qemu runs as root, so it
	// never needed world traversal). The dropped uid can't pass through a
	// 0o700 root-owned dir, so relax it to 0o711 to match VolumeTypeContainer
	// (`containers/`) - listability stays root-only but traversal is open.
	// Shared across instances in the same pool; idempotent under concurrent
	// starts.
	//
	// Timing note: UpdateBackupFile (called later in Start) re-enters
	// volume.go::EnsureMountPath which resets volRoot back to 0o100. That's
	// fine because libkrun's virtio-fs server opens an fd to rootfs/ during
	// smolvm-server start, and every subsequent guest fs op goes through
	// that fd via openat() - no fresh parent traversal needed. Crash recovery
	// also re-enters this function, so the 0o101 invariant is restored before
	// any new smolvm-server child starts.
	uid, gid, _, dropPriv := d.smolvmServerDropTarget()
	if dropPriv {
		if err := os.Chmod(filepath.Dir(volRoot), 0o711); err != nil {
			_ = pool.UnmountInstance(d, nil)
			return fmt.Errorf("Failed relaxing virtual-machines parent mode for dropped uid traversal: %w", err)
		}

		if err := os.Chmod(volRoot, 0o101); err != nil {
			_ = pool.UnmountInstance(d, nil)
			return fmt.Errorf("Failed relaxing volume root mode for dropped uid traversal: %w", err)
		}

		rootfsPath := filepath.Join(volRoot, "rootfs")
		info, statErr := os.Lstat(rootfsPath)
		switch {
		case statErr == nil:
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != uid {
				if err := smolvmServerChownTree(rootfsPath, uid, gid); err != nil {
					_ = pool.UnmountInstance(d, nil)
					return fmt.Errorf("Failed chowning agent rootfs to (%d, %d): %w", uid, gid, err)
				}
			}

		case errors.Is(statErr, os.ErrNotExist):
			// Instance from before per-instance rootfs landed - the
			// global agent-rootfs fallback in smolvmAgentRootfsPath
			// will take over. No chown to do here.

		default:
			_ = pool.UnmountInstance(d, nil)
			return fmt.Errorf("Failed stating agent rootfs %q: %w", rootfsPath, statErr)
		}
	}

	// Mirror the container `rootfs/` pattern: writable user-data lives in
	// `<volRoot>/smol/`, not the volume root. The dropped uid only needs
	// write access on this subdir; the volume root stays root-owned 0100.
	src := filepath.Join(volRoot, "smol")
	if err := os.MkdirAll(src, 0o700); err != nil {
		_ = pool.UnmountInstance(d, nil)
		return fmt.Errorf("Failed creating smolvm data subdir %q: %w", src, err)
	}

	err = storageDrivers.TryMount(src, dst, "none", unix.MS_BIND, "")
	if err != nil {
		_ = pool.UnmountInstance(d, nil)
		return fmt.Errorf("Failed bind-mounting %q to %q: %w", src, dst, err)
	}

	// smolvm-server records the machine name in a `name` file inside the
	// hash-derived data dir and refuses to use the dir if the recorded name
	// disagrees with the requested one ("hash collision"). After a rename,
	// the Incus storage volume still carries the OLD name file, so refresh
	// it to reflect the current machine name. Best-effort: a missing name
	// file is fine (smolvm-server will create it on first use).
	nameFile := filepath.Join(dst, "name")
	if err := os.WriteFile(nameFile, []byte(d.machineName()), 0o600); err != nil {
		d.logger.Warn("Failed refreshing smolvm name file", logger.Ctx{"path": nameFile, "err": err})
	}

	d.logger.Info("Bind-mounted instance volume to smolvm path", logger.Ctx{"src": src, "dst": dst})
	return nil
}

// smolvmEnsureUnmounted unbinds the smolvm machine path and unmounts the
// Incus storage volume. Best-effort and idempotent.
func (d *smolvm) smolvmEnsureUnmounted() error {
	dst, err := d.smolvmMachinePath()
	if err == nil {
		if linux.IsMountPoint(dst) {
			err = storageDrivers.TryUnmount(dst, 0)
			if err != nil {
				return fmt.Errorf("Failed unmounting smolvm bind mount %q: %w", dst, err)
			}
		}

		_ = os.Remove(dst)
	}

	pool, err := d.getStoragePool()
	if err != nil {
		return nil
	}

	return pool.UnmountInstance(d, nil)
}

//
// SECTION: lifecycle
//

// Start starts the instance.
//
// Lifecycle ordering:
//
//  1. Per-instance netns
//  2. Veth pair (host attached to nic device's parent bridge; peer in netns)
//  3. Mount Incus storage volume + bind-mount onto smolvm-server cache dir
//  4. Spawn per-instance smolvm-server inside the netns
//  5. CreateMachine + StartMachine via the per-instance unix socket
//
// Steps 1, 2, and 4 are skipped when smolvm.server points at an externally
// managed server (development escape hatch).
func (d *smolvm) Start(stateful bool) error {
	op, err := operationlock.CreateWaitGet(d.Project().Name, d.Name(), d.op, operationlock.ActionStart, []operationlock.Action{operationlock.ActionRestart, operationlock.ActionRestore}, false, false)
	if err != nil {
		return fmt.Errorf("Failed to create instance start operation: %w", err)
	}

	defer op.Done(nil)

	if stateful {
		op.Done(errSmolVMNotSupported)
		return errSmolVMNotSupported
	}

	if d.IsRunning() {
		return nil
	}

	reverter := revert.New()
	defer reverter.Fail()

	useEmbeddedServer := d.expandedConfig["smolvm.server"] == ""

	if useEmbeddedServer {
		err = d.smolvmEnsureNetns()
		if err != nil {
			op.Done(err)
			return fmt.Errorf("Failed creating smolvm netns: %w", err)
		}

		reverter.Add(func() { _ = d.smolvmRemoveNetns() })

		nics, classifyErr := d.smolvmAllNICs()
		if classifyErr != nil {
			op.Done(classifyErr)
			return fmt.Errorf("Failed classifying nic: %w", classifyErr)
		}

		if len(nics) > 0 {
			reverter.Add(func() { _ = d.smolvmDetachAllNICs() })

			for _, nic := range nics {
				err = d.smolvmAttachNIC(nic.Name, nic.Device, nic.Kind, nic.Network)
				if err != nil {
					op.Done(err)
					return fmt.Errorf("Failed attaching nic %q: %w", nic.Name, err)
				}
			}
		}
	}

	err = d.smolvmEnsureMounted()
	if err != nil {
		op.Done(err)
		return fmt.Errorf("Failed preparing smolvm storage: %w", err)
	}

	reverter.Add(func() { _ = d.smolvmEnsureUnmounted() })

	if useEmbeddedServer {
		// Load the per-instance AppArmor profile so aa-exec can attach
		// smolvm-server to it. Today the profile is a permissive baseline
		// (see instance_smolvm.profile.go) and exists to LSM-tag the process;
		// a later pass will tighten it to a deny-by-default policy without
		// changing this call site. No-op on systems without AppArmor.
		err = apparmor.InstanceLoad(d.state.OS, d, nil)
		if err != nil {
			op.Done(err)
			return fmt.Errorf("Failed loading AppArmor profile: %w", err)
		}

		reverter.Add(func() { _ = apparmor.InstanceUnload(d.state.OS, d) })

		serverCtx, cancelServer := context.WithTimeout(context.Background(), 60*time.Second)
		err = d.smolvmServerStart(serverCtx)
		cancelServer()
		if err != nil {
			op.Done(err)
			return fmt.Errorf("Failed starting smolvm-server: %w", err)
		}

		reverter.Add(func() { _ = d.smolvmServerStop() })
	}

	client := d.smolvmClient()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req := d.buildCreateRequest()

	_, err = client.CreateMachine(ctx, req)
	if err != nil && !errors.Is(err, smolvmsdk.ErrConflict) {
		op.Done(err)
		return fmt.Errorf("Failed creating smolvm machine: %w", err)
	}

	_, err = client.StartMachine(ctx, req.Name)
	if err != nil {
		op.Done(err)
		return fmt.Errorf("Failed starting smolvm machine: %w", err)
	}

	reverter.Success()

	err = d.VolatileSet(map[string]string{"volatile.last_state.power": instance.PowerStateRunning})
	if err != nil {
		d.logger.Warn("Failed updating last_state.power volatile key", logger.Ctx{"err": err})
	}

	d.lastUsedDate = time.Now().UTC()
	_ = d.state.DB.Cluster.Transaction(context.TODO(), func(ctx context.Context, tx *db.ClusterTx) error {
		return tx.UpdateInstanceLastUsedDate(d.id, d.lastUsedDate)
	})

	// Refresh backup.yaml so post-start volatile/runtime state is captured.
	// Missing-file is benign: pool may not have created the path yet.
	err = d.UpdateBackupFile()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		d.logger.Warn("Failed updating backup file after start", logger.Ctx{"err": err})
	}

	d.state.Events.SendLifecycle(d.project.Name, lifecycle.InstanceStarted.Event(d, nil))

	return nil
}

// Stop stops the instance immediately.
//
// Tears down the per-instance environment in reverse order from Start:
// machine → bind-mount → smolvm-server → veth → netns. Any single failure is
// logged and best-effort cleanup continues so a partial start can still be
// fully unwound.
func (d *smolvm) Stop(stateful bool) error {
	op, err := operationlock.CreateWaitGet(d.Project().Name, d.Name(), d.op, operationlock.ActionStop, []operationlock.Action{operationlock.ActionRestart, operationlock.ActionRestore, operationlock.ActionMigrate}, false, true)
	if err != nil {
		return fmt.Errorf("Failed to create instance stop operation: %w", err)
	}

	defer op.Done(nil)

	if stateful {
		op.Done(errSmolVMNotSupported)
		return errSmolVMNotSupported
	}

	useEmbeddedServer := d.expandedConfig["smolvm.server"] == ""

	if d.smolvmServerIsAlive() || !useEmbeddedServer {
		client := d.smolvmClient()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		_, stopErr := client.StopMachine(ctx, d.machineName())
		cancel()
		if stopErr != nil && !errors.Is(stopErr, smolvmsdk.ErrNotFound) && !errors.Is(stopErr, smolvmsdk.ErrConnection) {
			op.Done(stopErr)
			return fmt.Errorf("Failed stopping smolvm machine: %w", stopErr)
		}
	}

	if err := d.smolvmEnsureUnmounted(); err != nil {
		d.logger.Warn("Failed unmounting smolvm storage on stop", logger.Ctx{"err": err})
	}

	if useEmbeddedServer {
		if err := d.smolvmServerStop(); err != nil {
			d.logger.Warn("Failed stopping smolvm-server", logger.Ctx{"err": err})
		}

		if err := d.smolvmDetachAllNICs(); err != nil {
			d.logger.Warn("Failed detaching smolvm nics", logger.Ctx{"err": err})
		}

		if err := d.smolvmRemoveNetns(); err != nil {
			d.logger.Warn("Failed removing smolvm netns", logger.Ctx{"err": err})
		}

		if err := apparmor.InstanceUnload(d.state.OS, d); err != nil {
			d.logger.Warn("Failed unloading AppArmor profile", logger.Ctx{"err": err})
		}
	}

	err = d.VolatileSet(map[string]string{"volatile.last_state.power": instance.PowerStateStopped})
	if err != nil {
		d.logger.Warn("Failed updating last_state.power volatile key", logger.Ctx{"err": err})
	}

	d.state.Events.SendLifecycle(d.project.Name, lifecycle.InstanceStopped.Event(d, nil))

	return nil
}

// Shutdown gracefully stops the instance. The smolvm backend has no separate
// graceful path, so this defers to Stop.
func (d *smolvm) Shutdown(timeout time.Duration) error {
	err := d.Stop(false)
	if err != nil {
		return err
	}

	d.state.Events.SendLifecycle(d.project.Name, lifecycle.InstanceShutdown.Event(d, nil))
	return nil
}

// Restart stops then starts the instance.
func (d *smolvm) Restart(timeout time.Duration) error {
	return d.restartCommon(d, timeout)
}

// Rebuild rebuilds the instance using the supplied image.
func (d *smolvm) Rebuild(img *api.Image, op *operations.Operation) error {
	return d.rebuildCommon(d, img, op)
}

// Freeze is not supported by the smolvm backend.
func (d *smolvm) Freeze() error {
	return errSmolVMNotSupported
}

// Unfreeze is not supported by the smolvm backend.
func (d *smolvm) Unfreeze() error {
	return errSmolVMNotSupported
}

// Delete deletes the instance.
func (d *smolvm) Delete(force bool, cleanupDependencies bool) error {
	op, err := operationlock.CreateWaitGet(d.Project().Name, d.Name(), d.op, operationlock.ActionDelete, nil, false, false)
	if err != nil {
		return fmt.Errorf("Failed to create instance delete operation: %w", err)
	}

	defer op.Done(nil)

	if d.IsRunning() {
		return api.StatusErrorf(http.StatusBadRequest, "Instance is running")
	}

	err = d.delete(force, cleanupDependencies)
	if err != nil {
		return err
	}

	if d.IsSnapshot() {
		parentName, _, _ := api.GetParentAndSnapshotName(d.name)
		parent, err := instance.LoadByProjectAndName(d.state, d.project.Name, parentName)
		if err != nil {
			return fmt.Errorf("Invalid parent: %w", err)
		}

		err = parent.UpdateBackupFile()
		if err != nil {
			return err
		}
	}

	return nil
}

// delete performs the unlocked delete logic.
func (d *smolvm) delete(force bool, cleanupDependencies bool) error {
	if !force && util.IsTrue(d.expandedConfig["security.protection.delete"]) && !d.IsSnapshot() {
		return errors.New("Instance is protected")
	}

	err := d.warningsDelete()
	if err != nil {
		return err
	}

	// Tear down the per-instance environment. Each step is best-effort:
	// pool.DeleteInstance below removes the on-disk Incus storage volume
	// regardless, and any stale netns/veth/server gets reaped by the
	// per-instance cleanup helpers.
	if !d.IsSnapshot() {
		err = d.smolvmEnsureUnmounted()
		if err != nil {
			d.logger.Warn("Failed unmounting smolvm storage on delete", logger.Ctx{"err": err})
		}

		if d.expandedConfig["smolvm.server"] == "" {
			if err := d.smolvmServerStop(); err != nil {
				d.logger.Warn("Failed stopping smolvm-server on delete", logger.Ctx{"err": err})
			}

			if err := d.smolvmDetachAllNICs(); err != nil {
				d.logger.Warn("Failed detaching smolvm nics on delete", logger.Ctx{"err": err})
			}

			if err := d.smolvmRemoveNetns(); err != nil {
				d.logger.Warn("Failed removing smolvm netns on delete", logger.Ctx{"err": err})
			}

			if err := apparmor.InstanceUnload(d.state.OS, d); err != nil {
				d.logger.Warn("Failed unloading AppArmor profile on delete", logger.Ctx{"err": err})
			}

			if err := apparmor.InstanceDelete(d.state.OS, d); err != nil {
				d.logger.Warn("Failed deleting AppArmor profile on delete", logger.Ctx{"err": err})
			}
		}
	}

	pool, err := d.getStoragePool()
	if err == nil && pool != nil {
		if d.IsSnapshot() {
			err = pool.DeleteInstanceSnapshot(d, nil)
			if err != nil {
				return err
			}
		} else {
			err = d.deleteSnapshots(func(snapInst instance.Instance) error {
				return snapInst.(*smolvm).delete(true, cleanupDependencies)
			})
			if err != nil {
				return fmt.Errorf("Failed deleting instance snapshots: %w", err)
			}

			err = pool.DeleteInstance(d, nil)
			if err != nil {
				return err
			}
		}
	}

	if !d.IsSnapshot() {
		backups, err := d.Backups()
		if err != nil {
			return err
		}

		for _, b := range backups {
			err = b.Delete()
			if err != nil {
				return err
			}
		}

		d.devicesRemove(d, cleanupDependencies)
	}

	err = d.state.DB.Cluster.Transaction(context.TODO(), func(ctx context.Context, tx *db.ClusterTx) error {
		return tx.DeleteInstance(ctx, d.Project().Name, d.Name())
	})
	if err != nil {
		return err
	}

	if d.isSnapshot {
		d.state.Events.SendLifecycle(d.project.Name, lifecycle.InstanceSnapshotDeleted.Event(d, nil))
	} else {
		err = d.state.Authorizer.DeleteInstance(d.state.ShutdownCtx, d.project.Name, d.Name())
		if err != nil {
			d.logger.Warn("Failed to remove instance from authorizer", logger.Ctx{"err": err})
		}

		d.state.Events.SendLifecycle(d.project.Name, lifecycle.InstanceDeleted.Event(d, nil))
	}

	return nil
}

// Update updates the instance configuration.
//
// Mirrors the qemu/lxc contract: validate args, diff config/devices, run
// shared devicesUpdate (which fires deviceAdd/deviceRemove and the device's
// own Update), persist to DB, refresh backup.yaml. A reverter restores struct
// fields if any step fails so the in-memory view stays consistent with the DB.
//
// smolvm has no hot-plug or live-resize support, so any actual config or
// device change while the instance is running is rejected — stop first.
func (d *smolvm) Update(args db.InstanceArgs, userRequested bool) error {
	op, err := operationlock.CreateWaitGet(d.Project().Name, d.Name(), d.op, operationlock.ActionUpdate, []operationlock.Action{operationlock.ActionRestart, operationlock.ActionRestore}, false, false)
	if err != nil {
		return fmt.Errorf("Failed to create instance update operation: %w", err)
	}

	defer op.Done(nil)

	reverter := revert.New()
	defer reverter.Fail()

	if args.Project == "" {
		args.Project = api.ProjectDefaultName
	}

	if args.Architecture == 0 {
		args.Architecture = d.architecture
	}

	if args.Config == nil {
		args.Config = map[string]string{}
	}

	if args.Devices == nil {
		args.Devices = deviceConfig.Devices{}
	}

	if args.Profiles == nil {
		args.Profiles = []api.Profile{}
	}

	if userRequested {
		err = instance.ValidConfig(d.state.OS, args.Config, false, d.dbType)
		if err != nil {
			return fmt.Errorf("Invalid config: %w", err)
		}

		err = instance.ValidDevices(d.state, d.project, d.Type(), args.Devices, nil)
		if err != nil {
			return fmt.Errorf("Invalid devices: %w", err)
		}
	}

	var profiles []string
	err = d.state.DB.Cluster.Transaction(context.TODO(), func(ctx context.Context, tx *db.ClusterTx) error {
		profiles, err = tx.GetProfileNames(ctx, args.Project)
		return err
	})
	if err != nil {
		return fmt.Errorf("Failed to get profiles: %w", err)
	}

	checkedProfiles := []string{}
	for _, profile := range args.Profiles {
		if !slices.Contains(profiles, profile.Name) {
			return fmt.Errorf("Requested profile '%s' doesn't exist", profile.Name)
		}

		if slices.Contains(checkedProfiles, profile.Name) {
			return errors.New("Duplicate profile found in request")
		}

		checkedProfiles = append(checkedProfiles, profile.Name)
	}

	if args.Architecture != 0 {
		_, err = osarch.ArchitectureName(args.Architecture)
		if err != nil {
			return fmt.Errorf("Invalid architecture ID: %s", err)
		}
	}

	oldDescription := d.Description()
	oldArchitecture := 0
	err = util.DeepCopy(&d.architecture, &oldArchitecture)
	if err != nil {
		return err
	}

	oldEphemeral := false
	err = util.DeepCopy(&d.ephemeral, &oldEphemeral)
	if err != nil {
		return err
	}

	oldExpandedDevices := deviceConfig.Devices{}
	err = util.DeepCopy(&d.expandedDevices, &oldExpandedDevices)
	if err != nil {
		return err
	}

	oldExpandedConfig := map[string]string{}
	err = util.DeepCopy(&d.expandedConfig, &oldExpandedConfig)
	if err != nil {
		return err
	}

	oldLocalDevices := deviceConfig.Devices{}
	err = util.DeepCopy(&d.localDevices, &oldLocalDevices)
	if err != nil {
		return err
	}

	oldLocalConfig := map[string]string{}
	err = util.DeepCopy(&d.localConfig, &oldLocalConfig)
	if err != nil {
		return err
	}

	oldProfiles := []api.Profile{}
	err = util.DeepCopy(&d.profiles, &oldProfiles)
	if err != nil {
		return err
	}

	oldExpiryDate := d.expiryDate

	reverter.Add(func() {
		d.description = oldDescription
		d.architecture = oldArchitecture
		d.ephemeral = oldEphemeral
		d.expandedConfig = oldExpandedConfig
		d.expandedDevices = oldExpandedDevices
		d.localConfig = oldLocalConfig
		d.localDevices = oldLocalDevices
		d.profiles = oldProfiles
		d.expiryDate = oldExpiryDate
	})

	d.description = args.Description
	d.architecture = args.Architecture
	d.ephemeral = args.Ephemeral
	d.localConfig = args.Config
	d.localDevices = args.Devices
	d.profiles = args.Profiles
	d.expiryDate = args.ExpiryDate

	err = d.expandConfig()
	if err != nil {
		return err
	}

	changedConfig := []string{}
	for key := range oldExpandedConfig {
		if oldExpandedConfig[key] != d.expandedConfig[key] && !slices.Contains(changedConfig, key) {
			changedConfig = append(changedConfig, key)
		}
	}

	for key := range d.expandedConfig {
		if oldExpandedConfig[key] != d.expandedConfig[key] && !slices.Contains(changedConfig, key) {
			changedConfig = append(changedConfig, key)
		}
	}

	removeDevices, addDevices, updateDevices, _ := oldExpandedDevices.Update(d.expandedDevices, func(oldDevice deviceConfig.Device, newDevice deviceConfig.Device) []string {
		oldDevType, err := device.LoadByType(d.state, d.Project().Name, oldDevice)
		if err != nil {
			return []string{}
		}

		newDevType, err := device.LoadByType(d.state, d.Project().Name, newDevice)
		if err != nil {
			return []string{}
		}

		return newDevType.UpdatableFields(oldDevType)
	})

	if userRequested {
		err = instance.ValidConfig(d.state.OS, d.expandedConfig, true, instancetype.Any)
		if err != nil {
			return fmt.Errorf("Invalid expanded config: %w", err)
		}

		err = instance.ValidDevices(d.state, d.project, d.Type(), d.localDevices, d.expandedDevices)
		if err != nil {
			return fmt.Errorf("Invalid expanded devices: %w", err)
		}

		_, oldRootDev, oldErr := internalInstance.GetRootDiskDevice(oldExpandedDevices.CloneNative())
		_, newRootDev, newErr := internalInstance.GetRootDiskDevice(d.expandedDevices.CloneNative())
		if oldErr == nil && newErr == nil && oldRootDev["pool"] != newRootDev["pool"] {
			return fmt.Errorf("Cannot update root disk device pool name to %q", newRootDev["pool"])
		}

		if newErr != nil {
			return fmt.Errorf("Invalid root disk device: %w", newErr)
		}
	}

	isRunning := d.IsRunning()

	// smolvm has no hot-plug or live memory/CPU resize. While running, only
	// keys whose value is purely descriptive or "consumed at next start"
	// can change — anything that would need to be applied to the libkrun
	// guest would silently drift from the DB.
	if isRunning {
		if len(removeDevices) > 0 || len(addDevices) > 0 || len(updateDevices) > 0 {
			return errors.New("smolvm does not support device updates while running; stop the instance first")
		}

		liveUpdatablePrefixes := []string{
			"boot.",
			"cloud-init.",
			"environment.",
			"image.",
			"snapshots.",
			"user.",
			"volatile.",
		}

		liveUpdatableKeys := []string{
			"cluster.evacuate",
			"security.protection.delete",
		}

		for _, key := range changedConfig {
			if util.StringHasPrefix(key, liveUpdatablePrefixes...) {
				continue
			}

			if slices.Contains(liveUpdatableKeys, key) {
				continue
			}

			return fmt.Errorf("Key %q cannot be updated when smolvm is running", key)
		}
	}

	// Apply device add/remove/update via the shared device manager.
	// instanceRunning=false here means deviceStart/deviceStop are not invoked,
	// only deviceAdd/deviceRemove and dev.Update — exactly what smolvm needs.
	err = d.devicesUpdate(d, removeDevices, addDevices, updateDevices, oldExpandedDevices, isRunning, userRequested)
	if err != nil {
		return err
	}

	err = d.state.DB.Cluster.Transaction(context.TODO(), func(ctx context.Context, tx *db.ClusterTx) error {
		if d.IsSnapshot() {
			return tx.UpdateInstanceSnapshot(d.id, d.description, d.expiryDate)
		}

		object, err := dbCluster.GetInstance(ctx, tx.Tx(), d.project.Name, d.name)
		if err != nil {
			return err
		}

		object.Description = d.description
		object.Architecture = d.architecture
		object.Ephemeral = d.ephemeral
		object.ExpiryDate = sql.NullTime{Time: d.expiryDate, Valid: true}

		err = dbCluster.UpdateInstance(ctx, tx.Tx(), d.project.Name, d.name, *object)
		if err != nil {
			return fmt.Errorf("Failed updating instance row: %w", err)
		}

		err = dbCluster.UpdateInstanceConfig(ctx, tx.Tx(), int64(object.ID), d.localConfig)
		if err != nil {
			return fmt.Errorf("Failed updating instance config: %w", err)
		}

		devices, err := dbCluster.APIToDevices(d.localDevices.CloneNative())
		if err != nil {
			return err
		}

		err = dbCluster.UpdateInstanceDevices(ctx, tx.Tx(), int64(object.ID), devices)
		if err != nil {
			return fmt.Errorf("Failed updating instance devices: %w", err)
		}

		return dbCluster.UpdateInstanceProfiles(ctx, tx.Tx(), object.ID, object.Project, profileNames(d.profiles))
	})
	if err != nil {
		return fmt.Errorf("Failed to update database: %w", err)
	}

	err = d.UpdateBackupFile()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("Failed to write backup file: %w", err)
	}

	reverter.Success()

	if userRequested {
		if d.isSnapshot {
			d.state.Events.SendLifecycle(d.project.Name, lifecycle.InstanceSnapshotUpdated.Event(d, nil))
		} else {
			d.state.Events.SendLifecycle(d.project.Name, lifecycle.InstanceUpdated.Event(d, nil))
		}
	}

	return nil
}

// Rename renames the instance. Smolvm doesn't support live rename, so this
// only works while stopped. Per-instance smolvm-server state is keyed off
// the instance name, so a rename leaves no orphaned server to clean up:
// when stopped, no server is running.
//
// Mirrors qemu/lxc: also renames the storage volume, snapshot DB rows,
// log/run paths, backups, refreshes DNSMasq leases and backup.yaml, and
// updates the authorizer. Reverter rolls back the in-memory name on failure.
func (d *smolvm) Rename(newName string, applyTemplateTrigger bool) error {
	oldName := d.Name()

	err := instance.ValidName(newName, d.IsSnapshot())
	if err != nil {
		return err
	}

	if d.IsRunning() {
		return errors.New("Cannot rename a running smolvm instance")
	}

	pool, err := storagePools.LoadByInstance(d.state, d)
	if err != nil {
		return fmt.Errorf("Failed loading instance storage pool: %w", err)
	}

	// Rename the storage volume on disk, the storage_volumes DB row, and the
	// instance symlink. Without this the volume row stays anchored to the old
	// name; deleting the renamed instance leaves an orphan that blocks future
	// creates with the original name (UNIQUE constraint).
	if d.IsSnapshot() {
		_, newSnapName, _ := api.GetParentAndSnapshotName(newName)
		err = pool.RenameInstanceSnapshot(d, newSnapName, nil)
		if err != nil {
			return fmt.Errorf("Rename instance snapshot: %w", err)
		}
	} else {
		err = pool.RenameInstance(d, newName, nil)
		if err != nil {
			return fmt.Errorf("Rename instance: %w", err)
		}
	}

	// When renaming a parent (non-snapshot) instance, fix up the snapshot
	// DB rows so their `<oldName>/<snap>` keys become `<newName>/<snap>`.
	// Without this, follow-up snapshot operations look for rows that no
	// longer exist.
	if !d.IsSnapshot() {
		var snapNames []string

		err = d.state.DB.Cluster.Transaction(context.TODO(), func(ctx context.Context, tx *db.ClusterTx) error {
			var err error
			snapNames, err = tx.GetInstanceSnapshotsNames(ctx, d.project.Name, oldName)
			return err
		})
		if err != nil {
			return fmt.Errorf("Failed to get instance snapshots: %w", err)
		}

		err = d.state.DB.Cluster.Transaction(context.TODO(), func(ctx context.Context, tx *db.ClusterTx) error {
			for _, sname := range snapNames {
				oldSnapName := strings.SplitN(sname, internalInstance.SnapshotDelimiter, 2)[1]
				baseSnapName := filepath.Base(sname)

				err := dbCluster.RenameInstanceSnapshot(ctx, tx.Tx(), d.project.Name, oldName, oldSnapName, baseSnapName)
				if err != nil {
					return err
				}
			}

			return nil
		})
		if err != nil {
			return fmt.Errorf("Failed renaming instance snapshots: %w", err)
		}
	}

	err = d.state.DB.Cluster.Transaction(context.TODO(), func(ctx context.Context, tx *db.ClusterTx) error {
		if d.IsSnapshot() {
			oldParts := strings.SplitN(oldName, internalInstance.SnapshotDelimiter, 2)
			newParts := strings.SplitN(newName, internalInstance.SnapshotDelimiter, 2)
			return dbCluster.RenameInstanceSnapshot(ctx, tx.Tx(), d.project.Name, oldParts[0], oldParts[1], newParts[1])
		}

		return dbCluster.RenameInstance(ctx, tx.Tx(), d.project.Name, oldName, newName)
	})
	if err != nil {
		return err
	}

	// Rename the log and runtime directories so per-instance logs follow the
	// instance.
	newFullName := project.Instance(d.Project().Name, newName)
	_ = os.RemoveAll(internalUtil.LogPath(newFullName))
	if util.PathExists(d.LogPath()) {
		err = os.Rename(d.LogPath(), internalUtil.LogPath(newFullName))
		if err != nil {
			return fmt.Errorf("Failed renaming instance log path: %w", err)
		}
	}

	_ = os.RemoveAll(internalUtil.RunPath(newFullName))
	if util.PathExists(d.RunPath()) {
		err = os.Rename(d.RunPath(), internalUtil.RunPath(newFullName))
		if err != nil {
			return fmt.Errorf("Failed renaming instance run path: %w", err)
		}
	}

	reverter := revert.New()
	defer reverter.Fail()

	d.name = newName
	reverter.Add(func() { d.name = oldName })

	// Rename per-instance backup files.
	backups, err := d.Backups()
	if err != nil {
		return err
	}

	for _, backup := range backups {
		b := backup
		oldBackupName := b.Name()
		backupName := strings.Split(oldBackupName, "/")[1]
		newBackupName := fmt.Sprintf("%s/%s", newName, backupName)

		err = b.Rename(newBackupName)
		if err != nil {
			return err
		}

		reverter.Add(func() { _ = b.Rename(oldBackupName) })
	}

	// Refresh DNSMasq static leases — any bridged NIC with a static IP needs
	// its lease file regenerated under the new instance name.
	err = network.UpdateDNSMasqStatic(d.state, "")
	if err != nil {
		return err
	}

	// Refresh backup.yaml so the on-disk copy reflects the new name.
	err = d.UpdateBackupFile()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("Failed to write backup file: %w", err)
	}

	if d.IsSnapshot() {
		d.state.Events.SendLifecycle(d.project.Name, lifecycle.InstanceSnapshotRenamed.Event(d, map[string]any{"old_name": oldName}))
	} else {
		err = d.state.Authorizer.RenameInstance(d.state.ShutdownCtx, d.project.Name, oldName, newName)
		if err != nil {
			d.logger.Warn("Failed to rename instance in authorizer", logger.Ctx{"old_name": oldName, "new_name": newName, "err": err})
		}

		d.state.Events.SendLifecycle(d.project.Name, lifecycle.InstanceRenamed.Event(d, map[string]any{"old_name": oldName}))
	}

	reverter.Success()

	return nil
}

//
// SECTION: state
//

// IsRunning reports whether the smolvm machine is currently running.
func (d *smolvm) IsRunning() bool {
	return d.statusCode() == api.Running
}

// IsFrozen reports whether the instance is frozen. The smolvm backend does
// not support freeze, so this is always false.
func (d *smolvm) IsFrozen() bool {
	return false
}

// IsPrivileged is a container concept and does not apply.
func (d *smolvm) IsPrivileged() bool {
	return false
}

// statusCode probes the smolvm server for the machine's current state and
// converts it to an Incus api.StatusCode.
func (d *smolvm) statusCode() api.StatusCode {
	op := operationlock.Get(d.Project().Name, d.Name())
	if op != nil {
		switch op.Action() {
		case operationlock.ActionStart:
			return api.Stopped
		case operationlock.ActionStop:
			return api.Running
		}
	}

	// When using the per-instance embedded server, a missing server process
	// definitively means the instance isn't running. Skip the SDK call to
	// avoid noisy connection errors during normal Stopped state.
	if d.expandedConfig["smolvm.server"] == "" && !d.smolvmServerIsAlive() {
		return api.Stopped
	}

	client := d.smolvmClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info, err := client.GetMachine(ctx, d.machineName())
	if err != nil {
		if errors.Is(err, smolvmsdk.ErrNotFound) || errors.Is(err, smolvmsdk.ErrConnection) {
			return api.Stopped
		}
		return api.Error
	}

	switch info.State {
	case smolvmsdk.MachineStateRunning:
		return api.Running
	case smolvmsdk.MachineStateStopped, smolvmsdk.MachineStateCreated:
		return api.Stopped
	}

	// For any other state (e.g. "unreachable") treat a machine with a live PID as running.
	if info.PID != nil && *info.PID > 0 {
		return api.Running
	}

	return api.Error
}

// State returns the current power state as an upper-case string.
func (d *smolvm) State() string {
	return strings.ToUpper(d.statusCode().String())
}

// InitPID returns the host PID of the smolvm machine, if known.
func (d *smolvm) InitPID() int {
	client := d.smolvmClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info, err := client.GetMachine(ctx, d.machineName())
	if err != nil || info.PID == nil {
		return -1
	}

	return *info.PID
}

// GuestOS returns the guest operating system reported by the smolvm machine.
// We don't have a robust way to detect this, so we report it as best effort.
func (d *smolvm) GuestOS() string {
	if osName := d.expandedConfig["image.os"]; osName != "" {
		return strings.ToLower(osName)
	}
	return "linux"
}

//
// SECTION: render
//

// Render returns the API representation of this instance.
func (d *smolvm) Render() (any, any, error) {
	profileNames := make([]string, 0, len(d.profiles))
	for _, p := range d.profiles {
		profileNames = append(profileNames, p.Name)
	}

	if d.IsSnapshot() {
		snap := api.InstanceSnapshot{
			CreatedAt:       d.creationDate,
			Description:     d.description,
			ExpandedConfig:  d.expandedConfig,
			ExpandedDevices: d.expandedDevices.CloneNative(),
			LastUsedAt:      d.lastUsedDate,
			Name:            strings.SplitN(d.name, "/", 2)[1],
			Stateful:        d.stateful,
			Size:            -1,
		}

		snap.Architecture = d.architectureName
		snap.Config = d.localConfig
		snap.Devices = d.localDevices.CloneNative()
		snap.Ephemeral = d.ephemeral
		snap.Profiles = profileNames
		snap.ExpiresAt = d.expiryDate

		return &snap, d.ETag(), nil
	}

	statusCode := d.statusCode()
	inst := api.Instance{
		ExpandedConfig:  d.expandedConfig,
		ExpandedDevices: d.expandedDevices.CloneNative(),
		Name:            d.name,
		Status:          statusCode.String(),
		StatusCode:      statusCode,
		Location:        d.node,
		Type:            d.Type().String(),
	}

	inst.Description = d.description
	inst.Architecture = d.architectureName
	inst.Config = d.localConfig
	inst.CreatedAt = d.creationDate
	inst.Devices = d.localDevices.CloneNative()
	inst.Ephemeral = d.ephemeral
	inst.LastUsedAt = d.lastUsedDate
	inst.Profiles = profileNames
	inst.Stateful = d.stateful
	inst.Project = d.project.Name

	return &inst, d.ETag(), nil
}

// RenderWithUsage returns the instance with disk usage info. smolvm doesn't
// expose detailed usage, so this is identical to Render.
func (d *smolvm) RenderWithUsage() (any, any, error) {
	return d.Render()
}

// RenderFull renders the instance plus state, snapshots, and backups.
func (d *smolvm) RenderFull(hostInterfaces []net.Interface) (*api.InstanceFull, any, error) {
	if d.IsSnapshot() {
		return nil, nil, errors.New("RenderFull doesn't work with snapshots")
	}

	base, etag, err := d.Render()
	if err != nil {
		return nil, nil, err
	}

	full := api.InstanceFull{Instance: *base.(*api.Instance)}

	full.State, err = d.RenderState(hostInterfaces)
	if err != nil {
		return nil, nil, err
	}

	snaps, err := d.Snapshots()
	if err != nil {
		return nil, nil, err
	}

	for _, s := range snaps {
		render, _, err := s.Render()
		if err != nil {
			return nil, nil, err
		}

		if full.Snapshots == nil {
			full.Snapshots = []api.InstanceSnapshot{}
		}
		full.Snapshots = append(full.Snapshots, *render.(*api.InstanceSnapshot))
	}

	backups, err := d.Backups()
	if err != nil {
		return nil, nil, err
	}

	for _, b := range backups {
		r := b.Render()
		if full.Backups == nil {
			full.Backups = []api.InstanceBackup{}
		}
		full.Backups = append(full.Backups, *r)
	}

	return &full, etag, nil
}

// RenderState returns runtime state info for the instance.
func (d *smolvm) RenderState(hostInterfaces []net.Interface) (*api.InstanceState, error) {
	statusCode := d.statusCode()
	st := &api.InstanceState{
		Processes:  -1,
		Status:     statusCode.String(),
		StatusCode: statusCode,
	}

	if statusCode != api.Running {
		return st, nil
	}

	client := d.smolvmClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info, err := client.GetMachine(ctx, d.machineName())
	if err != nil {
		return st, nil
	}

	if info.PID != nil {
		st.Pid = int64(*info.PID)
	}

	if info.MemoryMB > 0 {
		st.Memory.Total = int64(info.MemoryMB) * 1024 * 1024
	}

	if info.CPUs > 0 {
		st.CPU.AllocatedTime = int64(info.CPUs) * 1_000_000_000
	}

	// Network state: the libkrun guest has no NIC (TSI does socket-level NAT),
	// so the bridge member is the per-instance netns. Read addresses via
	// netlink against the smolvm-server's netns — that's what other peers on
	// the bridge see, and what `incus list` should reflect.
	if pid, ok := d.smolvmServerPID(); ok {
		nw, err := netutils.NetnsGetifaddrs(int32(pid), hostInterfaces)
		if err != nil {
			d.logger.Warn("Failed reading smolvm netns interfaces", logger.Ctx{"err": err})
		} else {
			st.Network = nw
		}
	}

	return st, nil
}

//
// SECTION: snapshots, backups, migration — not supported
//

// Snapshot is not supported by the smolvm backend.
func (d *smolvm) Snapshot(name string, expiry time.Time, stateful bool) error {
	return errSmolVMNotSupported
}

// Restore is not supported by the smolvm backend.
func (d *smolvm) Restore(source instance.Instance, stateful bool, diskOnly bool) error {
	return errSmolVMNotSupported
}

// Export is not supported by the smolvm backend.
func (d *smolvm) Export(meta io.Writer, rootfs io.Writer, properties map[string]string, expiration time.Time, tracker *ioprogress.ProgressTracker) (*api.ImageMetadata, error) {
	return nil, errSmolVMNotSupported
}

// MigrateSend is not supported by the smolvm backend.
func (d *smolvm) MigrateSend(args instance.MigrateSendArgs) error {
	return errSmolVMNotSupported
}

// MigrateReceive is not supported by the smolvm backend.
func (d *smolvm) MigrateReceive(args instance.MigrateReceiveArgs) error {
	return errSmolVMNotSupported
}

// CanMigrate reports the migration capability of the smolvm backend.
func (d *smolvm) CanMigrate() string {
	return ""
}

// CanLiveMigrate reports whether live migration is supported. It is not.
func (d *smolvm) CanLiveMigrate() bool {
	return false
}

//
// SECTION: devices
//

// deviceStart satisfies the deviceManager interface used by the shared
// devicesUpdate helper. smolvm has no hot-plug support; running updates are
// rejected before this point, so this should never be invoked. Returning an
// explicit error makes accidental misuse loud rather than silent.
func (d *smolvm) deviceStart(dev device.Device, instanceRunning bool) (*deviceConfig.RunConfig, error) {
	return nil, errSmolVMNotSupported
}

// deviceStop is the deviceManager counterpart to deviceStart. Same reasoning.
func (d *smolvm) deviceStop(dev device.Device, instanceRunning bool, _ string) error {
	return errSmolVMNotSupported
}

// DeviceEventHandler handles runtime device events. The smolvm backend doesn't
// support hot-attach, so we silently ignore them.
func (d *smolvm) DeviceEventHandler(runConf *deviceConfig.RunConfig) error {
	return nil
}

// OnHook executes lifecycle hooks. The smolvm backend doesn't define any.
func (d *smolvm) OnHook(hookName string, args map[string]string) error {
	return instance.ErrNotImplemented
}

// ReloadDevice is a no-op since smolvm doesn't support hot-reload.
func (d *smolvm) ReloadDevice(devName string) error {
	return nil
}

// RegisterDevices is a no-op for smolvm.
func (d *smolvm) RegisterDevices() {}

// FillNetworkDevice generates a stable MAC address for a NIC device, mirroring
// the behaviour used by the QEMU driver.
func (d *smolvm) FillNetworkDevice(name string, m deviceConfig.Device) (deviceConfig.Device, error) {
	newDevice := m.Clone()

	if newDevice["hwaddr"] != "" {
		return newDevice, nil
	}

	configKey := fmt.Sprintf("volatile.%s.hwaddr", name)
	hwaddr := d.localConfig[configKey]
	if hwaddr == "" {
		generated, err := instance.DeviceNextInterfaceHWAddr(d.MACPattern())
		if err != nil || generated == "" {
			return nil, fmt.Errorf("Failed generating %q: %w", configKey, err)
		}

		err = d.VolatileSet(map[string]string{configKey: generated})
		if err != nil {
			return nil, fmt.Errorf("Failed storing generated config key %q: %w", configKey, err)
		}

		hwaddr = generated
	}

	newDevice["hwaddr"] = hwaddr
	return newDevice, nil
}

//
// SECTION: console / exec / files
//

// Console is not yet wired through the smolvm SDK.
func (d *smolvm) Console(protocol string) (*os.File, chan error, error) {
	return nil, nil, errSmolVMNotSupported
}

// Exec executes a command inside the smolvm machine. The smolvm-server's
// /api/v1/machines/{name}/exec/stream endpoint runs the command via vsock
// against the in-guest smolvm-agent and emits SSE events with stdout/stderr/
// exit. Stdin streaming and PTYs aren't supported by the smolvm transport,
// so interactive requests are rejected; non-interactive requests get their
// stdout/stderr proxied to the caller's pipe ends and Wait() blocks until
// the agent reports an exit code.
func (d *smolvm) Exec(req api.InstanceExecPost, stdin *os.File, stdout *os.File, stderr *os.File) (instance.Cmd, error) {
	if req.Interactive {
		return nil, errors.New("smolvm exec does not support interactive (PTY) sessions")
	}

	ctx, cancel := context.WithCancel(context.Background())

	var env []smolvmsdk.EnvVar
	for k, v := range req.Environment {
		env = append(env, smolvmsdk.EnvVar{Name: k, Value: v})
	}

	sdkReq := smolvmsdk.ExecRequest{
		Command: req.Command,
		Env:     env,
		Workdir: req.Cwd,
	}

	cmd := &smolvmCmd{
		cancel:   cancel,
		done:     make(chan struct{}),
		exitCode: -1,
	}

	client := d.smolvmClient()
	events, err := client.ExecStream(ctx, d.machineName(), sdkReq)
	if err != nil {
		// Map the agent's execve(2) ENOENT/EACCES failures into POSIX shell
		// exit codes (127/126) rather than bubbling them up as transport
		// errors — the upstream test suite expects `incus exec foo bogus` to
		// return 127, not the generic 255 the API would otherwise produce.
		if posixCode, stderrMsg := smolvmExecStartFailureExitCode(err, req.Command); posixCode != 0 {
			cmd.exitCode = posixCode
			go func() {
				defer close(cmd.done)
				defer cancel()
				if stderr != nil {
					_, _ = stderr.WriteString(stderrMsg + "\n")
				}
				if stdout != nil {
					_ = stdout.Close()
				}
				if stderr != nil && stderr != stdout {
					_ = stderr.Close()
				}
			}()
			d.state.Events.SendLifecycle(d.project.Name, lifecycle.InstanceExec.Event(d, logger.Ctx{"command": req.Command}))
			return cmd, nil
		}

		cancel()
		return nil, fmt.Errorf("Failed starting smolvm exec stream: %w", err)
	}

	go func() {
		defer close(cmd.done)
		defer cancel()
		// The pipe write ends are owned by the caller (instance_exec.go's
		// execWs); closing them on completion is what signals EOF to the
		// websocket reader and lets the client see the command finished.
		defer func() {
			if stdout != nil {
				_ = stdout.Close()
			}
			if stderr != nil && stderr != stdout {
				_ = stderr.Close()
			}
		}()

		for ev := range events {
			switch ev.Event {
			case "stdout":
				if stdout != nil {
					_, _ = stdout.WriteString(ev.Data + "\n")
				}
			case "stderr":
				if stderr != nil {
					_, _ = stderr.WriteString(ev.Data + "\n")
				}
			case "exit":
				var payload struct {
					ExitCode int `json:"exitCode"`
				}
				if jerr := json.Unmarshal([]byte(ev.Data), &payload); jerr == nil {
					cmd.mu.Lock()
					cmd.exitCode = payload.ExitCode
					cmd.mu.Unlock()
				}
			case "error":
				cmd.mu.Lock()
				if cmd.err == nil {
					cmd.err = errors.New(ev.Data)
				}
				cmd.mu.Unlock()
			}
		}
	}()

	d.state.Events.SendLifecycle(d.project.Name, lifecycle.InstanceExec.Event(d, logger.Ctx{"command": req.Command}))

	return cmd, nil
}

// FileSFTPConn is not supported. smolvm exposes its own file API instead.
func (d *smolvm) FileSFTPConn() (net.Conn, error) {
	return nil, errSmolVMNotSupported
}

// FileSFTP is not supported.
func (d *smolvm) FileSFTP() (*sftp.Client, error) {
	return nil, errSmolVMNotSupported
}

//
// SECTION: info / metrics / cgroups
//

// Info returns metadata about the smolvm driver. The driver spawns a
// per-instance smolvm-server at Start() time, so there is no shared server
// to probe at registration time. Runtime errors (missing binary, missing
// agent rootfs) surface when an instance is started.
func (d *smolvm) Info() instance.Info {
	return instance.Info{
		Name:     "smolvm",
		Features: make(map[string]any),
		Type:     instancetype.SmolVM,
		Version:  "1",
	}
}

// Metrics returns an empty metric set since smolvm does not expose detailed metrics.
func (d *smolvm) Metrics(hostInterfaces []net.Interface) (*metrics.MetricSet, error) {
	return metrics.NewMetricSet(nil), nil
}

// CGroup is a container concept and does not apply to smolvm instances.
func (d *smolvm) CGroup() (*cgroup.CGroup, error) {
	return nil, errSmolVMNotSupported
}

// LockExclusive obtains an exclusive operation lock for offline operations.
func (d *smolvm) LockExclusive() (*operationlock.InstanceOperation, error) {
	if d.IsRunning() {
		return nil, errors.New("Instance is running")
	}

	return operationlock.Create(d.Project().Name, d.Name(), d.op, operationlock.ActionCreate, false, false)
}

// UpdateBackupFile writes the instance's backup.yaml file via the storage pool.
// Serialised per (project, instance) so concurrent updates can't tear the file.
func (d *smolvm) UpdateBackupFile() error {
	unlock, err := d.updateBackupFileLock(context.Background())
	if err != nil {
		return err
	}

	defer unlock()

	pool, err := d.getStoragePool()
	if err != nil {
		return err
	}

	return pool.UpdateInstanceBackupFile(d, true, nil)
}

// LogFilePath returns the path to the smolvm driver log for this instance.
func (d *smolvm) LogFilePath() string {
	return filepath.Join(d.LogPath(), "smolvm.log")
}

//
// SECTION: QCOW2 / NBD / bitmap stubs
//

// CreateQcow2Snapshot is not supported by smolvm.
func (d *smolvm) CreateQcow2Snapshot(diskPath string, devName string, snapshotName string, backingFilename string, stateful bool) error {
	return errSmolVMNotSupported
}

// DeleteQcow2Snapshot is not supported by smolvm.
func (d *smolvm) DeleteQcow2Snapshot(devName string, snapshotIndex int, backingFilename string) error {
	return errSmolVMNotSupported
}

// ExportQcow2Block is not supported by smolvm.
func (d *smolvm) ExportQcow2Block(diskName string, blockIndex int) (func(), string, error) {
	return nil, "", errSmolVMNotSupported
}

// ConnectNBD is not supported by smolvm.
func (d *smolvm) ConnectNBD(diskName string, diskSize int64, writable bool) (net.Conn, func(), error) {
	return nil, nil, errSmolVMNotSupported
}

// CreateBitmap is not supported by smolvm.
func (d *smolvm) CreateBitmap(deviceNames []string, data api.StorageVolumeBitmapsPost) error {
	return errSmolVMNotSupported
}

// DeleteBitmap is not supported by smolvm.
func (d *smolvm) DeleteBitmap(deviceName string, bitmapName string) error {
	return errSmolVMNotSupported
}

// GetBitmaps is not supported by smolvm.
func (d *smolvm) GetBitmaps(deviceName string) ([]api.StorageVolumeBitmap, error) {
	return nil, errSmolVMNotSupported
}

//
// SECTION: helpers
//

// profileNames extracts profile names in stable order.
func profileNames(profiles []api.Profile) []string {
	names := make([]string, len(profiles))
	for i, p := range profiles {
		names[i] = p.Name
	}
	return names
}

// Compile-time check that *smolvm satisfies the Instance interface.
var _ instance.Instance = (*smolvm)(nil)
