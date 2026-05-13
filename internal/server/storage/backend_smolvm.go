package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/lxc/incus/v7/internal/rsync"
	"github.com/lxc/incus/v7/internal/server/instance"
	"github.com/lxc/incus/v7/internal/server/locking"
	"github.com/lxc/incus/v7/internal/server/operations"
	"github.com/lxc/incus/v7/internal/server/response"
	"github.com/lxc/incus/v7/internal/server/storage/drivers"
	"github.com/lxc/incus/v7/shared/api"
	"github.com/lxc/incus/v7/shared/revert"
)

// smolvmAgentRootfsSourceDefault is the canonical on-host location of the
// smolvm agent rootfs tree. Mirrors the resolution in
// driver_smolvm_network.go::smolvmAgentRootfsPath. The lookup is duplicated
// here because backend.go cannot import internal/server/instance/drivers
// (would create an import cycle).
const smolvmAgentRootfsSourceDefault = "/var/lib/smolvm/agent-rootfs"

// smolvmBaseImagePrefix prefixes the names of the cached agent-rootfs image
// volumes on each pool. The remainder of the name is a fingerprint of the
// source tree, so a smolvm package upgrade publishes a new image volume and
// old instances stay pinned to whichever clone they were created from.
const smolvmBaseImagePrefix = "smolvm-base-"

// smolvmAgentRootfsSource returns the host directory to clone into each
// smolvm instance volume's rootfs/ subdir at create time.
func smolvmAgentRootfsSource(inst instance.Instance) string {
	if p := inst.ExpandedConfig()["smolvm.agent_rootfs"]; p != "" {
		return p
	}

	if p := os.Getenv("SMOLVM_AGENT_ROOTFS"); p != "" {
		return p
	}

	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidate := filepath.Join(home, ".local", "share", "smolvm", "agent-rootfs")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	return smolvmAgentRootfsSourceDefault
}

// smolvmAgentRootfsFingerprint derives a stable identifier for the agent
// rootfs at src. The smolvm-agent binary is the only versioned file in the
// tree (the rest is a fixed busybox-style root), so we hash that and treat
// matching binaries as matching rootfs. Falls back to a size+mtime hash of
// the source root if the canonical binary isn't found, which keeps the
// driver working with custom agent rootfs trees built outside the upstream
// build script.
func smolvmAgentRootfsFingerprint(src string) (string, error) {
	bin := filepath.Join(src, "usr", "local", "bin", "smolvm-agent")

	info, err := os.Stat(bin)
	if err == nil && info.Mode().IsRegular() {
		f, err := os.Open(bin)
		if err != nil {
			return "", fmt.Errorf("Failed opening smolvm-agent binary %q: %w", bin, err)
		}

		defer func() { _ = f.Close() }()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return "", fmt.Errorf("Failed hashing smolvm-agent binary: %w", err)
		}

		return hex.EncodeToString(h.Sum(nil)), nil
	}

	info, err = os.Stat(src)
	if err != nil {
		return "", fmt.Errorf("Failed stating smolvm agent rootfs %q: %w", src, err)
	}

	h := sha256.New()
	fmt.Fprintf(h, "%s:%d:%d", src, info.Size(), info.ModTime().UnixNano())
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ensureSmolvmBaseImage caches the smolvm agent rootfs at src as a
// VolumeTypeImage on this pool. Returns the fingerprint that identifies the
// cached image volume so the caller can pass it to GetVolume +
// CreateVolumeFromCopy. Idempotent and safe under concurrent first-creates;
// callers serialise on a per-fingerprint lock so only one rsync runs across
// a parallel `incus init` burst.
//
// Mirrors EnsureImage's structure: take the lock, check on-disk state,
// reconcile any half-finished DB row, then create the image volume with a
// filler that populates the rootfs/ subdir.
func (b *backend) ensureSmolvmBaseImage(src string, op *operations.Operation) (string, error) {
	fingerprint, err := smolvmAgentRootfsFingerprint(src)
	if err != nil {
		return "", err
	}

	if !b.driver.Info().OptimizedImages {
		// No image-volume caching on this driver - the per-instance
		// CreateInstance path will rsync directly. The fingerprint is still
		// useful as an identifier (e.g. for diagnostics) so return it.
		return fingerprint, nil
	}

	volName := smolvmBaseImagePrefix + fingerprint

	unlock, err := locking.Lock(context.TODO(), drivers.OperationLockName("EnsureSmolvmBaseImage", b.name, drivers.VolumeTypeImage, "", fingerprint))
	if err != nil {
		return "", err
	}

	defer unlock()

	imgVol := b.GetVolume(drivers.VolumeTypeImage, drivers.ContentTypeFS, volName, nil)

	exists, err := b.driver.HasVolume(imgVol)
	if err != nil {
		return "", err
	}

	if exists {
		return fingerprint, nil
	}

	// Tear down any half-finished DB row from a crashed previous attempt.
	imgDBVol, err := VolumeDBGet(b, api.ProjectDefaultName, volName, drivers.VolumeTypeImage)
	if err != nil && !response.IsNotFoundError(err) {
		return "", err
	}

	if imgDBVol != nil {
		_ = VolumeDBDelete(b, api.ProjectDefaultName, volName, drivers.VolumeTypeImage)
	}

	reverter := revert.New()
	defer reverter.Fail()

	err = VolumeDBCreate(b, api.ProjectDefaultName, volName, "Cached smolvm agent rootfs", drivers.VolumeTypeImage, false, nil, time.Now().UTC(), time.Time{}, drivers.ContentTypeFS, false, false)
	if err != nil {
		return "", fmt.Errorf("Failed creating smolvm base image DB entry: %w", err)
	}

	reverter.Add(func() { _ = VolumeDBDelete(b, api.ProjectDefaultName, volName, drivers.VolumeTypeImage) })

	filler := &drivers.VolumeFiller{
		Fingerprint: fingerprint,
		Fill:        smolvmAgentRootfsFiller(src),
	}

	err = b.driver.CreateVolume(imgVol, filler, op)
	if err != nil {
		return "", fmt.Errorf("Failed creating smolvm base image volume: %w", err)
	}

	reverter.Add(func() { _ = b.driver.DeleteVolume(imgVol, op) })

	reverter.Success()
	return fingerprint, nil
}

// smolvmAgentRootfsFiller returns a VolumeFiller that rsyncs the agent rootfs
// at src into the target volume's rootfs/ subdir. Used by both
// ensureSmolvmBaseImage (to populate the cached image volume) and the
// non-optimized CreateInstance path (to populate the instance volume
// directly when the driver doesn't cache images, e.g. dir).
func smolvmAgentRootfsFiller(src string) func(vol drivers.Volume, _ string, _, _ bool, _ string) (int64, error) {
	return func(vol drivers.Volume, _ string, _, _ bool, _ string) (int64, error) {
		if src == "" {
			return 0, errors.New("smolvm agent rootfs source is empty")
		}

		info, err := os.Stat(src)
		if err != nil {
			return 0, fmt.Errorf("Failed to stat smolvm agent rootfs %q: %w", src, err)
		}

		if !info.IsDir() {
			return 0, fmt.Errorf("smolvm agent rootfs %q is not a directory", src)
		}

		dst := filepath.Join(vol.MountPath(), "rootfs")
		if _, err := rsync.LocalCopy(src, dst, "", false); err != nil {
			return 0, fmt.Errorf("Failed copying smolvm agent rootfs from %q to %q: %w", src, dst, err)
		}

		return 0, nil
	}
}
