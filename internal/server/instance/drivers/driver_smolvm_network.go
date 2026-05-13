package drivers

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	smolvmsdk "github.com/smol-machines/smolvm-sdk/smolvm-go"

	"github.com/lxc/incus/v7/internal/server/apparmor"
	"github.com/lxc/incus/v7/internal/server/db"
	deviceConfig "github.com/lxc/incus/v7/internal/server/device/config"
	"github.com/lxc/incus/v7/internal/server/ip"
	"github.com/lxc/incus/v7/internal/server/network"
	"github.com/lxc/incus/v7/internal/server/network/ovn"
	"github.com/lxc/incus/v7/internal/server/project"
	localUtil "github.com/lxc/incus/v7/internal/server/util"
	"github.com/lxc/incus/v7/shared/api"
	"github.com/lxc/incus/v7/shared/logger"
	"github.com/lxc/incus/v7/shared/revert"
	"github.com/lxc/incus/v7/shared/util"
)

// smolvmNetnsRoot is where iproute2 expects named network namespaces to live.
const smolvmNetnsRoot = "/var/run/netns"

// smolvmNetnsNICName returns the interface name that a nic device's peer is
// renamed to once it lands inside the per-instance netns. It honors the
// device's configured `name` (the standard Incus nic-device contract) and
// falls back to the device's map key when `name` is unset.
//
// The smolvm guest doesn't see netns interfaces directly — its TCP/IP stack
// is bypassed by TSI — so this name only affects routing decisions made by
// smolvm-server inside the netns. The kernel's FIB picks the egress NIC by
// destination, allowing multiple host networks to be reachable in parallel.
func smolvmNetnsNICName(devName string, dev deviceConfig.Device) string {
	if n := dev["name"]; n != "" {
		return n
	}
	return devName
}

// smolvmNetnsName returns a stable, sub-15-char name for this instance's
// network namespace. /run/netns names have no hard length limit but several
// downstream consumers (interface names, tooling) prefer something compact.
func (d *smolvm) smolvmNetnsName() string {
	sum := sha256.Sum256([]byte(d.machineName()))
	return "smolvm-" + hex.EncodeToString(sum[:6])
}

// smolvmNetnsPath returns the /run/netns path for this instance's namespace.
func (d *smolvm) smolvmNetnsPath() string {
	return filepath.Join(smolvmNetnsRoot, d.smolvmNetnsName())
}

// smolvmHostVethName derives a deterministic host-side veth interface name
// for an instance + nic device pair. Stays under Linux's 15-char interface
// name limit (3-char prefix + 12 hex chars).
func (d *smolvm) smolvmHostVethName(nicName string) string {
	sum := sha256.Sum256([]byte(d.machineName() + "/" + nicName))
	return "vsm" + hex.EncodeToString(sum[:6])
}

// smolvmEnsureNetns creates the per-instance network namespace if it doesn't
// already exist and brings up its loopback interface. Idempotent.
func (d *smolvm) smolvmEnsureNetns() error {
	nsPath := d.smolvmNetnsPath()
	if _, err := os.Stat(nsPath); err == nil {
		return nil
	}

	name := d.smolvmNetnsName()
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		return fmt.Errorf("Failed creating netns %q: %w (%s)", name, err, strings.TrimSpace(string(out)))
	}

	if out, err := exec.Command("ip", "-n", name, "link", "set", "lo", "up").CombinedOutput(); err != nil {
		_ = exec.Command("ip", "netns", "del", name).Run()
		return fmt.Errorf("Failed bringing up loopback in netns %q: %w (%s)", name, err, strings.TrimSpace(string(out)))
	}

	d.logger.Debug("Created smolvm netns", logger.Ctx{"name": name})
	return nil
}

// smolvmRemoveNetns deletes the per-instance network namespace if present.
// Best-effort: missing namespace is not an error.
func (d *smolvm) smolvmRemoveNetns() error {
	if _, err := os.Stat(d.smolvmNetnsPath()); err != nil {
		return nil
	}

	if out, err := exec.Command("ip", "netns", "del", d.smolvmNetnsName()).CombinedOutput(); err != nil {
		return fmt.Errorf("Failed deleting netns %q: %w (%s)", d.smolvmNetnsName(), err, strings.TrimSpace(string(out)))
	}

	d.logger.Debug("Removed smolvm netns", logger.Ctx{"name": d.smolvmNetnsName()})
	return nil
}

// Supported smolvm NIC kinds.
const (
	smolvmNICKindBridged = "bridged"
	smolvmNICKindOVN     = "ovn"
)

// smolvmNICAttachment is a fully-classified nic device ready to be attached
// to the per-instance netns by smolvmAttachNIC.
type smolvmNICAttachment struct {
	Name    string
	Device  deviceConfig.Device
	Kind    string
	Network network.Network
}

// smolvmAllNICs returns every nic device the driver knows how to attach,
// in sorted device order. Unsupported nics are logged and skipped.
//
// The netns can carry multiple veths in parallel: the kernel FIB selects
// the egress NIC by destination, so adding a second nic on a separate
// network gives the smolvm instance access to both networks without any
// smolvm-server change (TSI proxies guest sockets to smolvm-server, which
// then does standard kernel socket operations in the netns).
func (d *smolvm) smolvmAllNICs() ([]smolvmNICAttachment, error) {
	var nics []smolvmNICAttachment

	for _, devNamed := range d.expandedDevices.Sorted() {
		dev := devNamed.Config
		if dev["type"] != "nic" {
			continue
		}

		kind, n, err := d.smolvmClassifyNIC(dev)
		if err != nil {
			return nil, fmt.Errorf("nic %q: %w", devNamed.Name, err)
		}
		if kind == "" {
			d.logger.Warn("Ignoring unsupported nic on smolvm instance", logger.Ctx{"nic": devNamed.Name, "nictype": dev["nictype"]})
			continue
		}

		nics = append(nics, smolvmNICAttachment{
			Name:    devNamed.Name,
			Device:  d.smolvmHydrateNICFromVolatile(devNamed.Name, dev),
			Kind:    kind,
			Network: n,
		})
	}

	return nics, nil
}

// smolvmHydrateNICFromVolatile copies the persisted hwaddr (and any future
// volatile-only nic state) into a clone of the device config. The expanded
// device map skips volatile-derived keys, so the OVN port setup would
// otherwise see an empty MAC and reject the request.
func (d *smolvm) smolvmHydrateNICFromVolatile(nicName string, dev deviceConfig.Device) deviceConfig.Device {
	hydrated := dev.Clone()
	if hydrated["hwaddr"] == "" {
		hydrated["hwaddr"] = d.localConfig[fmt.Sprintf("volatile.%s.hwaddr", nicName)]
	}

	return hydrated
}

// smolvmClassifyNIC returns the kind of a nic device ("bridged" or "ovn") plus
// the parent network handle for OVN nics (nil for bridged). An empty kind
// means the device is not supported by the smolvm driver.
func (d *smolvm) smolvmClassifyNIC(dev deviceConfig.Device) (string, network.Network, error) {
	if dev["nictype"] == "bridged" {
		return smolvmNICKindBridged, nil, nil
	}

	if dev["network"] == "" {
		return "", nil, nil
	}

	networkProjectName, _, err := project.NetworkProject(d.state.DB.Cluster, d.Project().Name)
	if err != nil {
		return "", nil, fmt.Errorf("Failed resolving network project: %w", err)
	}

	n, err := network.LoadByName(d.state, networkProjectName, dev["network"])
	if err != nil {
		return "", nil, fmt.Errorf("Failed loading network %q: %w", dev["network"], err)
	}

	switch n.Type() {
	case "bridge":
		return smolvmNICKindBridged, n, nil
	case "ovn":
		return smolvmNICKindOVN, n, nil
	}

	return "", n, nil
}

// smolvmAttachNIC routes to the kind-specific attach helper.
func (d *smolvm) smolvmAttachNIC(nicName string, dev deviceConfig.Device, kind string, n network.Network) error {
	switch kind {
	case smolvmNICKindBridged:
		return d.smolvmAttachBridgedNIC(nicName, dev)
	case smolvmNICKindOVN:
		return d.smolvmAttachOVNNIC(nicName, dev, n)
	}

	return fmt.Errorf("Unknown smolvm nic kind %q", kind)
}

// smolvmAttachBridgedNIC creates a veth pair, attaches the host side to the
// device's parent bridge, and moves the peer into the per-instance netns
// where it is renamed to the device's configured `name` (eth0 by default),
// brought up, and (best-effort) configured for DHCP.
//
// Idempotent: if the host-side veth already exists, the call is a no-op.
func (d *smolvm) smolvmAttachBridgedNIC(nicName string, dev deviceConfig.Device) error {
	netnsNIC := smolvmNetnsNICName(nicName, dev)
	bridge := dev["network"]
	if bridge == "" {
		bridge = dev["parent"]
	}
	if bridge == "" {
		return fmt.Errorf("nic %q has no parent or network configured", nicName)
	}

	hostName := d.smolvmHostVethName(nicName)

	if network.InterfaceExists(hostName) {
		return nil
	}

	reverter := revert.New()
	defer reverter.Fail()

	// Pick a unique peer name; we'll rename it once it lands inside the netns.
	peerName := network.RandomDevName("vsmp")

	veth := &ip.Veth{
		Link: ip.Link{
			Name: hostName,
			Up:   true,
		},
		Peer: ip.Link{
			Name: peerName,
		},
	}

	if mtu, err := network.GetDevMTU(bridge); err == nil && mtu > 0 {
		veth.MTU = uint32(mtu)
		veth.Peer.MTU = uint32(mtu)
	}

	if hwaddr := dev["hwaddr"]; hwaddr != "" {
		mac, err := net.ParseMAC(hwaddr)
		if err != nil {
			return fmt.Errorf("Failed parsing hwaddr %q on nic %q: %w", hwaddr, nicName, err)
		}
		veth.Peer.Address = mac
	}

	if err := veth.Add(); err != nil {
		return fmt.Errorf("Failed creating veth pair (%s/%s): %w", hostName, peerName, err)
	}

	reverter.Add(func() { _ = network.InterfaceRemove(hostName) })

	if err := network.AttachInterface(d.state, bridge, hostName); err != nil {
		return fmt.Errorf("Failed attaching %q to bridge %q: %w", hostName, bridge, err)
	}

	reverter.Add(func() { _ = network.DetachInterface(d.state, bridge, hostName) })

	nsName := d.smolvmNetnsName()
	if out, err := exec.Command("ip", "link", "set", peerName, "netns", nsName).CombinedOutput(); err != nil {
		return fmt.Errorf("Failed moving peer %q into netns %q: %w (%s)", peerName, nsName, err, strings.TrimSpace(string(out)))
	}

	if out, err := exec.Command("ip", "-n", nsName, "link", "set", peerName, "name", netnsNIC).CombinedOutput(); err != nil {
		return fmt.Errorf("Failed renaming peer in netns %q: %w (%s)", nsName, err, strings.TrimSpace(string(out)))
	}

	if out, err := exec.Command("ip", "-n", nsName, "link", "set", netnsNIC, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("Failed bringing up %s in netns %q: %w (%s)", netnsNIC, nsName, err, strings.TrimSpace(string(out)))
	}

	if err := d.smolvmConfigureNetnsIP(nicName, netnsNIC, dev); err != nil {
		// Don't fail start over an IP misconfiguration; surface it loudly.
		d.logger.Warn("Failed configuring netns IP, smolvm guest may have no outbound network", logger.Ctx{"nic": nicName, "err": err})
	}

	d.logger.Info("Attached smolvm nic", logger.Ctx{"nic": nicName, "host": hostName, "bridge": bridge, "netns": nsName})

	reverter.Success()
	return nil
}

// smolvmDetachAllNICs walks every nic device on the instance and tears down
// whatever was set up for it on Start. Best-effort: a missing veth or stale
// classification does not block the rest of the cleanup.
//
// For bridged nics this is just `network.DetachInterface` + remove the veth.
// For OVN nics it also unassociates and deletes the OVS port and releases the
// OVN logical switch port.
func (d *smolvm) smolvmDetachAllNICs() error {
	var firstErr error

	for _, devNamed := range d.expandedDevices.Sorted() {
		dev := devNamed.Config
		if dev["type"] != "nic" {
			continue
		}

		hostName := d.smolvmHostVethName(devNamed.Name)
		if !network.InterfaceExists(hostName) {
			continue
		}

		// Classify with a tolerant fallback: a deleted/renamed parent network
		// would otherwise strand the veth here and leak it forever.
		kind, n, err := d.smolvmClassifyNIC(dev)
		if err != nil {
			d.logger.Warn("Failed classifying nic during detach; falling back to bridged cleanup", logger.Ctx{"nic": devNamed.Name, "err": err})
			kind = smolvmNICKindBridged
		}

		switch kind {
		case smolvmNICKindOVN:
			if err := d.smolvmDetachOneOVNNIC(devNamed.Name, dev, n); err != nil && firstErr == nil {
				firstErr = err
			}
		default:
			if err := d.smolvmDetachOneBridgedNIC(devNamed.Name, dev); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}

	return firstErr
}

// smolvmDetachOneBridgedNIC removes a single bridged nic's host-side veth,
// detaching it from its parent bridge first when one is configured.
func (d *smolvm) smolvmDetachOneBridgedNIC(nicName string, dev deviceConfig.Device) error {
	hostName := d.smolvmHostVethName(nicName)
	if !network.InterfaceExists(hostName) {
		return nil
	}

	bridge := dev["network"]
	if bridge == "" {
		bridge = dev["parent"]
	}
	if bridge != "" {
		_ = network.DetachInterface(d.state, bridge, hostName)
	}

	if err := network.InterfaceRemove(hostName); err != nil {
		return fmt.Errorf("Failed removing veth %q: %w", hostName, err)
	}

	return nil
}

// smolvmConfigureNetnsIP applies an IPv4 address + default route inside the
// per-instance netns. Logic:
//
//  1. If the device has ipv4.address set, use that with the bridge's gateway.
//  2. Otherwise, attempt DHCP (best-effort: skipped if no client is on PATH).
//
// When multiple nics are attached, each call adds a default route on its own
// interface; the kernel resolves duplicates by RTA_OIF and metric, so a
// secondary nic's "already exists" route add is logged but not fatal.
func (d *smolvm) smolvmConfigureNetnsIP(nicName string, netnsNIC string, dev deviceConfig.Device) error {
	nsName := d.smolvmNetnsName()

	if static := dev["ipv4.address"]; static != "" {
		bridge := dev["network"]
		if bridge == "" {
			bridge = dev["parent"]
		}

		gateway, prefix, err := smolvmBridgeIPv4(bridge)
		if err != nil {
			return fmt.Errorf("Failed reading bridge IPv4 details: %w", err)
		}

		addr := fmt.Sprintf("%s/%d", static, prefix)
		if out, err := exec.Command("ip", "-n", nsName, "addr", "add", addr, "dev", netnsNIC).CombinedOutput(); err != nil {
			return fmt.Errorf("Failed adding addr %q in netns: %w (%s)", addr, err, strings.TrimSpace(string(out)))
		}

		if gateway != "" {
			if out, err := exec.Command("ip", "-n", nsName, "route", "add", "default", "via", gateway, "dev", netnsNIC).CombinedOutput(); err != nil {
				// A duplicate default route from a second NIC on the same
				// gateway is expected; warn rather than fail the start.
				d.logger.Warn("Default route add skipped", logger.Ctx{"nic": nicName, "gateway": gateway, "err": err, "out": strings.TrimSpace(string(out))})
			}
		}

		return nil
	}

	return d.smolvmConfigureNetnsIPViaDHCP(nicName, netnsNIC)
}

// smolvmBridgeIPv4 returns the first IPv4 gateway address and prefix length
// configured on a bridge. Used to derive a default route when the user
// supplies a static ipv4.address but no gateway.
func smolvmBridgeIPv4(bridge string) (gateway string, prefix int, err error) {
	iface, err := net.InterfaceByName(bridge)
	if err != nil {
		return "", 0, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", 0, err
	}

	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.To4() == nil {
			continue
		}

		ones, _ := ipnet.Mask.Size()
		return ipnet.IP.To4().String(), ones, nil
	}

	return "", 0, errors.New("bridge has no IPv4 address")
}

// smolvmOVNNet is the subset of network.Network we need from an OVN-typed
// network: enough to allocate and release a logical switch port for the
// instance.
type smolvmOVNNet interface {
	network.Network
	InstanceDevicePortStart(opts *network.OVNInstanceNICSetupOpts, securityACLsRemove []string) (ovn.OVNSwitchPort, []net.IP, error)
	InstanceDevicePortStop(ovsExternalOVNPort ovn.OVNSwitchPort, opts *network.OVNInstanceNICStopOpts) error
}

// smolvmAttachOVNNIC plumbs an OVN-managed nic into the per-instance netns.
// The high-level steps mirror nic_ovn.Start in the standard device path:
// allocate an OVN logical switch port for the instance, attach a veth pair
// (host-side into the OVN integration bridge, peer into the netns under the
// device's configured `name`), then set requested-chassis on the LSP so
// ovn-controller binds it locally.
//
// Idempotent: a pre-existing host-side veth short-circuits the call.
func (d *smolvm) smolvmAttachOVNNIC(nicName string, dev deviceConfig.Device, n network.Network) error {
	netnsNIC := smolvmNetnsNICName(nicName, dev)
	ovnNet, ok := n.(smolvmOVNNet)
	if !ok {
		return fmt.Errorf("Network %q is not an OVN network", n.Name())
	}

	integrationBridge := d.state.GlobalConfig.NetworkOVNIntegrationBridge()
	if !util.PathExists(fmt.Sprintf("/sys/class/net/%s", integrationBridge)) {
		return fmt.Errorf("OVN integration bridge %q doesn't exist", integrationBridge)
	}

	hostName := d.smolvmHostVethName(nicName)
	if network.InterfaceExists(hostName) {
		return nil
	}

	ovnnb, _, err := d.state.OVN()
	if err != nil {
		return fmt.Errorf("Failed connecting to OVN northbound: %w", err)
	}

	vswitch, err := d.state.OVS()
	if err != nil {
		return fmt.Errorf("Failed connecting to OVS: %w", err)
	}

	reverter := revert.New()
	defer reverter.Fail()

	// Resolve the uplink so we can pass its config to InstanceDevicePortStart
	// (used by OVN to populate DHCP options, gateway, DNS, etc.).
	uplinkName := n.Config()["network"]
	var uplinkConfig map[string]string
	if uplinkName != "" && uplinkName != "none" {
		var uplink *api.Network
		err = d.state.DB.Cluster.Transaction(context.TODO(), func(ctx context.Context, tx *db.ClusterTx) error {
			_, uplink, _, err = tx.GetNetworkInAnyState(ctx, api.ProjectDefaultName, uplinkName)
			return err
		})
		if err != nil {
			return fmt.Errorf("Failed loading uplink network %q: %w", uplinkName, err)
		}

		uplinkConfig = uplink.Config
	}

	// Create the veth pair. The peer name is randomized; we rename it to
	// netnsNIC once it's inside the netns.
	peerName := network.RandomDevName("vsmp")

	veth := &ip.Veth{
		Link: ip.Link{
			Name: hostName,
			Up:   true,
		},
		Peer: ip.Link{
			Name: peerName,
		},
	}

	if mtuStr := n.Config()["bridge.mtu"]; mtuStr != "" {
		if mtu, mtuErr := strconv.Atoi(mtuStr); mtuErr == nil && mtu > 0 {
			veth.MTU = uint32(mtu)
			veth.Peer.MTU = uint32(mtu)
		}
	}

	if hwaddr := dev["hwaddr"]; hwaddr != "" {
		mac, err := net.ParseMAC(hwaddr)
		if err != nil {
			return fmt.Errorf("Failed parsing hwaddr %q on nic %q: %w", hwaddr, nicName, err)
		}
		veth.Peer.Address = mac
	}

	if err := veth.Add(); err != nil {
		return fmt.Errorf("Failed creating veth pair (%s/%s): %w", hostName, peerName, err)
	}

	reverter.Add(func() { _ = network.InterfaceRemove(hostName) })

	// The host-side veth is just a passthrough into br-int — disable IPv6
	// link-local and IPv4 forwarding so the host doesn't end up routing for
	// the instance. Mirrors nic_ovn.setupHostNIC.
	if err := localUtil.SysctlSet(fmt.Sprintf("net/ipv6/conf/%s/disable_ipv6", hostName), "1"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("Failed disabling IPv6 on %q: %w", hostName, err)
	}

	if err := localUtil.SysctlSet(fmt.Sprintf("net/ipv4/conf/%s/forwarding", hostName), "0"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("Failed disabling IPv4 forwarding on %q: %w", hostName, err)
	}

	// Allocate an OVN logical switch port for this instance/device pair.
	lspName, dnsIPs, err := ovnNet.InstanceDevicePortStart(&network.OVNInstanceNICSetupOpts{
		InstanceUUID: d.localConfig["volatile.uuid"],
		DeviceName:   nicName,
		DeviceConfig: dev,
		UplinkConfig: uplinkConfig,
		DNSName:      d.Name(),
	}, nil)
	if err != nil {
		return fmt.Errorf("Failed setting up OVN port: %w", err)
	}

	reverter.Add(func() {
		_ = ovnNet.InstanceDevicePortStop("", &network.OVNInstanceNICStopOpts{
			InstanceUUID: d.localConfig["volatile.uuid"],
			DeviceName:   nicName,
			DeviceConfig: dev,
		})
	})

	// Plug the host-side veth into the integration bridge and wire the OVS
	// port to the OVN logical switch port. The latter is what ovn-controller
	// watches for to claim the port.
	if err := vswitch.CreateBridgePort(context.TODO(), integrationBridge, hostName, true); err != nil {
		return fmt.Errorf("Failed adding %q to %q: %w", hostName, integrationBridge, err)
	}

	reverter.Add(func() { _ = vswitch.DeleteBridgePort(context.TODO(), integrationBridge, hostName) })

	if err := vswitch.AssociateInterfaceOVNSwitchPort(context.TODO(), hostName, string(lspName)); err != nil {
		return fmt.Errorf("Failed associating %q with LSP %q: %w", hostName, lspName, err)
	}

	// Pin the LSP to this chassis so ovn-controller activates it locally.
	chassisID, err := vswitch.GetChassisID(context.TODO())
	if err != nil {
		return fmt.Errorf("Failed reading OVS chassis ID: %w", err)
	}

	if err := ovnnb.UpdateLogicalSwitchPortOptions(context.TODO(), lspName, map[string]string{"requested-chassis": chassisID}); err != nil {
		return fmt.Errorf("Failed pinning LSP %q to chassis %q: %w", lspName, chassisID, err)
	}

	// Move the peer into the per-instance netns and rename it to netnsNIC.
	nsName := d.smolvmNetnsName()
	if out, err := exec.Command("ip", "link", "set", peerName, "netns", nsName).CombinedOutput(); err != nil {
		return fmt.Errorf("Failed moving peer %q into netns %q: %w (%s)", peerName, nsName, err, strings.TrimSpace(string(out)))
	}

	if out, err := exec.Command("ip", "-n", nsName, "link", "set", peerName, "name", netnsNIC).CombinedOutput(); err != nil {
		return fmt.Errorf("Failed renaming peer in netns %q: %w (%s)", nsName, err, strings.TrimSpace(string(out)))
	}

	if out, err := exec.Command("ip", "-n", nsName, "link", "set", netnsNIC, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("Failed bringing up %s in netns %q: %w (%s)", netnsNIC, nsName, err, strings.TrimSpace(string(out)))
	}

	// OVN-NB has already allocated the LSP's IPv4 (returned in dnsIPs).
	// Configure the netns directly instead of running dhcpcd, which would
	// otherwise spend ~7s on RFC 2131 randomized initial delay (1–10s) and
	// RFC 5227 ACD probing (~5s) — both guarding against conflicts that
	// can't occur on an OVN logical switch where allocation is exclusive
	// at the NB DB layer.
	if err := d.smolvmConfigureNetnsIPFromOVN(nicName, netnsNIC, n, dnsIPs); err != nil {
		d.logger.Warn("Failed configuring OVN-allocated IP in netns, smolvm guest may have no outbound network", logger.Ctx{"nic": nicName, "err": err})
	}

	d.logger.Info("Attached smolvm OVN nic", logger.Ctx{"nic": nicName, "host": hostName, "lsp": lspName, "netns": nsName, "chassis": chassisID, "dnsIPs": dnsIPs})

	reverter.Success()
	return nil
}

// smolvmConfigureNetnsIPFromOVN configures an IPv4 address + default route in
// the per-instance netns using the IP OVN-NB already allocated for the LSP
// (returned in dnsIPs from InstanceDevicePortStart). Bypasses dhcpcd entirely,
// which contributes ~7s per VM start to RFC-mandated defensive delays (RFC 2131
// randomized initial discover, RFC 5227 ACD probing). Both guard against
// conflicts OVN-NB already prevents at the database layer.
//
// Prefix and gateway come from the OVN network's `ipv4.address` (the logical
// router's internal port CIDR). DNS is not written to /etc/resolv.conf here,
// matching the existing static-IP code path — the smolvm guest uses TSI for
// outbound traffic, and smolvm-server inherits the host's resolver.
func (d *smolvm) smolvmConfigureNetnsIPFromOVN(nicName, netnsNIC string, n network.Network, dnsIPs []net.IP) error {
	var ipv4 net.IP
	for _, ip := range dnsIPs {
		if v4 := ip.To4(); v4 != nil {
			ipv4 = v4
			break
		}
	}
	if ipv4 == nil {
		d.logger.Warn("OVN port has no IPv4 in dnsIPs; skipping netns IP config", logger.Ctx{"nic": nicName})
		return nil
	}

	addrCIDR := n.Config()["ipv4.address"]
	if addrCIDR == "" || addrCIDR == "none" {
		return fmt.Errorf("OVN network %q has no ipv4.address; cannot derive netmask", n.Name())
	}

	routerIP, ipNet, err := net.ParseCIDR(addrCIDR)
	if err != nil {
		return fmt.Errorf("Failed parsing OVN ipv4.address %q: %w", addrCIDR, err)
	}

	// Gateway resolution mirrors network/driver_ovn.getGatewayIpv4:
	// ipv4.dhcp.gateway override > router internal port IP. "none" suppresses
	// the default route entirely (l2-only / custom-routed networks).
	gateway := routerIP
	if gwCfg := n.Config()["ipv4.dhcp.gateway"]; gwCfg != "" {
		if gwCfg == "none" {
			gateway = nil
		} else {
			gateway = net.ParseIP(gwCfg)
			if gateway == nil {
				return fmt.Errorf("Failed parsing OVN ipv4.dhcp.gateway %q", gwCfg)
			}
		}
	}

	prefix, _ := ipNet.Mask.Size()
	nsName := d.smolvmNetnsName()
	addr := fmt.Sprintf("%s/%d", ipv4.String(), prefix)

	if out, err := exec.Command("ip", "-n", nsName, "addr", "add", addr, "dev", netnsNIC).CombinedOutput(); err != nil {
		return fmt.Errorf("Failed adding addr %q in netns: %w (%s)", addr, err, strings.TrimSpace(string(out)))
	}

	if gateway != nil {
		if out, err := exec.Command("ip", "-n", nsName, "route", "add", "default", "via", gateway.String(), "dev", netnsNIC).CombinedOutput(); err != nil {
			// A second NIC on the same gateway will collide here; warn rather than fail the start.
			d.logger.Warn("Default route add skipped", logger.Ctx{"nic": nicName, "gateway": gateway.String(), "err": err, "out": strings.TrimSpace(string(out))})
		}
	}

	d.logger.Debug("Configured netns IP from OVN-allocated address", logger.Ctx{"nic": nicName, "netns": nsName, "addr": addr, "gateway": gateway})
	return nil
}

// smolvmConfigureNetnsIPViaDHCP runs a DHCP client inside the per-instance
// netns to pick up an IPv4 lease for the named netns interface. Used by both
// the bridged path (when no static config is supplied) and the OVN path.
//
// Tries udhcpc, dhcpcd, and dhclient in order — whichever is on PATH wins.
// Concurrent VM starts share the mount namespace through which dhcpcd and
// dhclient write their pid/lease files, so we shadow those directories with
// a private tmpfs inside each call. Multiple nics in the same netns get
// distinct pidfile/leasefile paths so they don't collide either.
func (d *smolvm) smolvmConfigureNetnsIPViaDHCP(nicName string, netnsNIC string) error {
	nsName := d.smolvmNetnsName()

	type dhcpClient struct {
		name string
		args []string
		// preCmd runs in the netns mount namespace (which is private, since
		// `ip netns exec` already unshares CLONE_NEWNS) immediately before the
		// client. Used to shadow shared state directories with tmpfs so
		// concurrent invocations don't collide on pidfiles or lease files.
		preCmd string
	}

	clients := []dhcpClient{
		// udhcpc is stateless, no isolation needed.
		{"udhcpc", []string{"-q", "-f", "-n", "-i", netnsNIC}, ""},
		// dhcpcd v10 has no runtime --pidfile/--dbdir flag, so tmpfs-shadow
		// its state dirs.
		{"dhcpcd", []string{"-1", "-q", netnsNIC}, "mkdir -p /run/dhcpcd /var/lib/dhcpcd && mount -t tmpfs none /run/dhcpcd && mount -t tmpfs none /var/lib/dhcpcd"},
		// dhclient supports -pf/-lf so it doesn't need a tmpfs shadow; give
		// each invocation a unique pidfile/leasefile under /tmp instead.
		{"dhclient", nil, ""},
	}

	var lastErr error
	for _, c := range clients {
		path, err := exec.LookPath(c.name)
		if err != nil {
			continue
		}

		args := c.args
		if c.name == "dhclient" {
			tag := d.smolvmNetnsName() + "." + netnsNIC
			args = []string{
				"-1", "-v",
				"-pf", fmt.Sprintf("/tmp/dhclient.%s.pid", tag),
				"-lf", fmt.Sprintf("/tmp/dhclient.%s.lease", tag),
				netnsNIC,
			}
		}

		var cmd *exec.Cmd
		if c.preCmd != "" {
			shellCmd := c.preCmd + " && exec \"$@\""
			shellArgs := append([]string{"netns", "exec", nsName, "sh", "-c", shellCmd, "sh", path}, args...)
			cmd = exec.Command("ip", shellArgs...)
		} else {
			cmd = exec.Command("ip", append([]string{"netns", "exec", nsName, path}, args...)...)
		}

		out, err := cmd.CombinedOutput()
		if err != nil {
			lastErr = fmt.Errorf("%s failed in netns %q: %w (%s)", c.name, nsName, err, strings.TrimSpace(string(out)))
			continue
		}

		d.logger.Debug("Configured netns IP via DHCP", logger.Ctx{"nic": nicName, "netns": nsName, "client": c.name})
		return nil
	}

	if lastErr != nil {
		return lastErr
	}
	return errors.New("no DHCP client (udhcpc/dhcpcd/dhclient) on PATH")
}

// smolvmDetachOneOVNNIC tears down OVN-side state and the host-side veth for
// a single OVN nic. Best-effort: every step is logged but does not block the
// next.
func (d *smolvm) smolvmDetachOneOVNNIC(nicName string, dev deviceConfig.Device, n network.Network) error {
	hostName := d.smolvmHostVethName(nicName)

	integrationBridge := d.state.GlobalConfig.NetworkOVNIntegrationBridge()

	// Read the LSP off the OVS interface (set when we created the port) so we
	// can release it. If OVS is unavailable we still try to remove the veth.
	var lspName string
	if vswitch, err := d.state.OVS(); err == nil {
		if name, lookupErr := vswitch.GetInterfaceAssociatedOVNSwitchPort(context.TODO(), hostName); lookupErr == nil {
			lspName = name
		}

		_ = vswitch.DeleteBridgePort(context.TODO(), integrationBridge, hostName)
	}

	if ovnNet, ok := n.(smolvmOVNNet); ok {
		_ = ovnNet.InstanceDevicePortStop(ovn.OVNSwitchPort(lspName), &network.OVNInstanceNICStopOpts{
			InstanceUUID: d.localConfig["volatile.uuid"],
			DeviceName:   nicName,
			DeviceConfig: dev,
		})
	}

	if network.InterfaceExists(hostName) {
		if err := network.InterfaceRemove(hostName); err != nil {
			return fmt.Errorf("Failed removing veth %q: %w", hostName, err)
		}
	}

	return nil
}

//
// SECTION: per-instance smolvm-server lifecycle
//
// One smolvm-server per Incus instance, running inside the per-instance
// netns. The server listens on a unix socket so the driver can talk to it
// without exposing it on a TCP port.
//
// The server is detached from incusd via setsid so it survives an incusd
// restart. On restart, the driver detects an existing server via a pidfile
// and reattaches. Crashed/missing servers are respawned on next Start().

// smolvmServerSocketPath returns the unix socket the per-instance smolvm-server
// listens on. Lives under d.RunPath() to keep it on tmpfs and out of the way.
func (d *smolvm) smolvmServerSocketPath() string {
	return filepath.Join(d.RunPath(), "smolvm-server.sock")
}

// smolvmServerPidPath returns the pidfile path for the per-instance smolvm-server.
func (d *smolvm) smolvmServerPidPath() string {
	return filepath.Join(d.RunPath(), "smolvm-server.pid")
}

// smolvmServerLogPath returns the log file path for the per-instance smolvm-server.
func (d *smolvm) smolvmServerLogPath() string {
	return filepath.Join(d.LogPath(), "smolvm-server.log")
}

// smolvmServerCacheDir returns the per-instance XDG_CACHE_HOME the smolvm-server
// uses. The bind-mounted Incus storage volume lands under this dir at
// $cache/smolvm/vms/$hash.
func (d *smolvm) smolvmServerCacheDir() string {
	return filepath.Join(d.RunPath(), "cache")
}

// smolvmServerDataDir returns the per-instance XDG_DATA_HOME the smolvm-server
// uses. Without this, every smolvm-server process resolves
// `dirs::data_local_dir()` to the same `~/.local/share` path and writes its
// VM database to the same SQLite file, causing the load_persisted_machines
// path on a new server to reach into other instances' state and (sometimes)
// reject CreateMachine for an unrelated machine. Per-instance XDG_DATA_HOME
// gives each server an isolated DB at $RunPath/data/smolvm/server/smolvm.db.
func (d *smolvm) smolvmServerDataDir() string {
	return filepath.Join(d.RunPath(), "data")
}

// smolvmAgentRootfsPath returns the path the smolvm-server should use as the
// agent VM rootfs. Default is the instance volume's `rootfs/` subdir,
// populated at create time from a per-pool image volume
// (storage/backend_smolvm.go::ensureSmolvmBaseImage). The container model:
// each instance gets its own CoW clone of the agent rootfs, so the guest
// agent can write `.smolvm-ready` through virtio-fs without colliding with
// peers and without needing a shared writable root.
//
// `smolvm.agent_rootfs` config is an escape hatch for operators who want to
// pin a custom path (development, custom builds). When set, materialization
// is bypassed - the path is used verbatim, AppArmor permitting. Stale
// instances created before per-instance rootfs landed fall back to the
// canonical global location so an in-place upgrade doesn't strand them.
func (d *smolvm) smolvmAgentRootfsPath() string {
	if p := d.expandedConfig["smolvm.agent_rootfs"]; p != "" {
		return p
	}

	if volRoot, err := filepath.EvalSymlinks(d.Path()); err == nil {
		candidate := filepath.Join(volRoot, "rootfs")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	if p := os.Getenv("SMOLVM_AGENT_ROOTFS"); p != "" {
		return p
	}

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "/root"
	}

	return filepath.Join(home, ".local", "share", "smolvm", "agent-rootfs")
}

// smolvmBinaryPath returns the path to the smolvm CLI binary, honouring the
// smolvm.binary_path config override and falling back to PATH lookup.
func (d *smolvm) smolvmBinaryPath() string {
	if p := d.expandedConfig["smolvm.binary_path"]; p != "" {
		return p
	}

	if p, err := exec.LookPath("smolvm"); err == nil {
		return p
	}

	// Last-resort: shell will surface a clear error if it's not on PATH.
	return "smolvm"
}

// smolvmServerDropTarget picks the host UID/GID the smolvm-server process
// should run as. Preference order:
//  1. Per-instance slot derived deterministically from the project's
//     restricted.idmap.uid window (matches the LXC isolation pattern, where
//     each instance lands at a different host UID inside the project range).
//  2. State.OS.UnprivUID (matches qemu's -runas — defense in depth without
//     per-tenant separation).
//  3. (0, 0) — preserve old root behavior if neither is available.
//
// The kvmGID return is the host GID of the `kvm` group (0 if absent); the
// caller adds it as a supplementary group post-drop so smolvm-server retains
// /dev/kvm access. dropPriv is true iff we picked a non-root target.
func (d *smolvm) smolvmServerDropTarget() (uid uint32, gid uint32, kvmGID uint32, dropPriv bool) {
	if rangeStr := d.project.Config["restricted.idmap.uid"]; rangeStr != "" {
		first := strings.SplitN(rangeStr, ",", 2)[0]
		start, size, err := util.ParseUint32Range(strings.TrimSpace(first))
		if err == nil && size > 0 {
			// Deterministic per-instance offset within the project window.
			// project+name+id keeps the slot stable across restarts and
			// distinct between any two instances on the same host.
			seed := fmt.Sprintf("%s/%s/%d", d.project.Name, d.name, d.id)
			sum := sha256.Sum256([]byte(seed))
			offset := binary.BigEndian.Uint32(sum[:4]) % size
			uid = start + offset
			gid = uid
		}
	}

	if uid == 0 {
		uid = d.state.OS.UnprivUID
		gid = d.state.OS.UnprivGID
	}

	if g, err := user.LookupGroup("kvm"); err == nil {
		if v, err := strconv.ParseUint(g.Gid, 10, 32); err == nil {
			kvmGID = uint32(v)
		}
	}

	dropPriv = uid != 0
	return uid, gid, kvmGID, dropPriv
}

// smolvmServerChownTree recursively chowns dir and its contents to (uid, gid).
// Used to hand the per-instance state directories to the dropped uid so the
// smolvm-server process can read/write them after the privilege drop.
// filepath.WalkDir only stats metadata; this is bounded by entry count, not
// file size, so it's fast even when sparse disks under cache/ are multi-GB.
func smolvmServerChownTree(dir string, uid, gid uint32) error {
	return filepath.WalkDir(dir, func(p string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		return os.Lchown(p, int(uid), int(gid))
	})
}

// smolvmServerStart spawns smolvm serve start inside the per-instance netns,
// listening on a per-instance unix socket. Returns once /health responds, or
// after ctx is done.
//
// Idempotent: a running server (detected via pidfile) is left alone.
func (d *smolvm) smolvmServerStart(ctx context.Context) error {
	if d.smolvmServerIsAlive() {
		return nil
	}

	// Stale state from a previous run.
	_ = os.Remove(d.smolvmServerSocketPath())
	_ = os.Remove(d.smolvmServerPidPath())

	targetUID, targetGID, kvmGID, dropPriv := d.smolvmServerDropTarget()

	if err := os.MkdirAll(d.RunPath(), 0o700); err != nil {
		return fmt.Errorf("Failed creating instance run dir: %w", err)
	}

	if err := os.MkdirAll(d.LogPath(), 0o700); err != nil {
		return fmt.Errorf("Failed creating instance log dir: %w", err)
	}

	if err := os.MkdirAll(d.smolvmServerCacheDir(), 0o700); err != nil {
		return fmt.Errorf("Failed creating smolvm cache dir: %w", err)
	}

	if err := os.MkdirAll(d.smolvmServerDataDir(), 0o700); err != nil {
		return fmt.Errorf("Failed creating smolvm data dir: %w", err)
	}

	// One recursive chown rooted at RunPath covers the socket dir, pidfile
	// dir, cache and data subdirs. LogPath is a separate tree. The WalkDir
	// descends into the bind-mounted `<volRoot>/smol/` subdir too, so the
	// on-disk subdir inode ends up owned by the dropped uid. We never
	// chown the volume root (which keeps Incus's mode-0100 invariant) -
	// see smolvmEnsureMounted for why the bind mount targets a subdir.
	if dropPriv {
		if err := smolvmServerChownTree(d.RunPath(), targetUID, targetGID); err != nil {
			return fmt.Errorf("Failed chowning run path: %w", err)
		}

		if err := smolvmServerChownTree(d.LogPath(), targetUID, targetGID); err != nil {
			return fmt.Errorf("Failed chowning log path: %w", err)
		}
	}

	logFile, err := os.OpenFile(d.smolvmServerLogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("Failed opening smolvm-server log: %w", err)
	}
	defer logFile.Close()

	if dropPriv {
		if err := logFile.Chown(int(targetUID), int(targetGID)); err != nil {
			return fmt.Errorf("Failed chowning smolvm-server log: %w", err)
		}
	}

	binaryPath := d.smolvmBinaryPath()
	nsName := d.smolvmNetnsName()
	sockPath := d.smolvmServerSocketPath()

	args := []string{"netns", "exec", nsName}
	if dropPriv {
		// Tier 3: unshare mount + PID namespaces before dropping privs. We're
		// still root here (under `ip netns exec`), so the unshare(2) calls
		// don't need a user namespace. --fork is required for --pid: unshare(2)
		// with CLONE_NEWPID only places future children in the new pidns, so
		// unshare(1) forks and the child becomes PID 1 in the new namespace.
		// --kill-child arranges PR_SET_PDEATHSIG on the child, so when incusd
		// kills the unshare parent (the PID we record), the new PID 1 receives
		// SIGKILL and the kernel reaps the entire pidns. --mount-proc remounts
		// /proc inside the new mount namespace so PID listings reflect the new
		// pidns. Default mount-propagation for --mount is private, so any
		// mounts we set up inside don't leak back to the host.
		args = append(args, "unshare",
			"--mount",
			"--pid",
			"--mount-proc",
			"--fork",
			"--kill-child",
		)

		// setpriv drops the uid/gid + supplementary groups + every capability
		// before exec'ing smolvm. --no-new-privs blocks any later setuid
		// binary from re-elevating. We retain the `kvm` group (if present) so
		// smolvm-server can open /dev/kvm.
		setprivArgs := []string{
			"setpriv",
			"--reuid", strconv.FormatUint(uint64(targetUID), 10),
			"--regid", strconv.FormatUint(uint64(targetGID), 10),
			"--no-new-privs",
			"--inh-caps", "-all",
			"--bounding-set", "-all",
		}

		if kvmGID != 0 {
			setprivArgs = append(setprivArgs, "--groups", strconv.FormatUint(uint64(kvmGID), 10))
		} else {
			setprivArgs = append(setprivArgs, "--clear-groups")
		}

		args = append(args, setprivArgs...)

		// Apply the per-instance AppArmor profile. Today the profile is a
		// permissive baseline (capability,/file,/etc.) — its job is to LSM-tag
		// the process so a later tightening pass can swap in a deny-by-default
		// policy without changing the runtime command. On systems without
		// AppArmor the wrapper is skipped (aa-exec would not exist).
		if d.state.OS.AppArmorAvailable {
			args = append(args, "aa-exec", "-p", apparmor.InstanceProfileName(d), "--")
		}
	}

	args = append(args, binaryPath, "serve", "start", "--listen", "unix://"+sockPath)

	cmd := exec.Command("ip", args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// XDG_DATA_HOME isolates each smolvm-server's SQLite DB. Without an
	// explicit SMOLVM_AGENT_ROOTFS, smolvm's default rootfs lookup would
	// also resolve through XDG_DATA_HOME and miss the agent rootfs entirely.
	// Default to the per-instance rootfs in the storage volume; see
	// smolvmAgentRootfsPath for resolution rules and overrides.
	rootfsEnv := d.smolvmAgentRootfsPath()

	cmd.Env = append(os.Environ(),
		"XDG_CACHE_HOME="+d.smolvmServerCacheDir(),
		"XDG_DATA_HOME="+d.smolvmServerDataDir(),
		"SMOLVM_AGENT_ROOTFS="+rootfsEnv,
		"HOME="+d.smolvmServerDataDir(),
		"RUST_LOG=trace",
		"RUST_BACKTRACE=1",
	)

	// Detach from the incusd process group so the server survives an
	// incusd restart. The kernel reparents to PID 1 when incusd exits.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("Failed spawning smolvm-server: %w", err)
	}

	pid := cmd.Process.Pid

	// Reap the child if it exits while incusd is still running.
	go func() { _ = cmd.Wait() }()

	if err := os.WriteFile(d.smolvmServerPidPath(), []byte(strconv.Itoa(pid)), 0o600); err != nil {
		_ = syscall.Kill(-pid, syscall.SIGTERM)
		return fmt.Errorf("Failed writing smolvm-server pidfile: %w", err)
	}

	if err := d.smolvmServerWaitHealthy(ctx, sockPath, pid); err != nil {
		_ = syscall.Kill(-pid, syscall.SIGTERM)
		_ = os.Remove(d.smolvmServerPidPath())
		_ = os.Remove(sockPath)
		return fmt.Errorf("smolvm-server failed to become healthy: %w", err)
	}

	d.logger.Info("Started smolvm-server", logger.Ctx{
		"pid":     pid,
		"socket":  sockPath,
		"netns":   nsName,
		"uid":     targetUID,
		"gid":     targetGID,
		"dropped": dropPriv,
		"mntns":   dropPriv,
		"pidns":   dropPriv,
	})
	return nil
}

// smolvmServerStop terminates the per-instance smolvm-server (SIGTERM, then
// SIGKILL after a grace period) and cleans up the pidfile + socket. Best
// effort: a missing/dead server is a no-op.
func (d *smolvm) smolvmServerStop() error {
	pid, ok := d.smolvmServerPID()
	if !ok {
		_ = os.Remove(d.smolvmServerSocketPath())
		_ = os.Remove(d.smolvmServerPidPath())
		return nil
	}

	// Signal the whole process group, not just the pidfile PID. The pidfile
	// records the outermost wrapper (Setsid makes it the pgid leader), but
	// setpriv's UID change inside the chain clears the PR_SET_PDEATHSIG that
	// unshare --kill-child relied on. Sending to -pid (the pgid) reaches every
	// process in the chain, including smolvm-server living as PID 1 inside its
	// new pidns.
	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		d.logger.Warn("Failed sending SIGTERM to smolvm-server group", logger.Ctx{"pid": pid, "err": err})
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !smolvmProcAlive(pid) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if smolvmProcAlive(pid) {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}

	_ = os.Remove(d.smolvmServerSocketPath())
	_ = os.Remove(d.smolvmServerPidPath())

	d.logger.Info("Stopped smolvm-server", logger.Ctx{"pid": pid})
	return nil
}

// smolvmServerPID reads the per-instance pidfile and validates the process is
// still alive. Returns (pid, true) when alive; (0, false) when missing/dead.
func (d *smolvm) smolvmServerPID() (int, bool) {
	raw, err := os.ReadFile(d.smolvmServerPidPath())
	if err != nil {
		return 0, false
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		return 0, false
	}

	if !smolvmProcAlive(pid) {
		return 0, false
	}

	return pid, true
}

// smolvmServerIsAlive returns true if a smolvm-server process exists for this
// instance (according to its pidfile). Does not validate the server is
// actually serving requests.
func (d *smolvm) smolvmServerIsAlive() bool {
	_, ok := d.smolvmServerPID()
	return ok
}

// smolvmServerWaitHealthy polls /health on the per-instance unix socket until
// it succeeds or ctx expires. The expectedPid is checked between polls so we
// fail fast if the server crashes.
func (d *smolvm) smolvmServerWaitHealthy(ctx context.Context, sockPath string, expectedPid int) error {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}

	client := smolvmsdk.NewClient("unix://" + sockPath)

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	for {
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("timed out: %w", lastErr)
			}
			return ctx.Err()
		case <-ticker.C:
			if !smolvmProcAlive(expectedPid) {
				return fmt.Errorf("smolvm-server pid %d exited; check %s", expectedPid, d.smolvmServerLogPath())
			}

			pollCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
			_, err := client.Health(pollCtx)
			cancel()
			if err == nil {
				return nil
			}
			lastErr = err
		}
	}
}

// smolvmProcAlive reports whether a process with the given PID exists. We use
// kill(pid, 0) which returns ESRCH on missing process.
func smolvmProcAlive(pid int) bool {
	if pid <= 0 {
		return false
	}

	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}

	// EPERM means the process exists but we can't signal it, which is good
	// enough for our liveness check.
	return errors.Is(err, syscall.EPERM)
}
