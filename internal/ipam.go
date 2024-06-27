package internal

import (
	"net"

	"github.com/vishvananda/netlink"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
	"go.uber.org/zap"
)

type NetworkLink = *netlink.Link
type CIDRAddress = *netlink.Addr

// Returns a network link based on the interface name
func LinkByName(interfaceName string) (NetworkLink, error) {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return nil, err
	}

	return &link, nil
}

// Parses an cidr address
func ParseAddress(address string) (CIDRAddress, error) {
	parsedAddress, err := netlink.ParseAddr(address)
	if err != nil {
		return nil, err
	}

	return parsedAddress, nil
}

// Adds an cidr address to a network link
func AddAddress(link NetworkLink, address CIDRAddress) error {
	addressExists, err := AddressExists(link, address)
	if err != nil {
		return err
	}
	if addressExists {
		zap.L().Info("Address already exists on interface",
			zap.String("interface-name", (*link).Attrs().Name),
			zap.String("address", address.String()),
		)
		return nil
	}

	err = netlink.AddrAdd(*link, address)
	if err != nil {
		zap.L().Error("Failed to add address to interface",
			zap.String("interface-name", (*link).Attrs().Name),
			zap.String("address", address.String()),
			zap.Error(err),
		)
		return err
	}

	zap.L().Info("Added address to interface",
		zap.String("interface-name", (*link).Attrs().Name),
		zap.String("address", address.String()),
	)

	err = AdvertiseAddress(link, address)
	if err != nil {
		zap.L().Error("Failed to advertise address to interface",
			zap.String("interface-name", (*link).Attrs().Name),
			zap.String("address", address.String()),
			zap.Error(err),
		)
		return err
	}

	zap.L().Info("Advertised address on interface",
		zap.String("interface-name", (*link).Attrs().Name),
		zap.String("address", address.String()),
	)

	return nil
}


// Advertises an cidr address on a network link
func AdvertiseAddress(link NetworkLink, address CIDRAddress) error {
	var proto uint16
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if address.IP.To4() != nil {  // It's an IPv4 address
		proto = unix.ETH_P_ARP

		ethLayer := &layers.Ethernet{
			SrcMAC:       (*link).Attrs().HardwareAddr,
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeARP,
		}

		arpLayer := &layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   (*link).Attrs().HardwareAddr,
			SourceProtAddress: address.IP.To4(),
			DstHwAddress:      net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			DstProtAddress:    address.IP.To4(),
		}

		if err := gopacket.SerializeLayers(buffer, opts,
			ethLayer,
			arpLayer,
		); err != nil {
			return err
		}
	} else {  // It's an IPv6 address
		proto = unix.ETH_P_IPV6

		ethLayer := &layers.Ethernet{
			SrcMAC:       (*link).Attrs().HardwareAddr,
			DstMAC:       net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01},
			EthernetType: layers.EthernetTypeIPv6,
		}

		ipv6Layer := &layers.IPv6{
			Version:    6,
			SrcIP:      address.IP,
			DstIP:      net.IPv6linklocalallnodes,
			NextHeader: layers.IPProtocolICMPv6,
			HopLimit:   255,
		}

		icmpv6Layer := &layers.ICMPv6{
			TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
		}
		icmpv6Layer.SetNetworkLayerForChecksum(ipv6Layer)

		icmpv6NALayer := &layers.ICMPv6NeighborAdvertisement{
			Flags:         0x20,
			TargetAddress: address.IP,
			Options: []layers.ICMPv6Option{
				layers.ICMPv6Option{
					Type: layers.ICMPv6OptTargetAddress,
					Data: (*link).Attrs().HardwareAddr,
				},
			},
		}

		if err := gopacket.SerializeLayers(buffer, opts,
			ethLayer,
			ipv6Layer,
			icmpv6Layer,
			icmpv6NALayer,
		); err != nil {
			return err
		}
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(proto))
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	sll := &unix.SockaddrLinklayer{
		Ifindex:  (*link).Attrs().Index,
		Protocol: proto,
	}

	if err := unix.Bind(fd, sll); err != nil {
		return err
	}

	if err := unix.Sendto(fd, buffer.Bytes(), 0, sll); err != nil {
		return err
	}

	return nil
}

// Checks whether a cidr address is already present on a network link
func AddressExists(link NetworkLink, address CIDRAddress) (bool, error) {
	existingAddresses, err := netlink.AddrList(*link, netlink.FAMILY_ALL)
	if err != nil {
		zap.L().Error("Error while retreiving existing addresses on interface",
			zap.String("interface-name", (*link).Attrs().Name),
			zap.String("address", address.String()),
			zap.Error(err),
		)
		return false, err
	}

	for _, existingAddress := range existingAddresses {
		if existingAddress.Equal(*address) {
			zap.L().Debug("Checked whether address already exists on interface",
				zap.String("interface-name", (*link).Attrs().Name),
				zap.String("address", address.String()),
				zap.Bool("result", true),
			)
			return true, nil
		}
	}

	zap.L().Debug("Checked whether address already exists on interface",
		zap.String("interface-name", (*link).Attrs().Name),
		zap.String("address", address.String()),
		zap.Bool("result", false),
	)
	return false, nil
}

// Removes a cidr address from a network link
func DeleteAddress(link NetworkLink, address CIDRAddress) error {
	addressExists, err := AddressExists(link, address)
	if err != nil {
		return err
	}
	if !addressExists {
		zap.L().Info("Address is already gone from interface",
			zap.String("interface-name", (*link).Attrs().Name),
			zap.String("address", address.String()),
		)
		return nil
	}

	err = netlink.AddrDel(*link, address)
	if err != nil {
		zap.L().Error("Failed to delete address from interface",
			zap.String("interface-name", (*link).Attrs().Name),
			zap.String("address", address.String()),
			zap.Error(err),
		)
		return err
	}

	zap.L().Info("Deleted address from interface",
		zap.String("interface-name", (*link).Attrs().Name),
		zap.String("address", address.String()),
	)

	return nil
}
