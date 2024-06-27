package internal

import (
	"net"

	"github.com/vishvananda/netlink"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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
	h, err := pcap.OpenLive((*link).Attrs().Name, 0, false, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer h.Close()

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	ethernetLayer := &layers.Ethernet{
		SrcMAC: (*link).Attrs().HardwareAddr,
		DstMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}

	if address.IP.To4() != nil {  // It's an IPv4 address
		arpLayer := &layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   (*link).Attrs().HardwareAddr,
			SourceProtAddress: address.IP,
			DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstProtAddress:    address.IP,
		}

		err = gopacket.SerializeLayers(buffer, opts,
			ethernetLayer,
			arpLayer,
		)
		if err != nil {
			return err
		}
	} else {  // It's an IPv6 address
		icmpv6Layer := &layers.ICMPv6{
			TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
		}

		icmpv6NALayer := &layers.ICMPv6NeighborAdvertisement{
			TargetAddress: address.IP,
			Flags: 0x80 | 0x20,
			Options: []layers.ICMPv6Option{
				layers.ICMPv6Option{
					Type: layers.ICMPv6OptTargetAddress,
					Data: (*link).Attrs().HardwareAddr,
				},
			},
		}

		err = gopacket.SerializeLayers(buffer, opts,
			ethernetLayer,
			icmpv6Layer,
			icmpv6NALayer,
		)
		if err != nil {
			return err
		}
	}

	outgoingPacket := buffer.Bytes()
	err = h.WritePacketData(outgoingPacket)
	if err != nil {
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
