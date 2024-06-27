package internal

import (
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"fmt"
	"os"
	"io/ioutil"
	"regexp"
)

// Holds configuration information
type Config struct {
	Port uint16 `json:"port"`
	ClientCACertificatePath string `json:"client_ca_certificate_path"`
	ServerCertificatePath string `json:"server_certificate_path"`
	ServerKeyPath string `json:"server_key_path"`
	AddressPolicies []AddressPolicy `json:"address_policies"`
}

// Holds configuration for a address policy
type AddressPolicy struct {
	IPNetwork IPNetwork `json:"ip_network"`
	InterfaceNameRegex Regexp `json:"interface_name_regex"`
}

// Custom type for ip network parsing
type IPNetwork struct {
	net.IPNet
}

// Implements parsing a json value to the ip network value
func (ipnet *IPNetwork) UnmarshalJSON(data []byte) error {
	var s string

	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		return err
	}

	*ipnet = IPNetwork{*cidr}

	return nil
}

// Custom type for regexp parsing
type Regexp struct {
	regexp.Regexp
}

// Implements parsing a json value to the regexp value
func (r *Regexp) UnmarshalJSON(data []byte) error {
	var s string

	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	regexp, err := regexp.Compile(s)
	if err != nil {
		return err
	}

	*r = Regexp{*regexp}

	return nil
}

// Prepends the path prefix to the path, if it's not absolute
func AbsPath(pathPrefix string, path string) string {
	if !filepath.IsAbs(path) {
		return filepath.Clean(filepath.Join(pathPrefix, path))
	} else {
		return path
	}
}

// Reads the configuration from a file
func ReadConfiguration(configFilePath string) (*Config, error) {
	if !filepath.IsAbs(configFilePath) {
		absConfigFilePath, err := filepath.Abs(configFilePath)
		if err != nil {
			return nil, fmt.Errorf("Failed to get absolute path of configuration '%s': %v", configFilePath, err)
		}
		configFilePath = absConfigFilePath
	}

	file, err := os.Open(configFilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var config Config
	err = json.Unmarshal(byteValue, &config)
	if err != nil {
		return nil, err
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Normalize paths in configuration
	configDirectoryPath := filepath.Dir(configFilePath)
	config.ClientCACertificatePath = AbsPath(configDirectoryPath, config.ClientCACertificatePath)
	config.ServerCertificatePath = AbsPath(configDirectoryPath, config.ServerCertificatePath)
	config.ServerKeyPath = AbsPath(configDirectoryPath, config.ServerKeyPath)

	return &config, nil
}

// Validates a configuration
func (c Config) Validate() error {
	if c.Port == 0 {
		return errors.New("The configuration is missing a port number")
	}

	if c.ClientCACertificatePath == "" {
		return errors.New("The configuration is missing a path to the client ca certificate")
	}

	if c.ServerCertificatePath == "" {
		return errors.New("The configuration is missing a path to the server certificate")
	}

	if c.ServerKeyPath == "" {
		return errors.New("The configuration is missing a path to the server key")
	}

	if len(c.AddressPolicies) == 0 {
		return errors.New("The configuration is missing address policies")
	}

	return nil
}

// Checks whether an interface name and address is allowed by an address policy
func (ap AddressPolicy) Allows(interfaceName string, address CIDRAddress) bool {
	return ap.InterfaceNameRegex.MatchString(interfaceName) &&
		ap.IPNetwork.Mask.String() == address.Mask.String() &&
		ap.IPNetwork.IP.Mask(ap.IPNetwork.Mask).Equal(address.IP.Mask(address.Mask))
}
