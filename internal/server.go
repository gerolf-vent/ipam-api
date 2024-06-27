package internal

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	"go.uber.org/zap"
)

type RequestData struct {
	Address string `json:"address"`
	InterfaceName string `json:"interface_name"`
}

// Checks the authenticity of a request
func authenticateRequest(w http.ResponseWriter, r *http.Request, clientCACertificatePool *x509.CertPool) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		zap.L().Error("Rejecting request, because no client certificate was send",
			zap.String("remote-addr", r.RemoteAddr),
		)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}

	clientCertificate := r.TLS.PeerCertificates[0]

	opts := x509.VerifyOptions{
		Roots: clientCACertificatePool,
		Intermediates: x509.NewCertPool(),
	}

	for _, clientIntermediateCertificate := range r.TLS.PeerCertificates[1:] {
		opts.Intermediates.AddCert(clientIntermediateCertificate)
	}

	if _, err := clientCertificate.Verify(opts); err != nil {
		zap.L().Error("Rejecting request, because verification of client certificate failed",
			zap.String("remote-addr", r.RemoteAddr),
			zap.Error(err),
		)
		http.Error(w, "Access denied", http.StatusForbidden)
		return false
	}

	zap.L().Debug("Accepting request with valid client certificate",
		zap.String("remote-addr", r.RemoteAddr),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
	)
	return true
}

// Handles an authenticated request
func handleRequest(w http.ResponseWriter, r *http.Request, policy []AddressPolicy) {
	zap.L().Debug("Handling request",
		zap.String("remote-addr", r.RemoteAddr),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
	)

	var requestAction string
	switch r.URL.Path {
	case "/add":
		requestAction = "add"
	case "/delete":
		requestAction = "delete"
	default:
		zap.L().Error("Requested path not found",
			zap.String("remote-addr", r.RemoteAddr),
			zap.String("path", r.URL.Path),
		)
		http.Error(w, "Path not found", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodPost {
		zap.L().Error("Invalid request method",
			zap.String("remote-addr", r.RemoteAddr),
			zap.String("path", r.URL.Path),
			zap.String("method", r.Method),
		)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var rd RequestData

	if r.Body == nil {
		zap.L().Error("Request body is empty",
			zap.String("remote-addr", r.RemoteAddr),
			zap.String("action", requestAction),
		)
		http.Error(w, "Request body is empty", http.StatusBadRequest)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		zap.L().Error("Invalid content type",
			zap.String("remote-addr", r.RemoteAddr),
			zap.String("action", requestAction),
			zap.String("content-type", contentType),
		)
		http.Error(w, "Invalid content type (expected \"application/json\")", http.StatusBadRequest)
		return
	}

	err := json.NewDecoder(r.Body).Decode(&rd)
	if err != nil {
		zap.L().Error("Invalid request body format",
			zap.String("remote-addr", r.RemoteAddr),
			zap.String("action", requestAction),
			zap.Error(err),
		)
		http.Error(w, fmt.Sprintf("Failed to parse request body: %v", err), http.StatusBadRequest)
		return
	}

	if rd.Address == "" {
		zap.L().Error("Validation of request body failed: Address is missing in request",
			zap.String("remote-addr", r.RemoteAddr),
			zap.String("action", requestAction),
			zap.Error(err),
		)
		http.Error(w, "Address (\"address\") is missing in request", http.StatusBadRequest)
		return
	}

	if rd.InterfaceName == "" {
		zap.L().Error("Validation of request body failed: Interface name is missing in request",
			zap.String("remote-addr", r.RemoteAddr),
			zap.String("action", requestAction),
			zap.Error(err),
		)
		http.Error(w, "Interface name (\"interface_name\") is missing in request", http.StatusBadRequest)
		return
	}

	address, err := ParseAddress(rd.Address)
	if err != nil {
		zap.L().Error("Failed to parse cidr address",
			zap.String("remote-addr", r.RemoteAddr),
			zap.String("action", requestAction),
			zap.String("address", rd.Address),
			zap.Error(err),
		)
		http.Error(w, fmt.Sprintf("Failed to parse cidr address: %v", err), http.StatusInternalServerError)
		return
	}

	policyPassed := false
	for _, p := range policy {
		if p.Allows(rd.InterfaceName, address) {
			policyPassed = true
		}
	}

	if !policyPassed {
		zap.L().Error("Rejected cidr address for interface, because no matching policy was found",
			zap.String("remote-addr", r.RemoteAddr),
			zap.String("action", requestAction),
			zap.String("address", rd.Address),
		)
		http.Error(w, "Rejected cidr address for interface, because no matching policy was found", http.StatusForbidden)
		return
	}

	link, err := LinkByName(rd.InterfaceName)
	if err != nil {
		zap.L().Error("Failed to retreive interface",
			zap.String("remote-addr", r.RemoteAddr),
			zap.String("action", requestAction),
			zap.String("interface-name", rd.InterfaceName),
			zap.Error(err),
		)
		http.Error(w, fmt.Sprintf("Failed to retreive interface: %v", err), http.StatusInternalServerError)
		return
	}

	switch requestAction {
	case "add":
		err = AddAddress(link, address)
		if err != nil {
			zap.L().Error("Failed to add cidr address to interface",
				zap.String("remote-addr", r.RemoteAddr),
				zap.String("action", requestAction),
				zap.String("interface-name", rd.InterfaceName),
				zap.String("address", rd.Address),
				zap.Error(err),
			)
			http.Error(w, fmt.Sprintf("Failed to add cidr address to interface: %v", err), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "Successfully added address to interface\n")
	case "delete":
		err = DeleteAddress(link, address)
		if err != nil {
			zap.L().Error("Failed to delete cidr address from interface",
				zap.String("remote-addr", r.RemoteAddr),
				zap.String("action", requestAction),
				zap.String("interface-name", rd.InterfaceName),
				zap.String("address", rd.Address),
				zap.Error(err),
			)
			http.Error(w, fmt.Sprintf("Failed to delete cidr address from interface: %v", err), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "Successfully deleted address from interface\n")
	}
}

// Handles a health request
func handleHealthzRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	fmt.Fprintf(w, "Server is healthy and ready to serve\n")
}

// Builds the client ca certificate pool
func buildClientCACertificatPool(clientCACertificatePath string) (*x509.CertPool, error) {
	clientCACertificate, err := os.ReadFile(clientCACertificatePath)
	if err != nil {
		zap.L().Error("Failed to read client ca certificate",
			zap.String("path", clientCACertificatePath),
			zap.Error(err),
		)
		return nil, err
	}

	clientCACertificatePool := x509.NewCertPool()
	if ok := clientCACertificatePool.AppendCertsFromPEM(clientCACertificate); !ok {
		zap.L().Error("Failed to add client ca certificate to certificate pool",
			zap.String("path", clientCACertificatePath),
		)
		return nil, errors.New("Failed to add client ca certificate to certificate pool")
	}

	return clientCACertificatePool, nil
}

// Runs the server
func RunServer(configFilePath string) error {
	// Read configuration file
	config, err := ReadConfiguration(configFilePath)
	if err != nil {
		zap.L().Error("Failed to read configuration",
			zap.String("path", configFilePath),
			zap.Error(err),
		)
		os.Exit(1)
	}

	// Read client ca certificate pool
	var clientCACertificatePool *x509.CertPool
	clientCACertificatePool, err = buildClientCACertificatPool(config.ClientCACertificatePath)
	if err != nil {
		return err
	}

	// Setup server
	server := &http.Server{
		Addr: fmt.Sprintf(":%d", config.Port),
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequestClientCert,
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				handleHealthzRequest(w, r)
			} else {
				if authenticateRequest(w, r, clientCACertificatePool) {
					handleRequest(w, r, config.AddressPolicies)
				}
			}
		}),
	}

	// Run server
	zap.L().Info("Starting server",
		zap.Uint16("port", config.Port),
	)
	err = server.ListenAndServeTLS(config.ServerCertificatePath, config.ServerKeyPath)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	} else if err != nil {
		return err
	}

	return nil
}
