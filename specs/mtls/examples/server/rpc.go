// Package server provides example server configuration for mTLS
//
// This is an example/reference implementation showing the server setup
// for mTLS authentication with dual listeners (443 for mTLS API, 8080 for health).
//
// For the complete implementation, see the original spec:
// specs/api_auth_v2_pki_implementation_alternative_with_mtls.md lines 1872-2032
//
// Key components demonstrated:
// - Dual listener configuration (mTLS + health check)
// - TLS configuration with client certificate verification
// - Server certificate loading
// - CA certificate pool setup
// - Connect RPC middleware integration
//
// Example usage structure:
//
// type RPCCmd struct {
//     MTLSListen   string // e.g., "0.0.0.0:443"
//     HealthListen string // e.g., "0.0.0.0:8080"
//     CACert       string // Path to CA certificate
//     ServerCert   string // Path to server certificate
//     ServerKey    string // Path to server private key
// }
//
// func (cmd *RPCCmd) Run(ctx context.Context) error {
//     // 1. Load server certificate
//     serverCert, err := tls.LoadX509KeyPair(cmd.ServerCert, cmd.ServerKey)
//
//     // 2. Load CA for client verification
//     caCert, err := os.ReadFile(cmd.CACert)
//     caCertPool := x509.NewCertPool()
//     caCertPool.AppendCertsFromPEM(caCert)
//
//     // 3. Configure TLS
//     tlsConfig := &tls.Config{
//         Certificates: []tls.Certificate{serverCert},
//         ClientAuth:   tls.RequireAndVerifyClientCert,
//         ClientCAs:    caCertPool,
//         MinVersion:   tls.VersionTLS12,
//     }
//
//     // 4. Start mTLS listener on port 443
//     // 5. Start health check listener on port 8080 (HTTP, no TLS)
// }
//
// See the original spec for the complete 160-line implementation.

package server

// Placeholder file - see spec lines 1872-2032 for complete implementation
