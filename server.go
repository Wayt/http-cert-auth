package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var (
	keyDir         = flag.String("clients", "./authorizedkeys", "Authorized crt directory")
	serverKey      = flag.String("key", "server.key", "Server key")
	serverCrt      = flag.String("cert", "server.crt", "Server crt")
	bind           = flag.String("bind", ":4242", "Bind address")
	authorizedKeys []*x509.Certificate
)

// Load authorized keys from directory
// Only load .crt files
func loadAuthorizedKeys(dirname string) (err error) {

	var files []os.FileInfo

	if files, err = ioutil.ReadDir(dirname); err != nil {
		return
	}

	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".crt") {

			var data []byte
			var certBlock *pem.Block
			var cert *x509.Certificate

			if data, err = ioutil.ReadFile(filepath.Join(dirname, f.Name())); err != nil {
				return
			}

			if certBlock, _ = pem.Decode(data); certBlock == nil {
				err = fmt.Errorf("fail to decode pem: %s", f.Name())
				return
			}

			if cert, err = x509.ParseCertificate(certBlock.Bytes); err != nil {
				return
			}

			authorizedKeys = append(authorizedKeys, cert)
		}
	}

	log.Printf("Loaded %d certificate(s)", len(authorizedKeys))
	return
}

// Check for authorized key
func isAuthorizedKey(peerCerts []*x509.Certificate) bool {

	for _, peerCert := range peerCerts {
		for _, authorized := range authorizedKeys {
			if bytes.Compare(authorized.Raw, peerCert.Raw) == 0 {
				return true
			}
		}
	}
	return false
}

// Load and setup TLS configuration
func loadTLSConfig(serverKey, serverCrt string) (tlsConfig *tls.Config, err error) {

	var cert tls.Certificate

	if cert, err = tls.LoadX509KeyPair(serverCrt, serverKey); err != nil {
		return
	}

	tlsConfig = &tls.Config{
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequestClientCert,
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
		PreferServerCipherSuites: true,
	}

	tlsConfig.BuildNameToCertificate()

	return
}

func main() {

	flag.Parse()

	if err := loadAuthorizedKeys(*keyDir); err != nil {
		log.Fatal("loadAuthorizedKeys:", err)
	}

	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {

		if r.TLS == nil {
			w.WriteHeader(http.StatusUnauthorized)
			log.Print("No client TLS")
			return
		}

		if !isAuthorizedKey(r.TLS.PeerCertificates) {
			w.WriteHeader(http.StatusUnauthorized)
			log.Print("Not authorized")
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Hello World !"))
	})

	tlsConfig, err := loadTLSConfig(*serverKey, *serverCrt)
	if err != nil {
		log.Fatalf("loadTLSConfig:", err)
	}

	tlsListener, err := tls.Listen("tcp", *bind, tlsConfig)
	if err != nil {
		log.Fatal("Listen:", err)
	}

	log.Printf("listen %s", *bind)
	if err := http.Serve(tlsListener, nil); err != nil {
		log.Fatal(err)
	}
}
