// Command server is the server side of the asyncua interop check in this
// directory. It serves one Basic256Sha256 endpoint with UserName
// authentication and a variable node whose value changes every 10 ms, so a
// client can read it and subscribe to it while its secure channel renews.
//
// See ../README.md.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/ua"
)

type stdLogger struct{ debug bool }

func (l stdLogger) out(level, msg string, args ...any) {
	s := fmt.Sprintf(msg, args...)
	if strings.Contains(s, "diag") && !l.debug {
		return
	}
	log.Printf("%s %s", level, s)
}
func (l stdLogger) Debug(msg string, args ...any) {
	if l.debug {
		l.out("DEBUG", msg, args...)
	}
}
func (l stdLogger) Info(msg string, args ...any)  { l.out("INFO", msg, args...) }
func (l stdLogger) Warn(msg string, args ...any)  { l.out("WARN", msg, args...) }
func (l stdLogger) Error(msg string, args ...any) { l.out("ERROR", msg, args...) }

func mkCert(appURI, cn string, parent *x509.Certificate, parentKey *rsa.PrivateKey, isCA bool) ([]byte, *rsa.PrivateKey, *x509.Certificate) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn, Organization: []string{"interop"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageContentCommitment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, IsCA: isCA,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	if appURI != "" {
		u, _ := url.Parse(appURI)
		tmpl.URIs = []*url.URL{u}
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	p, pk := tmpl, key
	if parent != nil {
		p, pk = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p, &key.PublicKey, pk)
	if err != nil {
		log.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return der, key, c
}

func main() {
	port := flag.Int("port", 48400, "port")
	insecure := flag.Bool("allow-insecure", false, "also serve None + anonymous")
	chain := flag.Bool("chain", false, "serve a leaf+CA chain as the server certificate")
	mode := flag.String("mode", "SignAndEncrypt", "SignAndEncrypt or Sign")
	debug := flag.Bool("debug", false, "debug logging")
	flag.Parse()

	var certDER []byte
	var key *rsa.PrivateKey
	if *chain {
		caDER, caKey, ca := mkCert("", "interop-ca", nil, nil, true)
		leafDER, leafKey, _ := mkCert("urn:interop:server", "interop-server", ca, caKey, false)
		certDER, key = append(append([]byte{}, leafDER...), caDER...), leafKey
	} else {
		certDER, key, _ = mkCert("urn:interop:server", "interop-server", nil, nil, false)
	}

	m := ua.MessageSecurityModeSignAndEncrypt
	if *mode == "Sign" {
		m = ua.MessageSecurityModeSign
	}
	opts := []server.Option{
		server.EndPoint("localhost", *port),
		server.SetLogger(stdLogger{debug: *debug}),
		server.Certificate(certDER),
		server.PrivateKey(key),
		server.EnableSecurity("Basic256Sha256", m),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.SetAuthenticator(func(id server.UserIdentity) error {
			if id.Username == "scada" && string(id.Password) == "correct horse battery staple" {
				return nil
			}
			return errors.New("bad credentials")
		}),
		server.ClientCertificateValidator(func(cert []byte) error { return nil }),
	}
	if *insecure {
		opts = append(opts, server.EnableSecurity("None", ua.MessageSecurityModeNone), server.EnableAuthMode(ua.UserTokenTypeAnonymous))
	}
	srv := server.New(opts...)

	ns := server.NewNodeNameSpace(srv, "interop")
	root, err := srv.Namespace(0)
	if err != nil {
		log.Fatal(err)
	}
	root.Objects().AddRef(ns.Objects(), id.HasComponent, true)
	var soc atomic.Value
	soc.Store(float64(0))
	node := ns.AddNode(server.NewVariableNode(ua.NewStringNodeID(ns.ID(), "soc"), "soc",
		server.ValueFunc(func() *ua.DataValue { return server.DataValueFromValue(soc.Load()) })))
	ns.Objects().AddRef(node, id.HasComponent, true)

	if err := srv.Start(context.Background()); err != nil {
		log.Fatal(err)
	}
	log.Printf("READY ns=%d port=%d", ns.ID(), *port)
	go func() {
		for i := 0; ; i++ {
			time.Sleep(10 * time.Millisecond)
			soc.Store(float64(i))
			srv.ChangeNotification(node.ID())
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	_ = srv.Close()
}
