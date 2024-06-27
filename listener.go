package tls_handler

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"github.com/mmaFR/CryptoUtils"
	"net"
)

func NewListener(args arguments) (net.Listener, error) {
	const function string = "NewListener"
	var err error
	var caCertBytes []byte
	var spoaCertBytes []byte
	var spoaCert *tls.Certificate
	var listener net.Listener
	var configTls *tls.Config = new(tls.Config)
	var pki *CryptoUtils.Pki = CryptoUtils.NewPki()
	var caPool *x509.CertPool = x509.NewCertPool()

	// Loading the CA certificate
	if caCertBytes, err = loadBytesFromFile(args.GetCaCert()); err != nil {
		Logger.Printf("%s %s: error encountered while loading the CA certificate: %s\n", structure, function, err.Error())
		return nil, err
	}

	// Loading the SPOA certificate
	if spoaCertBytes, err = loadBytesFromFile(args.GetSpoaCert()); err != nil {
		Logger.Printf("%s %s: error encountered while loading the SPOA certificate: %s\n", structure, function, err.Error())
		return nil, err
	}

	// Parsing the CA certificate
	if err = pki.InitCaFromPem(caCertBytes); err != nil {
		Logger.Printf("%s %s: error encountered while parsing the CA certificate: %s\n", structure, function, err.Error())
		return nil, err
	}
	caPool.AddCert(pki.GetCaCert())

	// Parsing the SPOA certificate
	if spoaCert, err = CryptoUtils.ConvertPemDataToTlsCertificateStructure(spoaCertBytes); err != nil {
		Logger.Printf("%s %s: error encountered while parsing the SPOA certificate: %s\n", structure, function, err.Error())
		return nil, err
	}

	if listener, err = net.Listen("tcp4", args.GetBindAddressAndPort()); err != nil {
		Logger.Printf("%s %s: error encountered while creating the listener: %s\n", structure, function, err.Error())
		return nil, err
	}
	if args.GetMTls() {
		configTls.ClientAuth = tls.RequireAndVerifyClientCert
		configTls.ClientCAs = caPool
	}
	configTls.Certificates = []tls.Certificate{*spoaCert}
	configTls.MinVersion = tls.VersionTLS12
	configTls.Rand = rand.Reader

	listener = tls.NewListener(listener, configTls)
	return listener, nil

}
