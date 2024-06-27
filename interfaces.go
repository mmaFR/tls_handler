package tls_handler

type arguments interface {
	GetBindAddressAndPort() string
	GetKeyType() string
	GetKeySize() uint16
	GetKeyCurve() string
	GetCertOut() string
	GetCn() string
	GetSpoaCert() string
	GetCaCert() string
	GetGenCa() bool
	GetGenSpoeCert() bool
	GetGenSpoaCert() bool
	GetMTls() bool
}
