package tls_handler

import (
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"github.com/mmaFR/CryptoUtils"
	"time"
)

var curveMap map[string]elliptic.Curve = map[string]elliptic.Curve{
	CurveP224: elliptic.P224(),
	CurveP256: elliptic.P256(),
	CurveP384: elliptic.P384(),
	CurveP521: elliptic.P521(),
}

func GenerateCertificate(args arguments) {
	const function string = "generateCertificate"
	var err error

	switch {
	case args.GetGenCa() && !args.GetGenSpoaCert() && !args.GetGenSpoeCert():
		Logger.Printf("%s %s: %s\n", structure, function, "Generating a CA certificate")
		Logger.Printf("%s %s: Using key of type %s\n", structure, function, args.GetKeyType())
		switch args.GetKeyType() {
		case RsaKeyType:
			Logger.Printf("%s %s: Using a key size of %d bits\n", structure, function, args.GetKeySize())
		case EcdsaKeyType:
			Logger.Printf("%s %s: Using the key curve %s\n", structure, function, args.GetKeyCurve())

		}
		if err = genCa(args); err != nil {
			Logger.Printf("%s %s: Error encountered while generating the CA certificate: %s\n", structure, function, err.Error())
		} else {
			Logger.Printf("%s %s: CA certificate and key saved in %s\n", structure, function, args.GetCertOut())
		}
		return
	case args.GetGenSpoeCert() && !args.GetGenCa() && !args.GetGenSpoaCert():
		Logger.Printf("%s %s: Generating an SPOE (HAProxy side) certificate\n", structure, function)
		Logger.Printf("%s %s: Using key of type %s\n", structure, function, args.GetKeyType())
		switch args.GetKeyType() {
		case RsaKeyType:
			Logger.Printf("%s %s: Using a key size of %d bits\n", structure, function, args.GetKeySize())
		case EcdsaKeyType:
			Logger.Printf("%s %s: Using the key curve %s\n", structure, function, args.GetKeyCurve())

		}
		if err = genSpoeCert(args); err != nil {
			Logger.Printf("%s %s: Error encountered while generating the SPOE certificate: %s\n", structure, function, err.Error())
		} else {
			Logger.Printf("%s %s: SPOE certificate and key saved in %s\n", structure, function, args.GetCertOut())
		}
		return
	case args.GetGenSpoaCert() && !args.GetGenCa() && !args.GetGenSpoeCert():
		Logger.Printf("%s %s: Generating an SPOA (HAProxy side) certificate\n", structure, function)
		Logger.Printf("%s %s: Using key of type %s\n", structure, function, args.GetKeyType())
		switch args.GetKeyType() {
		case RsaKeyType:
			Logger.Printf("%s %s: Using a key size of %d bits\n", structure, function, args.GetKeySize())
		case EcdsaKeyType:
			Logger.Printf("%s %s: Using the key curve %s\n", structure, function, args.GetKeyCurve())

		}
		if err = genSpoaCert(args); err != nil {
			Logger.Printf("%s %s: Error encountered while generating the SPOA certificate: %s\n", structure, function, err.Error())
		} else {
			Logger.Printf("%s %s: SPOA certificate and key saved in %s\n", structure, function, args.GetCertOut())
		}
		return
	case args.GetGenCa(), args.GetGenSpoaCert(), args.GetGenSpoeCert():
		Logger.Println("you can't mix GenCa, GenSpoe, and GenSpoa")
		return
	}
}

func genCa(args arguments) error {
	var err error
	var certDesc *CryptoUtils.CertificateDescription
	var pki *CryptoUtils.Pki = CryptoUtils.NewPki()

	if args.GetCn() == "" {
		return errors.New("please provide a common name with -cn")
	}

	switch args.GetKeyType() {
	case RsaKeyType:
		if err = pki.GenerateCaRsaKeys(int(args.GetKeySize())); err != nil {
			return err
		}
	case EcdsaKeyType:
		if err = pki.GenerateCaEcdsaKeys(curveMap[args.GetKeyCurve()]); err != nil {
			return err
		}
	}

	certDesc = CryptoUtils.NewCertificateDescription()
	certDesc.SetIsCA()
	certDesc.SetCommonName(args.GetCn())
	certDesc.SetOrganization("HAProxy Agent")
	certDesc.SetOrganizationalUnit("SPOA")
	certDesc.SetCountry("FR")
	certDesc.SetProvince("IDF")
	certDesc.SetLocality("Paris")
	certDesc.SetStreetAddress("")
	certDesc.SetPostalCode("75000")
	certDesc.SetNotValidBefore(time.Now())
	certDesc.SetNotValidAfter(time.Now().Add(time.Hour * 24 * 365 * 10))

	if err = pki.GenerateCaCert(certDesc); err != nil {
		return err
	}
	var crt []byte
	if crt, err = pki.ExportCa(CryptoUtils.FormatPEM); err != nil {
		return err
	}

	if err = dumpBytesToFile(args.GetCertOut(), crt); err != nil {
		return err
	}
	return nil
}
func genSpoeCert(args arguments) error {
	return genCert(args, true)
}
func genSpoaCert(args arguments) error {
	return genCert(args, false)
}
func genCert(args arguments, isClient bool) error {
	var err error
	var certDesc *CryptoUtils.CertificateDescription
	var pki *CryptoUtils.Pki = CryptoUtils.NewPki()
	var caCertBytes []byte
	var crt []byte

	if args.GetCn() == "" {
		return errors.New("please provide a common name with -cn")
	}

	if caCertBytes, err = loadBytesFromFile(args.GetCaCert()); err != nil {
		return err
	}

	if err = pki.InitCaFromPem(caCertBytes); err != nil {
		return err
	}

	switch args.GetKeyType() {
	case RsaKeyType:
		if err = pki.GenerateCertRsaKeys(int(args.GetKeySize())); err != nil {
			return err
		}
	case EcdsaKeyType:
		if err = pki.GenerateCertEcdsaKeys(curveMap[args.GetKeyCurve()]); err != nil {
			return err
		}
	}

	certDesc = CryptoUtils.NewCertificateDescription()
	certDesc.SetCommonName(args.GetCn())
	certDesc.SetOrganization("HAProxy Agent")
	certDesc.SetOrganizationalUnit("SPOA")
	certDesc.SetCountry("FR")
	certDesc.SetProvince("IDF")
	certDesc.SetLocality("Paris")
	certDesc.SetStreetAddress("")
	certDesc.SetPostalCode("75000")
	certDesc.SetNotValidBefore(time.Now())
	certDesc.SetNotValidAfter(time.Now().Add(time.Hour * 24 * 365 * 10))
	if isClient {
		certDesc.SetExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	} else {
		certDesc.SetExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	}

	if err = pki.GenerateCert(certDesc); err != nil {
		return err
	}

	if crt, err = pki.ExportCert(CryptoUtils.FormatPEM); err != nil {
		return err
	}

	if err = dumpBytesToFile(args.GetCertOut(), crt); err != nil {
		return err
	}
	return nil
}
