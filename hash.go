package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/urfave/cli/v2"
)

func genFingerPrint(pubKey interface{}) (string, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("unable to marshal public key: %w", err)
	}

	hash := sha256.Sum256(pubkeyBytes)
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

func hashCommand(c *cli.Context) error {
	certFile := c.String("cert")

	buf, err := ioutil.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read data from %s: %w", certFile, err)
	}

	certBlock, _ := pem.Decode(buf)
	if certBlock == nil {
		return fmt.Errorf("no PEM block is found in %s", certFile)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	fp, err := genFingerPrint(cert.PublicKey)
	if err != nil {
		return err
	}

	fmt.Println(fp)

	return nil
}
