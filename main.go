package main

import (
	"fmt"
	"os"
	"time"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:        "oreore",
		Usage:       "generate ore-ore TLS certificates.",
		Description: "oreore is a command line tool for generating ore-ore TLS certificates.",
		Commands: []*cli.Command{
			{
				Name:    "gen",
				Aliases: []string{"g"},
				Usage:   "Generate a ore-ore TLS certificate.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "host", Usage: "Comma-separated hostname and IPs to generate a certificate for.", Required: true},
					&cli.StringFlag{Name: "start-date", Usage: "Creation date formatted as Jan 1 15:04:05 2011."},
					&cli.DurationFlag{Name: "duration", Value: 365 * 24 * time.Hour, Usage: "Duration that certificate is valid for."},
					&cli.BoolFlag{Name: "ca", Value: false, Usage: "whether this cert should be its own Certificate Authority."},
					&cli.IntFlag{Name: "rsa-bits", Value: 2048, Usage: "Size of RSA key to generate."},
					&cli.StringFlag{Name: "ecdsa-curve", Usage: "ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521."},
					&cli.BoolFlag{Name: "ed25519", Value: false, Usage: "Generate an Ed25519 key."},
					&cli.StringFlag{Name: "cert", Value: "cert.pem", Usage: "File name to write a certificate."},
					&cli.StringFlag{Name: "key", Value: "key.pem", Usage: "File name to write a private key."},
					&cli.BoolFlag{Name: "hash", Value: false, Usage: "Show Base64-encoded SHA-256 SPKI Fingerprints (RFC 7469, Section 2.4)."},
				},
				Action: genCommand,
			},
			{
				Name:    "hash",
				Aliases: []string{"h"},
				Usage:   "Show Base64-encoded SHA-256 SPKI Fingerprints (RFC 7469, Section 2.4).",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "cert", Usage: "Certificate file used as input to generate a fingerprint.", Required: true},
				},
				Action: hashCommand,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
	}
}
