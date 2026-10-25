// frp-otp grants temporary visitor access after TOTP verification.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var buildVersion = "dev"
var buildRev = "unknown"
var buildDate = "unknown"

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("frp-otp", flag.ContinueOnError)
	flags.SetOutput(stderr)
	entry := flags.String("e", "web", "entry point: web or key")
	configFile := flags.String("c", "frp.otp.json", "configuration file")
	version := flags.Bool("v", false, "show version")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q; use -e web or -e key", flags.Arg(0))
	}
	if *version {
		_, err := fmt.Fprintf(stdout, "frp-otp %s (rev %s, built %s)\n", buildVersion, buildRev, buildDate)
		return err
	}
	switch *entry {
	case "key":
		key, err := totp.Generate(totp.GenerateOpts{Period: 30, SecretSize: 32, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA512, Issuer: "frp-otp", AccountName: "access"})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "Secret: %s\nImport URI (keep private):\n%s\n", key.Secret(), key.String())
		return err
	case "web":
		cfg, err := loadConfig(*configFile)
		if err != nil {
			return err
		}
		s, err := NewServer(cfg)
		if err != nil {
			return err
		}
		return s.Run(ctx)
	default:
		return fmt.Errorf("unknown entry %q; use web or key", *entry)
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "frp-otp:", err)
		os.Exit(1)
	}
}
