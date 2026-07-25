package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ruslanu439-spec/MorokSS/internal/endpointmanifest"
)

type endpointFlags []endpointmanifest.Endpoint

func (values *endpointFlags) String() string {
	items := make([]string, 0, len(*values))
	for _, item := range *values {
		items = append(items, item.Address+","+item.Hostname)
	}
	return strings.Join(items, ";")
}

func (values *endpointFlags) Set(value string) error {
	item, err := endpointmanifest.ParseEndpoint(value)
	if err != nil {
		return err
	}
	*values = append(*values, item)
	return nil
}

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("use 'keygen' or 'sign'")
	}
	switch arguments[0] {
	case "keygen":
		return keygen(arguments[1:])
	case "sign":
		return sign(arguments[1:])
	default:
		return fmt.Errorf("unknown command %q; use 'keygen' or 'sign'", arguments[0])
	}
}

func keygen(arguments []string) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	privatePath := flags.String("private", "morokss-manifest-private.key", "private key output path")
	publicPath := flags.String("public", "morokss-manifest-public.key", "public key output path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("keygen does not accept positional arguments")
	}
	if filepath.Clean(*privatePath) == filepath.Clean(*publicPath) {
		return errors.New("private and public key paths must be different")
	}
	for _, path := range []string{*privatePath, *publicPath} {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("refusing to overwrite existing key %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("check key path %s: %w", path, err)
		}
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := writeExclusive(*privatePath, endpointmanifest.EncodeKey(privateKey), 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := writeExclusive(*publicPath, endpointmanifest.EncodeKey(publicKey), 0o644); err != nil {
		return fmt.Errorf("write public key: %w; private key was already created at %s", err, *privatePath)
	}
	fmt.Printf("private key: %s\npublic key: %s\n", *privatePath, *publicPath)
	return nil
}

func sign(arguments []string) error {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	privatePath := flags.String("private", "morokss-manifest-private.key", "private key path")
	outputPath := flags.String("out", "endpoint-manifest.json", "signed manifest output path")
	validFor := flags.Duration("valid-for", 7*24*time.Hour, "manifest lifetime, at most 744h")
	var endpoints endpointFlags
	flags.Var(&endpoints, "endpoint", "endpoint as ADDRESS,HOSTNAME; may be repeated")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("sign does not accept positional arguments")
	}
	if len(endpoints) == 0 {
		return errors.New("at least one --endpoint is required")
	}
	if *validFor <= 0 || *validFor > endpointmanifest.MaxValidity {
		return fmt.Errorf("--valid-for must be between 1ns and %s", endpointmanifest.MaxValidity)
	}
	keyData, err := os.ReadFile(*privatePath)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}
	privateKey, err := endpointmanifest.DecodePrivateKey(keyData)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	document := endpointmanifest.Document{
		Version:     endpointmanifest.Version,
		GeneratedAt: now,
		ExpiresAt:   now.Add(*validFor),
		Endpoints:   endpoints,
	}
	if err := endpointmanifest.Sign(&document, privateKey); err != nil {
		return err
	}
	data, err := endpointmanifest.Encode(document)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := writeAtomic(*outputPath, data, 0o644); err != nil {
		return fmt.Errorf("write endpoint manifest: %w", err)
	}
	fmt.Printf("signed %d endpoints; valid until %s; output: %s\n", len(endpoints), document.ExpiresAt.Format(time.RFC3339), *outputPath)
	return nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	return file.Close()
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, "endpoint-manifest-*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		_ = os.Remove(path)
	}
	return os.Rename(temporaryName, path)
}
