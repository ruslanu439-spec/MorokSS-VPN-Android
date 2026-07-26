package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
)

type clientConfig struct {
	listen             string
	server             string
	hostname           string
	profile            string
	cachePath          string
	transport          string
	transportCachePath string
	endpointCachePath  string
	manifestSource     string
	manifestKeyPath    string
	manifestCachePath  string
	protectPath        string
	network            string
	udpListen          string
	udpIdleTimeout     time.Duration
	secret             []byte
	insecure           bool
	endpointIndex      int
	tlsSNI             string
	coverMode          string
	coverSNIs          stringList
	coverCachePath     string
	networkScope       string
	diagnostics        *diagnosticTrace
}

var sessionCache = utls.NewLRUClientSessionCache(64)

func main() {
	config := clientConfig{}
	var configuredEndpoints endpointList
	var diagnose bool
	var diagnoseNetwork string
	var diagnoseIncludeEndpoints bool
	flag.StringVar(&config.listen, "listen", "127.0.0.1:8389", "local TCP listen address")
	flag.StringVar(&config.server, "server", "", "MorokSS server in HOST:PORT format")
	flag.StringVar(&config.hostname, "hostname", "", "TLS hostname from the server certificate")
	flag.Var(&configuredEndpoints, "endpoint", "MorokSS endpoint as ADDRESS,HOSTNAME; may be repeated")
	flag.StringVar(&config.profile, "profile", "auto", "TLS profile: auto, chrome, firefox, safari, edge, ios, android, or randomized")
	flag.StringVar(&config.cachePath, "profile-cache", defaultProfileCachePath(), "path to the last-working TLS profile cache; empty disables it")
	flag.StringVar(&config.transport, "transport", transportAuto, "transport: auto, websocket, or http-stream")
	flag.StringVar(&config.transportCachePath, "transport-cache", defaultTransportCachePath(), "path to the last-working transport cache; empty disables it")
	flag.StringVar(&config.endpointCachePath, "endpoint-cache", defaultEndpointCachePath(), "path to the last-working endpoint cache; empty disables it")
	flag.StringVar(&config.manifestSource, "endpoint-manifest", "", "signed endpoint manifest as an HTTPS URL or local file")
	flag.StringVar(&config.manifestKeyPath, "manifest-public-key", "", "path to the Ed25519 public key for the endpoint manifest")
	flag.StringVar(&config.manifestCachePath, "manifest-cache", defaultManifestCachePath(), "path to the last verified endpoint manifest; empty disables it")
	flag.StringVar(&config.protectPath, "protect-path", "", "Android VpnService socket protection path")
	flag.StringVar(&config.coverMode, "cover-sni-mode", coverModeAuto, "cover SNI selection: auto or off")
	flag.Var(&config.coverSNIs, "cover-sni", "extra cover SNI candidate; may be repeated or comma-separated")
	flag.StringVar(&config.coverCachePath, "cover-sni-cache", defaultCoverCachePath(), "path to the last-working cover SNI cache; empty disables it")
	flag.StringVar(&config.networkScope, "network-scope", "default", "cache scope such as cellular or wifi")
	flag.StringVar(&config.udpListen, "udp-listen", "", "optional local UDP listen address, usually the same address as --listen")
	flag.DurationVar(&config.udpIdleTimeout, "udp-idle-timeout", 2*time.Minute, "idle timeout for a local UDP association")
	flag.BoolVar(&diagnose, "diagnose", false, "test tunnel readiness and print a privacy-safe JSON report instead of starting local listeners")
	flag.StringVar(&diagnoseNetwork, "diagnose-network", networkTCP, "network to test with --diagnose: tcp, udp, or all")
	flag.BoolVar(&diagnoseIncludeEndpoints, "diagnose-include-endpoints", false, "include endpoint addresses and TLS hostnames in the diagnostic report")
	flag.BoolVar(&config.insecure, "insecure", false, "disable certificate verification; development only")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	config.profile = strings.ToLower(strings.TrimSpace(config.profile))
	config.transport = strings.ToLower(strings.TrimSpace(config.transport))
	config.coverMode = strings.ToLower(strings.TrimSpace(config.coverMode))
	config.networkScope = strings.ToLower(strings.TrimSpace(config.networkScope))
	diagnoseNetwork = strings.ToLower(strings.TrimSpace(diagnoseNetwork))
	config.network = networkTCP

	config.secret = []byte(os.Getenv("MOROKSS_SECRET"))
	if len(config.secret) < 32 {
		log.Fatal("MOROKSS_SECRET must contain at least 32 UTF-8 bytes")
	}
	if (config.server == "") != (config.hostname == "") {
		log.Fatal("--server and --hostname must be used together")
	}
	endpoints := make([]endpoint, 0, len(configuredEndpoints)+1)
	if config.server != "" {
		legacyEndpoint, err := newEndpoint(config.server, config.hostname)
		if err != nil {
			log.Fatal(err)
		}
		endpoints = append(endpoints, legacyEndpoint)
	}
	endpoints = append(endpoints, configuredEndpoints...)
	if config.manifestSource != "" {
		if config.manifestKeyPath == "" {
			log.Fatal("--manifest-public-key is required with --endpoint-manifest")
		}
		manifestEndpoints, cached, err := loadEndpointManifest(
			ctx,
			config.manifestSource,
			config.manifestKeyPath,
			config.manifestCachePath,
			time.Now(),
		)
		if err != nil {
			if len(endpoints) == 0 {
				log.Fatal(err)
			}
			log.Printf("endpoint manifest is unavailable; using static endpoints: %v", err)
		} else {
			endpoints = append(endpoints, manifestEndpoints...)
			if cached {
				log.Printf("endpoint manifest source is unavailable; using the last verified copy")
			}
		}
	}
	endpoints = uniqueEndpoints(endpoints)
	if len(endpoints) == 0 {
		log.Fatal("use --endpoint or the --server and --hostname pair")
	}
	if config.profile != "auto" {
		if _, err := clientHelloID(config.profile); err != nil {
			log.Fatal(err)
		}
	}
	if !supportedTransport(config.transport) {
		log.Fatalf("unsupported transport %q", config.transport)
	}
	if config.coverMode != coverModeAuto && config.coverMode != coverModeOff {
		log.Fatalf("unsupported cover SNI mode %q", config.coverMode)
	}
	if config.udpListen != "" && config.udpIdleTimeout <= 0 {
		log.Fatal("--udp-idle-timeout must be positive")
	}
	if diagnose && !supportedDiagnosticNetwork(diagnoseNetwork) {
		log.Fatalf("unsupported --diagnose-network %q", diagnoseNetwork)
	}
	pool := newEndpointPool(endpoints, config.endpointCachePath, config.profile, config.cachePath, config.transport, config.transportCachePath, networkTCP)
	pool.configureCovers(config.coverMode, config.coverSNIs, config.coverCachePath, config.networkScope+":"+networkTCP)
	var udpPool *endpointPool
	if config.udpListen != "" || (diagnose && diagnoseNetwork != networkTCP) {
		udpPool = newEndpointPool(endpoints, config.endpointCachePath, config.profile, config.cachePath, config.transport, config.transportCachePath, networkUDP)
		udpPool.configureCovers(config.coverMode, config.coverSNIs, config.coverCachePath, config.networkScope+":"+networkUDP)
	}
	if diagnose {
		report, successful := runDiagnostics(ctx, config, pool, udpPool, diagnoseNetwork, diagnoseIncludeEndpoints)
		if err := writeDiagnosticReport(os.Stdout, report); err != nil {
			log.Print("cannot write diagnostic report")
			os.Exit(2)
		}
		if !successful {
			os.Exit(1)
		}
		return
	}

	if err := runClientServices(ctx, config, pool, udpPool); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func serve(ctx context.Context, config clientConfig, pool *endpointPool) error {
	listener, err := net.Listen("tcp", config.listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", config.listen, err)
	}
	defer listener.Close()
	log.Printf("MorokSS Go client listening on %s; endpoints=%d; TLS profile=%s; transport=%s", listener.Addr(), pool.len(), config.profile, config.transport)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		local, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("accept local connection: %w", err)
		}
		go func() {
			if err := handleLocal(ctx, local, config, pool); err != nil && !errors.Is(err, io.EOF) {
				log.Printf("connection failed: %v", err)
			}
		}()
	}
}

func handleLocal(ctx context.Context, local net.Conn, config clientConfig, pool *endpointPool) error {
	defer local.Close()
	tunnel, err := openAnyEndpoint(ctx, config, pool)
	if err != nil {
		return err
	}
	defer tunnel.close()
	return relay(local, tunnel)
}

type tunnelOpener func(context.Context, clientConfig, string) (tunnelStream, error)

func openTunnel(ctx context.Context, config clientConfig, selector *profileSelector) (tunnelStream, error) {
	return openTunnelWith(ctx, config, selector, openTunnelWithProfile)
}

func openTunnelWith(ctx context.Context, config clientConfig, selector *profileSelector, opener tunnelOpener) (tunnelStream, error) {
	profiles, retryAfter := selector.candidates()
	if len(profiles) == 0 {
		return nil, fmt.Errorf("all TLS profiles are cooling down; retry after %s", retryAfter.Round(time.Second))
	}
	var lastError error
	for _, profile := range profiles {
		attempt := -1
		if config.diagnostics != nil {
			attempt = config.diagnostics.startAttempt(config.endpointIndex, config.server, config.hostname, profile, config.transport)
		}
		tunnel, err := opener(ctx, config, profile)
		if config.diagnostics != nil {
			config.diagnostics.finishAttempt(attempt, err)
		}
		if err == nil {
			changed := selector.markSuccess(profile)
			if selector.mode == "auto" && changed {
				log.Printf("TLS profile %s is working and was selected", profile)
			}
			return tunnel, nil
		}
		lastError = err
		stage, _ := errorStage(err)
		log.Printf("TLS profile %s failed at %s stage: %v", profile, stage, errors.Unwrap(err))
		if !retryableTLSFailure(err) {
			return nil, err
		}
		selector.markTLSFailure(profile)
		log.Printf("possible ClientHello filtering or TLS incompatibility; trying another profile")
	}
	return nil, fmt.Errorf("all available TLS profiles failed: %w", lastError)
}

func openTunnelWithProfile(ctx context.Context, config clientConfig, profileName string) (tunnelStream, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	configureDialerProtection(&dialer, config.protectPath)
	raw, err := dialer.DialContext(ctx, "tcp", config.server)
	if err != nil {
		return nil, atStage(stageTCP, fmt.Errorf("connect to server: %w", err))
	}
	profile, _ := clientHelloID(profileName)
	tlsName := config.tlsSNI
	if tlsName == "" {
		tlsName = config.hostname
	}
	tlsConfig := &utls.Config{ServerName: tlsName, InsecureSkipVerify: config.insecure}
	if !config.insecure && !strings.EqualFold(tlsName, config.hostname) {
		tlsConfig.InsecureSkipVerify = true
		realHostname := config.hostname
		tlsConfig.VerifyConnection = func(state utls.ConnectionState) error {
			return verifyConnectionHostname(state, realHostname)
		}
	}
	tlsConn := utls.UClient(raw, tlsConfig, profile)
	tlsConn.SetSessionCache(sessionCache)
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, atStage(stageTLS, fmt.Errorf("TLS handshake: %w", err))
	}
	_ = tlsConn.SetDeadline(time.Time{})
	negotiated := tlsConn.ConnectionState().NegotiatedProtocol
	if negotiated != "" && negotiated != "http/1.1" {
		_ = tlsConn.Close()
		return nil, atStage(stageWebSocket, fmt.Errorf("server selected unsupported ALPN protocol %q", negotiated))
	}
	reader := bufio.NewReaderSize(tlsConn, 16*1024)
	if config.transport == transportHTTPStream {
		return openHTTPStreamTunnel(ctx, tlsConn, reader, config)
	}
	if config.transport != transportWebSocket {
		_ = tlsConn.Close()
		return nil, atStage(stageWebSocket, fmt.Errorf("unsupported selected transport %q", config.transport))
	}

	keyBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, keyBytes); err != nil {
		_ = tlsConn.Close()
		return nil, atStage(stageWebSocket, fmt.Errorf("read WebSocket key: %w", err))
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	path := dailyPath(config.secret, time.Now())
	protocolName := "morokss.v1"
	if config.network == networkUDP {
		protocolName = "morokss.udp.v1"
	} else if config.network == networkProbe {
		protocolName = "morokss.probe.v1"
	}
	hostHeader := tlsName
	request := strings.Join([]string{
		fmt.Sprintf("GET %s HTTP/1.1", path),
		fmt.Sprintf("Host: %s", hostHeader),
		"Connection: Upgrade",
		"Pragma: no-cache",
		"Cache-Control: no-cache",
		"Upgrade: websocket",
		"Origin: https://" + hostHeader,
		"Sec-WebSocket-Version: 13",
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
		"Accept-Encoding: gzip, deflate, br, zstd",
		"Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
		"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits",
		"Sec-WebSocket-Protocol: " + protocolName,
		"Sec-WebSocket-Key: " + key,
		"",
		"",
	}, "\r\n")
	if err := writeAll(tlsConn, []byte(request)); err != nil {
		_ = tlsConn.Close()
		return nil, atStage(stageWebSocket, fmt.Errorf("write WebSocket upgrade: %w", err))
	}
	statusLine, headers, err := readHTTPHead(reader)
	if err != nil {
		_ = tlsConn.Close()
		return nil, atStage(stageWebSocket, fmt.Errorf("read WebSocket upgrade: %w", err))
	}
	if statusLine != "HTTP/1.1 101 Switching Protocols" ||
		strings.ToLower(headers["upgrade"]) != "websocket" ||
		headers["sec-websocket-accept"] != websocketAccept(key) {
		_ = tlsConn.Close()
		return nil, atStage(stageWebSocket, fmt.Errorf("WebSocket upgrade rejected: %s", statusLine))
	}
	selectedProtocol := headers["sec-websocket-protocol"]
	if selectedProtocol != "" && selectedProtocol != protocolName {
		_ = tlsConn.Close()
		return nil, atStage(stageWebSocket, fmt.Errorf("server selected unsupported MorokSS subprotocol %q", selectedProtocol))
	}

	stream := newWebsocketStream(tlsConn, reader)
	auth, err := makeAuth(config.secret, time.Now(), rand.Reader)
	if err != nil {
		stream.close()
		return nil, atStage(stageAuth, err)
	}
	if err := stream.sendBinary(auth); err != nil {
		stream.close()
		return nil, atStage(stageAuth, fmt.Errorf("send authentication: %w", err))
	}
	if config.network == networkUDP && selectedProtocol != protocolName {
		stream.close()
		return nil, atStage(stageAuth, errors.New("server does not support MorokSS UDP"))
	}
	if selectedProtocol == protocolName {
		_ = tlsConn.SetReadDeadline(time.Now().Add(8 * time.Second))
		ready, err := stream.receiveBinary()
		_ = tlsConn.SetReadDeadline(time.Time{})
		if err != nil {
			stream.close()
			return nil, atStage(stageAuth, fmt.Errorf("wait for server readiness: %w", err))
		}
		readyData, err := unpackEnvelope(ready)
		if err != nil || len(readyData) != 0 {
			stream.close()
			return nil, atStage(stageAuth, errors.New("invalid server readiness response"))
		}
	}
	return stream, nil
}

func verifyConnectionHostname(state utls.ConnectionState, hostname string) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("TLS server sent no certificate")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       hostname,
		Intermediates: intermediates,
	})
	return err
}

func clientHelloID(profile string) (utls.ClientHelloID, error) {
	switch strings.ToLower(profile) {
	case "chrome":
		return utls.HelloChrome_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "edge":
		return utls.HelloEdge_Auto, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil
	case "randomized":
		return utls.HelloRandomizedALPN, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("unsupported TLS profile %q", profile)
	}
}

func relay(local net.Conn, tunnel tunnelStream) error {
	errorsChannel := make(chan error, 2)
	go func() {
		buffer := make([]byte, dataChunk)
		for {
			read, err := local.Read(buffer)
			if read > 0 {
				envelope, packErr := packEnvelope(buffer[:read], rand.Reader)
				if packErr != nil {
					errorsChannel <- packErr
					return
				}
				if sendErr := tunnel.sendBinary(envelope); sendErr != nil {
					errorsChannel <- sendErr
					return
				}
			}
			if err != nil {
				errorsChannel <- err
				return
			}
		}
	}()
	go func() {
		for {
			payload, err := tunnel.receiveBinary()
			if err != nil {
				errorsChannel <- err
				return
			}
			data, err := unpackEnvelope(payload)
			if err != nil {
				errorsChannel <- err
				return
			}
			if err := writeAll(local, data); err != nil {
				errorsChannel <- err
				return
			}
		}
	}()
	err := <-errorsChannel
	tunnel.close()
	_ = local.Close()
	return err
}
