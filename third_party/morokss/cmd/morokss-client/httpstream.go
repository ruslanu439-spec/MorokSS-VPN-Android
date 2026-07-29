package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type httpChunkStream struct {
	conn      net.Conn
	reader    *bufio.Reader
	writeMu   sync.Mutex
	closeOnce sync.Once
}

func newHTTPChunkStream(conn net.Conn, reader *bufio.Reader) *httpChunkStream {
	return &httpChunkStream{conn: conn, reader: reader}
}

func openHTTPStreamTunnel(_ context.Context, conn net.Conn, reader *bufio.Reader, config clientConfig) (tunnelStream, error) {
	path := dailyPath(config.secret, time.Now())
	networkMode := config.network
	if networkMode == "" {
		networkMode = networkTCP
	}
	hostHeader := config.tlsSNI
	if hostHeader == "" {
		hostHeader = config.hostname
	}
	request := strings.Join([]string{
		fmt.Sprintf("POST %s HTTP/1.1", path),
		fmt.Sprintf("Host: %s", hostHeader),
		"Connection: keep-alive",
		"Pragma: no-cache",
		"Cache-Control: no-cache",
		"Content-Type: application/octet-stream",
		"Accept: application/octet-stream",
		"Transfer-Encoding: chunked",
		"TE: trailers",
		"X-Stream-Network: " + networkMode,
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
		"Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
		"",
		"",
	}, "\r\n")
	if err := writeAll(conn, []byte(request)); err != nil {
		_ = conn.Close()
		return nil, atStage(stageHTTPStream, fmt.Errorf("write HTTP stream request: %w", err))
	}
	statusLine, headers, err := readHTTPHead(reader)
	if err != nil {
		_ = conn.Close()
		return nil, atStage(stageHTTPStream, fmt.Errorf("read HTTP stream response: %w", err))
	}
	if statusLine != "HTTP/1.1 200 OK" || !headerHasToken(headers["transfer-encoding"], "chunked") {
		_ = conn.Close()
		return nil, atStage(stageHTTPStream, fmt.Errorf("HTTP stream rejected: %s", statusLine))
	}
	stream := newHTTPChunkStream(conn, reader)
	auth, err := makeAuth(config.secret, time.Now(), rand.Reader)
	if err != nil {
		stream.close()
		return nil, atStage(stageAuth, err)
	}
	if err := stream.sendBinary(auth); err != nil {
		stream.close()
		return nil, atStage(stageAuth, fmt.Errorf("send authentication: %w", err))
	}
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	ready, err := stream.receiveBinary()
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		stream.close()
		return nil, atStage(stageAuth, fmt.Errorf("wait for server readiness: %w", err))
	}
	readyData, err := unpackEnvelope(ready)
	if err != nil || len(readyData) != 0 {
		stream.close()
		return nil, atStage(stageAuth, errors.New("invalid server readiness response"))
	}
	return stream, nil
}

func (stream *httpChunkStream) sendBinary(payload []byte) error {
	if len(payload) > maxWSPayload {
		return errors.New("HTTP stream payload too large")
	}
	stream.writeMu.Lock()
	defer stream.writeMu.Unlock()
	_ = stream.conn.SetWriteDeadline(time.Now().Add(tunnelWriteTimeout))
	defer stream.conn.SetWriteDeadline(time.Time{})
	header := []byte(strconv.FormatInt(int64(len(payload)), 16) + "\r\n")
	if err := writeAll(stream.conn, header); err != nil {
		return fmt.Errorf("write HTTP chunk header: %w", err)
	}
	if err := writeAll(stream.conn, payload); err != nil {
		return fmt.Errorf("write HTTP chunk: %w", err)
	}
	if err := writeAll(stream.conn, []byte("\r\n")); err != nil {
		return fmt.Errorf("finish HTTP chunk: %w", err)
	}
	return nil
}

func (stream *httpChunkStream) receiveBinary() ([]byte, error) {
	line, err := stream.reader.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	if len(line) > 128 || len(line) < 3 || line[len(line)-2] != '\r' {
		return nil, errors.New("invalid HTTP chunk header")
	}
	sizeText := strings.TrimSpace(string(line))
	if strings.Contains(sizeText, ";") {
		return nil, errors.New("HTTP chunk extensions aren't supported")
	}
	size, err := strconv.ParseUint(sizeText, 16, 64)
	if err != nil {
		return nil, errors.New("invalid HTTP chunk size")
	}
	if size == 0 {
		return nil, io.EOF
	}
	if size > maxWSPayload {
		return nil, errors.New("HTTP stream payload too large")
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(stream.reader, payload); err != nil {
		return nil, err
	}
	ending := make([]byte, 2)
	if _, err := io.ReadFull(stream.reader, ending); err != nil {
		return nil, err
	}
	if string(ending) != "\r\n" {
		return nil, errors.New("invalid HTTP chunk ending")
	}
	return payload, nil
}

func (stream *httpChunkStream) close() {
	stream.closeOnce.Do(func() {
		stream.writeMu.Lock()
		_ = writeAll(stream.conn, []byte("0\r\n\r\n"))
		stream.writeMu.Unlock()
		_ = stream.conn.Close()
	})
}

func headerHasToken(value, wanted string) bool {
	for _, token := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(token), wanted) {
			return true
		}
	}
	return false
}
