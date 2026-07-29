package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	websocketGUID      = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	dataChunk          = 8 * 1024
	maxWSPayload       = 64 * 1024
	maxDatagram        = 65507
	tunnelWriteTimeout = 15 * time.Second
)

var paddingBuckets = []int{256, 512, 1024, 2048, 4096, 8192, 12288}

func dailyPath(secret []byte, now time.Time) string {
	message := []byte("morokss:path:v1:" + now.UTC().Format("2006-01-02"))
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(message)
	return fmt.Sprintf("/api/events/%x", mac.Sum(nil)[:16])
}

func makeAuth(secret []byte, now time.Time, random io.Reader) ([]byte, error) {
	stamp := make([]byte, 8)
	binary.BigEndian.PutUint64(stamp, uint64(now.Unix()))
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, fmt.Errorf("read auth nonce: %w", err)
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("morokss:auth:v1:"))
	_, _ = mac.Write(stamp)
	_, _ = mac.Write(nonce)

	selector := []byte{0}
	if _, err := io.ReadFull(random, selector); err != nil {
		return nil, fmt.Errorf("read padding selector: %w", err)
	}
	padding := make([]byte, int(selector[0])%65)
	if _, err := io.ReadFull(random, padding); err != nil {
		return nil, fmt.Errorf("read auth padding: %w", err)
	}

	payload := make([]byte, 0, 56+len(padding))
	payload = append(payload, stamp...)
	payload = append(payload, nonce...)
	payload = append(payload, mac.Sum(nil)...)
	payload = append(payload, padding...)
	return payload, nil
}

func packEnvelope(data []byte, random io.Reader) ([]byte, error) {
	return packPayload(data, dataChunk, random)
}

func packDatagram(data []byte, random io.Reader) ([]byte, error) {
	return packPayload(data, maxDatagram, random)
}

func packPayload(data []byte, maximum int, random io.Reader) ([]byte, error) {
	if len(data) > maximum {
		return nil, fmt.Errorf("payload exceeds %d bytes", maximum)
	}
	required := len(data) + 2
	bucketIndex := -1
	for index, bucket := range paddingBuckets {
		if bucket >= required {
			bucketIndex = index
			break
		}
	}
	bucket := required
	if bucketIndex >= 0 {
		bucket = paddingBuckets[bucketIndex]
		selector := []byte{0}
		if _, err := io.ReadFull(random, selector); err != nil {
			return nil, fmt.Errorf("read envelope selector: %w", err)
		}
		if bucketIndex+1 < len(paddingBuckets) && int(selector[0])%5 == 0 {
			bucket = paddingBuckets[bucketIndex+1]
		}
	}

	payload := make([]byte, bucket)
	binary.BigEndian.PutUint16(payload[:2], uint16(len(data)))
	copy(payload[2:], data)
	if _, err := io.ReadFull(random, payload[2+len(data):]); err != nil {
		return nil, fmt.Errorf("read envelope padding: %w", err)
	}
	return payload, nil
}

func unpackEnvelope(payload []byte) ([]byte, error) {
	return unpackPayload(payload, dataChunk)
}

func unpackDatagram(payload []byte) ([]byte, error) {
	return unpackPayload(payload, maxDatagram)
}

func unpackPayload(payload []byte, maximum int) ([]byte, error) {
	if len(payload) < 2 {
		return nil, errors.New("truncated envelope")
	}
	size := int(binary.BigEndian.Uint16(payload[:2]))
	if size > maximum || size > len(payload)-2 {
		return nil, errors.New("invalid envelope length")
	}
	return payload[2 : 2+size], nil
}

func websocketAccept(key string) string {
	digest := sha1.Sum([]byte(key + websocketGUID))
	return base64.StdEncoding.EncodeToString(digest[:])
}

func readHTTPHead(reader *bufio.Reader) (string, map[string]string, error) {
	const maxHeaderSize = 16 * 1024
	total := 0
	readLine := func() (string, error) {
		line, err := reader.ReadSlice('\n')
		total += len(line)
		if errors.Is(err, bufio.ErrBufferFull) || total > maxHeaderSize {
			return "", errors.New("HTTP header too large")
		}
		return string(line), err
	}
	line, err := readLine()
	if err != nil {
		return "", nil, err
	}
	statusLine := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	headers := make(map[string]string)
	for {
		line, err = readLine()
		if err != nil {
			return "", nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			return "", nil, errors.New("invalid HTTP header line")
		}
		headers[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(value)
	}
	return statusLine, headers, nil
}

type websocketStream struct {
	conn      net.Conn
	reader    *bufio.Reader
	writeMu   sync.Mutex
	closeOnce sync.Once
}

func newWebsocketStream(conn net.Conn, reader *bufio.Reader) *websocketStream {
	return &websocketStream{conn: conn, reader: reader}
}

func (stream *websocketStream) sendFrame(opcode byte, payload []byte) error {
	if len(payload) > maxWSPayload {
		return errors.New("WebSocket payload too large")
	}
	stream.writeMu.Lock()
	defer stream.writeMu.Unlock()

	var frame bytes.Buffer
	frame.WriteByte(0x80 | opcode)
	size := len(payload)
	switch {
	case size < 126:
		frame.WriteByte(0x80 | byte(size))
	case size <= 0xffff:
		frame.WriteByte(0x80 | 126)
		_ = binary.Write(&frame, binary.BigEndian, uint16(size))
	default:
		frame.WriteByte(0x80 | 127)
		_ = binary.Write(&frame, binary.BigEndian, uint64(size))
	}
	mask := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, mask); err != nil {
		return fmt.Errorf("read WebSocket mask: %w", err)
	}
	frame.Write(mask)
	for index, value := range payload {
		_ = frame.WriteByte(value ^ mask[index%4])
	}
	_ = stream.conn.SetWriteDeadline(time.Now().Add(tunnelWriteTimeout))
	defer stream.conn.SetWriteDeadline(time.Time{})
	if err := writeAll(stream.conn, frame.Bytes()); err != nil {
		return fmt.Errorf("write WebSocket frame: %w", err)
	}
	return nil
}

func (stream *websocketStream) sendBinary(payload []byte) error {
	return stream.sendFrame(0x2, payload)
}

func (stream *websocketStream) receiveBinary() ([]byte, error) {
	for {
		opcode, payload, err := stream.readFrame()
		if err != nil {
			return nil, err
		}
		switch opcode {
		case 0x2:
			return payload, nil
		case 0x8:
			return nil, io.EOF
		case 0x9:
			if err := stream.sendFrame(0xA, payload); err != nil {
				return nil, err
			}
		case 0xA:
			continue
		default:
			return nil, fmt.Errorf("unsupported WebSocket opcode: %d", opcode)
		}
	}
}

func (stream *websocketStream) readFrame() (byte, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(stream.reader, header); err != nil {
		return 0, nil, err
	}
	if header[0]&0x70 != 0 {
		return 0, nil, errors.New("WebSocket extensions aren't supported")
	}
	if header[0]&0x80 == 0 {
		return 0, nil, errors.New("fragmented WebSocket message")
	}
	if header[1]&0x80 != 0 {
		return 0, nil, errors.New("server WebSocket frame must not be masked")
	}
	opcode := header[0] & 0x0f
	size := uint64(header[1] & 0x7f)
	switch size {
	case 126:
		encoded := make([]byte, 2)
		if _, err := io.ReadFull(stream.reader, encoded); err != nil {
			return 0, nil, err
		}
		size = uint64(binary.BigEndian.Uint16(encoded))
	case 127:
		encoded := make([]byte, 8)
		if _, err := io.ReadFull(stream.reader, encoded); err != nil {
			return 0, nil, err
		}
		size = binary.BigEndian.Uint64(encoded)
	}
	if opcode&0x08 != 0 && size > 125 {
		return 0, nil, errors.New("WebSocket control frame is too large")
	}
	if size > maxWSPayload {
		return 0, nil, errors.New("WebSocket payload too large")
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(stream.reader, payload); err != nil {
		return 0, nil, err
	}
	return opcode, payload, nil
}

func (stream *websocketStream) close() {
	stream.closeOnce.Do(func() {
		_ = stream.sendFrame(0x8, []byte{0x03, 0xe8})
		_ = stream.conn.Close()
	})
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		data = data[written:]
	}
	return nil
}
