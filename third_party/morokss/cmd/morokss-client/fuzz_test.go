package main

import (
	"bufio"
	"bytes"
	"testing"
)

func FuzzUnpackEnvelope(f *testing.F) {
	f.Add([]byte{0, 0})
	f.Add([]byte{0, 5, 'h', 'e', 'l', 'l', 'o'})
	f.Add([]byte{0xff, 0xff})
	f.Fuzz(func(t *testing.T, payload []byte) {
		data, err := unpackEnvelope(payload)
		if err == nil && len(data) > dataChunk {
			t.Fatalf("unpackEnvelope returned %d bytes", len(data))
		}
		data, err = unpackDatagram(payload)
		if err == nil && len(data) > maxDatagram {
			t.Fatalf("unpackDatagram returned %d bytes", len(data))
		}
	})
}

func FuzzReadHTTPHead(f *testing.F) {
	f.Add([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"))
	f.Add([]byte("broken\r\nheader-without-colon\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		reader := bufio.NewReaderSize(bytes.NewReader(data), 16*1024)
		_, _, _ = readHTTPHead(reader)
	})
}

func FuzzReadWebSocketFrame(f *testing.F) {
	f.Add([]byte{0x82, 0x00})
	f.Add([]byte{0x88, 0x7e, 0x00, 0x7e})
	f.Add([]byte{0x82, 0x05, 'h', 'e', 'l', 'l', 'o'})
	f.Fuzz(func(t *testing.T, data []byte) {
		stream := &websocketStream{reader: bufio.NewReader(bytes.NewReader(data))}
		_, _, _ = stream.readFrame()
	})
}
