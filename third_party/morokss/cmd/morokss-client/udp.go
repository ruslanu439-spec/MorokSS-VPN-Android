package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	networkTCP = "tcp"
	networkUDP = "udp"
)

func runClientServices(ctx context.Context, config clientConfig, tcpPool, udpPool *endpointPool) error {
	if udpPool == nil {
		return serve(ctx, config, tcpPool)
	}
	errorsChannel := make(chan error, 2)
	go func() {
		errorsChannel <- serve(ctx, config, tcpPool)
	}()
	go func() {
		errorsChannel <- serveUDP(ctx, config, udpPool)
	}()
	return <-errorsChannel
}

type udpAssociation struct {
	address  *net.UDPAddr
	outbound chan []byte
	done     chan struct{}
}

type udpAssociationManager struct {
	ctx          context.Context
	listener     *net.UDPConn
	config       clientConfig
	pool         *endpointPool
	mu           sync.Mutex
	associations map[string]*udpAssociation
}

func serveUDP(ctx context.Context, config clientConfig, pool *endpointPool) error {
	address, err := net.ResolveUDPAddr("udp", config.udpListen)
	if err != nil {
		return fmt.Errorf("resolve UDP listen address %s: %w", config.udpListen, err)
	}
	listener, err := net.ListenUDP("udp", address)
	if err != nil {
		return fmt.Errorf("listen for UDP on %s: %w", config.udpListen, err)
	}
	defer listener.Close()
	log.Printf("MorokSS Go client listening for UDP on %s; endpoints=%d", listener.LocalAddr(), pool.len())
	manager := &udpAssociationManager{
		ctx:          ctx,
		listener:     listener,
		config:       config,
		pool:         pool,
		associations: make(map[string]*udpAssociation),
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	buffer := make([]byte, maxDatagram+1)
	for {
		read, remote, err := listener.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read local UDP datagram: %w", err)
		}
		if read > maxDatagram {
			log.Printf("dropping oversized local UDP datagram from %s", remote)
			continue
		}
		manager.deliver(remote, append([]byte(nil), buffer[:read]...))
	}
}

func (manager *udpAssociationManager) deliver(address *net.UDPAddr, data []byte) {
	key := address.String()
	manager.mu.Lock()
	association := manager.associations[key]
	if association == nil {
		association = &udpAssociation{
			address:  address,
			outbound: make(chan []byte, 64),
			done:     make(chan struct{}),
		}
		manager.associations[key] = association
		go manager.run(key, association)
	}
	manager.mu.Unlock()
	select {
	case association.outbound <- data:
	case <-association.done:
	case <-manager.ctx.Done():
	default:
		log.Printf("dropping local UDP datagram for %s: association queue is full", address)
	}
}

func (manager *udpAssociationManager) run(key string, association *udpAssociation) {
	defer func() {
		manager.mu.Lock()
		if manager.associations[key] == association {
			delete(manager.associations, key)
		}
		manager.mu.Unlock()
		close(association.done)
	}()
	config := manager.config
	config.network = networkUDP
	tunnel, err := openAnyEndpoint(manager.ctx, config, manager.pool)
	if err != nil {
		log.Printf("UDP association %s failed: %v", association.address, err)
		return
	}
	defer tunnel.close()
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	errorsChannel := make(chan error, 2)
	go func() {
		for {
			select {
			case data := <-association.outbound:
				payload, err := packDatagram(data, rand.Reader)
				if err == nil {
					err = tunnel.sendBinary(payload)
				}
				if err != nil {
					errorsChannel <- atStage(stageTraffic, err)
					return
				}
				lastActivity.Store(time.Now().UnixNano())
			case <-association.done:
				return
			case <-manager.ctx.Done():
				errorsChannel <- manager.ctx.Err()
				return
			}
		}
	}()
	go func() {
		for {
			payload, err := tunnel.receiveBinary()
			if err != nil {
				errorsChannel <- atStage(stageTraffic, err)
				return
			}
			data, err := unpackDatagram(payload)
			if err != nil {
				errorsChannel <- atStage(stageTraffic, err)
				return
			}
			if _, err := manager.listener.WriteToUDP(data, association.address); err != nil {
				errorsChannel <- err
				return
			}
			lastActivity.Store(time.Now().UnixNano())
		}
	}()
	interval := manager.config.udpIdleTimeout / 2
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case err := <-errorsChannel:
			reportTunnelFailure(tunnel, err)
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
				log.Printf("UDP association %s closed: %v", association.address, err)
			}
			return
		case <-ticker.C:
			last := time.Unix(0, lastActivity.Load())
			if time.Since(last) >= manager.config.udpIdleTimeout {
				return
			}
		case <-manager.ctx.Done():
			return
		}
	}
}
