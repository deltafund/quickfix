// Copyright (c) quickfixengine.org  All rights reserved.
//
// This file may be distributed under the terms of the quickfixengine.org
// license as defined by quickfixengine.org and appearing in the file
// LICENSE included in the packaging of this file.
//
// This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING
// THE WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE.
//
// See http://www.quickfixengine.org/LICENSE for licensing information.
//
// Contact ask@quickfixengine.org if any conditions of this licensing
// are not clear to you.

package quickfix

import (
	"bufio"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

// https://github.com/torvalds/linux/blob/master/include/uapi/linux/in.h#L38
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/tcp.h#L92
// Más -> https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/socket.h

// Initiator initiates connections and processes messages for all sessions.
type Initiator struct {
	app             Application
	settings        *Settings
	sessionSettings map[SessionID]*SessionSettings
	storeFactory    MessageStoreFactory
	logFactory      LogFactory
	globalLog       Log
	stopChan        chan interface{}
	wg              sync.WaitGroup
	sessions        map[SessionID]*session
	sessionFactory
}

// Start Initiator.
func (i *Initiator) Start() (err error) {
	i.stopChan = make(chan interface{})

	for sessionID, settings := range i.sessionSettings {
		// TODO: move into session factory.
		var tlsConfig *tls.Config
		if tlsConfig, err = loadTLSConfig(settings); err != nil {
			return
		}

		var dialer proxy.Dialer
		if dialer, err = loadDialerConfig(settings); err != nil {
			return
		}

		i.wg.Add(1)
		go func(sessID SessionID) {
			i.handleConnection(i.sessions[sessID], tlsConfig, dialer)
			i.wg.Done()
		}(sessionID)
	}
	return
}

// Stop Initiator.
func (i *Initiator) Stop() {
	select {
	case <-i.stopChan:
		// Closed already.
		return
	default:
	}
	close(i.stopChan)
	i.wg.Wait()
}

// NewInitiator creates and initializes a new Initiator.
func NewInitiator(app Application, storeFactory MessageStoreFactory, appSettings *Settings, logFactory LogFactory) (*Initiator, error) {
	i := &Initiator{
		app:             app,
		storeFactory:    storeFactory,
		settings:        appSettings,
		sessionSettings: appSettings.SessionSettings(),
		logFactory:      logFactory,
		sessions:        make(map[SessionID]*session),
		sessionFactory:  sessionFactory{true},
	}

	var err error
	i.globalLog, err = logFactory.Create()
	if err != nil {
		return i, err
	}

	for sessionID, s := range i.sessionSettings {
		session, err := i.createSession(sessionID, storeFactory, s, logFactory, app)
		if err != nil {
			return nil, err
		}

		i.sessions[sessionID] = session
	}

	return i, nil
}

// waitForInSessionTime returns true if the session is in session, false if the handler should stop.
func (i *Initiator) waitForInSessionTime(session *session) bool {
	inSessionTime := make(chan interface{})
	go func() {
		session.waitForInSessionTime()
		close(inSessionTime)
	}()

	select {
	case <-inSessionTime:
	case <-i.stopChan:
		return false
	}

	return true
}

// waitForReconnectInterval returns true if a reconnect should be re-attempted, false if handler should stop.
func (i *Initiator) waitForReconnectInterval(reconnectInterval time.Duration) bool {
	select {
	case <-time.After(reconnectInterval):
	case <-i.stopChan:
		return false
	}

	return true
}

func (i *Initiator) handleConnection(session *session, tlsConfig *tls.Config, dialer proxy.Dialer) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		session.run()
		wg.Done()
	}()

	defer func() {
		session.stop()
		wg.Wait()
	}()

	connectionAttempt := 0

	for {
		if !i.waitForInSessionTime(session) {
			return
		}

		var disconnected chan interface{}
		var msgIn chan fixIn
		var msgOut chan []byte

		address := session.SocketConnectAddress[connectionAttempt%len(session.SocketConnectAddress)]
		session.log.OnEventf("Connecting to: %v", address)

		netConn, err := dialer.Dial("tcp", address)
		if err != nil {
			session.log.OnEventf("Failed to connect: %v", err)
			goto reconnect
		} else if tlsConfig != nil {
			tcpConn, _ := netConn.(*net.TCPConn)

			sockf, err := tcpConn.File() // Get the underlying file
			if err != nil {
				session.log.OnEventf("Error getting file descriptor:", err)
				goto reconnect
			}
			defer sockf.Close()
			sockfd := int(sockf.Fd())

			err = syscall.SetsockoptInt(sockfd, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, 307)
			maxSeg, _ := syscall.GetsockoptInt(sockfd, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
			session.log.OnEventf("TCP_MAXSEG is %d %v\n", maxSeg, err)
			// int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
			//err = unix.SetsockoptInt(sockfd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
			//nodelay, err := unix.GetsockoptInt(sockfd, unix.IPPROTO_TCP, unix.TCP_NODELAY)
			//session.log.OnEventf("TCP_NODELAY is %d %v\n", nodelay, err)

			err = syscall.SetsockoptInt(sockfd, syscall.IPPROTO_TCP, syscall.SO_OOBINLINE, 1)
			urgentFlag, _ := syscall.GetsockoptInt(sockfd, syscall.IPPROTO_TCP, syscall.SO_OOBINLINE)
			session.log.OnEventf("SO_OOBINLINE is %d %v\n", urgentFlag, err)

			// Unless InsecureSkipVerify is true, server name config is required for TLS
			// to verify the received certificate
			if !tlsConfig.InsecureSkipVerify && len(tlsConfig.ServerName) == 0 {
				serverName := address
				if c := strings.LastIndex(serverName, ":"); c > 0 {
					serverName = serverName[:c]
				}
				tlsConfig.ServerName = serverName
			}
			tlsConn := tls.Client(netConn, tlsConfig)
			if err = tlsConn.Handshake(); err != nil {
				session.log.OnEventf("Failed handshake: %v", err)
				goto reconnect
			}
			netConn = tlsConn
		}

		msgIn = make(chan fixIn)
		msgOut = make(chan []byte)
		if err := session.connect(msgIn, msgOut); err != nil {
			session.log.OnEventf("Failed to initiate: %v", err)
			goto reconnect
		}

		go readLoop(newParser(bufio.NewReader(netConn)), msgIn)
		disconnected = make(chan interface{})
		go func() {
			writeLoop(netConn, msgOut, session.log)
			if err := netConn.Close(); err != nil {
				session.log.OnEvent(err.Error())
			}
			close(disconnected)
		}()

		select {
		case <-disconnected:
		case <-i.stopChan:
			return
		}

	reconnect:
		connectionAttempt++
		session.log.OnEventf("Reconnecting in %v", session.ReconnectInterval)
		if !i.waitForReconnectInterval(session.ReconnectInterval) {
			return
		}
	}
}
