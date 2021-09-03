package rsocks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

/*
package main

import (
	"fmt"
	"github.com/rislah/rsocks"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)


func main() {
	socks, err := rsocks.New("80.211.165.175:48484", 10*time.Second, rsocks.Socks5)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(socks)
	tr := &http.Transport{
		DialContext: socks.Dialer(),
	}

	client := &http.Client{
		Transport: tr,
	}

	res, err := client.Get("https://httpbin.org/get?show_env")
	if err != nil {
		log.Fatal(err)
	}

	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(body))
}
*/

const (
	socks4Version  = 0x04
	connectCommand = 0x01
)

var (
	portValidationError = errors.New("cannot validate port")
	ipValidationError   = errors.New("cannot validate ip")
	portOutOfRangeError = errors.New("port out of range, max 65535")
)

type socksVersion int

const (
	Socks4 socksVersion = iota
	Socks5
)

type socks4ReplyCode byte

const (
	requestGranted                         socks4ReplyCode = 0x5A
	requestRejectedOrFailed                                = 0x5B
	requestRejectedIntendConnectionFailure                 = 0x5C
	requestRejectedUserIDMismatch                          = 0x5D
)

func (code socks4ReplyCode) toString() string {
	switch code {
	case requestGranted:
		return "request granted"
	case requestRejectedOrFailed:
		return "request rejected or failed"
	case requestRejectedIntendConnectionFailure:
		return "request failed because client is not running identd (or not reachable from the server)"
	case requestRejectedUserIDMismatch:
		return "request failed because client's identd could not confirm the user ID string in the request"
	default:
		return "request failed, unknown reply code"
	}
}

type socks5ReplyCode byte

const (
	accessGranted                      socks5ReplyCode = 0x00
	generalFailure                                     = 0x01
	connectionNotAllowedByRuleset                      = 0x02
	networkUnreachable                                 = 0x03
	hostUnreachable                                    = 0x04
	connectionRefusedByDestinationHost                 = 0x05
	TTLExpired                                         = 0x06
	commandNotSupportedOrProtocolError                 = 0x07
	addressTypeNotSupported                            = 0x08
	to0xFFUnassigned                                   = 0x09
)

func (code socks5ReplyCode) toString() string {
	switch code {
	case accessGranted:
		return "access granted"
	case generalFailure:
		return "general SOCKS server failure"
	case connectionNotAllowedByRuleset:
		return "connection not allowed by ruleset"
	case networkUnreachable:
		return "Network unreachable"
	case hostUnreachable:
		return "Host unreachable"
	case connectionRefusedByDestinationHost:
		return "Connection refused"
	case TTLExpired:
		return "TTL expired"
	case commandNotSupportedOrProtocolError:
		return "Command not supported"
	case addressTypeNotSupported:
		return "Address type not supported"
	case to0xFFUnassigned:
		return "to X'FF' unassigned"
	default:
		return "request failed, unknown reply code"
	}
}

type socks5AddressType byte

const (
	Ipv4       socks5AddressType = 0x01
	DomainName                   = 0x03
	Ipv6                         = 0x04
)

type socks5AuthType byte

const (
	NoAuth   socks5AuthType = 0x00
	UserPass                = 0x02
)

type RSocks struct {
	address            string
	timeout            time.Duration
	version            socksVersion
	addressType        socks5AddressType
	authenticationType socks5AuthType
	username           string
	password           string
}

func New(address string, timeout time.Duration, version socksVersion) (RSocks, error) {
	if err := validateProxyAddress(address); err != nil {
		return RSocks{}, err
	}
	return RSocks{
		address,
		timeout,
		version,
		DomainName,
		NoAuth,
		"",
		"",
	}, nil
}

func (r RSocks) SetUsername(username string) {
	r.username = username
}

func (r RSocks) SetPassword(password string) {
	r.password = password
}

func (r RSocks) SetSocks5AddressType(addrType socks5AddressType) {
	r.addressType = addrType
}

func (r RSocks) Dialer() func(context.Context, string, string) (net.Conn, error) {
	dialer := func(parentCtx context.Context, network, reqAddr string) (net.Conn, error) {
		var d net.Dialer
		ctx, _ := context.WithTimeout(parentCtx, r.timeout)
		conn, err := d.DialContext(ctx, "tcp", r.address)
		if err != nil {
			return nil, err
		}

		switch r.version {
		case Socks4:
			if err := r.socks4Connect(conn, reqAddr); err != nil {
				return nil, err
			}
			return conn, nil
		case Socks5:
			if err := r.socks5Connect(conn, reqAddr); err != nil {
				return nil, err
			}
			return conn, nil
		default:
			return nil, errors.New("Unsupported SOCKS version")
		}
	}
	return dialer
}

func (r RSocks) socks4Connect(conn net.Conn, reqAddr string) error {
	host, port, err := splitHostPort(reqAddr)
	if err != nil {
		return err
	}

	defer func() {
		err := conn.SetDeadline(time.Time{})
		if err != nil {
			return
		} // resets deadlines, so future read/writes on conn wont be timed out
	}()

	ip, err := r.lookupIP(host)
	if err != nil {
		return err
	}

	request := make([]byte, 0, 9)
	request = append(request, socks4Version, connectCommand)
	request = append(request, byte(port>>8), byte(port)) // network byte order
	request = append(request, ip[0], ip[1], ip[2], ip[3])
	request = append(request, 0) // userid

	if err := conn.SetWriteDeadline(time.Now().Add(r.timeout)); err != nil {
		return err
	}
	if _, err = conn.Write(request); err != nil {
		return err
	}

	if err := conn.SetReadDeadline(time.Now().Add(r.timeout)); err != nil {
		return err
	}

	request = request[:8]
	if _, err = io.ReadFull(conn, request); err != nil {
		return err
	}

	if code := socks4ReplyCode(request[1]); code != requestGranted {
		return fmt.Errorf(code.toString())
	}

	return nil
}

func (r RSocks) socks5Connect(conn net.Conn, reqAddr string) error {
	defer func() {
		err := conn.SetDeadline(time.Time{})
		if err != nil {
			return
		} // resets deadlines, so future read/writes on conn wont be timed out
	}()

	greeting := make([]byte, 0, 3)
	greeting = append(greeting, 5, 1, byte(r.authenticationType)) // version, number of authentication methods supported, auth type
	if err := r.write(conn, greeting); err != nil {
		return err
	}

	serverChoice := make([]byte, 2)
	if err := r.read(conn, serverChoice); err != nil {
		return nil
	}

	if serverChoice[0] != 5 {
		return fmt.Errorf("unsupported server version, got: %d", serverChoice[0])
	}

	if authType := socks5AuthType(serverChoice[1]); authType != r.authenticationType {
		return fmt.Errorf("unsupported auth type, got: %d", serverChoice[1])
	}

	if r.authenticationType == UserPass {
		authenticationRequest := make([]byte, 3+len(r.username)+len(r.password))
		authenticationRequest = append(authenticationRequest, 1, byte(len(r.username)))
		authenticationRequest = append(authenticationRequest, []byte(r.username)...)
		authenticationRequest = append(authenticationRequest, byte(len(r.password)))
		authenticationRequest = append(authenticationRequest, []byte(r.password)...)
		if err := r.write(conn, authenticationRequest); err != nil {
			return err
		}
		serverResponse := make([]byte, 2)
		if err := r.read(conn, serverResponse); err != nil {
			return err
		}
		if serverResponse[1] != 0 {
			return fmt.Errorf("authentication failed")
		}
	}

	host, port, err := splitHostPort(reqAddr)
	if err != nil {
		return err
	}

	var connectionRequest []byte

	switch r.addressType {
	case DomainName:
		connectionRequest = make([]byte, 0, 6+len(host)+1)
		connectionRequest = append(connectionRequest, 5, 1, 0, 3, byte(len(host)))
		connectionRequest = append(connectionRequest, []byte(host)...)
		connectionRequest = append(connectionRequest, byte(port>>8), byte(port))
	case Ipv4:
		ip, err := r.lookupIP(host)
		if err != nil {
			return err
		}
		connectionRequest = make([]byte, 0, 10)
		connectionRequest = append(connectionRequest, 5, 1, 0, 1)                 // version, connect, authtype, domaintype
		connectionRequest = append(connectionRequest, ip[0], ip[1], ip[2], ip[3]) //  ip
		connectionRequest = append(connectionRequest, byte(port>>8), byte(port))  // big endian port
	}

	if len(connectionRequest) == 0 {
		return nil
	}

	if err := r.write(conn, connectionRequest); err != nil {
		return err
	}

	response := make([]byte, 10)
	if err := r.read(conn, response); err != nil {
		return err
	}

	if code := socks5ReplyCode(response[1]); code != accessGranted {
		return fmt.Errorf(code.toString())
	}

	return nil
}

func (r RSocks) write(conn net.Conn, buf []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(r.timeout)); err != nil {
		return err
	}
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	return nil
}

func (r RSocks) read(conn net.Conn, buf []byte) error {
	if err := conn.SetReadDeadline(time.Now().Add(r.timeout)); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	return nil
}

func (r RSocks) lookupIP(host string) (net.IP, error) {
	addrs, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	switch r.version {
	case Socks4:
		var ip net.IP
		for _, addr := range addrs {
			ip = addr.To4()
			if ip != nil {
				break
			}
		}
		if ip == nil {
			return nil, errors.New("cannot use IPv6 IP for Socks4")
		}
		return ip, nil
	default:
		return addrs[0], nil
	}
}

func splitHostPort(address string) (string, int, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	portnum, err := strconv.Atoi(port)
	if err != nil {
		return "", 0, err
	}
	if 1 > portnum || portnum > 0xffff {
		return "", 0, errors.New("port number out of range " + port)
	}
	return host, portnum, nil
}

func validateProxyAddress(address string) error {
	colonIndex := strings.Index(address, ":")
	if colonIndex == -1 {
		return fmt.Errorf("%s: %w", address, portValidationError)
	}

	port := address[colonIndex+1:]
	portnum, err := strconv.Atoi(port)
	if err != nil {
		return err
	}

	if 1 > portnum || portnum > 65535 {
		return fmt.Errorf("%s: %w", address, portOutOfRangeError)
	}

	ip := net.ParseIP(address[:colonIndex])
	if ip == nil {
		return fmt.Errorf("%s: %w", address, ipValidationError)
	}

	return nil
}
