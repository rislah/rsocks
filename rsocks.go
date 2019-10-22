package rsocks

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

/*
func main() {
	socks, err := rsocks.New("127.0.0.1:1080", 2*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	tr := &http.Transport{
		Dial: socks.Dialer(),
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
type socksConnectionFunc func(net.Conn, string, time.Duration) error

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
	SOCKS4 socksVersion = iota
	SOCKS5
)

type replyCode byte

const (
	requestGranted                         replyCode = 0x5A
	requestRejectedOrFailed                          = 0x5B
	requestRejectedIntendConnectionFailure           = 0x5C
	requestRejectedUserIDMismatch                    = 0x5D
)

func (r replyCode) toString() string {
	switch r {
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

type rsocks struct {
	address string
	timeout time.Duration
}

func New(address string, timeout time.Duration) (rsocks, error) {
	err := validateProxyAddress(address)
	if err != nil {
		return rsocks{}, err
	}
	return rsocks{
		address, timeout,
	}, nil
}

func (r rsocks) Dialer() func(string, string) (net.Conn, error) {
	dialer := func(network, addr string) (net.Conn, error) {
		var d net.Dialer
		d.Timeout = r.timeout

		conn, err := d.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}

		if err := r.socks4Connect(conn, addr); err != nil {
			return nil, err
		}

		return conn, nil
	}
	return dialer
}

func (r rsocks) socks4Connect(conn net.Conn, address string) error {
	host, port, err := splitHostPort(address)
	if err != nil {
		return err
	}

	defer func() {
		conn.SetDeadline(time.Time{}) // resets the deadline, so future read/writes on conn wont time out
	}()

	ip, err := lookupIP(host, SOCKS4)
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

	if code := replyCode(request[1]); code != requestGranted {
		return fmt.Errorf(code.toString())
	}

	return nil
}

func lookupIP(host string, version socksVersion) (net.IP, error) {
	addrs, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	switch version {
	case SOCKS4:
		var ip net.IP
		for _, addr := range addrs {
			ip = addr.To4()
			if ip != nil {
				break
			}
		}
		if ip == nil {
			return nil, errors.New("cannot use IPv6 IP for SOCKS4")
		}
		return ip, nil
	default:
		return addrs[0], nil
	}
}

func calculateTimeout(timeout time.Duration) time.Duration {
	millis := float64(timeout) / float64(time.Millisecond)
	duration := time.Duration(millis) * time.Millisecond
	return duration / 3 // dialer, read, write deadline
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

	if 1 > portnum || portnum > 0xffff {
		return fmt.Errorf("%s: %w", address, portOutOfRangeError)
	}

	ip := net.ParseIP(address[:colonIndex])
	if ip == nil {
		return fmt.Errorf("%s: %w", address, ipValidationError)
	}

	return nil
}
