package rsocks

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestValidationPortOutOfRange(t *testing.T) {
	addr := "127.0.0.1:76667"
	_, err := New(addr, time.Second, Socks5)
	expected := fmt.Sprintf("%s: %v", addr, portOutOfRangeError)
	if !errors.Is(err, portOutOfRangeError) {
		t.Errorf("\nexpected error: %s\nfound error: %v", expected, err)
	}
}

func TestValidationBadIP(t *testing.T) {
	addr := "256.20.1.1:2312"
	_, err := New(addr, time.Second, Socks5)
	expected := fmt.Sprintf("%s: %v", addr, ipValidationError)
	if !errors.Is(err, ipValidationError) {
		t.Errorf("\nexpected error: %s\nfound error: %v", expected, err)
	}
}
