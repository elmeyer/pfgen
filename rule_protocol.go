package pf

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// #include <net/if.h>
// #include "pfvar.h"
import "C"

// Protocol that should be filtered by pf
type Protocol uint8

const (
	// ProtocolAny Any matches any protocol
	ProtocolAny Protocol = 0
	// ProtocolTCP TCP
	ProtocolTCP Protocol = C.IPPROTO_TCP
	// ProtocolUDP UDP
	ProtocolUDP Protocol = C.IPPROTO_UDP
	// ProtocolICMP ICMP
	ProtocolICMP Protocol = C.IPPROTO_ICMP
)

// Default set of protocols.
var Protocols = map[int]string{
	int(ProtocolAny):  "any",
	int(ProtocolICMP): "icmp",
	int(ProtocolTCP):  "tcp",
	int(ProtocolUDP):  "udp",
}

// Attempt to read valid protocols from the system's /etc/protocols file.
// Adapted from go/src/net/lookup_unix.go
func init() {
	file, err := os.Open("/etc/protocols")
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		// tcp    6   TCP    # transmission control protocol
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[0:i]
		}
		var f []string
		for _, separator := range []string{" ", "\r", "\t", "\n"} {
			f = strings.Split(line, separator)
			if len(f) >= 2 {
				break
			}
		}
		if len(f) < 2 {
			continue
		}
		if proto, err := strconv.Atoi(strings.TrimSpace(f[1])); err == nil {
			// We ignore all but the first entries.
			if _, ok := Protocols[proto]; !ok {
				Protocols[proto] = strings.TrimSpace(f[0])
			}
		}
	}
}

func (p Protocol) String() string {
	if s, ok := Protocols[int(p)]; ok {
		return s
	} else {
		return fmt.Sprintf("Protocol(%d)", p)
	}
}
