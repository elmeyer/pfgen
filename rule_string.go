package pf

import (
	"fmt"
	"strings"
)

// #include <sys/ioctl.h>
// #include <net/if.h>
// #include "pfvar.h"
// uint16_t Ntohs(uint16_t netshort) { return ntohs(netshort); }
import "C"

// String returns the rule as pf.conf representation
func (r Rule) String() string {
	var dump []string

	if r.Action() == ActionDrop {
		dump = append(dump, "block")
		if r.Return() {
			dump = append(dump, "return")
		} else {
			dump = append(dump, r.Action().String())
		}
	} else {
		dump = append(dump, r.Action().String())
	}

	dump = append(dump, r.Direction().String())

	if r.Log() {
		dump = append(dump, "log")
		if i := r.LogIf(); i != 0 {
			dump = append(dump, []string{"to", fmt.Sprintf("pflog%d", i)}...)
		}
	}

	if r.Quick() {
		dump = append(dump, "quick")
	}

	if af := r.AddressFamily(); af != AddressFamilyAny {
		dump = append(dump, r.AddressFamily().String())
	}

	if proto := r.Protocol(); proto != ProtocolAny {
		dump = append(dump, "proto", proto.String())
	}

	dump = append(dump, "from")
	dump = addressDump(dump, &r.wrap.rule.src, r.wrap.rule.af)

	dump = append(dump, "to")
	dump = addressDump(dump, &r.wrap.rule.dst, r.wrap.rule.af)

	if s := r.State(); s != StateNo {
		dump = append(dump, s.String())
	}

	return strings.Join(dump, " ")
}

// addressDump returns the pf.conf representation of the address
func addressDump(dump []string, addr *C.struct_pf_rule_addr, af C.sa_family_t) []string {
	if addr.neg == 1 {
		dump = append(dump, "!")
	}

	dump = append(dump, Address{wrap: &addr.addr, af: af}.String())

	return portRangeDump(dump, addr)
}

// portRangeDump returns the pf.conf representation of the port range
func portRangeDump(dump []string, addr *C.struct_pf_rule_addr) []string {
	startPort := uint16(C.Ntohs(C.uint16_t(addr.port[0])))
	endPort := uint16(C.Ntohs(C.uint16_t(addr.port[1])))
	operation := uint8(addr.port_op)

	if startPort == 0 && endPort == 0 {
		return dump
	}

	dump = append(dump, "port")

	def := ""
	switch operation {
	case C.PF_OP_RRG:
		def = fmt.Sprintf("%d:%d", startPort, endPort)
	case C.PF_OP_IRG:
		def = fmt.Sprintf("%d><%d", startPort, endPort)
	case C.PF_OP_EQ:
		def = fmt.Sprintf("%d", startPort)
	case C.PF_OP_NE:
		def = fmt.Sprintf("!=%d", startPort)
	case C.PF_OP_LT:
		def = fmt.Sprintf("<%d", startPort)
	case C.PF_OP_LE:
		def = fmt.Sprintf("<=%d", startPort)
	case C.PF_OP_GT:
		def = fmt.Sprintf(">%d", startPort)
	case C.PF_OP_GE:
		def = fmt.Sprintf(">=%d", startPort)
	case C.PF_OP_XRG:
		def = fmt.Sprintf("%d<>%d", startPort, endPort)
	case C.PF_OP_NONE:
	default:
		panic(fmt.Errorf("Port operation unknown: %d (%d:%d)", operation,
			startPort, endPort))
	}

	return append(dump, def)
}
