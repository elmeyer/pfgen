package pf

// #include <net/if.h>
// #include "pfvar.h"
import "C"

// Rule wraps the pf rule (cgo)
type Rule struct {
	wrap C.struct_pfioc_rule
}

// RuleStats contains usefule pf rule statistics
type RuleStats struct {
	Evaluations         uint64
	PacketIn, PacketOut uint64
	BytesIn, BytesOut   uint64
}

// Stats copies the rule statistics into the passed
// RuleStats struct
func (r Rule) Stats(stats *RuleStats) {
	stats.Evaluations = uint64(r.wrap.rule.evaluations)
	stats.PacketIn = uint64(r.wrap.rule.packets[0])
	stats.PacketOut = uint64(r.wrap.rule.packets[1])
	stats.BytesIn = uint64(r.wrap.rule.bytes[0])
	stats.BytesOut = uint64(r.wrap.rule.bytes[1])
}

// SetProtocol sets the protocol matcher of the rule if the
func (r *Rule) SetProtocol(p Protocol) {
	r.wrap.rule.proto = C.u_int8_t(p)
}

// Protocol that is matched by the rule
func (r Rule) Protocol() Protocol {
	return Protocol(r.wrap.rule.proto)
}

// SetLog enables logging of packets to the log interface
func (r *Rule) SetLog(enabled bool) {
	if enabled {
		r.wrap.rule.log |= C.PF_LOG
	} else {
		r.wrap.rule.log &= ^C.u_int8_t(C.PF_LOG)
	}
}

// Log returns true if matching packets are logged
func (r Rule) Log() bool {
	return r.wrap.rule.log > 0
}

// SetLogAll sets whether, for rules keeping state, all packets are logged instead of just the initial one.
func (r *Rule) SetLogAll(enabled bool) {
	if enabled {
		r.wrap.rule.log |= C.PF_LOG_ALL
	} else {
		r.wrap.rule.log &= ^C.u_int8_t(C.PF_LOG_ALL)
	}
}

// LogAll returns whether, for rules keeping state, all packets are logged instead of just the initial one.
func (r Rule) LogAll() bool {
	return r.wrap.rule.log&C.PF_LOG_ALL != 0
}

// SetLogIf sets the index of the pflog device to be used for logging.
func (r *Rule) SetLogIf(i uint8) {
	r.wrap.rule.logif = C.u_int8_t(i)
}

// LogIf returns the index of the pflog device to be used for logging.
func (r Rule) LogIf() uint8 {
	return uint8(r.wrap.rule.logif)
}

// SetQuick skips further evaluations if packet matched
func (r *Rule) SetQuick(enabled bool) {
	if enabled {
		r.wrap.rule.quick = 1
	} else {
		r.wrap.rule.quick = 0
	}
}

// Quick returns true if matching packets are last to evaluate in the rule list
func (r Rule) Quick() bool {
	return r.wrap.rule.quick == 1
}

// SetState sets if the rule keeps state or not
func (r *Rule) SetState(s State) {
	r.wrap.rule.keep_state = C.u_int8_t(s)
}

// State returns the state tracking configuration of the rule
func (r Rule) State() State {
	return State(r.wrap.rule.keep_state)
}

// SetDirection sets the direction the traffic flows
func (r *Rule) SetDirection(dir Direction) {
	r.wrap.rule.direction = C.u_int8_t(dir)
}

// Direction returns the rule matching direction
func (r Rule) Direction() Direction {
	return Direction(r.wrap.rule.direction)
}

// SetAction sets the action on the traffic flow
func (r *Rule) SetAction(a Action) {
	r.wrap.rule.action = C.u_int8_t(a)
}

// Action returns the action that is performed when rule matches
func (r Rule) Action() Action {
	return Action(r.wrap.rule.action)
}

// SetAddressFamily sets the address family to match on
func (r *Rule) SetAddressFamily(af AddressFamily) {
	r.wrap.rule.af = C.sa_family_t(af)
}

// AddressFamily returns the address family that is matched on
func (r Rule) AddressFamily() AddressFamily {
	return AddressFamily(r.wrap.rule.af)
}

// Return returns whether TCP RST/ICMP UNREACHABLE is returned
func (r Rule) Return() bool {
	return (r.wrap.rule.rule_flag & C.PFRULE_RETURN) != 0
}

// SetReturn sets whether TCP RST/ICMP UNREACHABLE is returned
func (r *Rule) SetReturn(t bool) {
	if t {
		r.wrap.rule.rule_flag = r.wrap.rule.rule_flag | C.PFRULE_RETURN
	} else {
		r.wrap.rule.rule_flag = r.wrap.rule.rule_flag & ^C.uint(C.PFRULE_RETURN)
	}
}

// Flags returns the TCP flags out of flagset that must be set for this rule to match.
// See pf.conf(5) for an explanation.
func (r Rule) Flags() Flags {
	return Flags{
		Set:   FlagHeader(r.wrap.rule.flags),
		OutOf: FlagHeader(r.wrap.rule.flagset),
	}
}

// Flags sets the TCP flags out of flagset that must be set for this rule to match.
// See pf.conf(5) for an explanation.
func (r *Rule) SetFlags(f Flags) {
	r.wrap.rule.flags = C.u_int8_t(f.Set)
	r.wrap.rule.flagset = C.u_int8_t(f.OutOf)
}
