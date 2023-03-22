package pf

// #include <netinet/tcp.h>
import "C"
import (
	"fmt"
	"strings"
)

// Flags specifies which TCP flags must be Set from the flags in OutOf for a rule to match.
// See pf.conf(5) for an explanation.
type Flags struct {
	Set   FlagHeader
	OutOf FlagHeader
}

// FlagHeader is a TCP flag header.
type FlagHeader uint8

const (
	FlagFIN FlagHeader = C.TH_FIN
	FlagSYN FlagHeader = C.TH_SYN
	FlagRST FlagHeader = C.TH_RST
	FlagPSH FlagHeader = C.TH_PUSH
	FlagACK FlagHeader = C.TH_ACK
	FlagURG FlagHeader = C.TH_URG
	FlagECE FlagHeader = C.TH_ECE
	FlagCWR FlagHeader = C.TH_CWR
)

func (f FlagHeader) String() string {
	switch f {
	case FlagFIN:
		return "F"
	case FlagSYN:
		return "S"
	case FlagRST:
		return "R"
	case FlagPSH:
		return "P"
	case FlagACK:
		return "A"
	case FlagURG:
		return "U"
	case FlagECE:
		return "E"
	case FlagCWR:
		return "W"
	default:
		return fmt.Sprintf("Flag(%d)", f)
	}
}

// Any returns whether any TCP flags are accepted.
func (f Flags) Any() bool {
	return f.OutOf == 0
}

// Default returns whether the default TCP flags of S/SA are set.
func (f Flags) Default() bool {
	return f.Set == FlagSYN && (f.OutOf&(FlagSYN|FlagACK) != 0)
}

var allFlags = []FlagHeader{FlagFIN, FlagSYN, FlagRST, FlagPSH, FlagACK, FlagURG, FlagECE, FlagCWR}

func (f Flags) String() string {
	flagstrings := []string{"flags"}

	var flagstring string
	if f.OutOf != 0 {
		if f.Set != 0 {
			for _, flag := range allFlags {
				if f.Set&flag != 0 {
					flagstring += flag.String()
				}
			}

		}

		flagstring += "/"
		for _, flag := range allFlags {
			if f.OutOf&flag != 0 {
				flagstring += flag.String()
			}
		}
	}

	if flagstring != "" {
		flagstrings = append(flagstrings, flagstring)
	} else {
		flagstrings = append(flagstrings, "any")
	}

	return strings.Join(flagstrings, " ")
}
