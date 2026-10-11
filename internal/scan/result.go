package scan

import (
	"net/netip"
	"time"
)

// Result is everything Sonar learned about one address.
type Result struct {
	IP        netip.Addr    `json:"ip"`
	Alive     bool          `json:"alive"`
	AliveBy   string        `json:"alive_by,omitempty"` // "icmp" | "tcp" | "arp"
	RTT       time.Duration `json:"rtt_ns"`
	Hostname  string        `json:"hostname,omitempty"`
	NameSrc   string        `json:"name_src,omitempty"` // "dns" | "netbios" | "mdns"
	MAC       string        `json:"mac,omitempty"`
	Vendor    string        `json:"vendor,omitempty"`
	Ports     []int         `json:"ports,omitempty"`
	HTTPTitle string        `json:"http_title,omitempty"`
}
