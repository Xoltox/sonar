package target

import (
	"errors"
	"fmt"
	"net/netip"
)

// Resolve turns CLI-style target specs into a host list. Empty specs select
// the auto-detected local subnets. The /16 cap is enforced unless force is
// set. desc holds one human description per range.
func Resolve(specs []string, force bool) (hosts []netip.Addr, locals []Local, desc []string, err error) {
	locals, lerr := LocalSubnets()
	if len(specs) > 0 {
		hosts, err = ParseAll(specs, force)
		if err != nil {
			return nil, locals, nil, err
		}
		return hosts, locals, append([]string(nil), specs...), nil
	}
	if lerr != nil {
		return nil, locals, nil, lerr
	}
	if len(locals) == 0 {
		return nil, locals, nil, errors.New("no local subnets found, give a target")
	}
	for _, l := range locals {
		desc = append(desc, fmt.Sprintf("%s (%s)", l.Prefix.Masked(), l.Iface))
	}
	if n := CountHosts(locals); n > MaxHostsDefault && !force {
		return nil, locals, desc, fmt.Errorf("local subnets expand to %d hosts, over the limit of %d; use --force to scan anyway", n, MaxHostsDefault)
	}
	return Hosts(locals), locals, desc, nil
}
