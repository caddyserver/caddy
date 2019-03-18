package dns01

import "github.com/miekg/dns"

// Update FQDN with CNAME if any
func updateDomainWithCName(r *dns.Msg, fqdn string) string {
	for _, rr := range r.Answer {
		if cn, ok := rr.(*dns.CNAME); ok {
			if cn.Hdr.Name == fqdn {
				return cn.Target
			}
		}
	}

	return fqdn
}
