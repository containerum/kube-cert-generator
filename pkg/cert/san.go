package cert

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

type SubjectAdditionalNames struct {
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URLs           []*url.URL
}

// Host represents single worker node
type Host struct {
	Alias     string   `toml:"alias"`
	Addresses []string `toml:"addresses"`
}

type Hosts []Host

var (
	ipv4regex = regexp.MustCompile(`\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}\b`)
	ipv6regex = regexp.MustCompile(`(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))`)
)

func (host Host) ToSANs() SubjectAdditionalNames {
	var ret SubjectAdditionalNames
	for _, hostAddr := range host.Addresses {
		urlAddr, urlParseErr := url.Parse(hostAddr)
		switch {
		case strings.Contains(hostAddr, "@"):
			ret.EmailAddresses = append(ret.EmailAddresses, hostAddr)
		case ipv4regex.MatchString(hostAddr) || ipv6regex.MatchString(hostAddr):
			ret.IPAddresses = append(ret.IPAddresses, net.ParseIP(hostAddr))
		case urlParseErr != nil:
			ret.URLs = append(ret.URLs, urlAddr)
		default:
			ret.DNSNames = append(ret.DNSNames, hostAddr)
		}
	}
	return ret
}
