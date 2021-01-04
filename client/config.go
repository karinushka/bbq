package client

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type Config struct {
	Strings map[string]string
	Values  map[string]uint32
}

func NewConfig(n string) (*Config, error) {
	cfg := &Config{
		Strings: make(map[string]string),
		Values:  make(map[string]uint32),
	}

	f, err := os.Open(n)
	if err != nil {
		return nil, fmt.Errorf("loading config: %s", err)
	}
	defer f.Close()

	p := regexp.MustCompile(`^\s*(\S+)\s*=\s+((0[xX])?\S+)\s*$`)

	s := bufio.NewScanner(f)
	for s.Scan() {
		l := strings.TrimSpace(s.Text())
		if len(l) > 0 {

			// Check for variable assignment
			if m := p.FindStringSubmatch(l); len(m) == 4 {
				if len(m[3]) == 2 {
					if i, err := strconv.ParseUint(m[2][len(m[3]):], 16, 32); err == nil {
						cfg.Values[m[1]] = uint32(i)
					}
				} else if i, err := strconv.ParseUint(m[2], 10, 32); err == nil {
					cfg.Values[m[1]] = uint32(i)
				} else {
					cfg.Strings[m[1]] = m[2]
				}
			}
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("reading config from: %s: %s\n", n, err)
	}

	for _, v := range []string{
		"StoreHostname",
		"AccountNumber",
		"KeysFile",
		"CertificateFile",
		"PrivateKeyFile",
		"TrustedCAsFile",
	} {
		_, ok1 := cfg.Strings[v]
		_, ok2 := cfg.Values[v]
		if !ok1 && !ok2 {
			return nil, fmt.Errorf("missing critical configuration value: %s", v)
		}
	}

	return cfg, nil
}
