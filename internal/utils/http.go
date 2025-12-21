package utils

import (
	"net/http"
)

func HTTPInfo(req *http.Request, trustForwardProxy bool) *Info {
	return &Info{req, trustForwardProxy}
}

type Info struct {
	req               *http.Request
	trustForwardProxy bool
}

func (hi *Info) ServerURL() string {
	return hi.Proto() + "://" + hi.Host()
}

func (hi *Info) Host() string {
	if hi.trustForwardProxy {
		if v := hi.req.Header.Get("X-Forwarded-Host"); v != "" {
			return v
		}
	}
	return hi.req.Host
}

func (hi *Info) Proto() string {
	if hi.trustForwardProxy {
		if v := hi.req.Header.Get("X-Forwarded-Proto"); v != "" {
			return v
		}
	}
	if hi.req.TLS != nil {
		return "https"
	}
	return "http"
}
