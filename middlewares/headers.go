package middlewares

//Middleware based on https://github.com/unrolled/secure

import (
	"fmt"
	"net/http"
	"strings"
)

const (
	stsHeader           = "Strict-Transport-Security"
	stsSubdomainString  = "; includeSubdomains"
	stsPreloadString    = "; preload"
	frameOptionsHeader  = "X-Frame-Options"
	frameOptionsValue   = "DENY"
	contentTypeHeader   = "X-Content-Type-Options"
	contentTypeValue    = "nosniff"
	xssProtectionHeader = "X-XSS-Protection"
	xssProtectionValue  = "1; mode=block"
	cspHeader           = "Content-Security-Policy"
	hpkpHeader          = "Public-Key-Pins"
)

func defaultBadHostHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Bad Host", http.StatusInternalServerError)
}

// HeaderOptions is a struct for specifying configuration options for the headers middleware.
type HeaderOptions struct {
	// AllowedHosts is a list of fully qualified domain names that are allowed. Default is empty list, which allows any and all host names.
	AllowedHosts []string
	// If SSLRedirect is set to true, then only allow https requests. Default is false.
	SSLRedirect bool
	// If SSLTemporaryRedirect is true, the a 302 will be used while redirecting. Default is false (301).
	SSLTemporaryRedirect bool
	// SSLHost is the host name that is used to redirect http requests to https. Default is "", which indicates to use the same host.
	SSLHost string
	// SSLProxyHeaders is set of header keys with associated values that would indicate a valid https request. Useful when using Nginx: `map[string]string{"X-Forwarded-Proto": "https"}`. Default is blank map.
	SSLProxyHeaders map[string]string
	// STSSeconds is the max-age of the Strict-Transport-Security header. Default is 0, which would NOT include the header.
	STSSeconds int64
	// If STSIncludeSubdomains is set to true, the `includeSubdomains` will be appended to the Strict-Transport-Security header. Default is false.
	STSIncludeSubdomains bool
	// If STSPreload is set to true, the `preload` flag will be appended to the Strict-Transport-Security header. Default is false.
	STSPreload bool
	// If ForceSTSHeader is set to true, the STS header will be added even when the connection is HTTP. Default is false.
	ForceSTSHeader bool
	// If FrameDeny is set to true, adds the X-Frame-Options header with the value of `DENY`. Default is false.
	FrameDeny bool
	// CustomFrameOptionsValue allows the X-Frame-Options header value to be set with a custom value. This overrides the FrameDeny option.
	CustomFrameOptionsValue string
	// If ContentTypeNosniff is true, adds the X-Content-Type-Options header with the value `nosniff`. Default is false.
	ContentTypeNosniff bool
	// If BrowserXssFilter is true, adds the X-XSS-Protection header with the value `1; mode=block`. Default is false.
	BrowserXSSFilter bool
	// ContentSecurityPolicy allows the Content-Security-Policy header value to be set with a custom value. Default is "".
	ContentSecurityPolicy string
	// PublicKey implements HPKP to prevent MITM attacks with forged certificates. Default is "".
	PublicKey string
	// When developing, the AllowedHosts, SSL, and STS options can cause some unwanted effects. Usually testing happens on http, not https, and on localhost, not your production domain... so set this to true for dev environment.
	// If you would like your development environment to mimic production with complete Host blocking, SSL redirects, and STS headers, leave this as false. Default if false.
	IsDevelopment bool
	// If Custom request headers are set, these will be added to the request
	CustomRequestHeaders map[string]string
	// If Custom response headers are set, these will be added to the ResponseWriter
	CustomResponseHeaders map[string]string
}

// HeaderStruct is a middleware that helps setup a few basic security features. A single headerOptions struct can be
// provided to configure which features should be enabled, and the ability to override a few of the default values.
type HeaderStruct struct {
	// Customize headers with a headerOptions struct.
	opt HeaderOptions

	// Handlers for when an error occurs (ie bad host).
	badHostHandler http.Handler
}

// NewHeader constructs a new header instance with supplied options.
func NewHeader(options ...HeaderOptions) *HeaderStruct {
	var o HeaderOptions
	if len(options) == 0 {
		o = HeaderOptions{}
	} else {
		o = options[0]
	}

	return &HeaderStruct{
		opt:            o,
		badHostHandler: http.HandlerFunc(defaultBadHostHandler),
	}
}

// SetBadHostHandler sets the handler to call when secure rejects the host name.
func (s *HeaderStruct) SetBadHostHandler(handler http.Handler) {
	s.badHostHandler = handler
}

// Handler implements the http.HandlerFunc for integration with the standard net/http lib.
func (s *HeaderStruct) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Let headers process the request. If it returns an error,
		// that indicates the request should not continue.
		err := s.Process(w, r)

		// If there was an error, do not continue.
		if err != nil {
			return
		}

		h.ServeHTTP(w, r)
	})
}

func (s *HeaderStruct) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	err := s.Process(w, r)

	// If there was an error, do not call next.
	if err == nil && next != nil {
		next(w, r)
	}
}

// Process runs the actual checks and returns an error if the middleware chain should stop.
func (s *HeaderStruct) Process(w http.ResponseWriter, r *http.Request) error {
	// Allowed hosts check.
	if len(s.opt.AllowedHosts) > 0 && !s.opt.IsDevelopment {
		isGoodHost := false
		for _, allowedHost := range s.opt.AllowedHosts {
			if strings.EqualFold(allowedHost, r.Host) {
				isGoodHost = true
				break
			}
		}

		if !isGoodHost {
			s.badHostHandler.ServeHTTP(w, r)
			return fmt.Errorf("Bad host name: %s", r.Host)
		}
	}

	// Determine if we are on HTTPS.
	isSSL := strings.EqualFold(r.URL.Scheme, "https") || r.TLS != nil
	if !isSSL {
		for k, v := range s.opt.SSLProxyHeaders {
			if r.Header.Get(k) == v {
				isSSL = true
				break
			}
		}
	}

	// SSL check.
	if s.opt.SSLRedirect && !isSSL && !s.opt.IsDevelopment {
		url := r.URL
		url.Scheme = "https"
		url.Host = r.Host

		if len(s.opt.SSLHost) > 0 {
			url.Host = s.opt.SSLHost
		}

		status := http.StatusMovedPermanently
		if s.opt.SSLTemporaryRedirect {
			status = http.StatusTemporaryRedirect
		}

		http.Redirect(w, r, url.String(), status)
		return fmt.Errorf("Redirecting to HTTPS")
	}

	// Strict Transport Security header. Only add header when we know it's an SSL connection.
	// See https://tools.ietf.org/html/rfc6797#section-7.2 for details.
	if s.opt.STSSeconds != 0 && (isSSL || s.opt.ForceSTSHeader) && !s.opt.IsDevelopment {
		stsSub := ""
		if s.opt.STSIncludeSubdomains {
			stsSub = stsSubdomainString
		}

		if s.opt.STSPreload {
			stsSub += stsPreloadString
		}

		w.Header().Add(stsHeader, fmt.Sprintf("max-age=%d%s", s.opt.STSSeconds, stsSub))
	}

	// Frame Options header.
	if len(s.opt.CustomFrameOptionsValue) > 0 {
		w.Header().Add(frameOptionsHeader, s.opt.CustomFrameOptionsValue)
	} else if s.opt.FrameDeny {
		w.Header().Add(frameOptionsHeader, frameOptionsValue)
	}

	// Content Type Options header.
	if s.opt.ContentTypeNosniff {
		w.Header().Add(contentTypeHeader, contentTypeValue)
	}

	// XSS Protection header.
	if s.opt.BrowserXXSSFilter {
		w.Header().Add(xssProtectionHeader, xssProtectionValue)
	}

	// HPKP header.
	if len(s.opt.PublicKey) > 0 && isSSL && !s.opt.IsDevelopment {
		w.Header().Add(hpkpHeader, s.opt.PublicKey)
	}

	// Content Security Policy header.
	if len(s.opt.ContentSecurityPolicy) > 0 {
		w.Header().Add(cspHeader, s.opt.ContentSecurityPolicy)
	}

	// Loop through Custom request headers
	if len(s.opt.CustomRequestHeaders) > 0 {
		for header, value := range s.opt.CustomRequestHeaders {
			r.Header.Set(header, value)
		}
	}

	// Loop through Custom response headers
	if len(s.opt.CustomResponseHeaders) > 0 {
		for header, value := range s.opt.CustomResponseHeaders {
			w.Header().Add(header, value)
		}
	}
	return nil
}
