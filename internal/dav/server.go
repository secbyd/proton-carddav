// Package dav implements an RFC 6352 CardDAV HTTP server.
//
// URL layout:
//
//	/.well-known/carddav                         → 301 /dav/principals/me/
//	/dav/principals/me/                          → DAV principal
//	/dav/addressbooks/me/                        → addressbook home
//	/dav/addressbooks/me/contacts/               → addressbook collection
//	/dav/addressbooks/me/contacts/{uid}.vcf      → vCard resource
package dav

import (
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	protonbridge "github.com/secbyd/proton-carddav/internal/proton"
)

// Server is the CardDAV HTTP handler.
type Server struct {
	bridge  *protonbridge.Bridge
	baseURL string // no trailing slash

	mu        sync.RWMutex
	syncToken string
}

// NewServer creates a CardDAV server backed by the given Proton bridge.
func NewServer(baseURL string, bridge *protonbridge.Bridge) *Server {
	return &Server{
		bridge:    bridge,
		baseURL:   strings.TrimRight(baseURL, "/"),
		syncToken: fmt.Sprintf("sync-%d", time.Now().UnixNano()),
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL.Path)

	// RFC 6764 §5 well-known redirect.
	if r.URL.Path == "/.well-known/carddav" {
		http.Redirect(w, r, "/dav/principals/me/", http.StatusMovedPermanently)
		return
	}

	switch r.Method {
	case "OPTIONS":
		s.handleOptions(w, r)
	case "PROPFIND":
		s.handlePropfind(w, r)
	case "REPORT":
		s.handleReport(w, r)
	case "GET", "HEAD":
		s.handleGet(w, r)
	case "PUT":
		s.handlePut(w, r)
	case "DELETE":
		s.handleDelete(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── OPTIONS ───────────────────────────────────────────────────────────────────

func (s *Server) handleOptions(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("DAV", "1, 2, addressbook")
	w.Header().Set("Allow", "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, REPORT")
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusNoContent)
}

// ── PROPFIND ──────────────────────────────────────────────────────────────────

func (s *Server) handlePropfind(w http.ResponseWriter, r *http.Request) {
	p := normPath(r.URL.Path)
	switch {
	case p == "/dav/principals/me/":
		s.propfindPrincipal(w, r)
	case p == "/dav/addressbooks/me/":
		s.propfindAddressbookHome(w, r)
	case p == "/dav/addressbooks/me/contacts/":
		s.propfindCollection(w, r)
	case strings.HasPrefix(p, "/dav/addressbooks/me/contacts/") && strings.HasSuffix(p, ".vcf"):
		s.propfindCard(w, r, path.Base(p))
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (s *Server) propfindPrincipal(w http.ResponseWriter, _ *http.Request) {
	writeMultiStatus(w, MultiStatus{
		XmlnsD: NsDAV, XmlnsC: NsCardDAV,
		Responses: []Response{{
			Href: s.baseURL + "/dav/principals/me/",
			Propstat: []Propstat{{
				Prop:   RawProp{Inner: PrincipalProps(s.baseURL)},
				Status: OK207,
			}},
		}},
	})
}

func (s *Server) propfindAddressbookHome(w http.ResponseWriter, _ *http.Request) {
	writeMultiStatus(w, MultiStatus{
		XmlnsD: NsDAV, XmlnsC: NsCardDAV,
		Responses: []Response{{
			Href: s.baseURL + "/dav/addressbooks/me/",
			Propstat: []Propstat{{
				Prop:   RawProp{Inner: AddressbookHomeProps(s.baseURL)},
				Status: OK207,
			}},
		}},
	})
}

func (s *Server) propfindCollection(w http.ResponseWriter, r *http.Request) {
	token := s.getSyncToken()
	responses := []Response{{
		Href: s.baseURL + "/dav/addressbooks/me/contacts/",
		Propstat: []Propstat{{
			Prop:   RawProp{Inner: AddressbookCollectionProps(s.baseURL, token)},
			Status: OK207,
		}},
	}}

	// Depth: 1 → include child card resources.
	depth := r.Header.Get("Depth")
	if depth == "1" || depth == "infinity" {
		cards, err := s.bridge.ListCards(r.Context())
		if err == nil {
			for _, card := range cards {
				responses = append(responses, Response{
					Href: s.baseURL + "/dav/addressbooks/me/contacts/" + card.Href,
					Propstat: []Propstat{{
						Prop:   RawProp{Inner: CardMetaProps(card.ETag)},
						Status: OK207,
					}},
				})
			}
		}
	}

	writeMultiStatus(w, MultiStatus{XmlnsD: NsDAV, XmlnsC: NsCardDAV, Responses: responses})
}

func (s *Server) propfindCard(w http.ResponseWriter, r *http.Request, filename string) {
	card, err := s.bridge.GetCardByHref(r.Context(), filename)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeMultiStatus(w, MultiStatus{
		XmlnsD: NsDAV, XmlnsC: NsCardDAV,
		Responses: []Response{{
			Href: s.baseURL + "/dav/addressbooks/me/contacts/" + card.Href,
			Propstat: []Propstat{{
				Prop:   RawProp{Inner: CardMetaProps(card.ETag)},
				Status: OK207,
			}},
		}},
	})
}

// ── REPORT ────────────────────────────────────────────────────────────────────

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	p := normPath(r.URL.Path)
	if p != "/dav/addressbooks/me/contacts/" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	var root struct{ XMLName xml.Name }
	_ = xml.Unmarshal(body, &root)

	switch root.XMLName.Local {
	case "addressbook-multiget":
		s.reportMultiget(w, r, body)
	case "addressbook-query":
		s.reportQuery(w, r)
	case "sync-collection":
		s.reportSyncCollection(w, r)
	default:
		http.Error(w, "unsupported report", http.StatusNotImplemented)
	}
}

func (s *Server) reportMultiget(w http.ResponseWriter, r *http.Request, body []byte) {
	var req struct {
		XMLName xml.Name `xml:"addressbook-multiget"`
		Hrefs   []string `xml:"href"`
	}
	if err := xml.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad multiget", http.StatusBadRequest)
		return
	}

	var responses []Response
	for _, href := range req.Hrefs {
		filename := path.Base(strings.TrimRight(href, "/"))
		card, err := s.bridge.GetCardByHref(r.Context(), filename)
		if err != nil {
			responses = append(responses, Response{Href: href, Status: "HTTP/1.1 404 Not Found"})
			continue
		}
		responses = append(responses, Response{
			Href: s.baseURL + "/dav/addressbooks/me/contacts/" + card.Href,
			Propstat: []Propstat{{
				Prop:   RawProp{Inner: CardDataProps(card.ETag, card.VCard)},
				Status: OK207,
			}},
		})
	}
	writeMultiStatus(w, MultiStatus{XmlnsD: NsDAV, XmlnsC: NsCardDAV, Responses: responses})
}

func (s *Server) reportQuery(w http.ResponseWriter, r *http.Request) {
	cards, err := s.bridge.ListCards(r.Context())
	if err != nil {
		http.Error(w, "backend error: "+err.Error(), http.StatusBadGateway)
		return
	}
	var responses []Response
	for _, card := range cards {
		responses = append(responses, Response{
			Href: s.baseURL + "/dav/addressbooks/me/contacts/" + card.Href,
			Propstat: []Propstat{{
				Prop:   RawProp{Inner: CardDataProps(card.ETag, card.VCard)},
				Status: OK207,
			}},
		})
	}
	writeMultiStatus(w, MultiStatus{XmlnsD: NsDAV, XmlnsC: NsCardDAV, Responses: responses})
}

func (s *Server) reportSyncCollection(w http.ResponseWriter, r *http.Request) {
	cards, err := s.bridge.ListCards(r.Context())
	if err != nil {
		http.Error(w, "backend error: "+err.Error(), http.StatusBadGateway)
		return
	}
	var responses []Response
	for _, card := range cards {
		responses = append(responses, Response{
			Href: s.baseURL + "/dav/addressbooks/me/contacts/" + card.Href,
			Propstat: []Propstat{{
				Prop:   RawProp{Inner: CardMetaProps(card.ETag)},
				Status: OK207,
			}},
		})
	}
	token := s.getSyncToken()
	w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
	w.WriteHeader(http.StatusMultiStatus)
	enc := xml.NewEncoder(w)
	_ = enc.Encode(MultiStatus{XmlnsD: NsDAV, XmlnsC: NsCardDAV, Responses: responses})
	_ = enc.EncodeToken(xml.StartElement{Name: xml.Name{Space: NsDAV, Local: "sync-token"}})
	_ = enc.EncodeToken(xml.CharData(token))
	_ = enc.EncodeToken(xml.EndElement{Name: xml.Name{Space: NsDAV, Local: "sync-token"}})
	_ = enc.Flush()
}

// ── GET / HEAD ────────────────────────────────────────────────────────────────

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	p := normPath(r.URL.Path)
	if !strings.HasPrefix(p, "/dav/addressbooks/me/contacts/") || !strings.HasSuffix(p, ".vcf") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	card, err := s.bridge.GetCardByHref(r.Context(), path.Base(p))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/vcard; charset=utf-8")
	w.Header().Set("ETag", card.ETag)
	w.Header().Set("Last-Modified", card.ModifyTime.UTC().Format(http.TimeFormat))
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(card.VCard)))
		return
	}
	_, _ = w.Write(card.VCard)
}

// ── PUT ───────────────────────────────────────────────────────────────────────

func (s *Server) handlePut(w http.ResponseWriter, r *http.Request) {
	p := normPath(r.URL.Path)
	if !strings.HasPrefix(p, "/dav/addressbooks/me/contacts/") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	filename := path.Base(p)

	raw, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil || len(raw) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Conditional PUT: If-Match / If-None-Match.
	if ifMatch := r.Header.Get("If-Match"); ifMatch != "" {
		existing, err := s.bridge.GetCardByHref(r.Context(), filename)
		if err != nil || existing.ETag != ifMatch {
			http.Error(w, "precondition failed", http.StatusPreconditionFailed)
			return
		}
	}

	obj, created, err := s.bridge.UpsertCardByVCard(r.Context(), filename, raw)
	if err != nil {
		http.Error(w, "backend error: "+err.Error(), http.StatusBadGateway)
		return
	}
	s.bumpSyncToken()
	w.Header().Set("ETag", obj.ETag)
	if created {
		w.Header().Set("Location", s.baseURL+"/dav/addressbooks/me/contacts/"+obj.Href)
		w.WriteHeader(http.StatusCreated)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── DELETE ────────────────────────────────────────────────────────────────────

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	p := normPath(r.URL.Path)
	if !strings.HasPrefix(p, "/dav/addressbooks/me/contacts/") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := s.bridge.DeleteCardByHref(r.Context(), path.Base(p)); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.bumpSyncToken()
	w.WriteHeader(http.StatusNoContent)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (s *Server) getSyncToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.syncToken
}

func (s *Server) bumpSyncToken() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncToken = fmt.Sprintf("sync-%d", time.Now().UnixNano())
}

func writeMultiStatus(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
	w.WriteHeader(http.StatusMultiStatus)
	_ = xml.NewEncoder(w).Encode(v)
}

// normPath cleans the request path and re-appends a trailing slash for
// collection paths (those with no file extension).
func normPath(p string) string {
	p = path.Clean("/" + p)
	if !strings.Contains(path.Base(p), ".") {
		p += "/"
	}
	return p
}
