// Package synology is a minimal CardDAV client targeting Synology CardDAV Server.
package synology

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

type Contact struct {
	UID   string
	Href  string
	ETag  string
	VCard []byte
}

type Client struct {
	baseURL    string
	bookPath   string
	username   string
	password   string
	httpClient *http.Client
}

func NewClient(baseURL, bookPath, username, password string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		bookPath:   bookPath,
		username:   username,
		password:   password,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) ListContacts(ctx context.Context) ([]Contact, error) {
	hrefs, err := c.propfindChildren(ctx)
	if err != nil {
		return nil, err
	}
	if len(hrefs) == 0 {
		return nil, nil
	}
	return c.multiGet(ctx, hrefs)
}

func (c *Client) GetContact(ctx context.Context, href string) (Contact, error) {
	resp, err := c.do(ctx, "GET", c.absURL(href), "", nil)
	if err != nil {
		return Contact{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Contact{}, fmt.Errorf("synology get: not found: %s", href)
	}
	if resp.StatusCode != http.StatusOK {
		return Contact{}, fmt.Errorf("synology get: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Contact{}, err
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		etag = etagOf(body)
	}
	uid := path.Base(strings.TrimSuffix(href, ".vcf"))
	return Contact{UID: uid, Href: href, ETag: etag, VCard: body}, nil
}

func (c *Client) PutContact(ctx context.Context, uid string, vcBytes []byte) (string, error) {
	href := c.cardHref(uid)
	req, err := http.NewRequestWithContext(ctx, "PUT", c.absURL(href),
		bytes.NewReader(vcBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "text/vcard; charset=utf-8")
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("synology put %s: %w", uid, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return "", fmt.Errorf("synology put %s: %s", uid, resp.Status)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		etag = etagOf(vcBytes)
	}
	return etag, nil
}

func (c *Client) DeleteContact(ctx context.Context, uid string) error {
	href := c.cardHref(uid)
	resp, err := c.do(ctx, "DELETE", c.absURL(href), "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("synology delete %s: %s", uid, resp.Status)
	}
	return nil
}

var propfindBody = []byte(`<?xml version="1.0" encoding="UTF-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:getetag/>
    <D:getcontenttype/>
  </D:prop>
</D:propfind>`)

func (c *Client) propfindChildren(ctx context.Context) ([]string, error) {
	resp, err := c.do(ctx, "PROPFIND", c.absURL(c.bookPath),
		"1", bytes.NewReader(propfindBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 207 {
		return nil, fmt.Errorf("synology propfind: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseHrefs(body, c.bookPath)
}

func (c *Client) multiGet(ctx context.Context, hrefs []string) ([]Contact, error) {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString(`<C:addressbook-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">`)
	sb.WriteString(`<D:prop><D:getetag/><C:address-data/></D:prop>`)
	for _, h := range hrefs {
		sb.WriteString(fmt.Sprintf("<D:href>%s</D:href>", h))
	}
	sb.WriteString(`</C:addressbook-multiget>`)

	resp, err := c.do(ctx, "REPORT", c.absURL(c.bookPath),
		"1", strings.NewReader(sb.String()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 207 {
		return nil, fmt.Errorf("synology multiget: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseMultiGetResponse(body)
}

func (c *Client) do(ctx context.Context, method, url, depth string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.username, c.password)
	if depth != "" {
		req.Header.Set("Depth", depth)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/xml; charset=utf-8")
	}
	return c.httpClient.Do(req)
}

func (c *Client) absURL(p string) string {
	if strings.HasPrefix(p, "http") {
		return p
	}
	return c.baseURL + p
}

func (c *Client) cardHref(uid string) string {
	return c.bookPath + uid + ".vcf"
}

type msDav struct {
	Responses []struct {
		Href     string `xml:"href"`
		Propstat []struct {
			Status string `xml:"status"`
			Prop   struct {
				ETag        string `xml:"getetag"`
				AddressData string `xml:"address-data"`
				ContentType string `xml:"getcontenttype"`
			} `xml:"prop"`
		} `xml:"propstat"`
	} `xml:"response"`
}

func parseHrefs(body []byte, bookPath string) ([]string, error) {
	var ms msDav
	if err := xml.Unmarshal(body, &ms); err != nil {
		return nil, fmt.Errorf("parse propfind: %w", err)
	}
	var out []string
	for _, r := range ms.Responses {
		if r.Href == bookPath || r.Href == strings.TrimRight(bookPath, "/")+"/" {
			continue
		}
		if strings.HasSuffix(r.Href, ".vcf") {
			out = append(out, r.Href)
		}
	}
	return out, nil
}

func parseMultiGetResponse(body []byte) ([]Contact, error) {
	var ms msDav
	if err := xml.Unmarshal(body, &ms); err != nil {
		return nil, fmt.Errorf("parse multiget: %w", err)
	}
	var out []Contact
	for _, r := range ms.Responses {
		for _, ps := range r.Propstat {
			if !strings.Contains(ps.Status, "200") {
				continue
			}
			if ps.Prop.AddressData == "" {
				continue
			}
			vcb := []byte(ps.Prop.AddressData)
			etag := ps.Prop.ETag
			if etag == "" {
				etag = etagOf(vcb)
			}
			uid := path.Base(strings.TrimSuffix(r.Href, ".vcf"))
			out = append(out, Contact{
				UID:   uid,
				Href:  r.Href,
				ETag:  etag,
				VCard: vcb,
			})
		}
	}
	return out, nil
}

func etagOf(b []byte) string {
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}
