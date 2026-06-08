// Package dav contains RFC 6352 CardDAV XML structures and property builders.
package dav

import (
	"bytes"
	"encoding/xml"
	"fmt"
)

const (
	NsDAV     = "DAV:"
	NsCardDAV = "urn:ietf:params:xml:ns:carddav"
	OK207     = "HTTP/1.1 200 OK"
)

// MultiStatus is the 207 Multi-Status response envelope (RFC 4918 §11.1).
type MultiStatus struct {
	XMLName   xml.Name   `xml:"D:multistatus"`
	XmlnsD    string     `xml:"xmlns:D,attr"`
	XmlnsC    string     `xml:"xmlns:C,attr"`
	Responses []Response `xml:"D:response"`
}

// Response is one DAV:response inside a MultiStatus.
type Response struct {
	Href     string     `xml:"D:href"`
	Propstat []Propstat `xml:"D:propstat,omitempty"`
	Status   string     `xml:"D:status,omitempty"`
}

// Propstat pairs a prop block with its HTTP status.
type Propstat struct {
	Prop   RawProp `xml:"D:prop"`
	Status string  `xml:"D:status"`
}

// RawProp embeds pre-rendered XML without re-escaping.
type RawProp struct {
	Inner []byte `xml:",innerxml"`
}

// XMLf is a small helper to build property XML from a format string.
func XMLf(format string, args ...any) []byte {
	return []byte(fmt.Sprintf(format, args...))
}

// XMLEscape returns the XML-escaped form of b.
func XMLEscape(b []byte) []byte {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, b)
	return buf.Bytes()
}

// PrincipalProps returns inner XML for a DAV principal resource.
// Advertises addressbook-home-set and supported-report-set for client discovery.
func PrincipalProps(baseURL string) []byte {
	return XMLf(
		`<D:resourcetype><D:collection/><D:principal/></D:resourcetype>`+
			`<D:displayname>ProtonMail Contacts</D:displayname>`+
			`<C:addressbook-home-set>`+
			`<D:href>%s/dav/addressbooks/me/</D:href>`+
			`</C:addressbook-home-set>`+
			`<D:current-user-principal>`+
			`<D:href>%s/dav/principals/me/</D:href>`+
			`</D:current-user-principal>`+
			`<D:supported-report-set>`+
			`<D:supported-report><D:report><C:addressbook-query/></D:report></D:supported-report>`+
			`<D:supported-report><D:report><C:addressbook-multiget/></D:report></D:supported-report>`+
			`<D:supported-report><D:report><D:sync-collection/></D:report></D:supported-report>`+
			`</D:supported-report-set>`,
		baseURL, baseURL,
	)
}

// AddressbookHomeProps returns inner XML for the addressbook home collection.
func AddressbookHomeProps(baseURL string) []byte {
	return XMLf(
		`<D:resourcetype><D:collection/></D:resourcetype>`+
			`<D:displayname>Address Books</D:displayname>`+
			`<C:addressbook-home-set>`+
			`<D:href>%s/dav/addressbooks/me/</D:href>`+
			`</C:addressbook-home-set>`+
			`<D:current-user-principal>`+
			`<D:href>%s/dav/principals/me/</D:href>`+
			`</D:current-user-principal>`,
		baseURL, baseURL,
	)
}

// AddressbookCollectionProps returns inner XML for the contacts addressbook collection.
// syncToken is embedded so clients can detect changes via sync-collection REPORT.
func AddressbookCollectionProps(baseURL, syncToken string) []byte {
	return XMLf(
		`<D:resourcetype><D:collection/><C:addressbook/></D:resourcetype>`+
			`<D:displayname>ProtonMail Contacts</D:displayname>`+
			`<C:supported-address-data>`+
			`<C:address-data-type content-type="text/vcard" version="4.0"/>`+
			`<C:address-data-type content-type="text/vcard" version="3.0"/>`+
			`</C:supported-address-data>`+
			`<D:sync-token>%s</D:sync-token>`+
			`<D:current-user-principal>`+
			`<D:href>%s/dav/principals/me/</D:href>`+
			`</D:current-user-principal>`+
			`<C:max-resource-size>10485760</C:max-resource-size>`+
			`<D:supported-report-set>`+
			`<D:supported-report><D:report><C:addressbook-query/></D:report></D:supported-report>`+
			`<D:supported-report><D:report><C:addressbook-multiget/></D:report></D:supported-report>`+
			`<D:supported-report><D:report><D:sync-collection/></D:report></D:supported-report>`+
			`</D:supported-report-set>`,
		syncToken, baseURL,
	)
}

// CardMetaProps returns inner XML for a .vcf resource without the card body.
// Used in PROPFIND Depth:1 collection listings.
func CardMetaProps(etag string) []byte {
	return XMLf(
		`<D:resourcetype/>`+
			`<D:getcontenttype>text/vcard; charset=utf-8</D:getcontenttype>`+
			`<D:getetag>%s</D:getetag>`,
		etag,
	)
}

// CardDataProps returns inner XML for a .vcf resource including the vCard body.
// Used in addressbook-query and addressbook-multiget REPORTs.
func CardDataProps(etag string, vcBytes []byte) []byte {
	return XMLf(
		`<D:resourcetype/>`+
			`<D:getcontenttype>text/vcard; charset=utf-8</D:getcontenttype>`+
			`<D:getetag>%s</D:getetag>`+
			`<C:address-data>%s</C:address-data>`,
		etag,
		string(XMLEscape(vcBytes)),
	)
}
