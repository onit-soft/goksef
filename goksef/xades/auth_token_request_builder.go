package xades

import (
	"encoding/xml"
	"errors"
	"strings"
)

type SubjectIdentifierTypeEnum string

const (
	CertificateSubject     SubjectIdentifierTypeEnum = "certificateSubject"
	CertificateFingerprint SubjectIdentifierTypeEnum = "certificateFingerprint"
)

func (s SubjectIdentifierTypeEnum) FromValue(v string) (SubjectIdentifierTypeEnum, error) {
	switch v {
	case "certificateSubject":
		return CertificateSubject, nil
	case "certificateFingerprint":
		return CertificateFingerprint, nil
	default:
		return "", errors.New("invalid SubjectIdentifierTypeEnum value: " + v)
	}
}

func (s SubjectIdentifierTypeEnum) Value() string {
	return string(s)
}

type TContextIdentifier struct {
	XMLName    xml.Name `xml:"ContextIdentifier"`
	Nip        string   `xml:"Nip,omitempty"`
	InternalID string   `xml:"InternalId,omitempty"`
	NipVatUE   string   `xml:"NipVatUe,omitempty"`
	PeppolID   string   `xml:"PeppolId,omitempty"`
}

type AllowedIps struct {
	XMLName    xml.Name `xml:"AllowedIps"`
	Ip4Address []string `xml:"Ip4Address,omitempty"`
	Ip4Range   []string `xml:"Ip4Range,omitempty"`
	Ip4Mask    []string `xml:"Ip4Mask,omitempty"`
}

type AuthorizationPolicy struct {
	XMLName    xml.Name    `xml:"AuthorizationPolicy"`
	AllowedIps *AllowedIps `xml:"AllowedIps"`
}

type AuthTokenRequest struct {
	XMLName xml.Name `xml:"AuthTokenRequest"`

	Xmlns    string `xml:"xmlns,attr"`
	XmlnsXSI string `xml:"xmlns:xsi,attr"`
	XmlnsXSD string `xml:"xmlns:xsd,attr"`

	Challenge             string                    `xml:"Challenge"`
	ContextIdentifier     *TContextIdentifier       `xml:"ContextIdentifier"`
	SubjectIdentifierType SubjectIdentifierTypeEnum `xml:"SubjectIdentifierType"`
	AuthorizationPolicy   *AuthorizationPolicy      `xml:"AuthorizationPolicy,omitempty"`
}

type AuthTokenRequestBuilder struct {
	challenge             string
	challengeSet          bool
	context               *TContextIdentifier
	subjectIdentifierType SubjectIdentifierTypeEnum
	authorizationPolicy   *AuthorizationPolicy
}

func NewAuthTokenRequestBuilder() *AuthTokenRequestBuilder {
	return &AuthTokenRequestBuilder{
		context: &TContextIdentifier{},
	}
}

func (b *AuthTokenRequestBuilder) WithChallenge(challenge string) *AuthTokenRequestBuilder {
	if strings.TrimSpace(challenge) == "" {
		panic("Challenge cannot be null or empty.")
	}
	b.challenge = challenge
	b.challengeSet = true
	return b
}

func (b *AuthTokenRequestBuilder) WithContextNip(value string) *AuthTokenRequestBuilder {
	if strings.TrimSpace(value) == "" {
		panic("Context value cannot be null or empty.")
	}
	if b.context.InternalID != "" || b.context.NipVatUE != "" || b.context.PeppolID != "" {
		panic("Other context type has been already set")
	}
	b.context.Nip = value
	return b
}

func (b *AuthTokenRequestBuilder) WithInternalID(value string) *AuthTokenRequestBuilder {
	if strings.TrimSpace(value) == "" {
		panic("Context value cannot be null or empty.")
	}
	if b.context.Nip != "" || b.context.NipVatUE != "" || b.context.PeppolID != "" {
		panic("Other context type has been already set")
	}
	b.context.InternalID = value
	return b
}

func (b *AuthTokenRequestBuilder) WithNipVatEU(value string) *AuthTokenRequestBuilder {
	if strings.TrimSpace(value) == "" {
		panic("Context value cannot be null or empty.")
	}
	if b.context.InternalID != "" || b.context.Nip != "" || b.context.PeppolID != "" {
		panic("Other context type has been already set")
	}
	b.context.NipVatUE = value
	return b
}

func (b *AuthTokenRequestBuilder) WithPeppolID(value string) *AuthTokenRequestBuilder {
	if strings.TrimSpace(value) == "" {
		panic("Context value cannot be null or empty.")
	}
	if b.context.InternalID != "" || b.context.Nip != "" || b.context.NipVatUE != "" {
		panic("Other context type has been already set")
	}
	b.context.PeppolID = value
	return b
}

func (b *AuthTokenRequestBuilder) WithSubjectType(value SubjectIdentifierTypeEnum) *AuthTokenRequestBuilder {
	b.subjectIdentifierType = value
	return b
}

func (b *AuthTokenRequestBuilder) WithAuthorizationPolicy(ipAddress, ipRange, ipMask []string) *AuthTokenRequestBuilder {
	allowedIps := &AllowedIps{
		Ip4Address: make([]string, 0),
		Ip4Range:   make([]string, 0),
		Ip4Mask:    make([]string, 0),
	}

	if ipAddress != nil {
		allowedIps.Ip4Address = append(allowedIps.Ip4Address, ipAddress...)
	}
	if ipRange != nil {
		allowedIps.Ip4Range = append(allowedIps.Ip4Range, ipRange...)
	}
	if ipMask != nil {
		allowedIps.Ip4Mask = append(allowedIps.Ip4Mask, ipMask...)
	}

	b.authorizationPolicy = &AuthorizationPolicy{
		AllowedIps: allowedIps,
	}
	return b
}

func (b *AuthTokenRequestBuilder) Build() (*AuthTokenRequest, error) {
	if !b.challengeSet {
		return nil, errors.New("challenge has not been set. Call WithChallenge() first")
	}

	return &AuthTokenRequest{
		Xmlns:    "http://ksef.mf.gov.pl/auth/token/2.0",
		XmlnsXSI: "http://www.w3.org/2001/XMLSchema-instance",
		XmlnsXSD: "http://www.w3.org/2001/XMLSchema",

		Challenge:             b.challenge,
		ContextIdentifier:     b.context,
		SubjectIdentifierType: b.subjectIdentifierType,
		AuthorizationPolicy:   b.authorizationPolicy,
	}, nil
}
