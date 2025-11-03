package goksef

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"time"
)

type X500NameHolder struct {
	Name pkix.Name
}

func NewX500NameHolder(name pkix.Name) *X500NameHolder {
	return &X500NameHolder{Name: name}
}

func (h *X500NameHolder) GetName() pkix.Name {
	return h.Name
}

type CertificateBuilder struct {
	name pkix.Name
}

func NewCertificateBuilder() *CertificateBuilder {
	return &CertificateBuilder{
		name: pkix.Name{
			ExtraNames: make([]pkix.AttributeTypeAndValue, 0),
		},
	}
}

func isNotBlank(s string) bool {
	return strings.TrimSpace(s) != ""
}

func (b *CertificateBuilder) WithOrganizationName(organizationName string) *CertificateBuilder {
	if isNotBlank(organizationName) {
		b.name.Organization = append(b.name.Organization, organizationName)
	}
	return b
}

func (b *CertificateBuilder) WithOrganizationIdentifier(organizationIdentifier string) *CertificateBuilder {
	if isNotBlank(organizationIdentifier) {
		b.name.ExtraNames = append(b.name.ExtraNames, pkix.AttributeTypeAndValue{
			Type:  []int{2, 5, 4, 97},
			Value: organizationIdentifier,
		})
	}
	return b
}

func (b *CertificateBuilder) WithCommonName(commonName string) *CertificateBuilder {
	if isNotBlank(commonName) {
		b.name.CommonName = commonName
	}
	return b
}

func (b *CertificateBuilder) WithSerialNumber(serialNumber string) *CertificateBuilder {
	if isNotBlank(serialNumber) {
		b.name.SerialNumber = serialNumber
	}
	return b
}

func (b *CertificateBuilder) WithGivenName(givenName string) *CertificateBuilder {
	if isNotBlank(givenName) {
		b.name.ExtraNames = append(b.name.ExtraNames, pkix.AttributeTypeAndValue{
			Type:  []int{2, 5, 4, 42},
			Value: givenName,
		})
	}
	return b
}

func (b *CertificateBuilder) WithGivenNames(givenNames []string) *CertificateBuilder {
	if givenNames != nil {
		for _, name := range givenNames {
			if isNotBlank(name) {
				b.name.ExtraNames = append(b.name.ExtraNames, pkix.AttributeTypeAndValue{
					Type:  []int{2, 5, 4, 42},
					Value: name,
				})
			}
		}
	}
	return b
}

func (b *CertificateBuilder) WithSurname(surname string) *CertificateBuilder {
	if isNotBlank(surname) {
		b.name.ExtraNames = append(b.name.ExtraNames, pkix.AttributeTypeAndValue{
			Type:  []int{2, 5, 4, 4},
			Value: surname,
		})
	}
	return b
}

func (b *CertificateBuilder) WithUniqueIdentifier(uniqueIdentifier string) *CertificateBuilder {
	if isNotBlank(uniqueIdentifier) {
		// Unique Identifier OID: 2.5.4.45
		b.name.ExtraNames = append(b.name.ExtraNames, pkix.AttributeTypeAndValue{
			Type:  []int{2, 5, 4, 45},
			Value: uniqueIdentifier,
		})
	}
	return b
}

func (b *CertificateBuilder) WithCountryCode(countryCode string) *CertificateBuilder {
	if isNotBlank(countryCode) {
		b.name.Country = append(b.name.Country, countryCode)
	}
	return b
}

func (b *CertificateBuilder) Build() *X500NameHolder {
	return NewX500NameHolder(b.name)
}

func (b *CertificateBuilder) BuildForOrganization(organizationName, organizationIdentifier, commonName, countryCode string) *X500NameHolder {
	b.WithOrganizationIdentifier(organizationIdentifier)
	b.WithOrganizationName(organizationName)
	b.WithCommonName(commonName)
	b.WithCountryCode(countryCode)
	return b.Build()
}

func (b *CertificateBuilder) BuildForPerson(givenName, surname, serialNumber, commonName, countryCode string) *X500NameHolder {
	b.WithGivenName(givenName)
	b.WithSurname(surname)
	b.WithSerialNumber(serialNumber)
	b.WithCommonName(commonName)
	b.WithCountryCode(countryCode)
	return b.Build()
}

type SelfSignedCertificateBuilder struct {
	organizationName  string
	organizationVatID string
	commonName        string
	countryCode       string
}

func NewSelfSignedCertificateBuilder(organizationName, organizationVatID, commonName, countryCode string) SelfSignedCertificateBuilder {
	return SelfSignedCertificateBuilder{
		organizationName:  organizationName,
		organizationVatID: organizationVatID,
		commonName:        commonName,
		countryCode:       countryCode,
	}
}

func (b SelfSignedCertificateBuilder) Build() (privateKey *rsa.PrivateKey, cert *x509.Certificate, err error) {
	builder := NewCertificateBuilder()
	nameHolder := builder.BuildForOrganization(
		b.organizationName,
		b.organizationVatID,
		b.commonName,
		b.countryCode,
	)

	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               nameHolder.GetName(),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certificate, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return privateKey, certificate, nil
}
