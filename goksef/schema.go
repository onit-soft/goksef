package goksef

import "time"

type AuthChallange struct {
	Challange string `json:"challenge"`
	Timestamp string `json:"timestamp"`
}

type AuthTokenResponse struct {
	ReferenceNumber string    `json:"referenceNumber"`
	AuthToken       AuthToken `json:"authenticationToken"`
}

type AuthToken struct {
	Token      string `json:"token"`
	ValidUntil string `json:"validUntil"`
}

type AccessTokenResponse struct {
	AccessToken AccessToken `json:"accessToken"`
}

type AccessToken struct {
	Token      string `json:"token"`
	ValidUntil string `json:"validUntil"`
}

type Filter struct {
	SubjectType   string    `json:"subjectType,omitempty"`
	DateRange     DateRange `json:"dateRange,omitempty"`
	Amount        *Amount   `json:"amount,omitempty"`
	CurrencyCodes []string  `json:"currencyCodes,omitempty"`
	InvoicingMode string    `json:"invoicingMode,omitempty"`
	FormType      string    `json:"formType,omitempty"`
	InvoiceTypes  []string  `json:"invoiceTypes,omitempty"`
	HasAttachment bool      `json:"hasAttachment,omitempty"`
}

type DateRange struct {
	DateType string    `json:"dateType,omitempty"`
	From     time.Time `json:"from,omitempty"`
	To       time.Time `json:"to,omitempty"`
}

type Amount struct {
	Type string  `json:"type,omitempty"`
	From float64 `json:"from,omitempty"`
	To   float64 `json:"to,omitempty"`
}

type InvoiceListResponse struct {
	HasMore     bool      `json:"hasMore"`
	IsTruncated bool      `json:"isTruncated"`
	Invoices    []Invoice `json:"invoices"`
}

type Invoice struct {
	KsefNumber           string     `json:"ksefNumber"`
	InvoiceNumber        string     `json:"invoiceNumber"`
	IssueDate            string     `json:"issueDate"`     // "YYYY-MM-DD"
	InvoicingDate        time.Time  `json:"invoicingDate"` // e.g. "2025-08-28T09:22:13.388+00:00"
	AcquisitionDate      time.Time  `json:"acquisitionDate"`
	PermanentStorageDate time.Time  `json:"permanentStorageDate"`
	Seller               Party      `json:"seller"`
	Buyer                Party      `json:"buyer"`
	NetAmount            float64    `json:"netAmount"`
	GrossAmount          float64    `json:"grossAmount"`
	VATAmount            float64    `json:"vatAmount"`
	Currency             string     `json:"currency"`
	InvoicingMode        string     `json:"invoicingMode"`
	InvoiceType          string     `json:"invoiceType"`
	FormCode             FormCode   `json:"formCode"`
	IsSelfInvoicing      bool       `json:"isSelfInvoicing"`
	HasAttachment        bool       `json:"hasAttachment"`
	InvoiceHash          string     `json:"invoiceHash"`
	ThirdSubjects        []Subject3 `json:"thirdSubjects"`
}

type Party struct {
	NIP        string      `json:"nip,omitempty"`
	Identifier *Identifier `json:"identifier,omitempty"`
	Name       string      `json:"name"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type FormCode struct {
	SystemCode    string `json:"systemCode"`
	SchemaVersion string `json:"schemaVersion"`
	Value         string `json:"value"`
}

type Subject3 struct {
	Identifier Identifier `json:"identifier"`
	Name       string     `json:"name"`
	Role       int        `json:"role"`
}
