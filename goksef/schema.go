package goksef

import "time"

type AuthChallange struct {
	Challange string `json:"challenge"`
	Timestamp string `json:"timestamp"`
}

type AuthKSEFTokenRequest struct {
	Challange         string            `json:"challenge"`
	ContextIdentifier ContextIdentifier `json:"contextIdentifier"`
	EncryptedToken    string            `json:"encryptedToken"`
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
	SubjectType     string           `json:"subjectType,omitempty"`
	DateRange       DateRange        `json:"dateRange,omitempty"`
	Amount          *Amount          `json:"amount,omitempty"`
	CurrencyCodes   []string         `json:"currencyCodes,omitempty"`
	InvoicingMode   string           `json:"invoicingMode,omitempty"`
	FormType        string           `json:"formType,omitempty"`
	InvoiceTypes    []string         `json:"invoiceTypes,omitempty"`
	HasAttachment   bool             `json:"hasAttachment,omitempty"`
	KsefNumber      string           `json:"ksefNumber,omitempty"`
	InvoiceNumber   string           `json:"invoiceNumber,omitempty"`
	SellerNip       string           `json:"sellerNip,omitempty"`
	BuyerIdentifier *BuyerIdentifier `json:"buyerIdentifier,omitempty"`
	IsSelfInvoicing bool             `json:"isSelfInvoicing,omitempty"`
}

type BuyerIdentifier struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
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
	OrdinalNumber        int32         `json:"ordinalNumber"`
	InvoiceNumber        string        `json:"invoiceNumber"`
	KsefNumber           string        `json:"ksefNumber"`
	ReferenceNumber      string        `json:"referenceNumber"`
	InvoiceFileName      string        `json:"invoiceFileName"`
	IssueDate            string        `json:"issueDate"`     // "YYYY-MM-DD"
	InvoicingDate        time.Time     `json:"invoicingDate"` // e.g. "2025-08-28T09:22:13.388+00:00"
	AcquisitionDate      time.Time     `json:"acquisitionDate"`
	PermanentStorageDate time.Time     `json:"permanentStorageDate"`
	Seller               Party         `json:"seller"`
	Buyer                Party         `json:"buyer"`
	NetAmount            float64       `json:"netAmount"`
	GrossAmount          float64       `json:"grossAmount"`
	VATAmount            float64       `json:"vatAmount"`
	Currency             string        `json:"currency"`
	InvoicingMode        string        `json:"invoicingMode"`
	InvoiceType          string        `json:"invoiceType"`
	FormCode             FormCode      `json:"formCode"`
	IsSelfInvoicing      bool          `json:"isSelfInvoicing"`
	HasAttachment        bool          `json:"hasAttachment"`
	InvoiceHash          string        `json:"invoiceHash"`
	ThirdSubjects        []Subject3    `json:"thirdSubjects"`
	Status               InvoiceStatus `json:"status"`
}

type InvoiceStatus struct {
	Code        int32    `json:"code"`
	Description string   `json:"description"`
	Details     []string `json:"details"`
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

type PublicKeyCertificate struct {
	Certificate string   `json:"certificate"`
	ValidFrom   string   `json:"validFrom"`
	ValidTo     string   `json:"validTo"`
	Usage       []string `json:"usage"`
}

type OpenOnlineSessionRequest struct {
	FormCode   FormCode   `json:"formCode"`
	Encryption Encryption `json:"encryption"`
}

type OpenOnlineSessionResponse struct {
	ReferenceNumber string `json:"referenceNumber"`
	ValidUntil      string `json:"validUntil"`
}

type Encryption struct {
	EncryptedSymetricKey string `json:"encryptedSymmetricKey"`
	InitializationVector string `json:"initializationVector"`
}

type SendInvoiceRequest struct {
	InvoiceHash             string `json:"invoiceHash"`
	InvoiceSize             int64  `json:"invoiceSize"`
	EncryptedInvoiceHash    string `json:"encryptedInvoiceHash"`
	EncryptedInvoiceSize    int64  `json:"encryptedInvoiceSize"`
	EncryptedInvoiceContent []byte `json:"encryptedInvoiceContent"`
	OfflineMode             bool   `json:"offlineMode"`
	HashOfCorrectedInvoice  string `json:"hashOfCorrectedInvoice,omitempty"`
}

type SendInvoices struct {
	InvoiceContents  [][]byte
	CorrectedInvoice [][]byte
	FormCode         FormCode
	OfflineMode      bool
}

type SendInvoiceResponse struct {
	ReferenceNumber string `json:"referenceNumber"`
}

type ListSessionsResponse struct {
	Sessions []Session `json:"sessions"`
}

type Session struct {
	ReferenceNumber        string        `json:"referenceNumber"`
	Status                 SessionStatus `json:"status"`
	DateCreated            string        `json:"dateCreated"`
	DateUpdated            string        `json:"dateUpdated"`
	ValidUntil             string        `json:"validUntil"`
	TotalInvoiceCount      int32         `json:"totalInvoiceCount"`
	SuccessfulInvoiceCount int32         `json:"successfulInvoiceCount"`
	FailedInvoiceCount     int32         `json:"failedInvoiceCount"`
}

type SessionStatus struct {
	Code        int32  `json:"code"`
	Description string `json:"description"`
	Details     string `json:"details"`
}

type ListFailedInvoicesResponse struct {
	Invoices []Invoice `json:"invoices"`
}

type InvoiceXMLTemplate struct {
	Header           HeaderXMLTemplate
	Issuer           CompanyXMLTemplate
	Payer            CompanyXMLTemplate
	SalesInformation SalesInformationXMLTemplate
}

type CompanyXMLTemplate struct {
	VATID        string // VAT identifier
	Name         string
	CountryCode  string // e.g. "PL"
	Email        string
	Phone        string
	AddressLine1 string
	AddressLine2 string
}

type HeaderXMLTemplate struct {
	Code          string
	SchemaVersion string
	IssueDate     string
}

type SalesInformationXMLTemplate struct {
	Currency      string
	IssueDate     string // "YYYY-MM-DD"
	IssuePlace    string
	InvoiceNumber string
	ExecutionDate string // "YYYY-MM-DD"
	NettoPrice    float32
	VatPrice      float32
	BruttoPrice   float32
	CashMethod    bool
	SelfBilling   bool
	ReverseCharge bool
	SplitPayment  bool
	TaxExemption  TaxExemptionXMLTemplate
	Type          string
	Rows          []SalesInformationRowXMLTemplate
}

type TaxExemptionXMLTemplate struct {
	Exception      bool
	ActLegalBasis  string
	DirectiveBasis string
	OtherBasis     string
}

type SalesInformationRowXMLTemplate struct {
	ItemNumber   int32
	Note         string
	UnitType     string
	Quantity     float32
	NetUnitPrice float32
	NetValue     float32
	VatRate      string
	VatValue     float32
	BruttoValue  float32
}

type ContextIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type InvoiceExportRequest struct {
	Encryption Encryption `json:"encryption"`
	Filters    Filter     `json:"filters"`
}

type InvoiceExportResponse struct {
	ReferenceNumber string `json:"referenceNumber"`
}

type InvoiceExportStatusResponse struct {
	Status        InvoiceExportStatus  `json:"status"`
	CompletedDate string               `json:"completedDate"`
	Package       InvoiceExportPackage `json:"package"`
}

type InvoiceExportStatus struct {
	Code        int    `json:"code"`
	Description string `json:"description"`
}

type InvoiceExportPackage struct {
	InvoiceCount             int                 `json:"invoiceCount"`
	Size                     int                 `json:"size"`
	Parts                    []InvoiceExportPart `json:"parts"`
	IsTruncated              bool                `json:"isTruncated"`
	LastPermanentStorageDate string              `json:"lastPermanentStorageDate"`
}

type InvoiceExportPart struct {
	OrdinalNumber     int    `json:"ordinalNumber"`
	PartName          string `json:"partName"`
	Method            string `json:"method"`
	Url               string `json:"url"`
	PartSize          int    `json:"partSize"`
	PartHash          string `json:"partHash"`
	EncryptedPartSize int    `json:"encryptedPartSize"`
	EncryptedPartHash string `json:"encryptedPartHash"`
	ExpirationDate    string `json:"expirationDate"`
}
