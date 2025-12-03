package goksef

type KSEFAuthMethod int

const (
	KSEFAuthMethodUnknown KSEFAuthMethod = iota
	KSEFAuthMethodCertificate
	KSEFAuthMethodToken
)

const (
	APIv2AuthXadesSignaturePath    = "/api/v2/auth/xades-signature"
	APIv2AuthKSEFTokenPath         = "/api/v2/auth/ksef-token"
	APIv2AuthChallengePath         = "/api/v2/auth/challenge"
	APIv2AuthTokenRedeemPath       = "/api/v2/auth/token/redeem"
	APIv2AuthStatusPath            = "/api/v2/auth/%s"
	APIv2InvoiceExportPath         = "/api/v2/invoices/exports"
	APIv2InvoiceExportStatusPath   = "/api/v2/invoices/exports/%s"
	APIv2InvoicesQueryMetadataPath = "/api/v2/invoices/query/metadata"
	APIv2PublicKeyCertificatesPath = "/api/v2/security/public-key-certificates"
	APIv2ListSessionsPath          = "/api/v2/sessions"
	APIv2OpenOnlineSessionPath     = "/api/v2/sessions/online"
	APIv2SendInvoicePath           = "/api/v2/sessions/online/%s/invoices"
	APIv2CloseOnlineSessionPath    = "/api/v2/sessions/online/%s/close"
	APIv2ListFailedInvoicesPath    = "/api/v2/sessions/%s/invoices/failed"
)

const (
	ContentTypeXML  = "application/xml"
	ContentTypeJSON = "application/json"
)

const (
	HTTPConentTypeHeader    = "Content-type"
	HTTPAuthorizationHeader = "Authorization"
)
