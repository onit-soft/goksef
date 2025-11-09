package goksef

const (
	APIv2AuthXadesSignaturePath    = "/api/v2/auth/xades-signature"
	APIv2AuthChallengePath         = "/api/v2/auth/challenge"
	APIv2AuthTokenRedeemPath       = "/api/v2/auth/token/redeem"
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
