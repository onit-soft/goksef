package goksef

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/onit-soft/goksef/goksef/xades"
)

type Client interface {
	WithAuthMethod(authMethod KSEFAuthMethod) Client
	WithKeyPair(cert *x509.Certificate, signer crypto.Signer) Client
	WithKSEFToken(ksefToken string) Client
	WithOrganizationName(organizationName string) Client
	WithVatID(vatID string) Client
	WithCommonName(commonName string) Client
	WithCountryCode(countryCode string) Client
	UseSelfSigned() error
	GetInvoicesMetadata(filter Filter) (*InvoiceListResponse, error)
	ListSessions(sessionType string) (ListSessionsResponse, error)
	ListFailedInvoices(referenceNumber string) (InvoiceListResponse, error)
	OpenOnlineSession(req OpenOnlineSessionRequest) (onlineSession OpenOnlineSessionResponse, err error)
	CloseOnlineSession(referenceNumber string) error
	SendInvoices(send SendInvoices) (string, error)
	GetSymetricKey() (string, error)
	GetInvoiceExportStatus(referenceNumber string) (*InvoiceExportStatusResponse, error)
	CreateInvoiceExport(request InvoiceExportRequest) (*InvoiceExportResponse, error)
	GetInvoiceExportPart(url string) ([]byte, error)
	ExportInvoices(filter Filter) (map[string][]byte, error)
}

type request struct {
	path          string
	contentType   string
	authorization string
	body          []byte
}

type client struct {
	client  http.Client
	baseURL string

	vatID            string
	organizationName string
	commonName       string
	countryCode      string
	authMethod       KSEFAuthMethod

	accessToken string
	validUntil  *time.Time

	cert      *x509.Certificate
	signer    crypto.Signer
	ksefToken string
}

func NewClient(baseURL string) Client {
	return &client{
		client:     http.Client{},
		baseURL:    baseURL,
		authMethod: KSEFAuthMethodCertificate,
	}
}

func (c *client) WithKeyPair(cert *x509.Certificate, signer crypto.Signer) Client {
	c.cert = cert
	c.signer = signer
	return c
}

func (c *client) WithOrganizationName(organizationName string) Client {
	c.organizationName = organizationName
	return c
}

func (c *client) WithVatID(vatID string) Client {
	c.vatID = vatID
	return c
}

func (c *client) WithCommonName(commonName string) Client {
	c.commonName = commonName
	return c
}

func (c *client) WithCountryCode(countryCode string) Client {
	c.countryCode = countryCode
	return c
}

func (c *client) UseSelfSigned() error {
	if c.organizationName == "" {
		return errors.New("missing organization name for certificate generation")
	}

	if c.vatID == "" {
		return errors.New("missing vat id for certificate generation")
	}

	if c.commonName == "" {
		return errors.New("missing commmon name for certificate generation")
	}

	if c.countryCode == "" {
		return errors.New("missing country code for certificate generation")
	}

	priv, cert, err := NewSelfSignedCertificateBuilder(
		c.organizationName,
		"VAT"+c.countryCode+"-"+c.vatID,
		c.commonName,
		c.countryCode,
	).Build()
	if err != nil {
		return err
	}

	c.signer = priv
	c.cert = cert
	return nil
}

func (c *client) WithAuthMethod(authMethod KSEFAuthMethod) Client {
	c.authMethod = authMethod
	return c
}

func (c *client) WithKSEFToken(ksefToken string) Client {
	c.ksefToken = ksefToken
	return c
}

func (k *client) GetInvoicesMetadata(filter Filter) (*InvoiceListResponse, error) {
	var invoiceListResponse InvoiceListResponse
	data, err := json.Marshal(filter)
	if err != nil {
		return nil, err
	}

	response, statusCode, err := k.postWithAuth(APIv2InvoicesQueryMetadataPath, ContentTypeJSON, data)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("error getting invoice metadata, status code %d, response: %s", statusCode, response)
	}

	err = json.Unmarshal(response, &invoiceListResponse)
	if err != nil {
		return nil, err
	}

	return &invoiceListResponse, nil
}

func (k *client) GetInvoiceExportStatus(referenceNumber string) (*InvoiceExportStatusResponse, error) {
	var invoiceExportStatusResponse InvoiceExportStatusResponse

	response, statusCode, err := k.getWithAuth(
		fmt.Sprintf(APIv2InvoiceExportStatusPath, referenceNumber),
	)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("error getting invoice export status, status code %d, response: %s", statusCode, response)
	}

	err = json.Unmarshal(response, &invoiceExportStatusResponse)
	if err != nil {
		return nil, err
	}

	return &invoiceExportStatusResponse, nil
}

func (k *client) GetInvoiceExportPart(url string) ([]byte, error) {
	data, statusCode, err := k.getWithUrl(url)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("error getting invoice export part, status code %d, response: %s", statusCode, data)
	}

	return data, nil
}

func (k *client) CreateInvoiceExport(request InvoiceExportRequest) (*InvoiceExportResponse, error) {
	var invoiceExportResponse InvoiceExportResponse
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	response, statusCode, err := k.postWithAuth(APIv2InvoiceExportPath, ContentTypeJSON, data)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK && statusCode != http.StatusCreated {
		return nil, fmt.Errorf("error getting invoice export, status code %d, response: %s", statusCode, response)
	}

	err = json.Unmarshal(response, &invoiceExportResponse)
	if err != nil {
		return nil, err
	}

	return &invoiceExportResponse, nil
}

func (k *client) ExportInvoices(filter Filter) (map[string][]byte, error) {
	symetricKey, err := k.GetSymetricKey()
	if err != nil {
		return nil, err
	}

	encryptionData, err := GetEncryptionData(symetricKey)
	if err != nil {
		return nil, err
	}

	exportResponse, err := k.CreateInvoiceExport(InvoiceExportRequest{
		Filters: filter,
		Encryption: Encryption{
			EncryptedSymetricKey: encryptionData.EncryptedSymmetricKey,
			InitializationVector: encryptionData.InitializationVector,
		},
	})
	if err != nil {
		return nil, err
	}

	var exportStatusResponse *InvoiceExportStatusResponse

	ticker := time.NewTicker(time.Second * 5)

	for range ticker.C {
		exportStatusResponse, err = k.GetInvoiceExportStatus(exportResponse.ReferenceNumber)
		if err != nil {
			return nil, err
		}

		if exportStatusResponse.Status.Code == http.StatusOK {
			break
		}
	}

	result := make(map[string][]byte)

	for _, part := range exportStatusResponse.Package.Parts {
		encryptedData, err := k.GetInvoiceExportPart(part.Url)
		if err != nil {
			return nil, err
		}

		decryptedData, err := DecryptBytesWithAES256(encryptedData, encryptionData.CipherKey, encryptionData.CipherIV)
		if err != nil {
			return nil, err
		}

		reader := bytes.NewReader(decryptedData)

		zipReader, err := zip.NewReader(reader, int64(len(decryptedData)))
		if err != nil {
			return nil, err
		}

		for _, f := range zipReader.File {
			fileName := f.FileInfo().Name()

			r, err := f.Open()
			if err != nil {
				return nil, err
			}

			body, err := io.ReadAll(r)
			if err != nil {
				return nil, err
			}

			ksefNumber, _ := strings.CutSuffix(fileName, ".xml")
			result[ksefNumber] = body
		}
	}
	return result, nil
}

func (k *client) GetPublicKeyCertificate() (publicKeyCertificates []PublicKeyCertificate, err error) {
	response, statusCode, err := k.get(request{
		path: APIv2PublicKeyCertificatesPath,
	})
	if err != nil {
		return
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("error getting public key certificate, status code %d, response: %s", statusCode, response)
	}

	err = json.Unmarshal(response, &publicKeyCertificates)
	if err != nil {
		return
	}

	return publicKeyCertificates, nil
}

func (k *client) GetSymetricKey() (string, error) {
	publicKeyCertificates, err := k.GetPublicKeyCertificate()
	if err != nil {
		return "", err
	}

	for _, key := range publicKeyCertificates {
		for _, usage := range key.Usage {
			if usage == "SymmetricKeyEncryption" {
				return base64PublicKeyToPEM(key.Certificate)
			}
		}
	}
	return "", fmt.Errorf("symetric key not found")
}

func (k *client) GetKsefTokenEncryption() (*rsa.PublicKey, error) {
	publicKeyCertificates, err := k.GetPublicKeyCertificate()
	if err != nil {
		return nil, err
	}

	for _, key := range publicKeyCertificates {
		for _, usage := range key.Usage {
			if usage == "KsefTokenEncryption" {
				pemKey, err := base64PublicKeyToPEM(key.Certificate)
				if err != nil {
					return nil, err
				}

				pubKey, err := parsePublicKeyFromCertificatePEM(pemKey)
				if err != nil {
					return nil, err
				}

				return pubKey, nil
			}
		}
	}
	return nil, fmt.Errorf("ksef token encryption key not found")
}

func (k *client) OpenOnlineSession(req OpenOnlineSessionRequest) (onlineSession OpenOnlineSessionResponse, err error) {
	content, err := json.Marshal(req)
	if err != nil {
		return
	}

	response, statusCode, err := k.postWithAuth(APIv2OpenOnlineSessionPath, ContentTypeJSON, content)
	if err != nil {
		return
	}

	if statusCode != http.StatusOK && statusCode != http.StatusCreated {
		return onlineSession, fmt.Errorf("error opening online session, status code %d, response: %s", statusCode, response)
	}

	err = json.Unmarshal(response, &onlineSession)
	if err != nil {
		return
	}

	return onlineSession, nil
}

func (k *client) CloseOnlineSession(referenceNumber string) error {

	response, statusCode, err := k.postWithAuth(
		fmt.Sprintf(APIv2CloseOnlineSessionPath, referenceNumber),
		ContentTypeJSON,
		nil,
	)
	if err != nil {
		return err
	}

	if statusCode != http.StatusNoContent {
		return fmt.Errorf("error closing online session, status code %d, response: %s", statusCode, response)
	}

	return nil
}

func (k *client) SendInvoices(send SendInvoices) (string, error) {
	symetricKey, err := k.GetSymetricKey()
	if err != nil {
		return "", err
	}

	encryptionData, err := GetEncryptionData(symetricKey)
	if err != nil {
		return "", err
	}

	session, err := k.OpenOnlineSession(OpenOnlineSessionRequest{
		FormCode: send.FormCode,
		Encryption: Encryption{
			EncryptedSymetricKey: encryptionData.EncryptedSymmetricKey,
			InitializationVector: encryptionData.InitializationVector,
		},
	})
	if err != nil {
		return "", nil
	}

	for _, invoiceContent := range send.InvoiceContents {
		invoiceMetadata, err := GetMetaData(invoiceContent)
		if err != nil {
			return "", nil
		}

		encryptedInvoice, err := EncryptBytesWithAES256(invoiceContent, encryptionData.CipherKey, encryptionData.CipherIV)
		if err != nil {
			return "", nil
		}

		encryptedInvoiceMetadata, err := GetMetaData(encryptedInvoice)
		if err != nil {
			return "", nil
		}

		invoiceRequest := SendInvoiceRequest{
			InvoiceHash:             invoiceMetadata.HashSHA,
			InvoiceSize:             invoiceMetadata.FileSize,
			EncryptedInvoiceHash:    encryptedInvoiceMetadata.HashSHA,
			EncryptedInvoiceSize:    encryptedInvoiceMetadata.FileSize,
			EncryptedInvoiceContent: encryptedInvoice,
		}

		content, err := json.Marshal(invoiceRequest)
		if err != nil {
			return "", nil
		}

		resp, statusCode, err := k.postWithAuth(
			fmt.Sprintf(APIv2SendInvoicePath, session.ReferenceNumber),
			ContentTypeJSON,
			content,
		)
		if err != nil {
			return "", err
		}

		if statusCode != http.StatusAccepted {
			return "", fmt.Errorf("error sending invoice, status code %d, body: %s", statusCode, resp)
		}

		var sendInvoiceResponse SendInvoiceResponse

		err = json.Unmarshal(resp, &sendInvoiceResponse)
		if err != nil {
			return "", err
		}
	}

	err = k.CloseOnlineSession(session.ReferenceNumber)
	if err != nil {
		return "", err
	}

	return session.ReferenceNumber, nil
}

func (k *client) ListSessions(sessionType string) (ListSessionsResponse, error) {
	response, statusCode, err := k.getWithAuth(
		APIv2ListSessionsPath + fmt.Sprintf("?sessionType=%s&pageSize=%d", sessionType, 100),
	)
	if err != nil {
		return ListSessionsResponse{}, err
	}

	if statusCode != http.StatusOK {
		return ListSessionsResponse{}, fmt.Errorf("error listing sessions, status code %d, response: %s", statusCode, response)
	}

	var listSessionseResponse ListSessionsResponse
	err = json.Unmarshal(response, &listSessionseResponse)
	if err != nil {
		return ListSessionsResponse{}, err
	}

	return listSessionseResponse, nil
}

func (k *client) ListFailedInvoices(referenceNumber string) (InvoiceListResponse, error) {
	response, statusCode, err := k.getWithAuth(
		fmt.Sprintf(APIv2ListFailedInvoicesPath, referenceNumber),
	)
	if err != nil {
		return InvoiceListResponse{}, err
	}

	if statusCode != http.StatusOK {
		return InvoiceListResponse{}, nil
	}

	var invoiceListResponse InvoiceListResponse
	err = json.Unmarshal(response, &invoiceListResponse)
	if err != nil {
		return InvoiceListResponse{}, err
	}

	return invoiceListResponse, nil
}

func (k *client) getAuthChallange() (authChallange AuthChallange, err error) {
	data, statusCode, err := k.post(request{
		path: APIv2AuthChallengePath,
	})
	if err != nil {
		return
	}

	if statusCode != http.StatusOK {
		return authChallange, fmt.Errorf("error getting auth challange, status code %d, body: %s", statusCode, data)
	}

	err = json.Unmarshal(data, &authChallange)
	if err != nil {
		return
	}

	return authChallange, nil
}

func (k *client) refreshAuthToken() error {
	authChallange, err := k.getAuthChallange()
	if err != nil {
		return err
	}

	var authTokenResponse AuthTokenResponse

	switch k.authMethod {
	case KSEFAuthMethodCertificate:
		authToken, err := xades.NewAuthTokenRequestBuilder().
			WithChallenge(authChallange.Challange).
			WithContextNip(k.vatID).
			WithSubjectType(xades.CertificateSubject).
			Build()
		if err != nil {
			return err
		}

		signedAuthToken, err := xades.Sign(*authToken, k.cert, k.signer)
		if err != nil {
			return err
		}

		authTokenResponse, err = k.getAuthTokenWithXAdES(signedAuthToken)
		if err != nil {
			return err
		}
	case KSEFAuthMethodToken:
		pubKey, err := k.GetKsefTokenEncryption()
		if err != nil {
			return err
		}

		fmt.Println("timestamp: ", authChallange.Timestamp)

		t, err := time.Parse(time.RFC3339Nano, authChallange.Timestamp)
		if err != nil {
			return err
		}

		tokenTimestamp := k.ksefToken + "|" + strconv.Itoa(int(t.UnixMilli()))

		encryptedToken, err := encryptWithRSAUsingPublicKey([]byte(tokenTimestamp), pubKey)
		if err != nil {
			return err
		}

		req := AuthKSEFTokenRequest{
			Challange: authChallange.Challange,
			ContextIdentifier: ContextIdentifier{
				Type:  "Nip",
				Value: k.vatID,
			},
			EncryptedToken: base64.StdEncoding.EncodeToString(encryptedToken),
		}

		authTokenResponse, err = k.getAuthTokenWithKSEFToken(req)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("error invalid auth method")
	}

	accessTokenResponse, err := k.getAccessToken(authTokenResponse.AuthToken.Token)
	if err != nil {
		return err
	}

	validUntil, err := time.Parse(time.RFC3339, accessTokenResponse.AccessToken.ValidUntil)
	if err != nil {
		return fmt.Errorf("error parsing time: %v", err)
	}

	k.accessToken = accessTokenResponse.AccessToken.Token
	k.validUntil = &validUntil
	return nil
}

func (k *client) getAuthTokenWithXAdES(signedAuthToken []byte) (AuthTokenResponse, error) {
	var authTokenResponse AuthTokenResponse

	data, statusCode, err := k.post(request{
		path:        APIv2AuthXadesSignaturePath,
		contentType: ContentTypeXML,
		body:        signedAuthToken,
	})
	if err != nil {
		return authTokenResponse, err
	}

	if statusCode != http.StatusOK && statusCode != http.StatusAccepted {
		return authTokenResponse, fmt.Errorf("error getting auth token, status code %d, body: %s", statusCode, data)
	}

	err = json.Unmarshal(data, &authTokenResponse)
	if err != nil {
		return authTokenResponse, fmt.Errorf("error unmarshaling auth token: %v", err)
	}

	return authTokenResponse, nil
}

func (k *client) getAuthTokenWithKSEFToken(req AuthKSEFTokenRequest) (AuthTokenResponse, error) {
	var authTokenResponse AuthTokenResponse

	body, err := json.Marshal(req)
	if err != nil {
		return authTokenResponse, err
	}

	data, statusCode, err := k.post(request{
		path:        APIv2AuthKSEFTokenPath,
		contentType: ContentTypeJSON,
		body:        body,
	})
	if err != nil {
		return authTokenResponse, err
	}

	if statusCode != http.StatusOK && statusCode != http.StatusAccepted {
		return authTokenResponse, fmt.Errorf("error getting auth token, status code %d, body: %s", statusCode, data)
	}

	err = json.Unmarshal(data, &authTokenResponse)
	if err != nil {
		return authTokenResponse, fmt.Errorf("error unmarshaling auth token: %v", err)
	}

	return authTokenResponse, nil
}

func (k *client) getAccessToken(authToken string) (AccessTokenResponse, error) {
	var accessTokenResponse AccessTokenResponse

	data, statusCode, err := k.post(request{
		path:          APIv2AuthTokenRedeemPath,
		authorization: "Bearer " + authToken,
	})
	if err != nil {
		return accessTokenResponse, fmt.Errorf("error sending request for access token: %v", err)
	}

	if statusCode != http.StatusOK {
		return accessTokenResponse, fmt.Errorf("error getting access token, status code %d, body: %s", statusCode, data)
	}

	err = json.Unmarshal(data, &accessTokenResponse)
	if err != nil {
		return accessTokenResponse, fmt.Errorf("error unmarshaling access token: %v", err)
	}

	return accessTokenResponse, nil
}

func (k *client) getWithUrl(url string) (data []byte, statusCode int, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return
	}

	resp, err := k.client.Do(req)
	if err != nil {
		return
	}

	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	return data, resp.StatusCode, nil
}

func (k *client) get(request request) (data []byte, statusCode int, err error) {
	req, err := http.NewRequest(http.MethodGet, k.baseURL+request.path, nil)
	if err != nil {
		return
	}

	if request.authorization != "" {
		req.Header.Set(HTTPAuthorizationHeader, request.authorization)
	}

	resp, err := k.client.Do(req)
	if err != nil {
		return
	}

	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	return data, resp.StatusCode, nil
}

func (k *client) post(request request) (data []byte, statusCode int, err error) {
	req, err := http.NewRequest(http.MethodPost, k.baseURL+request.path, bytes.NewReader(request.body))
	if err != nil {
		return
	}

	if request.contentType != "" {
		req.Header.Set(HTTPConentTypeHeader, request.contentType)
	}

	if request.authorization != "" {
		req.Header.Set(HTTPAuthorizationHeader, request.authorization)
	}

	resp, err := k.client.Do(req)
	if err != nil {
		return
	}

	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	return data, resp.StatusCode, nil
}

func (k *client) getWithAuth(path string) (data []byte, statusCode int, err error) {
	if k.validUntil == nil || time.Now().After(*k.validUntil) {
		err = k.refreshAuthToken()
		if err != nil {
			return nil, 0, fmt.Errorf("error refreshing auth token: %v", err)
		}
	}

	return k.get(request{
		path:          path,
		authorization: "Bearer " + k.accessToken,
	})
}

func (k *client) postWithAuth(path, contentType string, body []byte) (data []byte, statusCode int, err error) {
	if k.validUntil == nil || time.Now().After(*k.validUntil) {
		err = k.refreshAuthToken()
		if err != nil {
			return nil, 0, fmt.Errorf("error refreshing auth token: %v", err)
		}
	}

	return k.post(request{
		path:          path,
		contentType:   contentType,
		body:          body,
		authorization: "Bearer " + k.accessToken,
	})
}
