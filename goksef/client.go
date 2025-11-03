package goksef

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/onit-soft/goksef/goksef/xades"
)

type postRequest struct {
	path          string
	contentType   string
	authorization string
	body          []byte
}

type Client struct {
	client  http.Client
	baseURL string

	vatID            string
	organizationName string
	commonName       string
	countryCode      string

	accessToken string
	validUntil  *time.Time

	cert *x509.Certificate
	priv *rsa.PrivateKey
}

func NewClient(baseURL string) *Client {
	return &Client{
		client:  http.Client{},
		baseURL: baseURL,
	}
}

func (c *Client) WithKeyPair(cert *x509.Certificate, priv *rsa.PrivateKey) *Client {
	c.cert = cert
	c.priv = priv
	return c
}

func (c *Client) WithOrganizationName(organizationName string) *Client {
	c.organizationName = organizationName
	return c
}

func (c *Client) WithVatID(vatID string) *Client {
	c.vatID = vatID
	return c
}

func (c *Client) WithCommonName(commonName string) *Client {
	c.commonName = commonName
	return c
}

func (c *Client) WithCountryCode(countryCode string) *Client {
	c.countryCode = countryCode
	return c
}

func (c *Client) GenerateSelfSigned() error {
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

	c.priv = priv
	c.cert = cert
	return nil
}

func (k *Client) GetInvoicesMetadata(filter Filter) (*InvoiceListResponse, error) {
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

func (k *Client) getAuthChallange() (AuthChallange, error) {
	var authChallange AuthChallange

	data, statusCode, err := k.post(postRequest{
		path: APIv2AuthChallengePath,
	})
	if err != nil {
		return AuthChallange{}, err
	}

	if statusCode != http.StatusOK {
		return AuthChallange{}, fmt.Errorf("error getting auth challange, status code %d, body: %s", statusCode, data)
	}

	err = json.Unmarshal(data, &authChallange)
	if err != nil {
		return AuthChallange{}, err
	}

	return authChallange, nil
}

func (k *Client) refreshAuthToken() error {
	authChallange, err := k.getAuthChallange()
	if err != nil {
		return err
	}

	authToken, err := xades.NewAuthTokenRequestBuilder().
		WithChallenge(authChallange.Challange).
		WithContextNip(k.vatID).
		WithSubjectType(xades.CertificateSubject).
		Build()
	if err != nil {
		return err
	}

	signedAuthToken, err := xades.Sign(*authToken, k.cert, k.priv)
	if err != nil {
		return err
	}

	var authTokenResponse AuthTokenResponse
	var accessTokenResponse AccessTokenResponse

	data, statusCode, err := k.post(postRequest{
		path:        APIv2AuthXadesSignaturePath,
		contentType: ContentTypeXML,
		body:        signedAuthToken,
	})
	if err != nil {
		return err
	}

	if statusCode != http.StatusOK && statusCode != http.StatusAccepted {
		return fmt.Errorf("error getting auth token, status code %d, body: %s", statusCode, data)
	}

	err = json.Unmarshal(data, &authTokenResponse)
	if err != nil {
		return fmt.Errorf("error unmarshaling auth token: %v", err)
	}

	data, statusCode, err = k.post(postRequest{
		path:          APIv2AuthTokenRedeemPath,
		authorization: "Bearer " + authTokenResponse.AuthToken.Token,
	})
	if err != nil {
		return fmt.Errorf("error sending request for access token: %v", err)
	}

	if statusCode != http.StatusOK {
		return fmt.Errorf("error getting access token, status code %d, body: %s", statusCode, data)
	}

	err = json.Unmarshal(data, &accessTokenResponse)
	if err != nil {
		return fmt.Errorf("error unmarshaling access token: %v", err)
	}

	validUntil, err := time.Parse(time.RFC3339, accessTokenResponse.AccessToken.ValidUntil)
	if err != nil {
		return fmt.Errorf("error parsing time: %v", err)
	}

	k.accessToken = accessTokenResponse.AccessToken.Token
	k.validUntil = &validUntil
	return nil
}

func (k *Client) post(request postRequest) (data []byte, statusCode int, err error) {
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

func (k *Client) postWithAuth(path, contentType string, body []byte) (data []byte, statusCode int, err error) {
	if k.validUntil == nil || time.Now().After(*k.validUntil) {
		err = k.refreshAuthToken()
		if err != nil {
			return nil, 0, fmt.Errorf("error refreshing auth token: %v", err)
		}
	}

	return k.post(postRequest{
		path:          path,
		contentType:   contentType,
		body:          body,
		authorization: "Bearer " + k.accessToken,
	})
}
