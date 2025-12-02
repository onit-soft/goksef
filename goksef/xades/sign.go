package xades

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"math/big"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	nsDS    = "http://www.w3.org/2000/09/xmldsig#"
	nsXAdES = "http://uri.etsi.org/01903/v1.3.2#"

	algC14NExclusive   = "http://www.w3.org/2001/10/xml-exc-c14n#"
	algSigRSA_SHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algSigECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	algDigestSHA256    = "http://www.w3.org/2001/04/xmlenc#sha256"

	transformEnveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

	xadesTypeSignedProps = "http://uri.etsi.org/01903#SignedProperties"
)

// ecdsaSignature represents the ASN.1 structure of an ECDSA signature
type ecdsaSignature struct {
	R, S *big.Int
}

func c14nExclusive(el *etree.Element) ([]byte, error) {
	can := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	return can.Canonicalize(el)
}

func digestSHA256(canon []byte) string {
	h := sha256.Sum256(canon)
	return base64.StdEncoding.EncodeToString(h[:])
}

func digestSHA1(data []byte) string {
	h := sha1.Sum(data)
	return base64.StdEncoding.EncodeToString(h[:])
}

func buildReference(uri string, digestMethod string, transforms []string, digestValue string) *etree.Element {
	ref := etree.NewElement("ds:Reference")
	ref.CreateAttr("URI", uri)

	if digestMethod == "" {
		digestMethod = algDigestSHA256
	}

	dm := etree.NewElement("ds:DigestMethod")
	dm.CreateAttr("Algorithm", digestMethod)
	dv := etree.NewElement("ds:DigestValue")
	dv.SetText(digestValue)

	if len(transforms) > 0 {
		trs := etree.NewElement("ds:Transforms")
		for _, t := range transforms {
			tr := etree.NewElement("ds:Transform")
			tr.CreateAttr("Algorithm", t)
			trs.AddChild(tr)
		}
		ref.AddChild(trs)
	}
	ref.AddChild(dm)
	ref.AddChild(dv)
	return ref
}

// getSignatureAlgorithm returns the appropriate XML signature algorithm based on the certificate's public key type
func getSignatureAlgorithm(cert *x509.Certificate) (string, error) {
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return algSigRSA_SHA256, nil
	case *ecdsa.PublicKey:
		return algSigECDSA_SHA256, nil
	default:
		return "", fmt.Errorf("unsupported public key type: %T", cert.PublicKey)
	}
}

// formatSignature formats the signature based on the signer type
// ECDSA signatures need to be in IEEE P1363 format (concatenated R||S)
func formatSignature(sigRaw []byte, signer crypto.Signer) ([]byte, error) {
	switch signer.Public().(type) {
	case *ecdsa.PublicKey:
		// Parse ASN.1 DER encoded signature
		var sig ecdsaSignature
		if _, err := asn1.Unmarshal(sigRaw, &sig); err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA signature: %w", err)
		}

		// Get the key size to determine the component length
		ecdsaKey := signer.Public().(*ecdsa.PublicKey)
		keySize := (ecdsaKey.Params().BitSize + 7) / 8

		// Convert R and S to fixed-length byte arrays
		rBytes := sig.R.Bytes()
		sBytes := sig.S.Bytes()

		// Pad with leading zeros if necessary
		rPadded := make([]byte, keySize)
		sPadded := make([]byte, keySize)
		copy(rPadded[keySize-len(rBytes):], rBytes)
		copy(sPadded[keySize-len(sBytes):], sBytes)

		// Concatenate R||S
		return append(rPadded, sPadded...), nil
	case *rsa.PublicKey:
		// RSA signatures are already in the correct format
		return sigRaw, nil
	default:
		return nil, fmt.Errorf("unsupported signer type: %T", signer.Public())
	}
}

func Sign(authRequest AuthTokenRequest, cert *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	serialized, err := xml.Marshal(authRequest)
	if err != nil {
		return nil, err
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(serialized); err != nil {
		return nil, err
	}

	root := doc.Root()
	root.CreateAttr("xmlns:ds", nsDS)
	root.CreateAttr("xmlns:xades", nsXAdES)

	xadesPropsID := "xades-props-1"

	obj := etree.NewElement("ds:Object")
	qp := etree.NewElement("xades:QualifyingProperties")
	qp.CreateAttr("Target", "#sig-1")
	sp := etree.NewElement("xades:SignedProperties")
	sp.CreateAttr("Id", xadesPropsID)
	sp.CreateAttr("xmlns:ds", nsDS)
	sp.CreateAttr("xmlns:xades", nsXAdES)

	ssp := etree.NewElement("xades:SignedSignatureProperties")
	signingTime := etree.NewElement("xades:SigningTime")
	signingTime.SetText(time.Now().UTC().Format(time.RFC3339))
	ssp.AddChild(signingTime)

	sc := etree.NewElement("xades:SigningCertificate")
	sc1 := etree.NewElement("xades:Cert")
	sc1Digest := etree.NewElement("xades:CertDigest")
	dm := etree.NewElement("ds:DigestMethod")
	dm.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1")
	dv := etree.NewElement("ds:DigestValue")
	dv.SetText(digestSHA1(cert.Raw))
	sc1Digest.AddChild(dm)
	sc1Digest.AddChild(dv)
	is := etree.NewElement("xades:IssuerSerial")
	issName := etree.NewElement("ds:X509IssuerName")
	issName.SetText(cert.Issuer.String())
	issSN := etree.NewElement("ds:X509SerialNumber")
	issSN.SetText(cert.SerialNumber.String())
	is.AddChild(issName)
	is.AddChild(issSN)
	sc1.AddChild(sc1Digest)
	sc1.AddChild(is)
	sc.AddChild(sc1)
	ssp.AddChild(sc)

	sp.AddChild(ssp)
	qp.AddChild(sp)
	obj.AddChild(qp)

	sig := etree.NewElement("ds:Signature")
	sig.CreateAttr("Id", "sig-1")
	sig.CreateAttr("xmlns:ds", nsDS)
	sig.CreateAttr("xmlns:xades", nsXAdES)

	// Determine the signature algorithm based on the certificate type
	sigAlgorithm, err := getSignatureAlgorithm(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to determine signature algorithm: %w", err)
	}

	si := etree.NewElement("ds:SignedInfo")
	si.CreateAttr("xmlns:ds", nsDS)
	si.CreateAttr("xmlns:xades", nsXAdES)
	cm := etree.NewElement("ds:CanonicalizationMethod")
	cm.CreateAttr("Algorithm", algC14NExclusive)
	sim := etree.NewElement("ds:SignatureMethod")
	sim.CreateAttr("Algorithm", sigAlgorithm)

	refData := buildReference("", algDigestSHA256, []string{transformEnveloped, algC14NExclusive}, "")
	refProps := buildReference("#"+xadesPropsID, algDigestSHA256, []string{algC14NExclusive}, "")
	refProps.CreateAttr("Type", xadesTypeSignedProps)

	si.AddChild(cm)
	si.AddChild(sim)
	si.AddChild(refData)
	si.AddChild(refProps)

	ki := etree.NewElement("ds:KeyInfo")
	x509Data := etree.NewElement("ds:X509Data")
	x509Cert := etree.NewElement("ds:X509Certificate")
	x509Cert.SetText(base64.StdEncoding.EncodeToString(cert.Raw))
	x509Data.AddChild(x509Cert)
	ki.AddChild(x509Data)

	sig.AddChild(si)
	sig.AddChild(etree.NewElement("ds:SignatureValue"))
	sig.AddChild(ki)
	sig.AddChild(obj)

	qp.RemoveAttr("Target")
	qp.CreateAttr("Target", "#sig-1")

	root.AddChild(sig)

	spInDoc := sig.FindElement(".//xades:SignedProperties")
	canonProps, err := c14nExclusive(spInDoc)
	if err != nil {
		return nil, err
	}

	propsDigestVal := digestSHA256(canonProps)
	refProps.FindElement("./ds:DigestValue").SetText(propsDigestVal)

	rootClone := root.Copy()
	if sigInClone := rootClone.FindElement(".//ds:Signature"); sigInClone != nil {
		sigInClone.Parent().RemoveChild(sigInClone)
	}

	canonData, err := c14nExclusive(rootClone)
	if err != nil {
		return nil, err
	}

	dataDigestVal := digestSHA256(canonData)
	refData.FindElement("./ds:DigestValue").SetText(dataDigestVal)

	canonSI, err := c14nExclusive(si)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(canonSI)
	sigRaw, err := signer.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// Format the signature appropriately for the algorithm
	formattedSig, err := formatSignature(sigRaw, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to format signature: %w", err)
	}

	sig.FindElement("./ds:SignatureValue").SetText(base64.StdEncoding.EncodeToString(formattedSig))

	out := etree.NewDocument()
	out.SetRoot(root)
	out.WriteSettings = etree.WriteSettings{CanonicalAttrVal: true}
	rawBytes, err := out.WriteToBytes()
	if err != nil {
		return nil, err
	}

	return rawBytes, nil
}
