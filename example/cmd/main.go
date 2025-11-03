package main

import (
	"fmt"
	"time"

	"github.com/onit-soft/goksef/goksef"
)

func main() {
	baseURL := "https://ksef-test.mf.gov.pl"
	vatID := "6751787127"
	commonName := "OnitSoft"
	organizationName := "OnitSoft sp. z o.o."
	countryCode := "PL"

	c := goksef.NewClient(baseURL).
		WithOrganizationName(organizationName).
		WithVatID(vatID).
		WithCommonName(commonName).
		WithCountryCode(countryCode)

	err := c.GenerateSelfSigned()
	if err != nil {
		fmt.Println(err)
		return
	}

	response, err := c.GetInvoicesMetadata(goksef.Filter{
		SubjectType: "Subject1",
		DateRange: goksef.DateRange{
			DateType: "Issue",
			To:       time.Now(),
			From:     time.Now().Add(-24 * 7 * time.Hour),
		},
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%+v", response)
}
