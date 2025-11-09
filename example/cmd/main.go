package main

import (
	"encoding/xml"
	"fmt"
	"time"

	"github.com/onit-soft/goksef/goksef"
)

func main() {
	baseURL := "https://ksef-test.mf.gov.pl"

	issuerVatID := "6783120981"
	issuerCommonName := "Magda-trans"
	issuerName := "Magda-trans sp. z o.o."
	issuerCountryCode := "PL"

	f := goksef.Faktura{
		XMLNS:    "http://crd.gov.pl/wzor/2023/06/29/12648/",
		XMLNSetd: "http://crd.gov.pl/xml/schematy/dziedzinowe/mf/2022/01/05/eD/DefinicjeTypy/",
		XMLNSxsi: "http://www.w3.org/2001/XMLSchema-instance",
		Naglowek: goksef.Naglowek{
			KodFormularza: goksef.KodFormularza{
				Value:        "FA",
				KodSystemowy: "FA (2)",
				WersjaSchemy: "1-0E",
			},
			WariantFormularza: 2,
			DataWytworzeniaFa: time.Now().Format(time.RFC3339),
			SystemInfo:        "Aplikacja Podatnika KSeF",
		},
		Podmiot1: goksef.Podmiot{
			DaneIdentyfikacyjne: goksef.DaneIdentyfikacyjne{
				NIP:   issuerVatID,
				Nazwa: issuerCommonName,
			},
			Adres: goksef.Adres{
				KodKraju: issuerCountryCode,
				AdresL1:  "Fabryczna 20A",
				AdresL2:  "31-553 Kraków",
			},
			DaneKontaktowe: &goksef.DaneKontaktowe{
				Email:   "iza.skowronska@magda-trans.pl",
				Telefon: "+48668892167",
			},
		},
		Podmiot2: goksef.Podmiot{
			DaneIdentyfikacyjne: goksef.DaneIdentyfikacyjne{
				NIP:   "1251620344",
				Nazwa: "MAT DANIA",
			},
			Adres: goksef.Adres{
				KodKraju: "PL",
				AdresL1:  "Aleja Jana Pawła II 80",
				AdresL2:  "05-250 Słupno",
			},
			DaneKontaktowe: &goksef.DaneKontaktowe{
				Email:   "mat-dania@magda-trans.pl",
				Telefon: "+48668892167",
			},
		},
		Fa: goksef.Fa{
			KodWaluty: "PLN",
			P1:        "2025-11-06",
			P1M:       "Kraków",
			P2:        "F/2025/11/06/001", // Invoice number
			P6:        "2025-11-06",       // Execution date
			P13_1:     "950.00",           // Net amount
			P14_1:     "218.5",            // VAT amount
			P15:       "1168.50",          // Brutto amount
			Adnotacje: &goksef.Adnotacje{
				P16:  "2", // Cash method
				P17:  "2", // Self billing
				P18:  "2", // Reverse charge
				P18A: "2", // Split payment
				Zwolnienie: &goksef.Zwolnienie{
					P19:  "",  // Tax exception enabled, 1 if enabled
					P19A: "",  // ActLegalBasis
					P19B: "",  // DirectiveBasis
					P19C: "",  // OtherBasis
					P19N: "1", // 1 if no exception disabled
				},
				NoweSrodkiTransportu: &goksef.NoweSrodkiTransportu{
					P22N: "1",
				},
				P23: "2",
				PMarzy: &goksef.PMarzy{
					PPMarzyN: "1",
				},
			},
			// Available types:
			// VAT - Faktura podstawowa
			// KOR - Faktura korygująca
			// ZAL - Faktura zaliczkowa. Faktura dokumentująca otrzymanie zapłaty lub jej części przed dokonaniem czynności
			// ROZ - Faktura rozliczeniowa
			// KOR_ZAL - Faktura korygująca fakturę zaliczkową
			// KOR_ROZ - Faktura korygująca fakturę rozliczeniową
			RodzajFaktury: "VAT",
			FaWiersz: []goksef.FaWiersz{
				{
					NrWierszaFa: "1",
					P7:          "Usługa spedycyjna za transport towarów z Nowa Sól 67-100 do Słupno k. Radzymina 05-250",
					P8A:         "usługa", // unit type
					P8B:         "950.00", // quantity
					P9A:         "1.00",   // net unit price
					P11:         "950.00", // net value
					// Available vat rates:
					// 23
					// 22
					// 8
					// 7
					// 5
					// 4
					// 3
					// 0
					// zw - zwolnione od podatku
					// oo - odwrotne obciążenie
					// np - nie podlega
					P12: "23", // vat rate
				},
			},
			Platnosc: &goksef.Platnosc{
				TerminPlatnosci: &goksef.TerminPlatnosci{
					Termin: "2025-12-04",
				},
				// 1 - Gotówka
				// 2 - Karta
				// 3 - Bon
				// 4 - Czek
				// 5 Kredyt
				// 6 - Przelew
				// 7 - Mobilna
				FormaPlatnosci: "6",
				RachunekBankowy: &goksef.RachunekBankowy{
					NrRB:         "73111111111111111111111111",
					NazwaBanku:   "Bank Bankowości Bankowej S. A.",
					OpisRachunku: "PLN",
				},
			},
		},
	}

	invoiceContent, err := xml.Marshal(f)
	if err != nil {
		panic(err)
	}

	c := goksef.NewClient(baseURL).
		WithOrganizationName(issuerName).
		WithVatID(issuerVatID).
		WithCommonName(issuerCommonName).
		WithCountryCode(issuerCountryCode)

	err = c.UseSelfSigned()
	if err != nil {
		panic(err)
	}

	formCode := goksef.FormCode{
		SystemCode:    "FA (2)",
		SchemaVersion: "1-0E",
		Value:         "FA",
	}

	_, err = c.SendInvoices(goksef.SendInvoices{
		InvoiceContents: [][]byte{invoiceContent},
		FormCode:        formCode,
	})
	if err != nil {
		panic(err)
	}

	res, err := c.ListSessions("Online")
	if err != nil {
		panic(err)
	}

	for _, s := range res.Sessions {
		fmt.Println("Code: ", s.Status.Code)
		fmt.Println("Details: ", s.Status.Details)
		fmt.Println("Description: ", s.Status.Description)
		fmt.Println("Reference number: ", s.ReferenceNumber)
		fmt.Println("Total invoice count: ", s.TotalInvoiceCount)
		fmt.Println("Successful invoice count: ", s.SuccessfulInvoiceCount)
		fmt.Println("Failed invoice count: ", s.FailedInvoiceCount)
		fmt.Println("Created at: ", s.DateCreated)
		fmt.Println()
	}
}
