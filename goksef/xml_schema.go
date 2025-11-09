package goksef

import "encoding/xml"

const nsFaktura = "http://crd.gov.pl/wzor/2023/06/29/12648/"

type Faktura struct {
	XMLName  xml.Name `xml:"Faktura"`
	XMLNS    string   `xml:"xmlns,attr,omitempty"`
	XMLNSetd string   `xml:"xmlns:etd,attr,omitempty"`
	XMLNSxsi string   `xml:"xmlns:xsi,attr,omitempty"`
	Naglowek Naglowek `xml:"Naglowek"`
	Podmiot1 Podmiot  `xml:"Podmiot1"`
	Podmiot2 Podmiot  `xml:"Podmiot2"`
	Fa       Fa       `xml:"Fa"`
}

type Naglowek struct {
	KodFormularza     KodFormularza `xml:"KodFormularza"`
	WariantFormularza int           `xml:"WariantFormularza"`
	DataWytworzeniaFa string        `xml:"DataWytworzeniaFa"`
	SystemInfo        string        `xml:"SystemInfo"`
}

type KodFormularza struct {
	Value        string `xml:",chardata"`
	KodSystemowy string `xml:"kodSystemowy,attr"`
	WersjaSchemy string `xml:"wersjaSchemy,attr"`
}

type Podmiot struct {
	DaneIdentyfikacyjne DaneIdentyfikacyjne `xml:"DaneIdentyfikacyjne"`
	Adres               Adres               `xml:"Adres"`
	DaneKontaktowe      *DaneKontaktowe     `xml:"DaneKontaktowe,omitempty"`
}

type DaneIdentyfikacyjne struct {
	NIP   string `xml:"NIP"`
	Nazwa string `xml:"Nazwa"`
}

type Adres struct {
	KodKraju string `xml:"KodKraju"`
	AdresL1  string `xml:"AdresL1"`
	AdresL2  string `xml:"AdresL2"`
}

type DaneKontaktowe struct {
	Email   string `xml:"Email"`
	Telefon string `xml:"Telefon"`
}

type Fa struct {
	KodWaluty string `xml:"KodWaluty"`
	P1        string `xml:"P_1"`
	P1M       string `xml:"P_1M"`
	P2        string `xml:"P_2"`
	P6        string `xml:"P_6"`
	P13_1     string `xml:"P_13_1"`
	P14_1     string `xml:"P_14_1"`
	P15       string `xml:"P_15"`

	Adnotacje     *Adnotacje `xml:"Adnotacje,omitempty"`
	RodzajFaktury string     `xml:"RodzajFaktury"`
	FaWiersz      []FaWiersz `xml:"FaWiersz"`

	Platnosc *Platnosc `xml:"Platnosc,omitempty"`
}

type Adnotacje struct {
	P16  string `xml:"P_16"`
	P17  string `xml:"P_17"`
	P18  string `xml:"P_18"`
	P18A string `xml:"P_18A"`

	Zwolnienie           *Zwolnienie           `xml:"Zwolnienie,omitempty"`
	NoweSrodkiTransportu *NoweSrodkiTransportu `xml:"NoweSrodkiTransportu,omitempty"`

	P23    string  `xml:"P_23"`
	PMarzy *PMarzy `xml:"PMarzy,omitempty"`
}

type Zwolnienie struct {
	P19  string `xml:"P_19,omitempty"`
	P19A string `xml:"P_19A,omitempty"`
	P19B string `xml:"P_19B,omitempty"`
	P19C string `xml:"P_19C,omitempty"`
	P19N string `xml:"P_19N,omitempty"`
}

type NoweSrodkiTransportu struct {
	P22N string `xml:"P_22N"`
}

type PMarzy struct {
	PPMarzyN string `xml:"P_PMarzyN"`
}

type FaWiersz struct {
	NrWierszaFa string `xml:"NrWierszaFa"`
	P7          string `xml:"P_7"`
	P8A         string `xml:"P_8A"`
	P8B         string `xml:"P_8B"`
	P9A         string `xml:"P_9A"`
	P11         string `xml:"P_11"`
	P12         string `xml:"P_12"`
}

type Platnosc struct {
	TerminPlatnosci *TerminPlatnosci `xml:"TerminPlatnosci,omitempty"`
	FormaPlatnosci  string           `xml:"FormaPlatnosci"`
	RachunekBankowy *RachunekBankowy `xml:"RachunekBankowy,omitempty"`
}

type TerminPlatnosci struct {
	Termin string `xml:"Termin"`
}

type RachunekBankowy struct {
	NrRB         string `xml:"NrRB"`
	NazwaBanku   string `xml:"NazwaBanku"`
	OpisRachunku string `xml:"OpisRachunku"`
}
