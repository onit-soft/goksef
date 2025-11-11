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
	Podmiot3 *Podmiot `xml:"Podmiot3,omitempty"`
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
	PrefiksPodatnika    string              `xml:"PrefiksPodatnika,omitempty"`
	DaneIdentyfikacyjne DaneIdentyfikacyjne `xml:"DaneIdentyfikacyjne"`
	Adres               Adres               `xml:"Adres"`
	AresKoresp          *Adres              `xml:"AdresKoresp,omitempty"`
	DaneKontaktowe      *DaneKontaktowe     `xml:"DaneKontaktowe,omitempty"`
	NrKlienta           string              `xml:"NrKlienta,omitempty"`
	IDNabywcy           string              `xml:"IDNabywcy,omitempty"`
	StatusInfoPodatnika string              `xml:"StatusInfoPodatnika,omitempty"`
}

type DaneIdentyfikacyjne struct {
	NIP      string `xml:"NIP"`
	Nazwa    string `xml:"Nazwa"`
	KodUE    string `xml:"KodUE,omitempty"`
	NrVatUE  string `xml:"NrVatUE,omitempty"`
	KodKraju string `xml:"KodKraju,omitempty"`
	NrID     string `xml:"NrID,omitempty"`
	BrakID   string `xml:"BrakID,omitempty"`
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
	KodWaluty   string     `xml:"KodWaluty"`
	P1          string     `xml:"P_1"`                // Data wystawienia faktury
	P1M         string     `xml:"P_1M"`               // Miejsce wystawienia
	P2          string     `xml:"P_2"`                // Numer faktury
	WZ          string     `xml:"WZ,omitempty"`       // Numer dokumentów WZ
	OkresFA     OkresFA    `xml:"OkresFA,omitempty"`  // Okres którego dotyczy faktura
	P6          string     `xml:"P_6"`                // Data wykonania usługi
	P13_1       string     `xml:"P_13_1"`             // Wartość netto
	P14_1       string     `xml:"P_14_1"`             // Wartość VAT
	P14_1W      string     `xml:"P_14_1W,omitempty"`  // Wartość VAT Przeliczona z innej waluty
	P13_2       string     `xml:"P_13_2,omitempty"`   // Wartości Netto objętej stawką obniżoną pierwszą 8%
	P14_2       string     `xml:"P_14_2,omitempty"`   // Wartości VAT objętej stawką obniżoną pierwszą 8%
	P14_2W      string     `xml:"P_14_2W,omitempty"`  // Wartości VAT objętej stawką obniżoną pierwszą 8% Przeliczona z innej waluty
	P13_3       string     `xml:"P_13_3,omitempty"`   // Wartości Netto objętej stawką obniżoną drugą 5%
	P14_3       string     `xml:"P_14_3,omitempty"`   // Wartości VAT objętej stawką obniżoną drugą 5%
	P14_3W      string     `xml:"P_14_3W,omitempty"`  // Wartości VAT objętej stawką obniżoną drugą 5% Przeliczona z innej waluty
	P13_4       string     `xml:"P_13_4,omitempty"`   // Wartości Netto objętej ryczałtem dla taksówek
	P14_4       string     `xml:"P_14_4,omitempty"`   // Wartości VAT objętej ryczałtem dla taksówek
	P14_4W      string     `xml:"P_14_4W,omitempty"`  // Wartości VAT objętej ryczałtem dla taksówek Przeliczona z innej waluty
	P13_5       string     `xml:"P_13_5,omitempty"`   // Wartości Netto w przypadku procedury szczególnej
	P14_5       string     `xml:"P_14_5,omitempty"`   // Wartości VAT w przypadku procedury szczególnej
	P13_6_1     string     `xml:"P_13_6_1,omitempty"` // Suma wartości sprzedaży objętej stawką 0% z wyłączeniem wewnątrzwspólnotowej dostawy towarów i eksportu
	P13_6_2     string     `xml:"P_13_6_2,omitempty"` // Suma wartości sprzedaży objętej stawką 0% w przypadku wewnątrzwspólnotowej dostawy towarów
	P13_6_3     string     `xml:"P_13_6_3,omitempty"` // Suma wartości sprzedaży objętej stawką 0% w przypadku eksportu
	P13_7       string     `xml:"P_13_7,omitempty"`   // Suma wartości sprzedaży zwolnionej od podatku
	P13_8       string     `xml:"P_13_8,omitempty"`   // Suma wartości sprzedaży w przypadku dostawy towarów oraz świadczenia usług poza terytorium kraju, z wyłączeniem kwot wykazanych w polach P_13_5 i P_13_9
	P13_9       string     `xml:"P_13_9,omitempty"`   // Suma wartości świadczenia usług, o których mowa w art. 100 ust. 1 pkt 4 ustawy
	P13_10      string     `xml:"P_13_10,omitempty"`  // Suma wartości sprzedaży w procedurze odwrotnego obciążenia, dla której podatnikiem jest nabywca
	P13_11      string     `xml:"P_13_11,omitempty"`  // Suma wartości sprzedaży w procedurze marży
	P15         string     `xml:"P_15"`               // Wartość brutto
	KursWalutyZ float32    `xml:"KursWalutyZ,omitempty"`
	Adnotacje   *Adnotacje `xml:"Adnotacje,omitempty"`
	// VAT - Faktura podstawowa
	// KOR - Faktura korygująca
	// ZAL - Faktura zaliczkowa. Faktura dokumentująca otrzymanie zapłaty lub jej części przed dokonaniem czynności
	// ROZ - Faktura rozliczeniowa
	// KOR_ZAL - Faktura korygująca fakturę zaliczkową
	// KOR_ROZ - Faktura korygująca fakturę rozliczeniową
	RodzajFaktury string     `xml:"RodzajFaktury"`
	FaWiersz      []FaWiersz `xml:"FaWiersz"`
	Platnosc      *Platnosc  `xml:"Platnosc,omitempty"`
}

type OkresFA struct {
	P6Od string `xml:"P_6_Od"`
	P6Do string `xml:"P_6_Do"`
}

type Adnotacje struct {
	P16                  string                `xml:"P_16"`  // Metoda kasowa
	P17                  string                `xml:"P_17"`  // Samozafakturowanie
	P18                  string                `xml:"P_18"`  // Odwrotne obciążenie
	P18A                 string                `xml:"P_18A"` // Split payment
	Zwolnienie           *Zwolnienie           `xml:"Zwolnienie,omitempty"`
	NoweSrodkiTransportu *NoweSrodkiTransportu `xml:"NoweSrodkiTransportu,omitempty"`
	P23                  string                `xml:"P_23"` // Faktur w procedurze uproszczonej
	PMarzy               *PMarzy               `xml:"PMarzy,omitempty"`
}

type Zwolnienie struct {
	P19  string `xml:"P_19,omitempty"`  // Zwolnienie z podatku, 1 jeżeli jest zwolnienie
	P19A string `xml:"P_19A,omitempty"` // Należy wskazać przepis ustawy lub aktu
	P19B string `xml:"P_19B,omitempty"` // Należy wskazać przepis dyrektywy
	P19C string `xml:"P_19C,omitempty"` // Inny powód
	P19N string `xml:"P_19N,omitempty"` // 1 jeżeli niema zwolnienia z podatku
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
	P12 string `xml:"P_12"`
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
