package goksef

import "encoding/xml"

const nsFaktura = "http://crd.gov.pl/wzor/2023/06/29/12648/"

type Faktura struct {
	XMLName   xml.Name `xml:"Faktura"`
	XMLNS     string   `xml:"xmlns,attr,omitempty"`
	XMLNSetd  string   `xml:"xmlns:etd,attr,omitempty"`
	XMLNSxsi  string   `xml:"xmlns:xsi,attr,omitempty"`
	Naglowek  Naglowek `xml:"Naglowek"`
	Podmiot1  Podmiot  `xml:"Podmiot1"`
	Podmiot2  Podmiot  `xml:"Podmiot2"`
	Podmiot3  *Podmiot `xml:"Podmiot3,omitempty"`
	Fa        Fa       `xml:"Fa"`
	NumerKsef string   `xml:"-"`
	Stopka    Stopka   `xml:"Stopka"`
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
	JST                 string              `xml:"JST,omitempty"`
	GV                  string              `xml:"GV,omitempty"`
}

type Podmiot1K struct {
	PrefiksPodatnika    string              `xml:"PrefiksPodatnika,omitempty"`
	DaneIdentyfikacyjne DaneIdentyfikacyjne `xml:"DaneIdentyfikacyjne"`
	Adres               Adres               `xml:"Adres"`
}

type Podmiot2K struct {
	DaneIdentyfikacyjne DaneIdentyfikacyjne `xml:"DaneIdentyfikacyjne"`
	Adres               Adres               `xml:"Adres,omitempty"`
	IDNabywcy           string              `xml:"IDNabywcy,omitempty"`
}

type DaneIdentyfikacyjne struct {
	NIP      string `xml:"NIP,omitempty"`
	KodUE    string `xml:"KodUE,omitempty"`
	NrVatUE  string `xml:"NrVatUE,omitempty"`
	KodKraju string `xml:"KodKraju,omitempty"`
	NrID     string `xml:"NrID,omitempty"`
	BrakID   string `xml:"BrakID,omitempty"`
	Nazwa    string `xml:"Nazwa"`
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
	OkresFA     *OkresFA   `xml:"OkresFA,omitempty"`  // Okres którego dotyczy faktura
	P6          string     `xml:"P_6"`                // Data wykonania usługi
	P13_1       string     `xml:"P_13_1,omitempty"`   // Wartość netto
	P14_1       string     `xml:"P_14_1,omitempty"`   // Wartość VAT
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
	// Element order per FA(3) XSD:
	// Adnotacje → RodzajFaktury → [PrzyczynaKorekty → TypKorekty → DaneFaKorygowanej → OkresFaKorygowanej → NrFaKorygowany → Podmiot1K → Podmiot2K → P_15ZK → KursWalutyZK] → DodatkowyOpis → FaWiersz → Platnosc → WarunkiTransakcji → Zamowienie
	Adnotacje          *Adnotacje          `xml:"Adnotacje,omitempty"`
	RodzajFaktury      string              `xml:"RodzajFaktury"`
	PrzyczynaKorekty   string              `xml:"PrzyczynaKorekty,omitempty"`
	TypKorekty         string              `xml:"TypKorekty,omitempty"`           // 1=wstecz, 2=na bieżąco, 3=inna data
	DaneFaKorygowanej  []DaneFaKorygowanej `xml:"DaneFaKorygowanej,omitempty"`
	OkresFaKorygowanej string              `xml:"OkresFaKorygowanej,omitempty"`
	NrFaKorygowany     string              `xml:"NrFaKorygowany,omitempty"`
	Podmiot1K          *Podmiot1K          `xml:"Podmiot1K,omitempty"`
	Podmiot2K          []Podmiot2K         `xml:"Podmiot2K,omitempty"`     // 0..101
	P15ZK              string              `xml:"P_15ZK,omitempty"`
	KursWalutyZK       string              `xml:"KursWalutyZK,omitempty"`
	DodatkowyOpis      []DodatkowyOpis     `xml:"DodatkowyOpis,omitempty"`
	FaWiersz          []FaWiersz         `xml:"FaWiersz,omitempty"`
	Platnosc          *Platnosc          `xml:"Platnosc,omitempty"`
	WarunkiTransakcji *WarunkiTransakcji `xml:"WarunkiTransakcji,omitempty"`
	Zamowienie        *Zamowienie        `xml:"Zamowienie,omitempty"`
}

type Zamowienie struct {
	NrZamowienia   string `xml:"NrZamowienia,omitempty"`
	DataZamowienia string `xml:"DataZamowienia,omitempty"`
}

type DaneFaKorygowanej struct {
	DataWystFaKorygowanej string `xml:"DataWystFaKorygowanej"`         // Data wystawienia korygowanej faktury
	NrFaKorygowanej       string `xml:"NrFaKorygowanej"`               // Numer korygowanej faktury
	NrKSeF                string `xml:"NrKSeF,omitempty"`               // "1" jeśli oryginał w KSeF
	NrKSeFFaKorygowanej   string `xml:"NrKSeFFaKorygowanej,omitempty"` // Numer KSeF oryginału
	NrKSeFN               string `xml:"NrKSeFN,omitempty"`              // "1" jeśli oryginał poza KSeF
}

type WarunkiTransakcji struct {
	Umowy []Umowa `xml:"Umowy,omitempty"`
}

type Umowa struct {
	DataUmowy string `xml:"DataUmowy,omitempty"` // XSD pos 1
	NrUmowy   string `xml:"NrUmowy,omitempty"`   // XSD pos 2
}

type DodatkowyOpis struct {
	NrWiersza string `xml:"NrWiersza,omitempty"` // XSD pos 1 - must be first
	Klucz     string `xml:"Klucz,omitempty"`
	Wartosc   string `xml:"Wartosc,omitempty"`
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
	UU_ID       string `xml:"UU_ID,omitempty"`
	P6A         string `xml:"P_6A,omitempty"`
	P7          string `xml:"P_7"`
	Indeks      string `xml:"Indeks,omitempty"`
	GTIN        string `xml:"GTIN,omitempty"`
	PKWiU       string `xml:"PKWiU,omitempty"`
	CN          string `xml:"CN,omitempty"`
	PKOB        string `xml:"PKOB,omitempty"`
	P8A         string `xml:"P_8A"`
	P8B         string `xml:"P_8B"`
	P9A         string `xml:"P_9A"`
	P9B         string `xml:"P_9B,omitempty"`
	P10         string `xml:"P_10,omitempty"`
	P11         string `xml:"P_11"`
	P11A        string `xml:"P_11A,omitempty"`
	P11Vat      string `xml:"P_11Vat,omitempty"`
	// FA(3) 1-0E TStawkaPodatku enumeration:
	// 23, 22, 8, 7, 5, 4, 3
	// 0 KR  - stawka 0% sprzedaż krajowa
	// 0 WDT - stawka 0% wewnątrzwspólnotowa dostawa towarów
	// 0 EX  - stawka 0% eksport towarów
	// zw    - zwolnione od podatku
	// oo    - odwrotne obciążenie
	// np I  - niepodlegające (poza terytorium kraju)
	// np II - niepodlegające (na terytorium kraju)
	P12         string `xml:"P_12"`
	P12XII      string `xml:"P_12_XII,omitempty"`
	P12Zal15    string `xml:"P_12_Zal_15,omitempty"`
	KwotaAkcyzy string `xml:"KwotaAkcyzy,omitempty"`
	GTU         string `xml:"GTU,omitempty"`
	Procedura   string `xml:"Procedura,omitempty"`
	KursWaluty  string `xml:"KursWaluty,omitempty"`
	StanPrzed   string `xml:"StanPrzed,omitempty"` // "1" = wiersz przed korektą
}

type Platnosc struct {
	TerminPlatnosci *TerminPlatnosci `xml:"TerminPlatnosci,omitempty"`
	FormaPlatnosci  string           `xml:"FormaPlatnosci"`
	RachunekBankowy []RachunekBankowy `xml:"RachunekBankowy,omitempty"`
}

type TerminPlatnosci struct {
	Termin string `xml:"Termin"`
}

type RachunekBankowy struct {
	NrRB         string `xml:"NrRB"`
	NazwaBanku   string `xml:"NazwaBanku"`
	OpisRachunku string `xml:"OpisRachunku"`
}

type Stopka struct {
	// XSD FA(3) 1-0E order: Informacje → Rejestry
	Informacje []Informacje `xml:"Informacje,omitempty"`
	Rejestry   []Rejestr    `xml:"Rejestry,omitempty"`
}

type Rejestr struct {
	PelnaNazwa string `xml:"PelnaNazwa"`
	KRS        string `xml:"KRS,omitempty"`
	REGON      string `xml:"REGON,omitempty"`
	BDO        string `xml:"BDO,omitempty"`
}

type Informacje struct {
	StopkaFaktury string `xml:"StopkaFaktury,omitempty"`
}
