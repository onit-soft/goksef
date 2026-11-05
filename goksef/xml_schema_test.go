package goksef

import (
	"encoding/xml"
	"fmt"
	"strings"
	"testing"
)

const podmiot3FakturaTemplate = `<Faktura>
	<Podmiot3>
		<DaneIdentyfikacyjne>
			<NIP>6783120981</NIP>
			<Nazwa>MAGDA-TRANS</Nazwa>
		</DaneIdentyfikacyjne>
		<Adres>
			<KodKraju>PL</KodKraju>
			<AdresL1>ul. Fabryczna 20A</AdresL1>
		</Adres>
		%s
	</Podmiot3>
</Faktura>`

func TestPodmiot3RolaUnmarshal(t *testing.T) {
	doc := fmt.Sprintf(podmiot3FakturaTemplate, "<Rola>2</Rola>")

	var faktura Faktura
	if err := xml.Unmarshal([]byte(doc), &faktura); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(faktura.Podmiot3) != 1 {
		t.Fatalf("len(Podmiot3) = %d, want 1", len(faktura.Podmiot3))
	}
	if faktura.Podmiot3[0].Rola != "2" {
		t.Errorf("Rola = %q, want %q", faktura.Podmiot3[0].Rola, "2")
	}
}

func TestPodmiot3RolaInnaUnmarshal(t *testing.T) {
	doc := fmt.Sprintf(podmiot3FakturaTemplate, "<RolaInna>1</RolaInna><OpisRoli>Gwarant płatności</OpisRoli>")

	var faktura Faktura
	if err := xml.Unmarshal([]byte(doc), &faktura); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(faktura.Podmiot3) != 1 {
		t.Fatalf("len(Podmiot3) = %d, want 1", len(faktura.Podmiot3))
	}
	if faktura.Podmiot3[0].RolaInna != "1" {
		t.Errorf("RolaInna = %q, want %q", faktura.Podmiot3[0].RolaInna, "1")
	}
	if faktura.Podmiot3[0].OpisRoli != "Gwarant płatności" {
		t.Errorf("OpisRoli = %q, want %q", faktura.Podmiot3[0].OpisRoli, "Gwarant płatności")
	}
}

func TestPodmiot1MarshalOmitsRola(t *testing.T) {
	faktura := Faktura{
		Podmiot1: Podmiot{
			DaneIdentyfikacyjne: DaneIdentyfikacyjne{
				NIP:   "6783120981",
				Nazwa: "MAGDA-TRANS",
			},
			Adres: Adres{
				KodKraju: "PL",
				AdresL1:  "ul. Fabryczna 20A",
			},
		},
	}

	out, err := xml.Marshal(faktura)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	for _, unwanted := range []string{"<Rola>", "<NrEORI>"} {
		if strings.Contains(string(out), unwanted) {
			t.Errorf("marshalled invoice contains %s: %s", unwanted, out)
		}
	}
}

// FA(3) allows Podmiot3 up to 100 times. With a non-slice field encoding/xml
// merged the nodes: the factor's Rola/Udzial were attributed to the recipient's
// identity and both xsd:choice arms ended up set on one struct.
func TestPodmiot3MultipleNodesKeepOwnRoles(t *testing.T) {
	doc := `<Faktura>
	<Podmiot3>
		<DaneIdentyfikacyjne><NIP>1111111111</NIP><Nazwa>FAKTOR SA</Nazwa></DaneIdentyfikacyjne>
		<Adres><KodKraju>PL</KodKraju><AdresL1>ul. Bankowa 1</AdresL1></Adres>
		<Rola>1</Rola>
		<Udzial>30</Udzial>
	</Podmiot3>
	<Podmiot3>
		<DaneIdentyfikacyjne><NIP>6783120981</NIP><Nazwa>MAGDA-TRANS</Nazwa></DaneIdentyfikacyjne>
		<Adres><KodKraju>PL</KodKraju><AdresL1>ul. Fabryczna 20A</AdresL1></Adres>
		<RolaInna>1</RolaInna>
		<OpisRoli>miejsce dostawy</OpisRoli>
	</Podmiot3>
</Faktura>`

	var faktura Faktura
	if err := xml.Unmarshal([]byte(doc), &faktura); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(faktura.Podmiot3) != 2 {
		t.Fatalf("len(Podmiot3) = %d, want 2", len(faktura.Podmiot3))
	}

	factor, recipient := faktura.Podmiot3[0], faktura.Podmiot3[1]

	if factor.DaneIdentyfikacyjne.NIP != "1111111111" {
		t.Errorf("factor NIP = %q, want %q", factor.DaneIdentyfikacyjne.NIP, "1111111111")
	}
	if factor.Rola != "1" || factor.Udzial != "30" {
		t.Errorf("factor Rola/Udzial = %q/%q, want 1/30", factor.Rola, factor.Udzial)
	}
	if factor.RolaInna != "" || factor.OpisRoli != "" {
		t.Errorf("factor has the other choice arm set: RolaInna=%q OpisRoli=%q", factor.RolaInna, factor.OpisRoli)
	}

	if recipient.DaneIdentyfikacyjne.NIP != "6783120981" {
		t.Errorf("recipient NIP = %q, want %q", recipient.DaneIdentyfikacyjne.NIP, "6783120981")
	}
	if recipient.RolaInna != "1" || recipient.OpisRoli != "miejsce dostawy" {
		t.Errorf("recipient RolaInna/OpisRoli = %q/%q", recipient.RolaInna, recipient.OpisRoli)
	}
	if recipient.Rola != "" || recipient.Udzial != "" {
		t.Errorf("factor's role leaked onto the recipient: Rola=%q Udzial=%q", recipient.Rola, recipient.Udzial)
	}
}

func TestPodmiot3EmptySliceMarshalsAway(t *testing.T) {
	out, err := xml.Marshal(Faktura{})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if strings.Contains(string(out), "<Podmiot3>") {
		t.Errorf("marshalled invoice contains an empty Podmiot3: %s", out)
	}
}

// Odwzorowanie sekcji "Warunki transakcji" / "Transport" / "Wysyłka" z podglądu
// faktury w aplikacji KSeF (faktura 00003/11/2026/Just, NIP 7591764074).
const warunkiTransakcjiDoc = `<Faktura>
	<Fa>
		<WarunkiTransakcji>
			<Zamowienia>
				<NrZamowienia>14631/2026</NrZamowienia>
			</Zamowienia>
			<NrPartiiTowaru>PARTIA-1</NrPartiiTowaru>
			<NrPartiiTowaru>PARTIA-2</NrPartiiTowaru>
			<WarunkiDostawy>DAP</WarunkiDostawy>
			<Transport>
				<RodzajTransportu>3</RodzajTransportu>
				<Przewoznik>
					<DaneIdentyfikacyjne>
						<NIP>7591764074</NIP>
						<Nazwa>JUST WAY TSL</Nazwa>
					</DaneIdentyfikacyjne>
					<AdresPrzewoznika>
						<KodKraju>PL</KodKraju>
						<AdresL1>ul. Testowa 1, 42-200 Częstochowa</AdresL1>
					</AdresPrzewoznika>
				</Przewoznik>
				<NrZleceniaTransportu>ZL0110/10/2026/PC</NrZleceniaTransportu>
				<LadunekInny>1</LadunekInny>
				<OpisInnegoLadunku>brak informacji</OpisInnegoLadunku>
				<DataGodzZakTransportu>2026-10-30T00:00:00Z</DataGodzZakTransportu>
				<WysylkaZ>
					<KodKraju>PL</KodKraju>
					<AdresL1>42200 Częstochowa</AdresL1>
				</WysylkaZ>
				<WysylkaDo>
					<KodKraju>PL</KodKraju>
					<AdresL1>64360 Zbąszyń</AdresL1>
				</WysylkaDo>
			</Transport>
		</WarunkiTransakcji>
	</Fa>
</Faktura>`

func TestWarunkiTransakcjiUnmarshal(t *testing.T) {
	var faktura Faktura
	if err := xml.Unmarshal([]byte(warunkiTransakcjiDoc), &faktura); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	wt := faktura.Fa.WarunkiTransakcji
	if wt == nil {
		t.Fatal("WarunkiTransakcji = nil")
	}
	if len(wt.Zamowienia) != 1 || wt.Zamowienia[0].NrZamowienia != "14631/2026" {
		t.Errorf("Zamowienia = %+v, want one NrZamowienia 14631/2026", wt.Zamowienia)
	}
	if len(wt.NrPartiiTowaru) != 2 || wt.NrPartiiTowaru[1] != "PARTIA-2" {
		t.Errorf("NrPartiiTowaru = %v, want [PARTIA-1 PARTIA-2]", wt.NrPartiiTowaru)
	}
	if wt.WarunkiDostawy != "DAP" {
		t.Errorf("WarunkiDostawy = %q, want DAP", wt.WarunkiDostawy)
	}

	if len(wt.Transport) != 1 {
		t.Fatalf("len(Transport) = %d, want 1", len(wt.Transport))
	}
	tr := wt.Transport[0]
	if tr.RodzajTransportu != "3" {
		t.Errorf("RodzajTransportu = %q, want 3", tr.RodzajTransportu)
	}
	if tr.NrZleceniaTransportu != "ZL0110/10/2026/PC" {
		t.Errorf("NrZleceniaTransportu = %q", tr.NrZleceniaTransportu)
	}
	if tr.LadunekInny != "1" || tr.OpisInnegoLadunku != "brak informacji" {
		t.Errorf("ładunek = %q/%q", tr.LadunekInny, tr.OpisInnegoLadunku)
	}
	if tr.OpisLadunku != "" {
		t.Errorf("OpisLadunku = %q, drugie ramię xsd:choice nie powinno być ustawione", tr.OpisLadunku)
	}
	if tr.DataGodzZakTransportu != "2026-10-30T00:00:00Z" {
		t.Errorf("DataGodzZakTransportu = %q", tr.DataGodzZakTransportu)
	}
	if tr.Przewoznik == nil {
		t.Fatal("Przewoznik = nil")
	}
	if tr.Przewoznik.DaneIdentyfikacyjne.NIP != "7591764074" {
		t.Errorf("Przewoznik NIP = %q", tr.Przewoznik.DaneIdentyfikacyjne.NIP)
	}
	if tr.Przewoznik.AdresPrzewoznika.AdresL1 != "ul. Testowa 1, 42-200 Częstochowa" {
		t.Errorf("AdresPrzewoznika = %+v", tr.Przewoznik.AdresPrzewoznika)
	}
	if tr.WysylkaZ == nil || tr.WysylkaZ.AdresL1 != "42200 Częstochowa" {
		t.Errorf("WysylkaZ = %+v", tr.WysylkaZ)
	}
	if tr.WysylkaDo == nil || tr.WysylkaDo.AdresL1 != "64360 Zbąszyń" {
		t.Errorf("WysylkaDo = %+v", tr.WysylkaDo)
	}
}

// Marshaling WarunkiTransakcji jest używany przy wystawianiu faktur, a KSeF
// odrzuca dokument z elementami w innej kolejności niż xsd:sequence z FA(3).
func TestWarunkiTransakcjiMarshalKeepsXSDOrder(t *testing.T) {
	faktura := Faktura{Fa: Fa{WarunkiTransakcji: &WarunkiTransakcji{
		Umowy:                []Umowa{{NrUmowy: "U/1"}},
		Zamowienia:           []ZamowienieWT{{NrZamowienia: "14631/2026"}},
		NrPartiiTowaru:       []string{"PARTIA-1"},
		WarunkiDostawy:       "DAP",
		Transport:            []Transport{{RodzajTransportu: "3", NrZleceniaTransportu: "ZL/1", WysylkaDo: &Adres{KodKraju: "PL", AdresL1: "64360 Zbąszyń"}}},
		PodmiotPosredniczacy: "1",
	}}}

	out, err := xml.Marshal(faktura)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	order := []string{"<Umowy>", "<Zamowienia>", "<NrPartiiTowaru>", "<WarunkiDostawy>", "<Transport>", "<PodmiotPosredniczacy>"}
	prev := -1
	for _, el := range order {
		at := strings.Index(string(out), el)
		if at < 0 {
			t.Fatalf("brak %s w %s", el, out)
		}
		if at < prev {
			t.Fatalf("%s poza kolejnością XSD: %s", el, out)
		}
		prev = at
	}

	trOrder := []string{"<RodzajTransportu>", "<NrZleceniaTransportu>", "<WysylkaDo>"}
	prev = -1
	for _, el := range trOrder {
		at := strings.Index(string(out), el)
		if at < 0 {
			t.Fatalf("brak %s w %s", el, out)
		}
		if at < prev {
			t.Fatalf("%s poza kolejnością XSD: %s", el, out)
		}
		prev = at
	}
}
