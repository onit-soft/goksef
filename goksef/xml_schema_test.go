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
