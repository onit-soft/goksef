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

	if faktura.Podmiot3 == nil {
		t.Fatal("Podmiot3 is nil")
	}
	if faktura.Podmiot3.Rola != "2" {
		t.Errorf("Rola = %q, want %q", faktura.Podmiot3.Rola, "2")
	}
}

func TestPodmiot3RolaInnaUnmarshal(t *testing.T) {
	doc := fmt.Sprintf(podmiot3FakturaTemplate, "<RolaInna>1</RolaInna><OpisRoli>Gwarant płatności</OpisRoli>")

	var faktura Faktura
	if err := xml.Unmarshal([]byte(doc), &faktura); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if faktura.Podmiot3 == nil {
		t.Fatal("Podmiot3 is nil")
	}
	if faktura.Podmiot3.RolaInna != "1" {
		t.Errorf("RolaInna = %q, want %q", faktura.Podmiot3.RolaInna, "1")
	}
	if faktura.Podmiot3.OpisRoli != "Gwarant płatności" {
		t.Errorf("OpisRoli = %q, want %q", faktura.Podmiot3.OpisRoli, "Gwarant płatności")
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
