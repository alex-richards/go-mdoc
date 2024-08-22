package mdoc

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
	"reflect"
	"testing"
)

func TestSessionTranscript_MarshalCBOR(t *testing.T) {
	t.Fatal("TODO") // TODO
}

func TestSessionTranscript_UnmarshalCBOR(t *testing.T) {
	t.Fatal("TODO") // TODO
}

func TestSessionTranscript_CBOR_RoundTrip(t *testing.T) {
	deviceEngagementBytes, err := NewTaggedEncodedCBOR([]byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	eReaderKeyBytes := deviceEngagementBytes

	sessionTranscripts := []SessionTranscript{
		{
			DeviceEngagementBytes: *deviceEngagementBytes,
			EReaderKeyBytes:       *eReaderKeyBytes,
			Handover:              QRHandover{},
		},
		{
			DeviceEngagementBytes: *deviceEngagementBytes,
			EReaderKeyBytes:       *eReaderKeyBytes,
			Handover: NFCHandover{
				HandoverSelect:  []byte{1, 2, 3, 4},
				HandoverRequest: nil,
			},
		},
	}

	for _, sessionTranscript := range sessionTranscripts {
		sessionTranscriptBytes, err := cbor.Marshal(&sessionTranscript)
		if err != nil {
			t.Fatal(err)
		}

		var sessionTranscriptUnmarshalled SessionTranscript
		if err = cbor.Unmarshal(sessionTranscriptBytes, &sessionTranscriptUnmarshalled); err != nil {
			t.Fatal(err)
		}

		if diff := cmp.Diff(
			&sessionTranscript,
			&sessionTranscriptUnmarshalled,
			cmp.FilterPath(func(p cmp.Path) bool {
				return p.Last().Type() == reflect.TypeOf(TaggedEncodedCBOR{})
			}, cmp.Ignore()),
		); diff != "" {
			t.Fatal(diff)
		}
	}
}
