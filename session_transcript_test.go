package mdoc

import (
	"reflect"
	"testing"

	cbor2 "github.com/alex-richards/go-mdoc/internal/cbor"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
)

func TestSessionTranscript_CBOR_RoundTrip(t *testing.T) {
	deviceEngagementBytes, err := cbor2.NewTaggedEncodedCBOR([]byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	eReaderKeyBytes := deviceEngagementBytes

	sessionTranscripts := []SessionTranscript{
		{
			DeviceEngagementBytes: deviceEngagementBytes,
			EReaderKeyBytes:       eReaderKeyBytes,
			Handover:              QRHandover{},
		},
		{
			DeviceEngagementBytes: deviceEngagementBytes,
			EReaderKeyBytes:       eReaderKeyBytes,
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
				return p.Last().Type() == reflect.TypeOf(cbor2.TaggedEncodedCBOR{})
			}, cmp.Ignore()),
		); diff != "" {
			t.Fatal(diff)
		}
	}
}
