package mdoc

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
)

func TestSessionTranscriptCBORRoundTrip(t *testing.T) {
	sessionTranscripts := []SessionTranscript{
		{
			DeviceEngagementBytes: []byte{1, 2, 3, 4},
			EReaderKeyBytes:       []byte{5, 6, 7, 8},
			Handover:              QRHandover{},
		},
		{
			DeviceEngagementBytes: []byte{1, 2, 3, 4},
			EReaderKeyBytes:       []byte{5, 6, 7, 8},
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
		err = cbor.Unmarshal(sessionTranscriptBytes, &sessionTranscriptUnmarshalled)
		if err != nil {
			t.Fatal(err)
		}

		if diff := cmp.Diff(&sessionTranscript, &sessionTranscriptUnmarshalled); diff != "" {
			t.Fatal(diff)
		}
	}
}
