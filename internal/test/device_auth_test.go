package spec

import (
	"testing"

	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/cipher_suite/ecdsa"
	"github.com/alex-richards/go-mdoc/holder"
	"github.com/alex-richards/go-mdoc/internal/cbor"
	"github.com/alex-richards/go-mdoc/internal/testutil"
)

func Test_DeviceAuth_Verify(t *testing.T) {
	rand := testutil.NewDeterministicRand(t)

	tests := []struct {
		name                            string
		curve                           mdoc.Curve
		deviceAuthenticationBytesCreate *cbor.TaggedEncodedCBOR
		deviceAuthenticationBytesVerify *cbor.TaggedEncodedCBOR
		wantErr                         error
	}{
		{
			name:  "Sign P256",
			curve: mdoc.CurveP256,
			deviceAuthenticationBytesCreate: &cbor.TaggedEncodedCBOR{
				TaggedValue: []byte{1, 2, 3, 4},
			},
		},
		{
			name:  "Sign P521",
			curve: mdoc.CurveP521,
			deviceAuthenticationBytesCreate: &cbor.TaggedEncodedCBOR{
				TaggedValue: []byte{1, 2, 3, 4},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sDeviceKey, err := ecdsa.GeneratePrivateKey(rand, tt.curve)
			if err != nil {
				t.Fatal(err)
			}

			deviceAuth, err := holder.NewDeviceAuth(rand, sDeviceKey, tt.deviceAuthenticationBytesCreate)
			if err != nil {
				t.Fatal(err)
			}

			var deviceAuthenticationBytesVerify *cbor.TaggedEncodedCBOR
			if tt.deviceAuthenticationBytesVerify != nil {
				deviceAuthenticationBytesVerify = tt.deviceAuthenticationBytesVerify
			} else {
				deviceAuthenticationBytesVerify = tt.deviceAuthenticationBytesCreate
			}

			err = deviceAuth.Verify(&sDeviceKey.PublicKey, deviceAuthenticationBytesVerify)

			switch {
			case tt.wantErr == nil && err != nil:
				t.Fatal(err)
			case tt.wantErr != nil && err == nil:
				t.Fatal()
			case tt.wantErr != err:
				t.Fatal()
			}
		})
	}
}
