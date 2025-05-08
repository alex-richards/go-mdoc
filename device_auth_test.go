package mdoc

import (
	"github.com/alex-richards/go-mdoc/internal/testutil"
	"testing"
)

func Test_NewDeviceAuth(t *testing.T) {
	rand := testutil.NewDeterministicRand(t)
	tests := []struct {
		name string
		mode SDeviceKeyMode
	}{
		{
			name: "Sign",
			mode: SDeviceKeyModeSign,
		},
		// TODO MAC
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sDeviceKey, err := NewSDeviceKey(rand, CurveP256, tt.mode)
			if err != nil {
				t.Fatal(err)
			}

			deviceAuthenticationBytes, err := NewTaggedEncodedCBOR([]byte{1, 2, 3, 4})
			if err != nil {
				t.Fatal(err)
			}

			deviceAuth, err := NewDeviceAuth(rand, sDeviceKey, deviceAuthenticationBytes)
			if err != nil {
				t.Fatal(err)
			}

			switch tt.mode {
			case SDeviceKeyModeSign:
				if deviceAuth.DeviceSignature == nil {
					t.Fatal()
				}
				if deviceAuth.DeviceMAC != nil {
					t.Fatal()
				}

			default:
				t.Fatal()
			}
		})
	}
}

func Test_DeviceAuth_Verify(t *testing.T) {
	rand := testutil.NewDeterministicRand(t)

	tests := []struct {
		name                            string
		mode                            SDeviceKeyMode
		curve                           Curve
		deviceAuthenticationBytesCreate *TaggedEncodedCBOR
		deviceAuthenticationBytesVerify *TaggedEncodedCBOR
		wantErr                         error
	}{
		{
			name:  "Sign P256",
			mode:  SDeviceKeyModeSign,
			curve: CurveP256,
			deviceAuthenticationBytesCreate: &TaggedEncodedCBOR{
				TaggedValue: []byte{1, 2, 3, 4},
			},
		},
		{
			name:  "Sign P521",
			mode:  SDeviceKeyModeSign,
			curve: CurveP521,
			deviceAuthenticationBytesCreate: &TaggedEncodedCBOR{
				TaggedValue: []byte{1, 2, 3, 4},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sDeviceKey, err := NewSDeviceKey(rand, tt.curve, tt.mode)
			if err != nil {
				t.Fatal(err)
			}

			deviceAuth, err := NewDeviceAuth(rand, sDeviceKey, tt.deviceAuthenticationBytesCreate)
			if err != nil {
				t.Fatal(err)
			}

			deviceKey, err := sDeviceKey.DeviceKey()
			if err != nil {
				t.Fatal(err)
			}

			var deviceAuthenticationBytesVerify *TaggedEncodedCBOR
			if tt.deviceAuthenticationBytesVerify != nil {
				deviceAuthenticationBytesVerify = tt.deviceAuthenticationBytesVerify
			} else {
				deviceAuthenticationBytesVerify = tt.deviceAuthenticationBytesCreate
			}

			err = deviceAuth.Verify(deviceKey, deviceAuthenticationBytesVerify)

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
