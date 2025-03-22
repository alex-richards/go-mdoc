package mdoc

import (
	"errors"
	"testing"
)

func TestNewSDeviceKey(t *testing.T) {
	rand := NewDeterministicRand()

	tests := []struct {
		name    string
		curve   Curve
		mode    SDeviceKeyMode
		wantErr error
	}{
		{
			name:    "CurveP256 Sign",
			curve:   CurveP256,
			mode:    SDeviceKeyModeSign,
			wantErr: nil,
		},
		{
			name:    "CurveP256 MAC",
			curve:   CurveP256,
			mode:    SDeviceKeyModeMAC,
			wantErr: nil,
		},
		{
			name:    "CurveP384 Sign",
			curve:   CurveP384,
			mode:    SDeviceKeyModeSign,
			wantErr: nil,
		},
		{
			name:    "CurveP384 Mac",
			curve:   CurveP384,
			mode:    SDeviceKeyModeMAC,
			wantErr: nil,
		},
		{
			name:    "CurveP521 Sign",
			curve:   CurveP521,
			mode:    SDeviceKeyModeSign,
			wantErr: nil,
		},
		{
			name:    "CurveP521 MAC",
			curve:   CurveP521,
			mode:    SDeviceKeyModeMAC,
			wantErr: nil,
		},
		{
			name:    "CurveX25519 Sign",
			curve:   CurveX25519,
			mode:    SDeviceKeyModeSign,
			wantErr: ErrUnsupportedCurve,
		},
		{
			name:    "CurveX25519 MAC",
			curve:   CurveX25519,
			mode:    SDeviceKeyModeMAC,
			wantErr: nil,
		},
		{
			name:    "CurveEd25519 Sign",
			curve:   CurveEd25519,
			mode:    SDeviceKeyModeSign,
			wantErr: nil,
		},
		{
			name:    "CurveEd25519 MAC",
			curve:   CurveEd25519,
			mode:    SDeviceKeyModeMAC,
			wantErr: ErrUnsupportedCurve,
		},
		{
			name:    "CurveX448 Sign",
			curve:   CurveX448,
			mode:    SDeviceKeyModeSign,
			wantErr: ErrUnsupportedCurve,
		},
		{
			name:    "CurveX448 MAC",
			curve:   CurveX448,
			mode:    SDeviceKeyModeMAC,
			wantErr: ErrUnsupportedCurve,
		},
		{
			name:    "CurveEd448 Sign",
			curve:   CurveEd448,
			mode:    SDeviceKeyModeSign,
			wantErr: ErrUnsupportedCurve,
		},
		{
			name:    "CurveEd448 MAC",
			curve:   CurveEd448,
			mode:    SDeviceKeyModeMAC,
			wantErr: ErrUnsupportedCurve,
		},
		{
			name:    "CurveBrainpoolP256r1 Sign",
			curve:   CurveBrainpoolP256r1,
			mode:    SDeviceKeyModeSign,
			wantErr: ErrUnsupportedCurve,
		},
		{
			name:    "CurveBrainpoolP256r1 MAC",
			curve:   CurveBrainpoolP256r1,
			mode:    SDeviceKeyModeMAC,
			wantErr: ErrUnsupportedCurve,
		},
		{
			name:    "CurveBrainpoolP320r1 Sign",
			curve:   CurveBrainpoolP320r1,
			mode:    SDeviceKeyModeSign,
			wantErr: ErrUnsupportedCurve,
		},
		{
			name:    "CurveBrainpoolP320r1 MAC",
			curve:   CurveBrainpoolP320r1,
			mode:    SDeviceKeyModeMAC,
			wantErr: ErrUnsupportedCurve,
		},
		{
			name:    "CurveBrainpoolP384r1 Sign",
			curve:   CurveBrainpoolP384r1,
			mode:    SDeviceKeyModeSign,
			wantErr: ErrUnsupportedCurve,
		},
		{
			name:    "CurveBrainpoolP384r1 MAC",
			curve:   CurveBrainpoolP384r1,
			mode:    SDeviceKeyModeMAC,
			wantErr: ErrUnsupportedCurve,
		},
		{
			name:    "CurveBrainpoolP512r1 Sign",
			curve:   CurveBrainpoolP512r1,
			mode:    SDeviceKeyModeSign,
			wantErr: ErrUnsupportedCurve,
		},
		{
			name:    "CurveBrainpoolP512r1 MAC",
			curve:   CurveBrainpoolP512r1,
			mode:    SDeviceKeyModeMAC,
			wantErr: ErrUnsupportedCurve,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SDeviceKey, err := NewSDeviceKey(rand, tt.curve, tt.mode)
			if err != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && tt.wantErr != nil {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			_ = SDeviceKey
		})
	}
}

func TestNewEDeviceKey(t *testing.T) {
	rand := NewDeterministicRand()

	tests := []struct {
		name    string
		curve   Curve
		wantErr error
	}{
		{
			name:    "CurveP256",
			curve:   CurveP256,
			wantErr: nil,
		},
		{
			name:    "CurveP384",
			curve:   CurveP384,
			wantErr: nil,
		},
		{
			name:    "CurveP521",
			curve:   CurveP521,
			wantErr: nil,
		},
		{
			name:    "CurveX25519",
			curve:   CurveX25519,
			wantErr: nil,
		},
		{
			name:    "CurveX448",
			curve:   CurveX448,
			wantErr: ErrUnsupportedCurve,
		},
		{
			name:    "CurveEd25519",
			curve:   CurveEd25519,
			wantErr: ErrUnsupportedCurve,
		},
		{
			name:    "CurveEd448",
			curve:   CurveEd448,
			wantErr: ErrUnsupportedCurve,
		},
		{
			name:    "CurveBrainpoolP256r1",
			curve:   CurveBrainpoolP256r1,
			wantErr: ErrUnsupportedCurve,
		},
		{
			name:    "CurveBrainpoolP320r1",
			curve:   CurveBrainpoolP320r1,
			wantErr: ErrUnsupportedCurve,
		},
		{
			name:    "CurveBrainpoolP384r1",
			curve:   CurveBrainpoolP384r1,
			wantErr: ErrUnsupportedCurve,
		},
		{
			name:    "CurveBrainpoolP512r1",
			curve:   CurveBrainpoolP512r1,
			wantErr: ErrUnsupportedCurve,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			EDeviceKey, err := NewEDeviceKey(rand, tt.curve)
			if err != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && tt.wantErr != nil {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			_ = EDeviceKey
		})
	}
}

func TestDeviceKeyPrivate_DeviceKey(t *testing.T) {
	//rand := NewDeterministicRand()

	tests := []struct {
		name  string
		curve Curve
		mode  SDeviceKeyMode
	}{
		{
			name:  "CurveP256",
			curve: CurveP256,
			mode:  SDeviceKeyModeSign,
		},
		{
			name:  "CurveP384",
			curve: CurveP384,
			mode:  SDeviceKeyModeSign,
		},
		{
			name:  "CurveP521",
			curve: CurveP521,
			mode:  SDeviceKeyModeSign,
		},
		{
			name:  "CurveX25519",
			curve: CurveX25519,
			mode:  SDeviceKeyModeMAC,
		},
		{
			name:  "CurveEd25519",
			curve: CurveEd25519,
			mode:  SDeviceKeyModeSign,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//EDeviceKeyPrivate, err := NewSDeviceKey(rand, tt.curve, tt.mode)
			//if err != nil {
			//	t.Fatal(err)
			//}

			//EDeviceKey, err := EDeviceKeyPrivate.DeviceKey()
			//if err != nil {
			//	t.Fatal(err)
			//}

			//_ = EDeviceKey // TODO test content
		})
	}
}
