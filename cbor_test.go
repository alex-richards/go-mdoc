package mdoc

import (
	"bytes"
	"encoding/hex"
	"errors"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
	"testing"
)

const (
	cborMajorTypeBstr        = 2 << 5
	cborMajorTypeMap         = 5 << 5
	cborMajorTypeTaggedValue = 6 << 5
)

const (
	cborArgumentLength1 = 24
	//cborArgumentLength2 = 25
	//cborArgumentLength3 = 26
	//cborArgumentLength4 = 27
)

const (
	cborEmptyMap = cborMajorTypeMap | 0
)

func TestNewTaggedEncodedCBOR(t *testing.T) {
	tests := []struct {
		name          string
		untaggedValue []byte
		want          *TaggedEncodedCBOR
	}{
		{
			name:          "value",
			untaggedValue: []byte{1, 2, 3, 4},
			want: &TaggedEncodedCBOR{
				TaggedValue: []byte{
					cborMajorTypeTaggedValue | cborArgumentLength1, cborTagEncodedCBOR,
					cborMajorTypeBstr | 4, 1, 2, 3, 4,
				},
				UntaggedValue: []byte{1, 2, 3, 4},
			},
		},
		{
			name:          "nil",
			untaggedValue: nil,
			want: &TaggedEncodedCBOR{
				TaggedValue: []byte{
					cborNull,
				},
				UntaggedValue: nil,
			},
		},
		{
			name:          "empty",
			untaggedValue: []byte{},
			want: &TaggedEncodedCBOR{
				TaggedValue: []byte{
					cborMajorTypeTaggedValue | cborArgumentLength1, cborTagEncodedCBOR,
					cborMajorTypeBstr | 0,
				},
				UntaggedValue: []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewTaggedEncodedCBOR(tt.untaggedValue)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestTaggedEncodedCBOR_MarshalCBOR(t *testing.T) {
	tests := []struct {
		name              string
		taggedEncodedCBOR TaggedEncodedCBOR
		want              []byte
		wantErr           error
	}{
		{
			name: "marshal complete",
			taggedEncodedCBOR: TaggedEncodedCBOR{
				TaggedValue: []byte{
					cborMajorTypeTaggedValue | cborArgumentLength1, cborTagEncodedCBOR,
					cborMajorTypeBstr | 1, cborEmptyMap,
				},
				UntaggedValue: []byte{
					cborEmptyMap,
				},
			},
			want: []byte{
				cborMajorTypeTaggedValue | cborArgumentLength1, cborTagEncodedCBOR,
				cborMajorTypeBstr | 1, cborEmptyMap,
			},
		},
		{
			name: "marshal tagged only",
			taggedEncodedCBOR: TaggedEncodedCBOR{
				TaggedValue: []byte{
					cborMajorTypeTaggedValue | cborArgumentLength1, cborTagEncodedCBOR,
					cborMajorTypeBstr | 1, cborEmptyMap,
				},
			},
			want: []byte{
				cborMajorTypeTaggedValue | cborArgumentLength1, cborTagEncodedCBOR,
				cborMajorTypeBstr | 1, cborEmptyMap,
			},
		},
		{
			name: "marshal untagged only",
			taggedEncodedCBOR: TaggedEncodedCBOR{
				UntaggedValue: []byte{
					cborEmptyMap,
				},
			},
			wantErr: ErrEmptyTaggedValue,
		},
		{
			name:              "marshal empty",
			taggedEncodedCBOR: TaggedEncodedCBOR{},
			wantErr:           ErrEmptyTaggedValue,
		},
		{
			name:    "marshal nil",
			wantErr: ErrEmptyTaggedValue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cbor.Marshal(tt.taggedEncodedCBOR)
			if err != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && (tt.wantErr != nil) {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !bytes.Equal(tt.want, got) {
				t.Errorf("got = %v, want %v", hex.EncodeToString(got), hex.EncodeToString(tt.want))
			}
		})
	}
}

func TestTaggedEncodedCBOR_UnmarshalCBOR(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    TaggedEncodedCBOR
		wantErr string
	}{
		{
			name: "unmarshal tagged",
			data: []byte{
				cborMajorTypeTaggedValue | cborArgumentLength1, cborTagEncodedCBOR,
				cborMajorTypeBstr | 1, cborEmptyMap,
			},
			want: TaggedEncodedCBOR{
				TaggedValue: []byte{
					cborMajorTypeTaggedValue | cborArgumentLength1, cborTagEncodedCBOR,
					cborMajorTypeBstr | 1, cborEmptyMap,
				},
				UntaggedValue: []byte{
					cborEmptyMap,
				},
			},
		},
		{
			name: "unmarshal untagged",
			data: []byte{
				cborEmptyMap,
			},
			wantErr: "cbor: cannot unmarshal map into Go value of type mdoc.bstr (expect CBOR tag value)",
		},
		{
			name:    "unmarshal empty",
			data:    []byte{},
			wantErr: "EOF",
		},
		{
			name:    "unmarshal nil",
			data:    nil,
			wantErr: "EOF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got TaggedEncodedCBOR
			err := cbor.Unmarshal(tt.data, &got)
			if err != nil && (err.Error() != tt.wantErr) {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && (tt.wantErr != "") {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(&tt.want, &got, cmp.AllowUnexported(TaggedEncodedCBOR{})); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
