package cbor

import (
	"io"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
)

const (
	cborMajorTypeBstr        = 2 << 5
	cborMajorTypeStr         = 3 << 5
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

func Test_MarshalToTaggedEncodedCBOR(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  *TaggedEncodedCBOR
	}{
		{
			name:  "string",
			value: "string",
			want: &TaggedEncodedCBOR{
				TaggedValue: []byte{
					cborMajorTypeTaggedValue | cborArgumentLength1, tagEncodedCBOR,
					cborMajorTypeBstr | 7,
					cborMajorTypeStr | 6, 's', 't', 'r', 'i', 'n', 'g',
				},
				UntaggedValue: []byte{
					cborMajorTypeStr | 6, 's', 't', 'r', 'i', 'n', 'g',
				},
			},
		},
		{
			name:  "nil",
			value: nil,
			want: &TaggedEncodedCBOR{
				TaggedValue: []byte{
					cborMajorTypeTaggedValue | cborArgumentLength1, tagEncodedCBOR,
					cborMajorTypeBstr | 1,
					Null,
				},
				UntaggedValue: []byte{
					Null,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MarshalToNewTaggedEncodedCBOR(tt.value)
			if err != nil {
				t.Fatalf("Want error to be nil, got %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func Test_NewTaggedEncodedCBOR(t *testing.T) {
	tests := []struct {
		name          string
		untaggedValue []byte
		want          *TaggedEncodedCBOR
		wantErr       error
	}{
		{
			name:          "value",
			untaggedValue: []byte{1, 2, 3, 4},
			want: &TaggedEncodedCBOR{
				TaggedValue: []byte{
					cborMajorTypeTaggedValue | cborArgumentLength1, tagEncodedCBOR,
					cborMajorTypeBstr | 4, 1, 2, 3, 4,
				},
				UntaggedValue: []byte{1, 2, 3, 4},
			},
		},
		{
			name:          "nil",
			untaggedValue: nil,
			wantErr:       ErrEmptyUntaggedValue,
		},
		{
			name:          "empty",
			untaggedValue: []byte{},
			want: &TaggedEncodedCBOR{
				TaggedValue: []byte{
					cborMajorTypeTaggedValue | cborArgumentLength1, tagEncodedCBOR,
					cborMajorTypeBstr | 0,
				},
				UntaggedValue: []byte{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewTaggedEncodedCBOR(tt.untaggedValue)
			if err != tt.wantErr {
				t.Fatalf("Want error %v, got %v", tt.wantErr, err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func Test_TaggedEncodedCBOR_MarshalCBOR(t *testing.T) {
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
					cborMajorTypeTaggedValue | cborArgumentLength1, tagEncodedCBOR,
					cborMajorTypeBstr | 1, cborEmptyMap,
				},
				UntaggedValue: []byte{
					cborEmptyMap,
				},
			},
			want: []byte{
				cborMajorTypeTaggedValue | cborArgumentLength1, tagEncodedCBOR,
				cborMajorTypeBstr | 1, cborEmptyMap,
			},
		},
		{
			name: "marshal tagged only",
			taggedEncodedCBOR: TaggedEncodedCBOR{
				TaggedValue: []byte{
					cborMajorTypeTaggedValue | cborArgumentLength1, tagEncodedCBOR,
					cborMajorTypeBstr | 1, cborEmptyMap,
				},
			},
			want: []byte{
				cborMajorTypeTaggedValue | cborArgumentLength1, tagEncodedCBOR,
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
			if err != tt.wantErr {
				t.Fatalf("Want error %v, got %v", tt.wantErr, err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Error()
			}
		})
	}
}

func Test_TaggedEncodedCBOR_UnmarshalCBOR(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		want           TaggedEncodedCBOR
		wantErr        error
		wantErrMessage string
	}{
		{
			name: "unmarshal tagged",
			data: []byte{
				cborMajorTypeTaggedValue | cborArgumentLength1, tagEncodedCBOR,
				cborMajorTypeBstr | 1, cborEmptyMap,
			},
			want: TaggedEncodedCBOR{
				TaggedValue: []byte{
					cborMajorTypeTaggedValue | cborArgumentLength1, tagEncodedCBOR,
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
			wantErrMessage: "cbor: cannot unmarshal map into Go value of type cbor.bstr (expect CBOR tag value)",
		},
		{
			name:    "unmarshal empty",
			data:    []byte{},
			wantErr: io.EOF,
		},
		{
			name:    "unmarshal nil",
			data:    nil,
			wantErr: io.EOF,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got TaggedEncodedCBOR
			err := cbor.Unmarshal(tt.data, &got)
			if err != nil && !(err == tt.wantErr || err.Error() == tt.wantErrMessage) {
				t.Fatalf("Want error %v or %v, got %v", tt.wantErr, tt.wantErrMessage, err)
			}
			if diff := cmp.Diff(&tt.want, &got, cmp.AllowUnexported(TaggedEncodedCBOR{})); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
