package main

import (
	"errors"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/alex-richards/go-mdoc"
)

type CurveValue mdoc.Curve

func (v *CurveValue) Get() mdoc.Curve {
	return mdoc.Curve(*v)
}

func (v *CurveValue) Set(value string) error {
	curve, err := mdoc.CurveFromName(value)
	if err != nil {
		return err
	}

	*v = CurveValue(curve)
	return nil
}

func (v *CurveValue) String() string {
	if v == nil {
		return ""
	}

	return (mdoc.Curve)(*v).Name()
}

type BigIntValue big.Int

func (v *BigIntValue) Get() big.Int {
	return (big.Int)(*v)
}

func (v *BigIntValue) Set(value string) error {
	_, ok := (*big.Int)(v).SetString(value, 10)
	if !ok {
		return errors.New("invalid int value")
	}

	return nil
}

func (v *BigIntValue) String() string {
	if (*big.Int)(v).BitLen() == 0 {
		return ""
	}

	return (*big.Int)(v).String()
}

type TimeValue time.Time

func (v *TimeValue) Get() time.Time {
	return time.Time(*v)
}

func (v *TimeValue) Set(value string) error {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return err
	}

	*v = (TimeValue)(t)
	return nil
}

func (v *TimeValue) String() string {
	if (*time.Time)(v).IsZero() {
		return ""
	}

	return (*time.Time)(v).Format(time.RFC3339)
}

type ReaderValue struct {
	value     string
	withStdin bool
}

func (v *ReaderValue) String() string {
	return v.value
}

func (v *ReaderValue) Open() (io.ReadCloser, error) {
	switch {
	case v.value == "":
		return nil, errors.New("reader value is empty")
	case v.value == "-" && v.withStdin:
		return os.Stdin, nil
	default:
		return os.OpenFile(v.value, os.O_RDONLY, 0)
	}
}

func (v *ReaderValue) Set(value string) error {
	v.value = value
	return nil
}

type WriterValue struct {
	value      string
	withStdout bool
}

func (v *WriterValue) String() string {
	return v.value
}

func (v *WriterValue) Open() (io.WriteCloser, error) {
	switch {
	case v.value == "":
		return nil, errors.New("writer value is empty")
	case v.value == "-" && v.withStdout:
		return os.Stdout, nil
	default:
		return os.OpenFile(v.value, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	}
}

func (v *WriterValue) Set(value string) error {
	v.value = value
	return nil
}
