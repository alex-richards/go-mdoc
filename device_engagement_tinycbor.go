//go:build mdoc_tinycbor

package mdoc

import (
	"bytes"
	"errors"
	"io"

	"github.com/alex-richards/tiny-cbor"
)

func (de *DeviceEngagement) ReadCBOR(in io.Reader) error {
	return cbor.ReadMap(
		in,
		func(indefinite bool, length uint64) error {
			if indefinite {
				return errors.New("indf")
			}
			if length < 2 {
				return errors.New("too small")
			}
			return nil
		},
		func(in io.Reader) error {
			k, err := cbor.ReadUnsigned[uint8](in)
			if err != nil {
				return err
			}
			switch k {
			case 0:
				version := bytes.NewBuffer(nil)
				err = cbor.ReadBytes(
					in,
					func(indefinite bool, length uint64) error {
						version.Grow(int(length))
						return nil
					},
					version,
				)
				if err != nil {
					return err
				}
				de.Version = string(version.Bytes())
			case 1:
				de.Security = Security{}
				err = de.Security.ReadCBOR(in)
				if err != nil {
					return err
				}
			case 2:
				err = cbor.ReadArray(
					in,
					func(indefinite bool, length uint64) error {
						de.DeviceRetrievalMethods = make([]DeviceRetrievalMethod, length)
						return nil
					},
					func(i uint64, in io.Reader) error {
						var drm DeviceRetrievalMethod
						err = drm.ReadCBOR(in)
						if err != nil {
							return err
						}
						de.DeviceRetrievalMethods[i] = drm
						return nil
					},
				)
				if err != nil {
					return err
				}
			default:
				err = cbor.ReadOver(in)
				if err != nil {
					return err
				}
			}
			return nil
		},
	)
}

func (de *DeviceEngagement) WriteCBOR(out io.Writer) error {
	_, err := cbor.WriteMapHeader(out, 3)
	if err != nil {
		return err
	}
	_, err = cbor.WriteUnsigned(out, uint8(0))
	if err != nil {
		return err
	}
	_, err = cbor.WriteString(out, de.Version)
	if err != nil {
		return err
	}
	_, err = cbor.WriteUnsigned(out, uint8(1))
	if err != nil {
		return err
	}
	err = de.Security.WriteCBOR(out)
	if err != nil {
		return err
	}
	_, err = cbor.WriteUnsigned(out, uint8(2))
	if err != nil {
		return err
	}
	_, err = cbor.WriteArrayHeader(out, uint64(len(de.DeviceRetrievalMethods)))
	if err != nil {
		return err
	}
	for _, o := range de.DeviceRetrievalMethods {
		err = o.WriteCBOR(out)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Security) ReadCBOR(in io.Reader) error {
	return cbor.ReadArray(
		in,
		func(indefinite bool, length uint64) error {
			return nil
		},
		func(i uint64, in io.Reader) error {
			switch i {
			case 0:
				csi, err := cbor.ReadSigned[int64](in)
				if err != nil {
					return err
				}
				s.CipherSuiteIdentifier = int(csi)
			case 1:
				out := bytes.NewBuffer(nil)
				err := cbor.ReadRaw(in, out)
				if err != nil {
					return err
				}
				s.EDeviceKeyBytes = TaggedEncodedCBOR{
					TaggedValue: out.Bytes(),
				}
			default:
				err := cbor.ReadOver(in)
				if err != nil {
					return err
				}
			}
			return nil
		},
	)
}

func (s *Security) WriteCBOR(out io.Writer) error {
	_, err := cbor.WriteArrayHeader(out, 2)
	if err != nil {
		return err
	}
	_, err = cbor.WriteSigned(out, int8(s.CipherSuiteIdentifier))
	if err != nil {
		return err
	}
	_, err = cbor.WriteBytes(out, s.EDeviceKeyBytes.TaggedValue)
	if err != nil {
		return err
	}
	return nil
}

func (drm *DeviceRetrievalMethod) ReadCBOR(in io.Reader) error {
	return cbor.ReadArray(in,
		func(indefinite bool, length uint64) error { return nil },
		func(i uint64, in io.Reader) error {
			switch i {
			case 0:
				t, err := cbor.ReadUnsigned[uint64](in)
				if err != nil {
					return err
				}
				drm.Type = DeviceRetrievalMethodType(t)
			case 1:
				v, err := cbor.ReadUnsigned[uint64](in)
				if err != nil {
					return err
				}
				drm.Version = uint(v)
			case 2:
				switch drm.Type {
				case DeviceRetrievalMethodTypeWiFiAware:
					o := WifiOptions{}
					err := o.ReadCBOR(in)
					if err != nil {
						return err
					}
					drm.RetrievalOptions = o
				case DeviceRetrievalMethodTypeBLE:
					o := BLEOptions{}
					err := o.ReadCBOR(in)
					if err != nil {
						return err
					}
					drm.RetrievalOptions = o
				case DeviceRetrievalMethodTypeNFC:
					o := NFCOptions{}
					err := o.ReadCBOR(in)
					if err != nil {
						return err
					}
					drm.RetrievalOptions = o
				default:
					return errors.New("TODO unknown type")
				}
			default:
				err := cbor.ReadOver(in)
				if err != nil {
					return err
				}
			}
			i++
			return nil
		},
	)
}

func (drm *DeviceRetrievalMethod) WriteCBOR(out io.Writer) error {
	_, err := cbor.WriteArrayHeader(out, uint64(3))
	if err != nil {
		return err
	}
	_, err = cbor.WriteUnsigned(out, uint64(drm.Type))
	if err != nil {
		return err
	}
	_, err = cbor.WriteUnsigned(out, uint64(drm.Version))
	if err != nil {
		return err
	}
	switch o := drm.RetrievalOptions.(type) {
	case WifiOptions:
		err = o.WriteCBOR(out)
	case BLEOptions:
		err = o.WriteCBOR(out)
	case NFCOptions:
		err = o.WriteCBOR(out)
	default:
		return errors.New("TODO - unsupported type")
	}
	return err
}

func (wo *WifiOptions) ReadCBOR(in io.Reader) error {
	return cbor.ReadMap(in,
		func(indefinite bool, length uint64) error { return nil },
		func(in io.Reader) error {
			k, err := cbor.ReadUnsigned[uint8](in)
			if err != nil {
				return err
			}
			switch k {
			case 0:
				pp := bytes.NewBuffer(nil)
				err := cbor.ReadBytes(in,
					func(indefinite bool, length uint64) error {
						pp.Grow(int(length))
						return nil
					},
					pp,
				)
				if err != nil {
					return err
				}
				wo.PassPhraseInfoPassPhrase = string(pp.Bytes())
			case 1:
				oc, err := cbor.ReadUnsigned[uint64](in)
				if err != nil {
					return err
				}
				wo.ChannelInfoOperatingClass = uint(oc)
			case 2:
				cn, err := cbor.ReadUnsigned[uint64](in)
				if err != nil {
					return err
				}
				wo.ChannelInfoChannelNumber = uint(cn)
			case 3:
				bi := bytes.NewBuffer(nil)
				err := cbor.ReadBytes(in,
					func(indefinite bool, length uint64) error {
						bi.Grow(int(length))
						return nil
					},
					bi,
				)
				if err != nil {
					return err
				}
				wo.BandInfoSupportedBands = bi.Bytes()
			default:
				err = cbor.ReadOver(in)
				if err != nil {
					return err
				}
			}
			return nil
		},
	)
}

func (wo *WifiOptions) WriteCBOR(out io.Writer) error {
	l := uint64(0)
	if wo.PassPhraseInfoPassPhrase != "" {
		l++
	}
	if wo.ChannelInfoOperatingClass != 0 {
		l++
	}
	if wo.ChannelInfoChannelNumber != 0 {
		l++
	}
	if wo.BandInfoSupportedBands != nil {
		l++
	}
	_, err := cbor.WriteMapHeader(out, l)
	if err != nil {
		return err
	}
	if wo.PassPhraseInfoPassPhrase != "" {
		_, err = cbor.WriteUnsigned(out, uint64(0))
		if err != nil {
			return err
		}
		_, err = cbor.WriteString(out, wo.PassPhraseInfoPassPhrase)
		if err != nil {
			return err
		}
	}
	if wo.ChannelInfoOperatingClass != 0 {
		_, err = cbor.WriteUnsigned(out, uint64(1))
		if err != nil {
			return err
		}
		_, err = cbor.WriteUnsigned(out, uint64(wo.ChannelInfoOperatingClass))
		if err != nil {
			return err
		}
	}
	if wo.ChannelInfoChannelNumber != 0 {
		_, err = cbor.WriteUnsigned(out, uint64(2))
		if err != nil {
			return err
		}
		_, err = cbor.WriteUnsigned(out, uint64(wo.ChannelInfoChannelNumber))
		if err != nil {
			return err
		}
	}
	if wo.BandInfoSupportedBands != nil {
		_, err = cbor.WriteUnsigned(out, uint64(3))
		if err != nil {
			return err
		}
		_, err = cbor.WriteBytes(out, wo.BandInfoSupportedBands)
		if err != nil {
			return err
		}
	}
	return nil
}

func (bo *BLEOptions) ReadCBOR(in io.Reader) error {
	return cbor.ReadMap(in,
		func(indefinite bool, length uint64) error { return nil },
		func(in io.Reader) error {
			k, err := cbor.ReadUnsigned[uint8](in)
			if err != nil {
				return err
			}
			switch k {
			case 0:
				sps, err := cbor.ReadBool(in)
				if err != nil {
					return err
				}
				bo.SupportsPeripheralServer = sps
			case 1:
				scc, err := cbor.ReadBool(in)
				if err != nil {
					return err
				}
				bo.SupportsCentralClient = scc
			case 10:
				psid := bytes.NewBuffer(nil)
				err = cbor.ReadBytes(in,
					func(indefinite bool, length uint64) error {
						psid.Grow(int(length))
						return nil
					},
					psid,
				)
				if err != nil {
					return err
				}
				psuuid, err := UUIDFromBytes(psid.Bytes())
				if err != nil {
					return err
				}
				bo.PeripheralServerUUID = psuuid
			case 11:
				ccid := bytes.NewBuffer(nil)
				err = cbor.ReadBytes(in,
					func(indefinite bool, length uint64) error {
						ccid.Grow(int(length))
						return nil
					},
					ccid,
				)
				if err != nil {
					return err
				}
				ccuuid, err := UUIDFromBytes(ccid.Bytes())
				if err != nil {
					return err
				}
				bo.CentralClientUUID = ccuuid
			case 20:
				psda := bytes.NewBuffer(nil)
				err = cbor.ReadBytes(in,
					func(indefinite bool, length uint64) error {
						psda.Grow(int(length))
						return nil
					},
					psda,
				)
				if err != nil {
					return err
				}
				var da BLEAddress
				if psda.Len() != 6 {
					return errors.New("TODO - invalid ble addr")
				}
				copy(da[:], psda.Bytes())
				bo.PeripheralServerDeviceAddress = &da
			default:
				err := cbor.ReadOver(in)
				if err != nil {
					return err
				}
			}
			return nil
		},
	)
}

func (bo *BLEOptions) WriteCBOR(out io.Writer) error {
	l := uint64(2)
	if bo.PeripheralServerUUID != nil {
		l++
	}
	if bo.CentralClientUUID != nil {
		l++
	}
	if bo.PeripheralServerDeviceAddress != nil {
		l++
	}
	_, err := cbor.WriteMapHeader(out, l)
	if err != nil {
		return err
	}
	_, err = cbor.WriteUnsigned(out, uint8(0))
	if err != nil {
		return err
	}
	_, err = cbor.WriteBool(out, bo.SupportsPeripheralServer)
	if err != nil {
		return err
	}
	_, err = cbor.WriteUnsigned(out, uint8(1))
	if err != nil {
		return err
	}
	_, err = cbor.WriteBool(out, bo.SupportsCentralClient)
	if err != nil {
		return err
	}
	if bo.PeripheralServerUUID != nil {
		_, err = cbor.WriteUnsigned(out, uint8(10))
		if err != nil {
			return err
		}
		_, err = cbor.WriteBytes(out, bo.PeripheralServerUUID[:])
		if err != nil {
			return err
		}
	}
	if bo.CentralClientUUID != nil {
		_, err = cbor.WriteUnsigned(out, uint8(11))
		if err != nil {
			return err
		}
		_, err = cbor.WriteBytes(out, bo.CentralClientUUID[:])
		if err != nil {
			return err
		}
	}
	if bo.PeripheralServerDeviceAddress != nil {
		_, err = cbor.WriteUnsigned(out, uint8(20))
		if err != nil {
			return err
		}
		_, err = cbor.WriteBytes(out, bo.PeripheralServerDeviceAddress[:])
		if err != nil {
			return err
		}
	}
	return nil
}

func (no *NFCOptions) ReadCBOR(in io.Reader) error {
	return cbor.ReadMap(in,
		func(indefinite bool, length uint64) error {
			return nil
		},
		func(in io.Reader) error {
			k, err := cbor.ReadUnsigned[uint8](in)
			if err != nil {
				return err
			}
			switch k {
			case 0:
				lcd, err := cbor.ReadUnsigned[uint64](in)
				if err != nil {
					return err
				}
				no.MaxLengthCommandData = uint(lcd)
			case 1:
				lrd, err := cbor.ReadUnsigned[uint64](in)
				if err != nil {
					return err
				}
				no.MaxLengthResponseData = uint(lrd)
			default:
				err := cbor.ReadOver(in)
				if err != nil {
					return err
				}
			}
			return nil
		},
	)
}

func (no *NFCOptions) WriteCBOR(out io.Writer) error {
	_, err := cbor.WriteMapHeader(out, 2)
	if err != nil {
		return err
	}
	_, err = cbor.WriteUnsigned(out, uint8(0))
	if err != nil {
		return err
	}
	_, err = cbor.WriteUnsigned(out, uint64(no.MaxLengthCommandData))
	if err != nil {
		return err
	}
	return nil
}
