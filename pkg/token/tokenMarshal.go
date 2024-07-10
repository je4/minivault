package token

import (
	"emperror.dev/errors"
	"encoding"
	"github.com/deneonet/benc"
	"github.com/deneonet/benc/bstd"
)

func (t *Token) UnmarshalBinary(data []byte) error {
	var err error
	var n int
	t.uris = []string{}
	t.names = []string{}

	var num uint16
	if n, num, err = bstd.UnmarshalUInt16(n, data); err != nil {
		return errors.Wrap(err, "cannot unmarshal type")
	}
	t.t = Type(num)

	var exp []byte
	if n, exp, err = bstd.UnmarshalByteSlice(n, data); err != nil {
		return errors.Wrap(err, "cannot unmarshal expiration")
	}
	if err := t.expiration.UnmarshalBinary(exp); err != nil {
		return errors.Wrap(err, "cannot unmarshal binary expiration")
	}

	if n, num, err = bstd.UnmarshalUInt16(n, data); err != nil {
		return errors.Wrap(err, "cannot unmarshal length URIs")
	}
	for i := 0; i < int(num); i++ {
		var s string
		if n, s, err = bstd.UnmarshalString(n, data); err != nil {
			return errors.Wrap(err, "cannot unmarshal URI")
		}
		t.uris = append(t.uris, s)
	}
	if n, num, err = bstd.UnmarshalUInt16(n, data); err != nil {
		return errors.Wrap(err, "cannot unmarshal length names")
	}
	for i := 0; i < int(num); i++ {
		var s string
		if n, s, err = bstd.UnmarshalString(n, data); err != nil {
			return errors.Wrap(err, "cannot unmarshal name")
		}
		t.names = append(t.names, s)
	}

	if err := benc.VerifyUnmarshal(n, data); err != nil {
		return errors.Wrap(err, "cannot unmarshal token")
	}

	return nil
}
func (t *Token) MarshalBinary() ([]byte, error) {
	size := bstd.SizeUInt16() // type
	exp, err := t.expiration.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "cannot marshal expiration")
	}
	eSize, err := bstd.SizeByteSlice(exp) // expiration
	if err != nil {
		return nil, errors.Wrap(err, "cannot marshal expiration")
	}
	size += eSize
	size += bstd.SizeUInt16() // length URIs
	size += bstd.SizeUInt16() // length names
	for _, u := range append(t.uris, t.names...) {
		s, err := bstd.SizeString(u)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot marshal %s", u)
		}
		size += s
	}
	n, buf := benc.Marshal(size)
	n = bstd.MarshalUInt16(n, buf, uint16(t.t))
	n, err = bstd.MarshalByteSlice(n, buf, exp)
	if err != nil {
		return nil, errors.Wrap(err, "cannot marshal expiration")
	}
	n = bstd.MarshalUInt16(n, buf, uint16(len(t.uris)))
	n = bstd.MarshalUInt16(n, buf, uint16(len(t.names)))
	for _, u := range append(t.uris, t.names...) {
		if n, err = bstd.MarshalString(n, buf, u); err != nil {
			return nil, errors.Wrapf(err, "cannot marshal %s", u)
		}
	}
	if err := benc.VerifyMarshal(n, buf); err != nil {
		return nil, errors.Wrap(err, "cannot marshal token")
	}
	return buf, nil
}

var _ encoding.BinaryMarshaler = (*Token)(nil)
var _ encoding.BinaryUnmarshaler = (*Token)(nil)
