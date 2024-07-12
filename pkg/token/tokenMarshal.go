package token

import (
	"emperror.dev/errors"
	"encoding"
	"github.com/deneonet/benc"
	"github.com/deneonet/benc/bstd"
)

func (t *Token) MarshalBinary() ([]byte, error) {
	// type
	size := bstd.SizeUInt16()

	// expiration
	exp, err := t.expiration.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "cannot marshal expiration")
	}
	eSize, err := bstd.SizeByteSlice(exp) // expiration
	if err != nil {
		return nil, errors.Wrap(err, "cannot marshal expiration")
	}
	size += eSize

	// Policies
	size += bstd.SizeUInt16()      // length Policies
	for _, u := range t.policies { // Policies
		s, err := bstd.SizeString(u)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot marshal %s", u)
		}
		size += s
	}

	// Parent
	s, err := bstd.SizeString(t.parent) // parent
	if err != nil {
		return nil, errors.Wrapf(err, "cannot marshal %s", t.parent)
	}
	size += s

	// Metadata
	size += bstd.SizeUInt16() // length metadata
	for key, val := range t.metadata {
		s, err := bstd.SizeString(key)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot marshal %s", key)
		}
		size += s
		s, err = bstd.SizeString(val)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot marshal %s", val)
		}
		size += s
	}

	n, buf := benc.Marshal(size)

	// Type
	n = bstd.MarshalUInt16(n, buf, uint16(t.t))

	// Expiration
	n, err = bstd.MarshalByteSlice(n, buf, exp)
	if err != nil {
		return nil, errors.Wrap(err, "cannot marshal expiration")
	}

	// Policies
	n = bstd.MarshalUInt16(n, buf, uint16(len(t.policies)))
	for _, u := range t.policies {
		if n, err = bstd.MarshalString(n, buf, u); err != nil {
			return nil, errors.Wrapf(err, "cannot marshal %s", u)
		}
	}

	// Parent
	n, err = bstd.MarshalString(n, buf, t.parent)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot marshal %s", t.parent)
	}

	// Metadata
	n = bstd.MarshalUInt16(n, buf, uint16(len(t.metadata)))
	for key, val := range t.metadata {
		if n, err = bstd.MarshalString(n, buf, key); err != nil {
			return nil, errors.Wrapf(err, "cannot marshal %s", key)
		}
		if n, err = bstd.MarshalString(n, buf, val); err != nil {
			return nil, errors.Wrapf(err, "cannot marshal %s", val)
		}
	}

	if err := benc.VerifyMarshal(n, buf); err != nil {
		return nil, errors.Wrap(err, "cannot marshal token")
	}
	return buf, nil
}

func (t *Token) UnmarshalBinary(data []byte) error {
	var err error
	var n int
	t.policies = []string{}
	t.metadata = map[string]string{}

	// Type
	var num uint16
	if n, num, err = bstd.UnmarshalUInt16(n, data); err != nil {
		return errors.Wrap(err, "cannot unmarshal type")
	}
	t.t = Type(num)

	// Expiration
	var exp []byte
	if n, exp, err = bstd.UnmarshalByteSlice(n, data); err != nil {
		return errors.Wrap(err, "cannot unmarshal expiration")
	}
	if err := t.expiration.UnmarshalBinary(exp); err != nil {
		return errors.Wrap(err, "cannot unmarshal binary expiration")
	}

	// Policies
	if n, num, err = bstd.UnmarshalUInt16(n, data); err != nil {
		return errors.Wrap(err, "cannot unmarshal length URIs")
	}
	for i := 0; i < int(num); i++ {
		var s string
		if n, s, err = bstd.UnmarshalString(n, data); err != nil {
			return errors.Wrap(err, "cannot unmarshal URI")
		}
		t.policies = append(t.policies, s)
	}

	// Parent
	if n, t.parent, err = bstd.UnmarshalString(n, data); err != nil {
		return errors.Wrap(err, "cannot unmarshal parent")
	}

	// Metadata
	if n, num, err = bstd.UnmarshalUInt16(n, data); err != nil {
		return errors.Wrap(err, "cannot unmarshal length metadata")
	}
	for i := 0; i < int(num); i++ {
		var key, val string
		if n, key, err = bstd.UnmarshalString(n, data); err != nil {
			return errors.Wrap(err, "cannot unmarshal key")
		}
		if n, val, err = bstd.UnmarshalString(n, data); err != nil {
			return errors.Wrap(err, "cannot unmarshal value")
		}
		t.metadata[key] = val
	}

	if err := benc.VerifyUnmarshal(n, data); err != nil {
		return errors.Wrap(err, "cannot unmarshal token")
	}

	return nil
}

var _ encoding.BinaryMarshaler = (*Token)(nil)
var _ encoding.BinaryUnmarshaler = (*Token)(nil)
