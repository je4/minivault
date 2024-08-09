package token

import (
	"emperror.dev/errors"
	"encoding"
	"github.com/deneonet/benc"
	"github.com/deneonet/benc/bstd"
	"time"
)

func (t *Token) MarshalBinary() ([]byte, error) {
	// type
	size := bstd.SizeUInt16()

	// Expiration
	exp, err := t.Expiration.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "cannot marshal Expiration")
	}
	eSize, err := bstd.SizeByteSlice(exp) // Expiration
	if err != nil {
		return nil, errors.Wrap(err, "cannot marshal Expiration")
	}
	size += eSize

	// MaxTTL
	size += bstd.SizeInt64() // length MaxTTL

	// Policies
	size += bstd.SizeUInt16()      // length Policies
	for _, u := range t.Policies { // Policies
		s, err := bstd.SizeString(u)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot marshal %s", u)
		}
		size += s
	}

	// Parent
	s, err := bstd.SizeString(t.Parent) // Parent
	if err != nil {
		return nil, errors.Wrapf(err, "cannot marshal %s", t.Parent)
	}
	size += s

	// Metadata
	size += bstd.SizeUInt16() // length Metadata
	for key, val := range t.Metadata {
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
	n = bstd.MarshalUInt16(n, buf, uint16(t.T))

	// Expiration
	n, err = bstd.MarshalByteSlice(n, buf, exp)
	if err != nil {
		return nil, errors.Wrap(err, "cannot marshal Expiration")
	}

	// MaxTTL
	n = bstd.MarshalInt64(n, buf, int64(t.MaxTTL))

	// Policies
	n = bstd.MarshalUInt16(n, buf, uint16(len(t.Policies)))
	for _, u := range t.Policies {
		if n, err = bstd.MarshalString(n, buf, u); err != nil {
			return nil, errors.Wrapf(err, "cannot marshal %s", u)
		}
	}

	// Parent
	n, err = bstd.MarshalString(n, buf, t.Parent)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot marshal %s", t.Parent)
	}

	// Metadata
	n = bstd.MarshalUInt16(n, buf, uint16(len(t.Metadata)))
	for key, val := range t.Metadata {
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
	t.Policies = []string{}
	t.Metadata = map[string]string{}

	// Type
	var num uint16
	if n, num, err = bstd.UnmarshalUInt16(n, data); err != nil {
		return errors.Wrap(err, "cannot unmarshal type")
	}
	t.T = Type(num)

	// Expiration
	var exp []byte
	if n, exp, err = bstd.UnmarshalByteSlice(n, data); err != nil {
		return errors.Wrap(err, "cannot unmarshal Expiration")
	}
	if err := t.Expiration.UnmarshalBinary(exp); err != nil {
		return errors.Wrap(err, "cannot unmarshal binary Expiration")
	}

	// MaxTTL
	var maxTTL int64
	if n, maxTTL, err = bstd.UnmarshalInt64(n, data); err != nil {
		return errors.Wrap(err, "cannot unmarshal MaxTTL")
	}
	t.MaxTTL = time.Duration(maxTTL)

	// Policies
	if n, num, err = bstd.UnmarshalUInt16(n, data); err != nil {
		return errors.Wrap(err, "cannot unmarshal length URIs")
	}
	for i := 0; i < int(num); i++ {
		var s string
		if n, s, err = bstd.UnmarshalString(n, data); err != nil {
			return errors.Wrap(err, "cannot unmarshal URI")
		}
		t.Policies = append(t.Policies, s)
	}

	// Parent
	if n, t.Parent, err = bstd.UnmarshalString(n, data); err != nil {
		return errors.Wrap(err, "cannot unmarshal Parent")
	}

	// Metadata
	if n, num, err = bstd.UnmarshalUInt16(n, data); err != nil {
		return errors.Wrap(err, "cannot unmarshal length Metadata")
	}
	for i := 0; i < int(num); i++ {
		var key, val string
		if n, key, err = bstd.UnmarshalString(n, data); err != nil {
			return errors.Wrap(err, "cannot unmarshal key")
		}
		if n, val, err = bstd.UnmarshalString(n, data); err != nil {
			return errors.Wrap(err, "cannot unmarshal value")
		}
		t.Metadata[key] = val
	}

	if err := benc.VerifyUnmarshal(n, data); err != nil {
		return errors.Wrap(err, "cannot unmarshal token")
	}

	return nil
}

var _ encoding.BinaryMarshaler = (*Token)(nil)
var _ encoding.BinaryUnmarshaler = (*Token)(nil)
