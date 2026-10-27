// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uasc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"testing"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uapolicy"
	"github.com/stretchr/testify/require"
)

// A secured server decrypts chunks from clients it has not authenticated, and
// an OpenSecureChannel is decrypted before anything about the peer is known.
// Decrypting slices the signature and padding out of attacker-controlled
// lengths, so every length has to be checked first. An unchecked slice panics
// the receive goroutine, which takes the whole process down.

func opnHeader(t *testing.T, uri string) []byte {
	t.Helper()
	h := NewAsymmetricSecurityHeader(uri, nil, nil)
	b := make([]byte, 12, 12+h.Len())
	copy(b, "OPNF")
	binary.LittleEndian.PutUint32(b[8:], 0) // secure channel id
	hb, err := h.Encode()
	require.NoError(t, err)
	return append(b, hb...)
}

// craftOPN builds an OPN chunk the way a client with its own key would: sign
// header+tail, then encrypt tail+signature. tail is whatever the test wants
// the decrypted body and padding to be, valid or not.
func craftOPN(t *testing.T, algo *uapolicy.EncryptionAlgorithm, hdr, tail []byte) (*MessageChunk, []byte) {
	t.Helper()
	sig, err := algo.Signature(append(append([]byte{}, hdr...), tail...))
	require.NoError(t, err)
	ct, err := algo.Encrypt(append(append([]byte{}, tail...), sig...))
	require.NoError(t, err)
	return decodeChunk(t, append(append([]byte{}, hdr...), ct...))
}

func decodeChunk(t *testing.T, raw []byte) (*MessageChunk, []byte) {
	t.Helper()
	binary.LittleEndian.PutUint32(raw[4:], uint32(len(raw)))
	c := new(MessageChunk)
	_, err := c.Decode(raw)
	require.NoError(t, err)
	return c, raw
}

func TestVerifyAndDecryptRejectsMalformedOPN(t *testing.T) {
	const uri = ua.SecurityPolicyURIBasic256Sha256
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	// The attacker is its own peer: it signs with its key and encrypts to ours.
	algo, err := uapolicy.Asymmetric(uri, key, &key.PublicKey)
	require.NoError(t, err)
	hdr := opnHeader(t, uri)

	dec := &channelInstance{
		sc:   &SecureChannel{cfg: &Config{SecurityMode: ua.MessageSecurityModeNone, SecurityPolicyURI: uri}},
		algo: algo,
	}

	type chunk struct {
		m   *MessageChunk
		raw []byte
	}
	build := func(tail []byte) chunk {
		m, raw := craftOPN(t, algo, hdr, tail)
		return chunk{m, raw}
	}
	// A chunk with nothing after the headers: no ciphertext, so no signature
	// to slice, and it needs no key at all to send.
	empty := func() chunk {
		m, raw := decodeChunk(t, append([]byte{}, hdr...))
		return chunk{m, raw}
	}()
	// A chunk whose raw bytes are shorter than its own headers.
	truncated := func() chunk {
		m, raw := decodeChunk(t, append(append([]byte{}, hdr...), 1, 2, 3))
		return chunk{m, raw[:10]}
	}()

	cases := map[string]chunk{
		"no ciphertext":                   empty,
		"raw shorter than headers":        truncated,
		"empty body before signature":     build(nil),
		"one 0xff byte before signature":  build([]byte{0xff}),
		"padding larger than body":        build([]byte{0x00, 0x7f}),
		"padding size byte only, too big": build([]byte{0xfe}),
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, err := dec.verifyAndDecrypt(c.m, c.raw)
				require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)
			})
		})
	}
}

func TestVerifyAndDecryptRejectsMalformedMSG(t *testing.T) {
	for _, uri := range symmetricPolicyURIs {
		t.Run(testName(uri, 0), func(t *testing.T) {
			c := symmetricInstance(t, uri)
			raw, m := symmetricChunk(nil)
			headerLength := 12 + m.SymmetricSecurityHeader.Len()
			hdr := raw[:headerLength]

			// The peer holds the symmetric keys, so it can sign whatever
			// padding it likes: only length checks stand in the way. AES-CBC
			// takes whole blocks only, so the tail is front-padded with
			// zeros to align it; the bytes that matter are its last ones.
			craft := func(t *testing.T, tail []byte) (*MessageChunk, []byte) {
				sig, err := c.algo.Signature(append(append([]byte{}, hdr...), tail...))
				require.NoError(t, err)
				if rem := (len(tail) + len(sig)) % 16; rem != 0 {
					filler := make([]byte, 16-rem)
					tail = append(filler, tail...)
					sig, err = c.algo.Signature(append(append([]byte{}, hdr...), tail...))
					require.NoError(t, err)
					if (len(tail)+len(sig))%16 != 0 {
						t.Skip("a peer cannot encrypt a tail of this size")
					}
				}
				ct, err := c.algo.Encrypt(append(append([]byte{}, tail...), sig...))
				require.NoError(t, err)
				return decodeChunk(t, append(append([]byte{}, hdr...), ct...))
			}

			for name, tail := range map[string][]byte{
				"empty body":        nil,
				"one 0xff byte":     {0xff},
				"padding too large": {0x7f},
			} {
				t.Run(name, func(t *testing.T) {
					chunk, cipher := craft(t, tail)
					require.NotPanics(t, func() {
						_, err := c.verifyAndDecrypt(chunk, cipher)
						require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)
					})
				})
			}

			t.Run("no ciphertext", func(t *testing.T) {
				chunk, cipher := decodeChunk(t, append([]byte{}, hdr...))
				require.NotPanics(t, func() {
					_, err := c.verifyAndDecrypt(chunk, cipher)
					require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)
				})
			})
		})
	}
}
