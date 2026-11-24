// Copyright 2018-2026 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uasc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"strconv"
	"testing"
	"time"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uapolicy"
	"github.com/stretchr/testify/require"
)

// An OpenSecureChannel is decrypted with the local private key before its
// signature can be checked, one private-key operation per ciphertext block, so
// the amount of ciphertext accepted has to be bounded by what a real
// OpenSecureChannel needs rather than by the receive buffer.

// sealOPN signs and encrypts body as the OPN chunk a peer holding algo sends.
func sealOPN(t *testing.T, algo *uapolicy.EncryptionAlgorithm, uri string, body []byte) (*MessageChunk, []byte) {
	t.Helper()
	m := &Message{
		MessageHeader: &MessageHeader{
			Header:                   NewHeader(MessageTypeOpenSecureChannel, ChunkTypeFinal, 0),
			AsymmetricSecurityHeader: NewAsymmetricSecurityHeader(uri, nil, nil),
			SequenceHeader:           NewSequenceHeader(1, 1),
		},
	}
	enc := &channelInstance{
		sc:   &SecureChannel{cfg: &Config{SecurityMode: ua.MessageSecurityModeSignAndEncrypt, SecurityPolicyURI: uri}},
		algo: algo,
	}
	raw, err := enc.signAndEncrypt(m, append(opnHeader(t, uri), body...))
	require.NoError(t, err)
	chunk := new(MessageChunk)
	_, err = chunk.Decode(raw)
	require.NoError(t, err)
	return chunk, raw
}

func TestVerifyAndDecryptRefusesOversizedOPN(t *testing.T) {
	const uri = ua.SecurityPolicyURIBasic256Sha256
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	algo, err := uapolicy.Asymmetric(uri, key, &key.PublicKey)
	require.NoError(t, err)
	dec := &channelInstance{
		sc:   &SecureChannel{cfg: &Config{SecurityMode: ua.MessageSecurityModeNone, SecurityPolicyURI: uri}},
		algo: algo,
	}

	// Each chunk is well formed and correctly signed, so nothing but its size
	// can be the reason it is refused.
	seal := func(blocks int) (*MessageChunk, []byte) {
		// signature, padding size byte and sequence header fill the rest
		n := blocks*algo.PlaintextBlockSize() - algo.SignatureLength() - 1 - 8
		body := append(make([]byte, 8), bytes.Repeat([]byte{0xab}, n)...)
		m, raw := sealOPN(t, algo, uri, body)
		require.Equal(t, blocks*algo.BlockSize(), len(raw)-12-m.AsymmetricSecurityHeader.Len())
		return m, raw
	}
	atLimit := maxOpenCiphertext / algo.BlockSize()

	m, raw := seal(atLimit)
	_, err = dec.verifyAndDecrypt(m, raw)
	require.NoError(t, err, "an OPN at the limit must still be decrypted")

	for _, blocks := range []int{atLimit + 1, 200} {
		t.Run(strconv.Itoa(blocks)+" blocks", func(t *testing.T) {
			m, raw := seal(blocks)
			_, err := dec.verifyAndDecrypt(m, raw)
			require.ErrorIs(t, err, ua.StatusBadSecurityChecksFailed)
		})
	}
}

// The largest OpenSecureChannelRequest a client legitimately sends, for every
// policy and the key sizes it allows, must stay well inside the limit.
func TestLargestLegitimateOPNFitsLimit(t *testing.T) {
	keys := map[int]*rsa.PrivateKey{}
	for _, bits := range []int{1024, 2048, 4096} {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		require.NoError(t, err)
		keys[bits] = k
	}
	keySizes := map[string][]int{
		ua.SecurityPolicyURIBasic128Rsa15:       {1024, 2048},
		ua.SecurityPolicyURIBasic256:            {1024, 2048},
		ua.SecurityPolicyURIBasic256Sha256:      {2048, 4096},
		ua.SecurityPolicyURIAes128Sha256RsaOaep: {2048, 4096},
		ua.SecurityPolicyURIAes256Sha256RsaPss:  {2048, 4096},
	}

	for _, uri := range symmetricPolicyURIs {
		for _, serverBits := range keySizes[uri] {
			for _, clientBits := range keySizes[uri] {
				t.Run(testName(uri, serverBits)+"/"+strconv.Itoa(clientBits), func(t *testing.T) {
					server, client := keys[serverBits], keys[clientBits]
					clientAlgo, err := uapolicy.Asymmetric(uri, client, &server.PublicKey)
					require.NoError(t, err)
					serverAlgo, err := uapolicy.Asymmetric(uri, server, &client.PublicKey)
					require.NoError(t, err)

					req := &ua.OpenSecureChannelRequest{
						RequestHeader: &ua.RequestHeader{
							AuthenticationToken: ua.NewTwoByteNodeID(0),
							Timestamp:           time.Now(),
							RequestHandle:       1,
							TimeoutHint:         10000,
							AdditionalHeader:    ua.NewExtensionObject(nil),
						},
						RequestType:       ua.SecurityTokenRequestTypeIssue,
						SecurityMode:      ua.MessageSecurityModeSignAndEncrypt,
						ClientNonce:       bytes.Repeat([]byte{0x5a}, clientAlgo.NonceLength()),
						RequestedLifetime: 3600000,
					}
					reqBytes, err := ua.Encode(req)
					require.NoError(t, err)
					body := make([]byte, 8) // sequence header
					body = append(body, 0x01, 0x00, 0xbe, 0x01)
					body = append(body, reqBytes...)

					m, raw := sealOPN(t, clientAlgo, uri, body)
					ct := len(raw) - 12 - m.AsymmetricSecurityHeader.Len()
					require.LessOrEqual(t, ct, maxOpenCiphertext/2, "limit leaves no headroom")

					dec := &channelInstance{
						sc:   &SecureChannel{cfg: &Config{SecurityMode: ua.MessageSecurityModeNone, SecurityPolicyURI: uri}},
						algo: serverAlgo,
					}
					got, err := dec.verifyAndDecrypt(m, raw)
					require.NoError(t, err)
					require.Equal(t, body, got)
				})
			}
		}
	}
}
