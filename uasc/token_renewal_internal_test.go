package uasc

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uapolicy"
	"github.com/stretchr/testify/require"
)

func TestRenewalKeepsOutgoingTokenUntilVerifiedPeerSwitch(t *testing.T) {
	old := symmetricInstance(t, ua.SecurityPolicyURIBasic256Sha256)
	nonce := bytes.Repeat([]byte{0x6b}, 32)
	newAlgo, err := uapolicy.Symmetric(ua.SecurityPolicyURIBasic256Sha256, nonce, nonce)
	require.NoError(t, err)
	current := &channelInstance{
		sc:   &SecureChannel{kind: server, cfg: &Config{SecurityMode: ua.MessageSecurityModeSignAndEncrypt}},
		algo: newAlgo, securityTokenID: 2, prevAlgo: old.algo, prevTokenID: 1,
		prevExpires:  time.Now().Add(time.Minute),
		previousSend: &serverSendToken{id: 1, algo: old.algo, expires: time.Now().Add(time.Minute)},
	}
	current.waitingForPeer.Store(true)
	m := current.newMessage(&ua.ReadResponse{}, id.ReadResponse_Encoding_DefaultBinary, 1)
	require.Equal(t, uint32(1), m.SymmetricSecurityHeader.TokenID, "server switched before the peer")

	// A response whose header already chose the old token must keep its keys
	// even if a concurrent receive observes the peer's switch before encoding.
	plain, response := symmetricChunk([]byte("response"))
	current.waitingForPeer.Store(false)
	encrypted, err := current.signAndEncrypt(response, plain)
	require.NoError(t, err)
	chunk := new(MessageChunk)
	_, err = chunk.Decode(encrypted)
	require.NoError(t, err)
	_, err = old.verifyAndDecrypt(chunk, encrypted)
	require.NoError(t, err, "header and signing keys disagreed")
	current.waitingForPeer.Store(true)

	// Naming the new token is insufficient: its signature must verify.
	plain, request := symmetricChunk([]byte("new-token request"))
	request.SymmetricSecurityHeader.TokenID = 2
	binary.LittleEndian.PutUint32(plain[12:16], 2)
	sender := symmetricInstance(t, ua.SecurityPolicyURIBasic256Sha256)
	sender.algo = newAlgo
	encrypted, err = sender.signAndEncrypt(request, plain)
	require.NoError(t, err)
	bad := append([]byte(nil), encrypted...)
	bad[len(bad)-1] ^= 0x80
	_, err = chunk.Decode(bad)
	require.NoError(t, err)
	_, err = current.verifyAndDecrypt(chunk, bad)
	require.Error(t, err)
	require.True(t, current.waitingForPeer.Load(), "invalid packet switched outgoing keys")
	_, err = chunk.Decode(encrypted)
	require.NoError(t, err)
	_, err = current.verifyAndDecrypt(chunk, encrypted)
	require.NoError(t, err)
	require.False(t, current.waitingForPeer.Load())
	require.Equal(t, uint32(2), current.outgoingTokenID())

	current.waitingForPeer.Store(true)
	current.previousSend.expires = time.Now().Add(-time.Second)
	require.Equal(t, uint32(2), current.outgoingTokenID(), "expired outgoing token was retained")
}
