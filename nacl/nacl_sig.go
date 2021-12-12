package nacl

import "crypto/ed25519"

const SignatureOverhead = 64

func (priv *Key) Sign(out, message []byte) (sig []byte) {
	return append(out, ed25519.Sign(ed25519.PrivateKey(priv.Bytes()), message)...)
}

func (pub *Key) Verify(message, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey((*pub.PubKey)[:]), message, sig)
}
