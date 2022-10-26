package p256

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"regexp"
	"testing"

	"github.com/go-webdl/crypto/pkcs7"
	"github.com/go-webdl/crypto/sha256"
)

func h2b(h string) []byte {
	b, _ := hex.DecodeString(regexp.MustCompile(`[^a-fA-F0-9]+`).ReplaceAllString(h, ""))
	return b
}

func testPointMapping(t *testing.T, p, P []byte) {
	x, y := BytesToPoint(p)
	if x == nil || y == nil {
		t.Errorf("P256PointMapping returned nil")
		return
	}
	if !bytes.Equal(x.Bytes(), P[0:32]) {
		t.Errorf("Expecting mapped X point to be\n%s\nbut got\n%s", hex.Dump(P[0:32]), hex.Dump(x.Bytes()))
	}
	if !bytes.Equal(y.Bytes(), P[32:64]) {
		t.Errorf("Expecting mapped Y point to be\n%s\nbut got\n%s", hex.Dump(P[32:64]), hex.Dump(y.Bytes()))
	}
}

func TestP256PointMapping(t *testing.T) {
	testPointMapping(t,
		h2b("04dd440d 0bebaca7 7636a928 26c395ac 27e7afe2 078c72f7 3ccac568 68b1b92d"),
		h2b("(04dd440d 0bebaca7 7636a928 26c395ac 27e7afe2 078c72f7 3ccac568 68b1b92d, 4ebfab93 ef455b4c 8c033dd6 83ce71c7 e6e63e4f e77cb08a a42f64fd 4d1f1242)"),
	)
	testPointMapping(t,
		h2b("dd8b64f1 5d0fd86e 754bb55e a225ad6e 3cadbab1 7c1ab8c6 c593330e 6a6ba16d"),
		h2b("(dd8b64f1 5d0fd86e 754bb55e a225ad6e 3cadbab1 7c1ab8c6 c593330e 6a6ba16d, 5d0caf70 b8aa63d2 da79c32a ee46fcc7 40c46c21 2a3f5bfa c3ad70d8 625596e2)"),
	)
	testPointMapping(t,
		h2b("804616f3 d0a4ea15 455e95d9 6a02d07d f30e21d3 6ccef3ec a82f0fbb 56056a60"),
		h2b("(804616f3 d0a4ea15 455e95d9 6a02d07d f30e21d3 6ccef3ec a82f0fbb 56056a60, d755f078 417e5cbc 8d8be077 b15d8d12 0eeebfd6 2b75a74f 5c62a344 a74fe8c8)"),
	)
	testPointMapping(t,
		h2b("abfb68d8 f93b74fa 83bc1dc4 bcbf815f 7f910175 6060d8c9 f929af4a 37aa6eb2"),
		h2b("(abfb68d8 f93b74fa 83bc1dc4 bcbf815f 7f910175 6060d8c9 f929af4a 37aa6eb2, 69dc5e6e 61be4bcb 6205a68a 7344ba84 6b5c3879 b59821ae 7febeb84 8d4e104d)"),
	)
}

func testEncrypt(t *testing.T, pubkey *Key, p, r, C, D []byte) {
	ciphertext := pubkey.Encrypt(p, bytes.NewReader(r))
	if ciphertext == nil {
		t.Errorf("Encrypt returned nil")
		return
	}

	if !bytes.Equal(ciphertext[0:32], C[0:32]) {
		t.Errorf("Expecting C x point to be\n%s\nbut got\n%s", hex.Dump(C[0:32]), hex.Dump(ciphertext[0:32]))
	}
	if !bytes.Equal(ciphertext[32:64], C[32:64]) {
		t.Errorf("Expecting C y point to be\n%s\nbut got\n%s", hex.Dump(C[32:64]), hex.Dump(ciphertext[32:64]))
	}

	if !bytes.Equal(ciphertext[64:96], D[0:32]) {
		t.Errorf("Expecting D x point to be\n%s\nbut got\n%s", hex.Dump(D[0:32]), hex.Dump(ciphertext[64:96]))
	}
	if !bytes.Equal(ciphertext[96:128], D[32:64]) {
		t.Errorf("Expecting D y point to be\n%s\nbut got\n%s", hex.Dump(D[32:64]), hex.Dump(ciphertext[96:128]))
	}
}

func testDecrypt(t *testing.T, priv *Key, p, r, C, D []byte) {
	ciphertext := make([]byte, 128)
	copy(ciphertext[0:64], C)
	copy(ciphertext[64:128], D)

	plaintext := priv.Decrypt(ciphertext)
	if plaintext == nil {
		t.Errorf("Decrypt returned nil")
		return
	}

	if !bytes.Equal(plaintext, p) {
		t.Errorf("Expecting plaintext to be\n%s\nbut got\n%s", hex.Dump(p), hex.Dump(plaintext))
	}
}

func testEncryptDecrypt(t *testing.T, k, K, p, r, C, D []byte) {
	priv := PrivKey(k)
	if !bytes.Equal(priv.X.Bytes(), K[0:32]) {
		t.Errorf("Expecting public key X point to be\n%s\nbut got\n%s", hex.Dump(K[0:32]), hex.Dump(priv.X.Bytes()))
	}
	if !bytes.Equal(priv.Y.Bytes(), K[32:64]) {
		t.Errorf("Expecting public key Y point to be\n%s\nbut got\n%s", hex.Dump(K[32:64]), hex.Dump(priv.Y.Bytes()))
	}
	testEncrypt(t, priv, p, r, C, D)
	testDecrypt(t, priv, p, r, C, D)
}

func TestP256EncryptDecrypt(t *testing.T) {
	testEncryptDecrypt(t,
		h2b("b4ab9d45 023700de c9b44209 7618bcc7 0cdfa62e a31baa1b cc77fb02 5db373d2"),
		h2b("(d93f6fd0 0c27151e 41630577 80dc2622 48a7429c 0122ed84 e855a49b 90ee31a3), (4bcfa196 2b4da384 175f2720 99b3204c a73970d2 d6cbbac7 028bb8f8 f89fa3bf)"),
		h2b("90d7656c 8231d6cd 1d2d637d e39159cf be53cc68 75badc61 2ec1da03 00a21f04"),
		h2b("8037a3f5 8adeae0f 9a3ebaaa 9d981ce9 caad01f2 abb4da5b ff1aa2f4 37fcc617"),
		h2b("(66d5a176 5ce4220c 083312de fb35e9ee b4a171d2 992e897a 44d3c181 8c0cda12, 30a723ef cbb4bbc7 54b64f14 37bea271 59bec0ad 6de5c48b bd9609b0 00b52a2a)"),
		h2b("(e3390ee1 325f8471 77ef6dfc a47c5fa9 aac472e4 15e9ed96 0be569ae a795f863, 4a783679 86a75ca7 0c5c3072 830c3fb7 5956e5bc d911bed7 d462793d c058593a)"),
	)
	testEncryptDecrypt(t,
		h2b("6a25343d 675b1dfb f02916d4 e4d94197 fbf2aa1e e75fcfd0 62886ac8 a9d3b7c9"),
		h2b("(4de73242 88911962 41a98669 2063f32c 6f79a53d e44d9c54 f0f43407 ba5b0311), (80a2f014 a0be6ee8 6732004b 44fd3c78 c435b8fd a568a515 16f7d86f 04f40927)"),
		h2b("eb358189 39c09775 ba37cc00 09c99128 409d1fed 5b3b97d5 6613c3fc 30f9dc43"),
		h2b("07fa9681 4cd92dca d9d8a89c 71d815db 5e6d8642 947d21e3 789fb225 02b4c3d4"),
		h2b("(24ea593c 660b5552 47214795 06c842a5 0aa01051 a4999e23 2d579421 ed8dbb2b, 2d130930 e0492e8a e2b5f949 a55198e7 61be7270 e0ab6ff3 d6180e6b c04c333e)"),
		h2b("(d5b61e8b 32ddc642 ce275337 c72a3c05 8c17f1ee d3bd0f6c 05b767df 76504da7, f8ad6bca ea82d729 ba21c424 1d8dd74e d9d4e899 31431758 e5a75c47 43d7aea6)"),
	)
	testEncryptDecrypt(t,
		h2b("e94718ea 32ea3f8a f038a678 76360481 b4c8ce92 1ea27a8b 906fc439 2bee1fb4"),
		h2b("(d390077e fb0b042c 64918f54 04340ef6 2bc98d07 150a3d39 174bbd6c 13cd2c5a), (7de2431c 36e9436b f5e80f1a 1336526c 0ff0bbc5 b7b9eed1 fd8281f8 1ee5a034)"),
		h2b("592d7259 12f27563 66f9af8e a99eb0e6 2a3b3038 cdee7b20 9524da8e cf0aad6e"),
		h2b("865eb122 f1000206 aaa96c8c 5d4b3789 19668a3b 41d9cbc5 a4a610f8 42c99cb7"),
		h2b("(70da7363 8b6e53d4 65b51790 1bd479f7 1b16c136 6368a245 8f376709 cc5eb261, 152edc41 7805c877 1d2e99f2 0e979e24 b0baba1e c7c361f1 6af75ab3 94e263d1)"),
		h2b("(4ebd5e7e 889d4842 986bbd56 3cb013cf 002a28d6 d231a6f2 326c17d7 a94bc5f0, a5863d40 35384e37 364232f6 a62c3d5d 6f030686 dce84471 8fbecbd1 045efade)"),
	)
	testEncryptDecrypt(t,
		h2b("c9547638 1a66a83a 00bc2481 bef66075 859cfa3e e8048e28 3a9f8793 f3fe06b8"),
		h2b("(28ea9cde 91ac2711 31e738f6 62544eac c688c435 d2d2eea1 e4ee918a e65dcfea), (451d8f0c 8f8b8440 22347212 593bb6a1 38d7863c 0a37aec0 7a5dbfe6 e0a78a14)"),
		h2b("5a6ca3fb ca5e0995 a1746360 91456245 66eeca51 644bcc70 bd7ddd3a b7fc6b3a"),
		h2b("28096a59 c7040528 fb5e8a83 254035f7 e5bb1686 ee42d40a afa6c42b f511356f"),
		h2b("(554bc2af f9a0ee3d 85cab03b 647bbc58 700880b1 abd896e1 c99d3417 275a4387, c80e0d43 0b1abd25 44419bf0 68fc3e33 d17ae9eb 19a537e2 c84e5022 18a5063c)"),
		h2b("(73da2a0d 77a80a06 c017a27d c6dc0ff0 6abbdcd5 4e8b7787 43f26c1c fd411fde, 2c3e0c50 f6196aa0 2f1e3ecd 3050d50a c5e42d48 cc032029 99654dc2 37e36ab4)"),
	)
}

func testSign(t *testing.T, priv *Key, m, r, s []byte) {
	sig := priv.Sign(m, bytes.NewReader(r))
	if !bytes.Equal(sig, s) {
		t.Errorf("Expecting signature to be\n%s\nbut got\n%s", hex.Dump(s), hex.Dump(sig))
	}
}

func testVerify(t *testing.T, pub *Key, m, r, s []byte) {
	if !pub.Verify(m, s) {
		t.Errorf("Verify failed")
	}
}

func testSignVerify(t *testing.T, k, h, r, s []byte) {
	priv := PrivKey(k)
	m := sha256.SHA256(h)
	testSign(t, priv, m, r, s)
	testVerify(t, priv, m, r, s)
}

func TestSign(t *testing.T) {
	testSignVerify(t,
		h2b("b4ab9d45 023700de c9b44209 7618bcc7 0cdfa62e a31baa1b cc77fb02 5db373d2"),
		h2b("00010203 04050607 0809"),
		h2b("a6e99298 cc50eebe 8ada44a2 7c74e58d 6cb8b5a4 5c28f58e 84c6b4b3 554ea7b7"),
		h2b("(7f97e0c7 e44011fe e337e35f f1e1e7ac 87d8f7f9 ffa61234 87931822 c0674ac3, 8fc3525c cf67772f 45785dde 1d8cfe9d 240f9a26 05a1acee 6e1209ca 4ffa494b)"),
	)
	testSignVerify(t,
		h2b("6a25343d 675b1dfb f02916d4 e4d94197 fbf2aa1e e75fcfd0 62886ac8 a9d3b7c9"),
		h2b("11223344 55667788 9900aabb ccddeeff"),
		h2b("b7bfa2ee 3e8fd53a 9b04c661 c695854b 6ac7fcfe bac2327b 97d0378e ba518b06"),
		h2b("(d409ee0e 8ce17b21 3f6665a9 33264fd6 ad959fd0 41c27041 2e744a0f 1500f636, 583e9467 9c92e73e 096efe3a bb5e5f59 21e7c03e 3df7dceb 7560031c a94f7afa)"),
	)
	testSignVerify(t,
		h2b("e94718ea 32ea3f8a f038a678 76360481 b4c8ce92 1ea27a8b 906fc439 2bee1fb4"),
		h2b("0c17222d 3843595a 010c1722 2d384359 5a010c17 222d3843 595a010c 17222d38 43595a01 0c17222d 3843595a 010c1722 2d384359 5a010c17 222d3843 595a010c 17222d38 43595a01 0c17222d 3843595a 01"),
		h2b("cf4df1c9 c9a70556 600d9bb4 dab3a534 a742458f 91b5939f 1f454e37 91df7bc3"),
		h2b("(aed7327d a5091ada 9068aef7 bd14a81a c0b0c7cb 1bf4d0aa d635d357 9058f035, 8ef13135 eda10cbd 49f58c47 70f69f00 08569fae 81328647 c73b318e f587efd3)"),
	)
	testSignVerify(t,
		h2b("c9547638 1a66a83a 00bc2481 bef66075 859cfa3e e8048e28 3a9f8793 f3fe06b8"),
		h2b("00"),
		h2b("b248db58 612f0208 ca6737f3 9a25f5d7 408574b9 8b8bc0aa e7c47e9a 2bf3d2d7"),
		h2b("(f72fb757 10f95087 d7a9f349 5cf14f59 9bd66343 7849fb50 e1040a4e 64bf566d, 510629e2 a83c766d 924c09e4 fa2865e8 7ba30f58 e8995943 81278457 30e19e0e)"),
	)
	testVerify(t,
		PubKey(h2b("5f 18 ad 61 2b 64 ed 9e 8f a1 aa f4 18 26 2f 79 66 9e 0a 9d c4 f5 41 cb f7 36 74 e8 bf 99 c5 01 6b c8 15 d1 87 08 01 11 8f 35 ed 9e 26 b0 41 e4 83 3d c6 f9 f8 9c 15 56 0a 43 63 50 65 d2 84 3e")),
		sha256.SHA256(h2b(
			"3c 53 69 67 6e 65 64 49 6e 66 6f 20 78 6d 6c 6e 73 3d 22 68 74 74 70 3a 2f 2f 77 77 77 2e 77 33 2e 6f 72 67 2f 32 30 30 30 2f 30 39 2f 78 6d 6c 64 73 69 67 23 22 3e 3c 43 61 6e 6f 6e 69 63 61 6c 69 7a 61 74 69 6f 6e 4d 65 74 68 6f 64 20 41 6c 67 6f 72 69 74 68 6d 3d 22 68 74 74 70 3a 2f 2f 77 77 77 2e 77 33 2e 6f 72 67 2f 54 52 2f 32 30 30 31 2f 52 45 43 2d 78 6d 6c 2d 63 31 34 6e 2d 32 30 30 31 30 33 31 35 22 3e 3c 2f 43 61 6e 6f 6e 69 63 61 6c 69 7a 61 74 69 6f 6e 4d 65 74 68 6f 64 3e 3c 53 69 67 6e 61 74 75 72 65 4d 65 74 68 6f 64 20 41 6c 67 6f 72 69 74 68 6d 3d 22 68 74 74 70 3a 2f 2f 73 63 68 65 6d 61 73 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 2f 44 52 4d 2f 32 30 30 37 2f 30 33 2f 70 72 6f 74 6f 63 6f 6c 73 23 65 63 64 73 61 2d 73 68 61 32 35 36 22 3e 3c 2f 53 69 67 6e 61 74 75 72 65 4d 65 74 68 6f 64 3e 3c 52 65 66 65 72 65 6e 63 65 20 55 52 49 3d 22 23 53 69 67 6e 65 64 44 61 74 61 22 3e 3c 44 69 67 65 73 74 4d 65 74 68 6f 64 20 41 6c 67 6f 72 69 74 68 6d 3d 22 68 74 74 70 3a 2f 2f 73 63 68 65 6d 61 73 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 2f 44 52 4d 2f 32 30 30 37 2f 30 33 2f 70 72 6f 74 6f 63 6f 6c 73 23 73 68 61 32 35 36 22 3e 3c 2f 44 69 67 65 73 74 4d 65 74 68 6f 64 3e 3c 44 69 67 65 73 74 56 61 6c 75 65 3e 74 73 67 68 51 74 30 76 6c 73 67 43 43 72 52 51 64 79 38 76 6c 52 6a 49 72 6e 73 68 36 2b 72 69 39 70 78 4c 37 67 37 46 70 4f 73 3d 3c 2f 44 69 67 65 73 74 56 61 6c 75 65 3e 3c 2f 52 65 66 65 72 65 6e 63 65 3e 3c 2f 53 69 67 6e 65 64 49 6e 66 6f 3e")),
		nil,
		h2b("55 40 a5 b2 56 07 7f 24 38 76 8b 01 bb 45 1b cd 7f bd 4a 59 ee 13 ca 7c 84 16 60 76 2c 26 35 d7 5a e8 e8 f0 ef 8e 77 2d 58 d8 88 57 9f c0 40 f8 a2 c6 18 8b 59 99 a6 c9 5c bf 6e b9 c8 81 aa ee"),
	)
}

func TestFixedKey(t *testing.T) {
	r := rand.New(rand.NewSource(0))

	rootKey := New(r)
	fmt.Printf("MITM Root Encrypting Key:\n%s\n", hex.Dump(rootKey.Bytes()))

	encryptedKeydata, err := base64.StdEncoding.DecodeString(
		`CDpVn9MQRyi7JmYHvlzTUdITagUfJuJTK0seBSjF1usMaf7h7jndfl84BDvsUZqFgvUH1MVlBiby+dTjzdPnLqGflZuiPHgdSbvR9p3S+NRDBy/JIYOWecCma6y1m5vsJWd059/KFkYNc9KdSkpxB/aYX+znhNJHM6THsVOVvDo=`,
	)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("Encrypted Key Data:\n%s\n", hex.Dump(encryptedKeydata))

	keydata := rootKey.Decrypt(encryptedKeydata)
	fmt.Printf("Decrypted Key Data:\n%s\n", hex.Dump(keydata))

	encryptedDeviceCert, err := base64.StdEncoding.DecodeString(
		`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`,
	)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("Encrypted Device Cert:\n%s\n", hex.Dump(encryptedDeviceCert))

	block, err := aes.NewCipher(keydata[0x10:0x20])
	if err != nil {
		t.Error(err)
		return
	}

	cbc := cipher.NewCBCDecrypter(block, encryptedDeviceCert[:0x10])
	cbc.CryptBlocks(encryptedDeviceCert[0x10:], encryptedDeviceCert[0x10:])

	encodedDeviceCert, err := pkcs7.Unpad(encryptedDeviceCert[0x10:], 0x10)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("Decrypted Device Cert:\n%s\n", hex.Dump(encodedDeviceCert))
}
