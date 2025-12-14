package cryptutil_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/KarpelesLab/cryptutil"
)

// Pre-generated test data for regression testing
var (
	// Bottles
	aliceSignedCleartext   = mustDecode("haBRSGVsbG8gZnJvbSBBbGljZSEA9oGDAFhbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE09oIghTDnluvtv0+NKMhTS2nfC3TzR4DWnZK7czzFPZSH6bJN5oMZCp5X7pfI4BbIyTVtGeRKg6GTpzzfE+KYFhHMEUCIQCPEWPr/SDCeJXS73kn0oQwXWH70EfgSPtlhyLhvRHHYQIgbvITapFSnsuY2dAQorY+mTLOsMYOJB95nucHxIOzUME=")
	chloeSignedCleartext   = mustDecode("haBRSGVsbG8gZnJvbSBDaGxvZSEA9oGDAFgsMCowBQYDK2VwAyEATL6PjuPHSTIG2UXmJfEMvJESSp7zLqTncBBc4ElE/D5YQPMG5xy/onBTIEHWfvlayb3lCTfGSClApscby4WP919SOs7c5iq7xsLrYkcGpwGCFKObAbT1C0+omag8EiDWNwY=")
	aliceToBobEncrypted    = mustDecode("haBZAUSFoFhDm5+MnDHvHavDG26WIRahkvXRyopa5BCzFgv25By0k3ase9e/d7hvr+Eq7wKobH/11VQkZmc6gel8TtIAuutYZ7ZmqgKBgwBYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIoEQn7veaBj/RTUi1qMYYQgxJoMWBvLTMJRSLcwLlelv38NDoNgTRt8nNKjm/nBCY0ClkSPYv5tRVHPe2o2k65YmQBbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEu2rfO4Mdj5HJ+ahL7WVbBZXrSzD2FoOOAjqFQ7PDTSfIucQV0gWOjLjPLg7SQ5yiO3pv1RKzJLotq6UyKA3B6iMtBkT4Sn0fVU2Nw0fw0bBjZFj1MPCFnXGqK9Qd3/EyzTA5XzksY+EZaBkOej1ckTc1fpXTEn8HZuPa/PYB9oGDAFhbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE09oIghTDnluvtv0+NKMhTS2nfC3TzR4DWnZK7czzFPZSH6bJN5oMZCp5X7pfI4BbIyTVtGeRKg6GTpzzfE+KYFhHMEUCIGgCMEL82ywkMC0PuAf4HUqS1wmnzXTtzUHSBy5Aok4ZAiEAn7pHkUVyWhCfb/aiGvwm0PW347iaKDOmywOwrZG1YNk=")
	chloeToDanielEncrypted = mustDecode("haBY6YWgWEbOz5dzuHVoDJGbbegel6QHqyxa7U7NuVznwNxeCQvqTgz8gEPb38MMsTxq5IR+Qu9cfgZ2a2/2DQg+0oJJPRl7ZUYrekXAAoGDAFgsMCowBQYDK2VwAyEA9lV/yry+XMvMGqwhUQXef+3FOjAGD4Mj/gxoJN3X+79YagAsMCowBQYDK2VuAyEAA943R8RqHeZffQ+TH4RlmrtXvklkBdKgddPyttXfvCxrZFHDb9X2oVfQRCbb4fIjc0VqVZT5HvVKf9bz+ymcWbkv+iWCc/Q+B8oLHebH9sE+0zytOy/e1Kamcir2AfaBgwBYLDAqMAUGAytlcAMhAEy+j47jx0kyBtlF5iXxDLyREkqe8y6k53AQXOBJRPw+WECeTEDNYixOSd2tj7BchCLVoLCkmr84L9CwxLo10mYgQoW5wZFOUEME0VdL3kaJfeHuX2/UiRWMk3rssnp6lJgO")
	aliceToBobAndDaniel    = mustDecode("haBZAdmFoFg8uyjLChvFnHR+sq8bfbuziw/PeYrFriKzQSqZzQV3RWwGMsB1pz6hE9FnMqoIamLD2oM1HsHy1+GU8RERAoKDAFhbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEigRCfu95oGP9FNSLWoxhhCDEmgxYG8tMwlFItzAuV6W/fw0Og2BNG3yc0qOb+cEJjQKWRI9i/m1FUc97ajaTrliZAFswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARF6feIhWN/vC1edEjEccG0ajlShDmBYyIrat0c+fz+yy43aIzQJKC5QQRpf8fG57Y5wZb3KhQIg63NOkYe3tIB1bsrUSWZUw/6uHoWAM1GT+oasplV4WxkRWzetoxH6vWtuRQgMzDTv9qjfSchaHpQgjMaPTknIqHNC8uRgwBYLDAqMAUGAytlcAMhAPZVf8q8vlzLzBqsIVEF3n/txTowBg+DI/4MaCTd1/u/WGoALDAqMAUGAytlbgMhAFuGnMFD6MCASWo8xOy9HSITAxPzu2UJuXSUCzRyZqYmy1uE1/Y7w1a3kOhitndcYPSMGnE7AKJmnjiAyf8vPnvv5ijUQlrm1Zcy+QavS33BopdG1HXKYxn6pF1r9gH2gYMAWFswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATT2giCFMOeW6+2/T40oyFNLad8LdPNHgNadkrtzPMU9lIfpsk3mgxkKnlful8jgFsjJNW0Z5EqDoZOnPN8T4pgWEcwRQIge6OK+2IEUVmPo7ZSovRJ5IJb9dZTT2ZcGgp4A2erM80CIQC3HMt9VGk0+tpEyripSdfobx1TcRByY3CI6Gbr2sZjiA==")
	anonymousToBob         = mustDecode("haBYOYK78ifrqu7W6Uh3vF7PnqUr8CNJ5cezriuZb+EzFZ/NdacKr6s37y5jRbnOw5seoUtp54ClCJjzWgKBgwBYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIoEQn7veaBj/RTUi1qMYYQgxJoMWBvLTMJRSLcwLlelv38NDoNgTRt8nNKjm/nBCY0ClkSPYv5tRVHPe2o2k65YmQBbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4gO8JMnJc1wZLg7Ne1Ze3I4yKe7J7yRVnJTYe0PEkO8/61OFivv5YcdNZjNSoRvZx0O0KJEP7u1CtHDQPYcXbaGBQU/XVmP1NY0yepic+jWelsZNO8HScpaNY4HNtghcanOY0GDoZkokU5lvJzUARx1pmoowtqgSFkm6b/Y=")
	aliceAndChloeSigned    = mustDecode("haBYHlNpZ25lZCBieSBib3RoIEFsaWNlIGFuZCBDaGxvZQD2goMAWFswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATT2giCFMOeW6+2/T40oyFNLad8LdPNHgNadkrtzPMU9lIfpsk3mgxkKnlful8jgFsjJNW0Z5EqDoZOnPN8T4pgWEYwRAIgKfCLaGT93SX/tGQvesD5y+XCNVLlcO9k2NJqVpA/IrYCIEnrnZ+9YdAGCjBvGt8IkPEJmrKpbDOlDx4zRr7WkYmngwBYLDAqMAUGAytlcAMhAEy+j47jx0kyBtlF5iXxDLyREkqe8y6k53AQXOBJRPw+WEBSiwkh3t4Q+Nrq/bRc6HNSjpJUo8GS22KgaJlUxAPnB8BfnOrp/zs07hJRgvtOrIy96BSRzDZSdDlNCpJ21zoE")
	nestedBobThenDaniel    = mustDecode("haBZAfyFoFkBWCYLkGEdT1Q7jJSGLAzAIZmXKmTQF9XDNNm9IGRxFJQaXYkhdyO4z67pw8Nrb6OZwRUNCvC12qYkW9iZdypuw8seyMwA7SAtXRsJTDpXF3WSauqwr7ayvurrzxSThFoQfWhJ71Eb2WrzwDmROYvl4Wm2ooAKzxYuutKjKuzVF5VeF0m3scOSjHlP7KSF3vo3GyAMLhVHBYeLx7MvrVxY98BxB09oED4GhlIKzq8BIcdHYmkn8ckhH8APwx/oHaBKI/m7ppBTUdqW9qIPAn/CJb7r6pZlvVx/oepDoH5291BJCj/YHTm/V+VCA9iGnw+3Oac+M4krD5/tiPph3yDsgGVg2SzF8S2FrhHd4b1tfqBMzecKcAhgFFHaZcP7hyVSVPry/QnkcSI85fKdgpQnyfoGGb1a9usdOMyQAW0G8ywIiI/IpU1Pm7rGQaQ3wlh25FYiC6ZfglvpAoGDAFgsMCowBQYDK2VwAyEA9lV/yry+XMvMGqwhUQXef+3FOjAGD4Mj/gxoJN3X+79YagAsMCowBQYDK2VuAyEAK7KqTeAgS1FkPMGF2jgEny1TmvsxRx3H70OLhhKy73oeSpRThl/5KQGRuuYDWDW4kyFrXjqJd7F0gzgSzOYD2QBIkKESzYHSPDr9xdGTnO43jC0tan2NKaFuCY32AfaBgwBYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNPaCIIUw55br7b9PjSjIU0tp3wt080eA1p2Su3M8xT2Uh+myTeaDGQqeV+6XyOAWyMk1bRnkSoOhk6c83xPimBYRjBEAiAT7cGQNP43M/T+L3Ve1LBpMF2cb4WySB1g3qHXotcOdwIgDbXdEgVyXMM/j5rfIL+cIvck2SYfTdnA4zpYYctUNxA=")

	// IDCards
	aliceIDCard  = mustDecode("haBY/YWhYmN0ZmlkY2FyZFjspgFYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNPaCIIUw55br7b9PjSjIU0tp3wt080eA1p2Su3M8xT2Uh+myTeaDGQqeV+6XyOAWyMk1bRnkSoOhk6c83xPimACGmk+hQMDgaMBWFswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATT2giCFMOeW6+2/T40oyFNLad8LdPNHgNadkrtzPMU9lIfpsk3mgxkKnlful8jgFsjJNW0Z5EqDoZOnPN8T4pgAhppPoUDBIJnZGVjcnlwdGRzaWduBPYF9gahZG5hbWVlQWxpY2UA9vYB9oGDAFhbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE09oIghTDnluvtv0+NKMhTS2nfC3TzR4DWnZK7czzFPZSH6bJN5oMZCp5X7pfI4BbIyTVtGeRKg6GTpzzfE+KYFhHMEUCIAM0VfD5ON6ajKxrR2sMcqlU+karsg4ha+HRWVJsPjWvAiEAlAx6nGF3vHDvV2wlzQ2qgwDuOXQ1dulxuZI+2UEL26Q=")
	bobIDCard    = mustDecode("haBY+4WhYmN0ZmlkY2FyZFjqpgFYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIoEQn7veaBj/RTUi1qMYYQgxJoMWBvLTMJRSLcwLlelv38NDoNgTRt8nNKjm/nBCY0ClkSPYv5tRVHPe2o2k64CGmk+hQMDgaMBWFswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASKBEJ+73mgY/0U1ItajGGEIMSaDFgby0zCUUi3MC5Xpb9/DQ6DYE0bfJzSo5v5wQmNApZEj2L+bUVRz3tqNpOuAhppPoUDBIJnZGVjcnlwdGRzaWduBPYF9gahZG5hbWVjQm9iAPb2AfaBgwBYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIoEQn7veaBj/RTUi1qMYYQgxJoMWBvLTMJRSLcwLlelv38NDoNgTRt8nNKjm/nBCY0ClkSPYv5tRVHPe2o2k65YRzBFAiEAufvr4HAcHDhwD7zrCXHfzqGbNCJKf2HzSVPMXEARoRYCIEZnD7EobO3zNmDSJLXf6mMi4WWqr9qLEwl3poV/x9wv")
	chloeIDCard  = mustDecode("haBYn4WhYmN0ZmlkY2FyZFiOpgFYLDAqMAUGAytlcAMhAEy+j47jx0kyBtlF5iXxDLyREkqe8y6k53AQXOBJRPw+AhppPoUDA4GjAVgsMCowBQYDK2VwAyEATL6PjuPHSTIG2UXmJfEMvJESSp7zLqTncBBc4ElE/D4CGmk+hQMEgmdkZWNyeXB0ZHNpZ24E9gX2BqFkbmFtZWVDaGxvZQD29gH2gYMAWCwwKjAFBgMrZXADIQBMvo+O48dJMgbZReYl8Qy8kRJKnvMupOdwEFzgSUT8PlhAzjf6zY5rD2kD0/12qFbscTK6Ib6OsssCoZaIyNpDOKFGLMTiMGHS3k+Ha9bHGcBo/DuoSWuDrxj/WThyRx0YBA==")
	danielIDCard = mustDecode("haBYoIWhYmN0ZmlkY2FyZFiPpgFYLDAqMAUGAytlcAMhAPZVf8q8vlzLzBqsIVEF3n/txTowBg+DI/4MaCTd1/u/AhppPoUDA4GjAVgsMCowBQYDK2VwAyEA9lV/yry+XMvMGqwhUQXef+3FOjAGD4Mj/gxoJN3X+78CGmk+hQMEgmdkZWNyeXB0ZHNpZ24E9gX2BqFkbmFtZWZEYW5pZWwA9vYB9oGDAFgsMCowBQYDK2VwAyEA9lV/yry+XMvMGqwhUQXef+3FOjAGD4Mj/gxoJN3X+79YQH4yeA5Oluwr9Av5EjDcMBo11ax2eNKVtDvLK37V4DCMr6rF4y41oRXiud9sr4Lwg0AGeW+OE9S14N5Emzj4GQQ=")
)

func mustDecode(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestPregenAliceSignedCleartext(t *testing.T) {
	opener := cryptutil.MustOpener()
	res, info, err := opener.OpenCbor(aliceSignedCleartext)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}
	if string(res) != "Hello from Alice!" {
		t.Errorf("unexpected message: %s", res)
	}
	if !info.SignedBy(alice.Public()) {
		t.Error("message should be signed by Alice")
	}
	if info.Decryption != 0 {
		t.Errorf("expected 0 decryptions, got %d", info.Decryption)
	}
}

func TestPregenChloeSignedCleartext(t *testing.T) {
	chloeKey := chloe.(ed25519.PrivateKey)
	opener := cryptutil.MustOpener()
	res, info, err := opener.OpenCbor(chloeSignedCleartext)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}
	if string(res) != "Hello from Chloe!" {
		t.Errorf("unexpected message: %s", res)
	}
	if !info.SignedBy(chloeKey.Public()) {
		t.Error("message should be signed by Chloe")
	}
}

func TestPregenAliceToBobEncrypted(t *testing.T) {
	opener := cryptutil.MustOpener(bob)
	res, info, err := opener.OpenCbor(aliceToBobEncrypted)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}
	if string(res) != "Secret message from Alice to Bob" {
		t.Errorf("unexpected message: %s", res)
	}
	if !info.SignedBy(alice.Public()) {
		t.Error("message should be signed by Alice")
	}
	if info.Decryption != 1 {
		t.Errorf("expected 1 decryption, got %d", info.Decryption)
	}

	// Should fail without Bob's key
	openerNoKey := cryptutil.MustOpener()
	_, _, err = openerNoKey.OpenCbor(aliceToBobEncrypted)
	if err == nil {
		t.Error("should fail without Bob's key")
	}
}

func TestPregenChloeToDanielEncrypted(t *testing.T) {
	chloeKey := chloe.(ed25519.PrivateKey)
	danielKey := daniel.(ed25519.PrivateKey)

	opener := cryptutil.MustOpener(danielKey)
	res, info, err := opener.OpenCbor(chloeToDanielEncrypted)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}
	if string(res) != "Secret message from Chloe to Daniel" {
		t.Errorf("unexpected message: %s", res)
	}
	if !info.SignedBy(chloeKey.Public()) {
		t.Error("message should be signed by Chloe")
	}
	if info.Decryption != 1 {
		t.Errorf("expected 1 decryption, got %d", info.Decryption)
	}
}

func TestPregenAliceToBobAndDaniel(t *testing.T) {
	danielKey := daniel.(ed25519.PrivateKey)

	// Open with Bob's key
	openerBob := cryptutil.MustOpener(bob)
	res, info, err := openerBob.OpenCbor(aliceToBobAndDaniel)
	if err != nil {
		t.Fatalf("failed to open with Bob: %v", err)
	}
	if string(res) != "Secret for Bob and Daniel" {
		t.Errorf("unexpected message: %s", res)
	}
	if !info.SignedBy(alice.Public()) {
		t.Error("message should be signed by Alice")
	}

	// Open with Daniel's key
	openerDaniel := cryptutil.MustOpener(danielKey)
	res2, info2, err := openerDaniel.OpenCbor(aliceToBobAndDaniel)
	if err != nil {
		t.Fatalf("failed to open with Daniel: %v", err)
	}
	if string(res2) != "Secret for Bob and Daniel" {
		t.Errorf("unexpected message: %s", res2)
	}
	if !info2.SignedBy(alice.Public()) {
		t.Error("message should be signed by Alice")
	}
}

func TestPregenAnonymousToBob(t *testing.T) {
	opener := cryptutil.MustOpener(bob)
	res, info, err := opener.OpenCbor(anonymousToBob)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}
	if string(res) != "Anonymous secret to Bob" {
		t.Errorf("unexpected message: %s", res)
	}
	if len(info.Signatures) != 0 {
		t.Error("message should not be signed")
	}
	if info.Decryption != 1 {
		t.Errorf("expected 1 decryption, got %d", info.Decryption)
	}
}

func TestPregenAliceAndChloeSigned(t *testing.T) {
	chloeKey := chloe.(ed25519.PrivateKey)

	opener := cryptutil.MustOpener()
	res, info, err := opener.OpenCbor(aliceAndChloeSigned)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}
	if string(res) != "Signed by both Alice and Chloe" {
		t.Errorf("unexpected message: %s", res)
	}
	if !info.SignedBy(alice.Public()) {
		t.Error("message should be signed by Alice")
	}
	if !info.SignedBy(chloeKey.Public()) {
		t.Error("message should be signed by Chloe")
	}
	if len(info.Signatures) != 2 {
		t.Errorf("expected 2 signatures, got %d", len(info.Signatures))
	}
}

func TestPregenNestedBobThenDaniel(t *testing.T) {
	danielKey := daniel.(ed25519.PrivateKey)

	// Need both keys to decrypt nested bottle
	opener := cryptutil.MustOpener(bob, danielKey)
	res, info, err := opener.OpenCbor(nestedBobThenDaniel)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}
	if string(res) != "Doubly encrypted message" {
		t.Errorf("unexpected message: %s", res)
	}
	if !info.SignedBy(alice.Public()) {
		t.Error("message should be signed by Alice")
	}
	if info.Decryption != 2 {
		t.Errorf("expected 2 decryptions, got %d", info.Decryption)
	}

	// Should fail with only Daniel's key (outer layer)
	openerDanielOnly := cryptutil.MustOpener(danielKey)
	_, _, err = openerDanielOnly.OpenCbor(nestedBobThenDaniel)
	if err == nil {
		t.Error("should fail with only Daniel's key")
	}
}

func TestPregenAliceIDCard(t *testing.T) {
	var id cryptutil.IDCard
	err := id.UnmarshalBinary(aliceIDCard)
	if err != nil {
		t.Fatalf("failed to unmarshal Alice's IDCard: %v", err)
	}
	if id.Meta["name"] != "Alice" {
		t.Errorf("expected name Alice, got %s", id.Meta["name"])
	}
	// Check key purposes
	if err := id.TestKeyPurpose(alice.Public(), "sign"); err != nil {
		t.Errorf("Alice's key should have sign purpose: %v", err)
	}
	if err := id.TestKeyPurpose(alice.Public(), "decrypt"); err != nil {
		t.Errorf("Alice's key should have decrypt purpose: %v", err)
	}
}

func TestPregenBobIDCard(t *testing.T) {
	var id cryptutil.IDCard
	err := id.UnmarshalBinary(bobIDCard)
	if err != nil {
		t.Fatalf("failed to unmarshal Bob's IDCard: %v", err)
	}
	if id.Meta["name"] != "Bob" {
		t.Errorf("expected name Bob, got %s", id.Meta["name"])
	}
	if err := id.TestKeyPurpose(bob.Public(), "sign"); err != nil {
		t.Errorf("Bob's key should have sign purpose: %v", err)
	}
	if err := id.TestKeyPurpose(bob.Public(), "decrypt"); err != nil {
		t.Errorf("Bob's key should have decrypt purpose: %v", err)
	}
}

func TestPregenChloeIDCard(t *testing.T) {
	chloeKey := chloe.(ed25519.PrivateKey)

	var id cryptutil.IDCard
	err := id.UnmarshalBinary(chloeIDCard)
	if err != nil {
		t.Fatalf("failed to unmarshal Chloe's IDCard: %v", err)
	}
	if id.Meta["name"] != "Chloe" {
		t.Errorf("expected name Chloe, got %s", id.Meta["name"])
	}
	if err := id.TestKeyPurpose(chloeKey.Public(), "sign"); err != nil {
		t.Errorf("Chloe's key should have sign purpose: %v", err)
	}
	if err := id.TestKeyPurpose(chloeKey.Public(), "decrypt"); err != nil {
		t.Errorf("Chloe's key should have decrypt purpose: %v", err)
	}
}

func TestPregenDanielIDCard(t *testing.T) {
	danielKey := daniel.(ed25519.PrivateKey)

	var id cryptutil.IDCard
	err := id.UnmarshalBinary(danielIDCard)
	if err != nil {
		t.Fatalf("failed to unmarshal Daniel's IDCard: %v", err)
	}
	if id.Meta["name"] != "Daniel" {
		t.Errorf("expected name Daniel, got %s", id.Meta["name"])
	}
	if err := id.TestKeyPurpose(danielKey.Public(), "sign"); err != nil {
		t.Errorf("Daniel's key should have sign purpose: %v", err)
	}
	if err := id.TestKeyPurpose(danielKey.Public(), "decrypt"); err != nil {
		t.Errorf("Daniel's key should have decrypt purpose: %v", err)
	}
}
