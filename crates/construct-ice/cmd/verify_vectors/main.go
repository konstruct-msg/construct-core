// verify_vectors — confirms construct-ice Elligator2/DH test vectors match
// the Go obfs4 reference (gitlab.com/yawning/obfs4.git internal/x25519ell2).
//
// Run from this directory after init: go run .
package main

import (
"encoding/hex"
"fmt"
"os"

"golang.org/x/crypto/curve25519"
)

func h32(s string) [32]byte {
b, err := hex.DecodeString(s)
if err != nil {
panic(err)
}
var out [32]byte
copy(out[:], b)
return out
}

type vec struct{ priv, pub, repr, shared string }

var vecs = []vec{
{"07102132435c6d7e8f98a9bacbe4f50617203142536c7d8e9fa8b9cadbf40516",
"276dca70899bf3dc12a90a25b42c77c8b43419d27361d452e565a2f514af547b",
"1f951cd36fa4a5a5e9e309dd3a229b8d97903399fbce97b52db759a424976110",
"8fc2795f8c9d28ad275429e249481e23b461c2ce3abaf531e2b6ce553d1f8c04"},
{"0b1c2d3e4f5061728394a5b6c7e8f90a1b2c3d4e5f60718293a4b5c6d7f8091a",
"78229a8773105ac4b8ea5266f340b3818fe94b46748a01eef68e4485e771344d",
"73fc82fa7ac2e9a242dce50b1d6d3e2890f8cef2bfe7e24da5c09813d051292d",
"8c04504e4bcd31069fe42de6a5534ae2c03943da369059e9d49a75519d1f3b1f"},
{"091e2f3c4d5263708196a7b4c5eafb08192e3f4c5d62738091a6b7c4d5fa0b18",
"3e9cbc3cda79fd048dcac74d612fc65ef2e817f29e0072bf083a585558f0e605",
"ff7c23872b63fea261799d46000f94026c86c00ecb85240f8eac414a5936df0c",
"76550fcaa817039458d7d2543719fee231e984535a67cc2805772d5d84c2a51a"},
{"081f2e3d4c5362718097a6b5c4ebfa09182f3e4d5c63728190a7b6c5d4fb0a19",
"f222ce310ac58879b3045a7c8b68191d58edd4f16fedf0dbdd2d292cb311e606",
"06c9bacbe8b8ea4ade0fba293c74a8a22024991c6067e0ec5b587215a9fe5738",
"d963ec91a8c38899cda534a68c2f05410700db752d6ffdbd5ec58cc11377975d"},
{"0d1a2b38495667748592a3b0c1eeff0c1d2a3b485966778495a2b3c0d1fe0f1c",
"c5bf86037ae1aff54935d7ea0ac77fe736f783518d06a5bf4910802038506a46",
"43dc4f51899c479700e00b2e65a3df9db31d351b19e0d29fdf50f4bedf74ea33",
"f06af6b9a8d55472179692375592bbd1efeb0b1d21bf1cc2c35c99cc08257249"},
{"0c1b2a39485766758493a2b1c0effe0d1c2b3a495867768594a3b2c1d0ff0e1d",
"d8e19c7c739e7f8a395f3fe4f1f153a849b975f4a1cbe8f7ca7e7363d9faa250",
"5c022575b420d87b35ec05bf5e1d9e64daeffa689a82750e65ccd9ab43d47d38",
"d47942fa0c4851799d795dde08212fdf3734fe49614d99dc37de9e07c9e3a255"},
{"11063724554a7b68998ebfacddf2e31001362754457a6b9889beafdccde21300",
"be892e6b8286027aff4643636964af19718cf2333759a4600cdae989345d494b",
"1f08a902c07758cfa22360a608c0cc612771676da17ff8fbf419ae51caa6872f",
"1fa47669311e59480bf862497cd8b6884b92ace6e96dcbb26bfa9dd7c2289e7a"},
{"17003122534c7d6e9f88b9aadbf4e51607302152437c6d9e8fb8a9dacbe41506",
"7f3afd731adfccdf12735b37e92f6b7611daffad1e9fe1e90dda872b458e3545",
"fa6d3872297e2ce360d6b41edd9fdb6d0434f7f1f4664777194db8b279f5e223",
"6cc4732959987a2c4c43624d396d727adf85897dc3047e722225c2da57358155"},
{"15023320514e7f6c9d8abba8d9f6e71405322350417e6f9c8dbaabd8c9e61704",
"dc09139f05bcb1a6d1ecd99e300a0d0ba9af68c3800f58016f9448bdaabcaa2f",
"ef8f6ee6211a19be9a05126a7672ecd3745e76294f5d97ca63d8ff18a0e9c514",
"9d3552c6fa8749e33654a24f92322f511d4938ffce40fa23cdb32fec13764a30"},
{"1a0d3c2f5e4170639285b4a7d6f9e81b0a3d2c5f4e71609382b5a4d7c6e9180b",
"ebdc7fd75a6f34a55291b70fe171048b84719592b249bbfefeb544d1ee11365d",
"8d3ee385c4e43962a2d61d2960dd9703f71c196aa0bda539d9b9f42155a76f1d",
"dfef3b268518811b1abf822577ecaaa51949fd592c8e391d66da14a5da71dc7a"},
}

const peerHex = "deadbeefcafebabe0123456789abcdeffedcba98765432100011223344556677"

func main() {
peer := h32(peerHex)
failures := 0
fmt.Println("=== Verifying construct-ice test vectors against Go x25519ell2 (tweak=0) ===")
fmt.Println()

for i, v := range vecs {
priv := h32(v.priv)
var pub, repr [32]byte

ok := ScalarBaseMult(&pub, &repr, &priv, 0)
if !ok {
fmt.Printf("vector %d: NOT representable with tweak=0 (privkey needs retry)\n", i)
failures++
continue
}

pubHex := hex.EncodeToString(pub[:])
reprHex := hex.EncodeToString(repr[:])

// DH: shared = X25519(peer, pub)
sharedBytes, err := curve25519.X25519(peer[:], pub[:])
if err != nil {
fmt.Printf("vector %d: X25519 error: %v\n", i, err)
failures++
continue
}
sharedHex := hex.EncodeToString(sharedBytes)

match := pubHex == v.pub && reprHex == v.repr && sharedHex == v.shared
if match {
fmt.Printf("vector %2d: ✅\n", i)
} else {
fmt.Printf("vector %2d: ❌\n", i)
failures++
if pubHex != v.pub {
fmt.Printf("   pub  expected: %s\n        got:      %s\n", v.pub, pubHex)
}
if reprHex != v.repr {
fmt.Printf("   repr expected: %s\n        got:      %s\n", v.repr, reprHex)
}
if sharedHex != v.shared {
fmt.Printf("   DH   expected: %s\n        got:      %s\n", v.shared, sharedHex)
}
}
}

fmt.Println()
if failures == 0 {
fmt.Printf("All %d vectors match Go reference ✅\n", len(vecs))
} else {
fmt.Printf("%d/%d vectors FAILED\n", failures, len(vecs))
os.Exit(1)
}
}
// debug is added at the end - won't conflict
