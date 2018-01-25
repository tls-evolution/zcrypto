package tls

// Taken from https://github.com/bifurcation/mint

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
	"sync"
)

var initonce sync.Once

var (
	finiteFieldPrime2048hex = "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1" +
		"D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9" +
		"7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561" +
		"2433F51F5F066ED0856365553DED1AF3B557135E7F57C935" +
		"984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735" +
		"30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB" +
		"B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19" +
		"0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61" +
		"9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73" +
		"3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA" +
		"886B423861285C97FFFFFFFFFFFFFFFF"
	finiteFieldPrime2048bytes, _ = hex.DecodeString(finiteFieldPrime2048hex)
	finiteFieldPrime2048         = big.NewInt(0).SetBytes(finiteFieldPrime2048bytes)

	finiteFieldPrime3072hex = "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1" +
		"D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9" +
		"7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561" +
		"2433F51F5F066ED0856365553DED1AF3B557135E7F57C935" +
		"984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735" +
		"30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB" +
		"B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19" +
		"0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61" +
		"9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73" +
		"3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA" +
		"886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238" +
		"61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C" +
		"AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3" +
		"64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D" +
		"ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF" +
		"3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF"
	finiteFieldPrime3072bytes, _ = hex.DecodeString(finiteFieldPrime3072hex)
	finiteFieldPrime3072         = big.NewInt(0).SetBytes(finiteFieldPrime3072bytes)

	finiteFieldPrime4096hex = "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1" +
		"D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9" +
		"7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561" +
		"2433F51F5F066ED0856365553DED1AF3B557135E7F57C935" +
		"984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735" +
		"30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB" +
		"B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19" +
		"0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61" +
		"9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73" +
		"3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA" +
		"886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238" +
		"61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C" +
		"AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3" +
		"64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D" +
		"ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF" +
		"3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB" +
		"7930E9E4E58857B6AC7D5F42D69F6D187763CF1D55034004" +
		"87F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832" +
		"A907600A918130C46DC778F971AD0038092999A333CB8B7A" +
		"1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF" +
		"8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6A" +
		"FFFFFFFFFFFFFFFF"
	finiteFieldPrime4096bytes, _ = hex.DecodeString(finiteFieldPrime4096hex)
	finiteFieldPrime4096         = big.NewInt(0).SetBytes(finiteFieldPrime4096bytes)

	finiteFieldPrime6144hex = "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1" +
		"D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9" +
		"7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561" +
		"2433F51F5F066ED0856365553DED1AF3B557135E7F57C935" +
		"984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735" +
		"30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB" +
		"B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19" +
		"0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61" +
		"9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73" +
		"3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA" +
		"886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238" +
		"61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C" +
		"AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3" +
		"64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D" +
		"ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF" +
		"3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB" +
		"7930E9E4E58857B6AC7D5F42D69F6D187763CF1D55034004" +
		"87F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832" +
		"A907600A918130C46DC778F971AD0038092999A333CB8B7A" +
		"1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF" +
		"8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD902" +
		"0BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA6" +
		"3BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3A" +
		"CDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477" +
		"A52471F7A9A96910B855322EDB6340D8A00EF092350511E3" +
		"0ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B4" +
		"763E4E4B94B2BBC194C6651E77CAF992EEAAC0232A281BF6" +
		"B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538C" +
		"D72B03746AE77F5E62292C311562A846505DC82DB854338A" +
		"E49F5235C95B91178CCF2DD5CACEF403EC9D1810C6272B04" +
		"5B3B71F9DC6B80D63FDD4A8E9ADB1E6962A69526D43161C1" +
		"A41D570D7938DAD4A40E329CD0E40E65FFFFFFFFFFFFFFFF"
	finiteFieldPrime6144bytes, _ = hex.DecodeString(finiteFieldPrime6144hex)
	finiteFieldPrime6144         = big.NewInt(0).SetBytes(finiteFieldPrime6144bytes)

	finiteFieldPrime8192hex = "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1" +
		"D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9" +
		"7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561" +
		"2433F51F5F066ED0856365553DED1AF3B557135E7F57C935" +
		"984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735" +
		"30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB" +
		"B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19" +
		"0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61" +
		"9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73" +
		"3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA" +
		"886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C0238" +
		"61B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C" +
		"AEFE130985139270B4130C93BC437944F4FD4452E2D74DD3" +
		"64F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D" +
		"ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF" +
		"3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB" +
		"7930E9E4E58857B6AC7D5F42D69F6D187763CF1D55034004" +
		"87F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832" +
		"A907600A918130C46DC778F971AD0038092999A333CB8B7A" +
		"1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF" +
		"8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD902" +
		"0BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA6" +
		"3BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3A" +
		"CDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477" +
		"A52471F7A9A96910B855322EDB6340D8A00EF092350511E3" +
		"0ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B4" +
		"763E4E4B94B2BBC194C6651E77CAF992EEAAC0232A281BF6" +
		"B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538C" +
		"D72B03746AE77F5E62292C311562A846505DC82DB854338A" +
		"E49F5235C95B91178CCF2DD5CACEF403EC9D1810C6272B04" +
		"5B3B71F9DC6B80D63FDD4A8E9ADB1E6962A69526D43161C1" +
		"A41D570D7938DAD4A40E329CCFF46AAA36AD004CF600C838" +
		"1E425A31D951AE64FDB23FCEC9509D43687FEB69EDD1CC5E" +
		"0B8CC3BDF64B10EF86B63142A3AB8829555B2F747C932665" +
		"CB2C0F1CC01BD70229388839D2AF05E454504AC78B758282" +
		"2846C0BA35C35F5C59160CC046FD8251541FC68C9C86B022" +
		"BB7099876A460E7451A8A93109703FEE1C217E6C3826E52C" +
		"51AA691E0E423CFC99E9E31650C1217B624816CDAD9A95F9" +
		"D5B8019488D9C0A0A1FE3075A577E23183F81D4A3F2FA457" +
		"1EFC8CE0BA8A4FE8B6855DFE72B0A66EDED2FBABFBE58A30" +
		"FAFABE1C5D71A87E2F741EF8C1FE86FEA6BBFDE530677F0D" +
		"97D11D49F7A8443D0822E506A9F4614E011E2A94838FF88C" +
		"D68C8BB7C5C6424CFFFFFFFFFFFFFFFF"
	finiteFieldPrime8192bytes, _ = hex.DecodeString(finiteFieldPrime8192hex)
	finiteFieldPrime8192         = big.NewInt(0).SetBytes(finiteFieldPrime8192bytes)
)

func primeFromNamedGroup(group CurveID) (p *big.Int) {
	switch group {
	case FFDHE2048:
		p = finiteFieldPrime2048
	case FFDHE3072:
		p = finiteFieldPrime3072
	case FFDHE4096:
		p = finiteFieldPrime4096
	case FFDHE6144:
		p = finiteFieldPrime6144
	case FFDHE8192:
		p = finiteFieldPrime8192
	}
	return
}

func keyExchangeSizeFromNamedGroup(group CurveID) (size int) {
	size = 0
	switch group {
	case FFDHE2048:
		size = 256
	case FFDHE3072:
		size = 384
	case FFDHE4096:
		size = 512
	case FFDHE6144:
		size = 768
	case FFDHE8192:
		size = 1024
	}
	return
}

func ffdheKeyShareFromPrime(prng io.Reader, p *big.Int) (priv, pub *big.Int, err error) {
	primeLen := len(p.Bytes())
	for {
		// g = 2 for all ffdhe groups
		priv, err = rand.Int(prng, p)
		if err != nil {
			return
		}

		pub = big.NewInt(0)
		pub.Exp(big.NewInt(2), priv, p)

		if len(pub.Bytes()) == primeLen {
			return
		}
	}
}

////////////////////////////////////////////////////////////////////////////////
// AEAD wrapper

type FiniteField interface {
	// returns x**y mod p
	Pow(x, y []byte) []byte
	Size() int
}

type ffdhe struct {
	p    *big.Int
	size int
}

func (c *ffdhe) Pow(x, y []byte) []byte {
	_x := big.NewInt(0).SetBytes(x)
	_y := big.NewInt(0).SetBytes(y)
	return big.NewInt(0).Exp(_x, _y, c.p).Bytes()
}

func (c *ffdhe) Size() int {
	return c.size
}

var ffdhe2048 *ffdhe
var ffdhe3072 *ffdhe
var ffdhe4096 *ffdhe
var ffdhe6144 *ffdhe
var ffdhe8192 *ffdhe

func initAll() {
	initFFDHE2048()
	initFFDHE3072()
	initFFDHE4096()
	initFFDHE6144()
	initFFDHE8192()
}

func initFFDHE2048() {
	ffdhe2048 = &ffdhe{
		p:    finiteFieldPrime2048,
		size: 256,
	}
}

func initFFDHE3072() {
	ffdhe3072 = &ffdhe{
		p:    finiteFieldPrime3072,
		size: 384,
	}
}

func initFFDHE4096() {
	ffdhe4096 = &ffdhe{
		p:    finiteFieldPrime4096,
		size: 512,
	}
}

func initFFDHE6144() {
	ffdhe6144 = &ffdhe{
		p:    finiteFieldPrime6144,
		size: 768,
	}
}

func initFFDHE8192() {
	ffdhe8192 = &ffdhe{
		p:    finiteFieldPrime8192,
		size: 1024,
	}
}

func FieldGenerateKey(field FiniteField, rand io.Reader) (priv []byte, pub *big.Int, err error) {
	f := field.(*ffdhe)
	_priv, pub, err := ffdheKeyShareFromPrime(rand, f.p)
	priv = _priv.Bytes()
	return
}

func fieldForCurveID(id CurveID) (FiniteField, bool) {
	initonce.Do(initAll)
	switch id {
	case FFDHE2048:
		return ffdhe2048, true
	case FFDHE3072:
		return ffdhe3072, true
	case FFDHE4096:
		return ffdhe4096, true
	case FFDHE6144:
		return ffdhe6144, true
	case FFDHE8192:
		return ffdhe8192, true
	}

	return nil, false
}
