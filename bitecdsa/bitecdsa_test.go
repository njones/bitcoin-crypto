// Copyright 2011 The Go Authors. All rights reserved.
// Copyright 2011 ThePiachu. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bitecdsa

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/runeaune/bitcoin-crypto/bitelliptic"
)

func testKeyGeneration(t *testing.T, c *bitelliptic.BitCurve, tag string) {
	priv, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Errorf("%s: error: %s", tag, err)
		return
	}
	if !c.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Errorf("%s: public key invalid: %s", tag, err)
	}
}

func TestKeyGeneration(t *testing.T) {
	testKeyGeneration(t, bitelliptic.S256(), "S256")
	if testing.Short() {
		return
	}
	testKeyGeneration(t, bitelliptic.S160(), "S160")
	testKeyGeneration(t, bitelliptic.S192(), "S192")
	testKeyGeneration(t, bitelliptic.S224(), "S224")
}

func testSignAndVerify(t *testing.T, c *bitelliptic.BitCurve, tag string) {
	priv, _ := GenerateKey(c, rand.Reader)

	hashed := []byte("testing")
	r, s, err := Sign(rand.Reader, priv, hashed)
	if err != nil {
		t.Errorf("%s: error signing: %s", tag, err)
		return
	}

	if !Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("%s: Verify failed", tag)
	}

	hashed[0] ^= 0xff
	if Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("%s: Verify always works!", tag)
	}
}

func TestSignAndVerify(t *testing.T) {
	testSignAndVerify(t, bitelliptic.S256(), "S256")
	if testing.Short() {
		return
	}
	testSignAndVerify(t, bitelliptic.S160(), "S160")
	testSignAndVerify(t, bitelliptic.S192(), "S192")
	testSignAndVerify(t, bitelliptic.S224(), "S224")
}

func fromHex(s string) *big.Int {
	r, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bad hex")
	}
	return r
}

// These test vectors were generated with OpenSSL using vectorgen.rb
var testVectors = []struct {
	hash   string
	Qx, Qy string
	r, s   string
	ok     bool
}{
	{
		"rWO/YB4Ur9u5yXRkOC0QrRmutzuGReCslws/wgt3uaE=",
		"75180709339c672ffb8db4fe8ca27a0603b2c85a4460371f7bd69618000935e6",
		"54e67cde188fcd0e3ade6b94422834505e17ba44c98b945f80596ed4c5d57ff1",
		"acbd37fb3876e5580556855f51b158b7462069283c15e337b47562d9246b7cf9",
		"117ff1e940b28f3add88d138f7c4b67145c508019c4fa0bf5b2fdbf622db6226",
		true,
	},
	{
		"MhMQsu+hkicpORVDX+liavMDRvH2IBidH9Z1UO77GWk=",
		"2a81f04c0ed31850f7701c72179b4f0cf5f438705c821c2c340775f31589694d",
		"9c7e176c645de82d00e80a6980eda165b6840ad4fb66f305f0994f299dee83cc",
		"3f154d5d2214958197fa777c7aeb114c29ce3c9d1978e08413b72a56476317c6",
		"b79b8da65ec1f31607de2d5697c4d8e4460c34bcf0b595979ee8886a7a22490f",
		true,
	},
	{
		"mPVLf1SunM/ffOxrFaC+NV5dHbaHDeFJy0ViI3bSddw=",
		"b3b5e83a406478b26ff5a051286b9295c7bb11e350a75806c7e21fd067dd3caa",
		"404da2f031a5e1697d7e3550db992b3f1093b1cfb26a43ac1136d1e34175520c",
		"7334611111a2df05bcc8955ea12eda1187be693d59977aef8a537e83a7cf0228",
		"227a8054c147a5b89c88cd524a4b81da8f07457add995e35fa5ff02a96b01dbb",
		true,
	},
	{
		"2MNMltlFPVVmpqOx524b7l0W+aRcHtokKZSKBA2/8z8=",
		"51bc15c20131a92f3161be567dcde6675b866d11e6d64f9094f93ec91536136d",
		"69f6d1b74743e1857d02cd720e4378822e0598485ce65422d27b0090f7276c64",
		"2225f7e1dfb852989e8ab085afcc3a4941e10e73fdd31b06b4cdf315ee982980",
		"d1bc806b74a85232b3cd843595a201d6910e6a370faf639657b45e5e7dd06d68",
		true,
	},
	{
		"05oUbaIeMArcXpe2Q4U6s5UfcmyoluHoRdZb0H0LOP8=",
		"7653996b68c20e98e32f1f062bf66c4d906f4573fba5ba317d614f886535d4fe",
		"bf9e3f48523b2d49962c5cc29f67eb4ddf6de6afebda0d777b10a1bc94b58cee",
		"8f42e09fc02c7caa7471d1fb010b99ab6d0fdc173dcb546d8014eace25c6b4e0",
		"3c951d468ba26c59d3c3008310b46c5986b1e6fc21c030e5fd5824d677e76ea3",
		true,
	},
	{
		"XQKZz3vOw9t76d102XJty/1gIeMr4jxoV0vakfB64hg=",
		"54e298ad4bbe26e1935eacb057e621b0cf496a11ca2ee485d56567c631989978",
		"a96039cee81be6fc95c4d4c5f6f0c69f48ce4be56d0156ee694f7bdaef3ee0cd",
		"6ce6c3cc8ead129d0da35d378da07fa86330993fd3f166b3fccf8c9ea9067af0",
		"c481fd7360ceef79357f5beefcedc21fa6b8aa3fb8eea6c7a13b18d8b679256c",
		true,
	},
	{
		"UZ/P1J1K+64bLnNc+K5JSxZX5ZupRSaxMLI0JedXdRs=",
		"1b994a0fdecff7cf3a4392743727a3a74be726f4d7c02224d0fad910f1714ee2",
		"8b3b37234126c6764fbebbb45adb9be0e13a08b3e30659232b54bd73d0dd9508",
		"8ca7216aaa8ff2ccc101b6a15710fe273a41a04d5a43360c7d6a889c9f71fb78",
		"44a74dd5c2b39257308fbc36f83291a8748de26e3cf42d0533e4348a58d4a899",
		true,
	},
	{
		"U16DczVy8AqDWnFvJGVPfLM8UZL6WHMfkIjeiRGCRSY=",
		"77f6e0d2a20c161b8788a18dfd77662dfb60e3cd408b74591f48acb6dac2d7d4",
		"5557af02ad7c227e71639f00c08ec34ab94d2877c9089701b619f23789334f0d",
		"3b75c6d5124b2e71c8bea53acce1bf7587b00a68705571f609c33547f696f469",
		"b6024e1ff27e2775690b37f18e74c8e3845226557bb3b40be0206a6c64fd928b",
		true,
	},
	{
		"7vXxpKXjgoeuGYrSSZsemM8pLehnB22kR8He88iyGEM=",
		"0d6b65ac0699fab1c22f9fdfbb63b540d692aa6a0e6127e495af55d11d49d60e",
		"214b168e985cd03acc0c7e0c79b8cefea0f57fd482b042bbea898ab9dadb69fe",
		"86af531e21cb21bb26a460d48f0859865e13d421018607983827d18e6dac9115",
		"11de053699e0ab61c09840e7f2f2b994bd3a642246852e6d781303fb3cde0f21",
		true,
	},
	{
		"Ys16vX2HP0xLQ/qs/B0ibIG74OklkW7HGHFBt+Jrars=",
		"1dcb5989e0ea5dafe23c20f16fcbd5304f0111d1b2d9787bc8e27e4b309df58b",
		"6c7fd68e517bc301e028b9b4b857a0c0c17dcab5091dda7cccebe41b023bab58",
		"b91bfb1e04f142359e204c547d5d9d0103b3242f22481266c0dd2d0f550afce2",
		"f27b01154367ada77ef0864159f67e5d8a8b9c147c109cc7dbb58edf4d31fb3d",
		true,
	},
	{
		"WQ6cVAnMSU1EY/TqxPlEf6NiukEqwg6I9SQawOafdfA=",
		"434709b03bc6a4f85e41b36cb363fcffacfa6004cd88319c4f198dfb55817c9d",
		"a328f6f34135070008db8627a2bcc059d2d22f94ab997f324efd8ed7b46eeca9",
		"0ec1168e5492a30c6d7416728fbff65e09d8a5604cccd300ce78a03f3bb6a819",
		"e67a8c628a62c9d8c290ad80d720c301099eac6980d70d460b83496fd3897880",
		false,
	},
	{
		"HKl7FWfgW6Ak94ul+d0h2EBoWMrmQ+UvObs02G253fI=",
		"6fe145fd43ce35776a7a100572dce5a56ed99e0d016e9a3492001f07e3b94bb4",
		"51f409be7a06f45a5b50b968a074475261d2c295a6361f9fba7938d84d98a07f",
		"6bf5928119b50383d5a0827246c54332e5195a16f67c7d0d0395785e8ec6b37a",
		"9893394f8b8d72d83e170a6fc75f6cab3014023ffb9dba78132d07fff303aac9",
		false,
	},
	{
		"HMiKpuZ77GXybslRjcXVGQeZtsXoO+43RXYOfZNqaco=",
		"df869c02298562f61daf77b14ec61d9846bee5b3a0ad889ba7579bcea654d930",
		"a90586b5f7edac6bfd36082f1caa75b9ad6c5b14608c37292f291018de2459aa",
		"3a63a928dd7ae2a893375a5ff59ceeb514af4f50cc59403ed1ce678fbb740678",
		"72dbfd3ed248ec227308d84c1c7b51ae3d45e1f56ff9da6a4469f5a75353a20e",
		false,
	},
	{
		"I9yE0WBaIWJi1b30cXLnCU6f9ZHpZYnqu/iexCSOAis=",
		"6b12278a10906d7a7bdea6f4acd27b8aab7aff741291e2c0936a7e9195a139ea",
		"2eb90f005a796cb9e4ac916eb9ada784b0a6e7f00b400a4d1112163d18ce642c",
		"78825efc06632ce1e8c18740e7c890e43874d409f4990ebbf574157724166b24",
		"8fbc10a9cffd6f51da9a1b3dca808575d7b5848ba5744fab85bfed9722617008",
		false,
	},
	{
		"zdwUrQPYBZBYiRTFHkpT7m5Y2g9dmIOEUOeg1UT8Q3E=",
		"14860c07172ee7bbfedefe36a88732a3b6b0c881b9267b06c1ddad3df0e74cc0",
		"c02612cdf33db35ed3a396c461f3fab0c0a02fda8377aed94927315fbf37f3fb",
		"51abd6dc6a5128640cfaece311444c81758317806ebcd5c7cd5e4be87939aa48",
		"ca9aeadc7ab478de83fa4ed7e7462340c7cb85292b077db0b553ebd6afa8e27d",
		false,
	},
	{
		"DRyVx9Nh8TzP0Dvf6mWg49PzVDu1lFzgvplIeOyCryI=",
		"e11380da9773efa620793e250e3aae5f35968e752f869b268b4a85a840051012",
		"8a22802d8bd396c442d82f8143c85c2a2f0f38fa9f4c7abd020b24c4e60d7592",
		"dc499e27300a12a0c64a682a921c7b493f025734f14404cb87b6b16afa73fcba",
		"334b81cae281a0d255ec32174a2c71960a45bf7dbc83aa063da476ea08e47ad0",
		false,
	},
	{
		"A4gPHKhpDW6TfM+iqTs9ERCMEH1D4JWDp/ikIXx+8DE=",
		"5d72e49d777228163a02ab7a44627ccfeed65a539db2d10b9b870244a101c56b",
		"15e4e579a75bc535c4597292b4c4e7f465681b8b5e1cdfb7e2832a3340984628",
		"a035ad65506baa9dd031fdeea7fbf8c2561cf8b078c488d1d2e5a953bc1dd9fc",
		"5c0f7f2b250d3ec79b200f2f8ee2e1d07b55a8d8f1ba7cf1f97634a6463c6676",
		false,
	},
	{
		"O9VfPlCHlELFnfyk3XyWe61sqrWFdIjhX/9YKuHcpc0=",
		"160a5c3e40c612755aa92c7bafa2ec0d30beaf3c5e8502357598ef1ff5a30d39",
		"ec0157612f8bc12fd3401a623d74cf995474652b02d9157bf6a516e28e581b2d",
		"753af6d5ef6bc9b619a65c935abc10ca9669fa36fc0f04eb0d770cfa9851bb53",
		"cde3845f37da3b48a5d73bc4da9721e0420ffdc90fcff3d4e6327741ce489d67",
		false,
	},
	{
		"mslv4d71bz33jMEVkhYCYZambPkF1AGl1XeKzAqUHdI=",
		"177fac6032f5e7943887c649f2d1d644e46fe9a4855deff3dbee7501658eebb9",
		"b936a5174434aa416190f3b934d33517560a1e9986ca2c6fdd30988425090e62",
		"e85f7bc9d1f497e70b24a950fa1247fa45b4abc125445de96499f511298d7f1b",
		"b86ad799a14a580074c3be6f04947d71fcf0fe65e325dc601a9ea4a5f05e722f",
		false,
	},
	{
		"jHOF5JG6NDz3qvXxc7BMFvQnuaDFu6w2WNOzrVS3c5s=",
		"1cab54e51f4f0a29bdb6469e5991db6808ec9feee87c390f23850f45dbb46cde",
		"4eb3a2ba5d5c3f6f5236e46f01d4c1f6e7a6bb1d28925d5a4ee4b4c39198b481",
		"efebf536c797cf0544f604590c9308785ea01b9ef9383f037dde205dcc19abed",
		"f7c8463a43b722b11bfff0043e4c4b4da3b4a7a3d532b1a0b2e7492869ecf877",
		false,
	},
}

// These test vectors were generated with OpenSSL using vectorgen.rb
var testVectors224 = []struct {
	hash   string
	Qx, Qy string
	r, s   string
	ok     bool
}{
	{
		"UuKml8aOeeE2urmZDcpnKS3Jt+wU06WL1I95JTTLF8o=",
		"d08c21db30c52e907c48498266c3bb1b266d3534886f4c9c88abefd6",
		"712b2a602ab7df8aae81d8350bd02591d1aa9fc9e4ab1319c828cc80",
		"de2eddb766aa9e58aa043f2213a71027413a638d55c7c5fb952d1dc6",
		"67a107dc70d7a00581cc7b3dc459ba54d259a9703e1082e9ed0762ba",
		true,
	},
	{
		"h1uIWz5niypHBwA+exlAo630wMydGEv7wCVD3JeRpEM=",
		"d64f191ba1e94ba1b3fa2bcc25035c97ff2a95409597883aa020451b",
		"026099d210dcd2a28537054883753ce082484541a15d8810dff94c66",
		"ee3bae46f6119c138df772b587d3c79b91886689ee1cce170508a8ba",
		"dfd75542bbdbabab1ce145f6c6f4814e775edb6869e4b13bd8568595",
		true,
	},
	{
		"Oh2UE1NDfVXyyU6syFIoGfBNmGwZtIODaM3/4lMqbzA=",
		"c429c52939d2b813b1393c633d321ad0f50a29aa966f51040d05acfb",
		"76b53d4476bac4b2347cb29aeacfb9da35a6d9cdd8526eeb5f171a2a",
		"a9bb6562076d10652e4acd61bc4b05ca437e03653ba046c056333101",
		"24cacf46d60e0f024902113e9eaeecb832e6891af5b963ab40e26554",
		true,
	},
	{
		"Z/LUphX+3CnxhKC7WSiuRzpYw0vyF4WROqWI3jkqOeg=",
		"1ec944787c2468014feceed664a2b7ffcd72e7e9d0598469342083f9",
		"319b5b6be3bef5751f90377965e7641a660976b05ea000696ec16b9e",
		"f9a8b817351c65c3ef4acb01bdff96caf18e5806f01004cf58f1a3e6",
		"e55e168d9f7fc6879d7fdd6bfd92d81ca996f52ba383f4045402508c",
		true,
	},
	{
		"kra7yS1U5C642EV3SLISkmmynnNDgHAeJhHMXc8uZMc=",
		"85bf8fed26c46a79f4616cb9ac130285d70396ab662ba8c585909e39",
		"4f2771e2d05fa4c148355a47a30618c958b0f42189843bf076bf4d24",
		"cecc2d251e433421b1cf98061ca6132002fa995cb8b564b003d8becf",
		"5e23f12ce90d6167ca034f6cf162dde6a0294eaf5fa2b2e3fd4b6a1c",
		true,
	},
	{
		"IFYjqmzcKTdilUKTi8XCisLaZX64l64av4gh8exLIQA=",
		"848b5189b3f418f7ba15e18e4a09d60147da3beb6df81e8c16245987",
		"19841978aab89f934b41a783e863b35cd228e8fcde7a93916c66f103",
		"f35edfe252100757ee47494904b4da82787d914338e9e42534467b28",
		"79fd9664baf251906cae69f700c2f120431f46c7be519fbddfaa528a",
		true,
	},
	{
		"8xqjsKyNnLCYc7lGDkyyZ5cTeZCm0HC+/Zo5z/Hs9cA=",
		"518e8319b6679645c17b23d800ddf26f9f57f6f9f9d8a76d49c472b2",
		"e53596f2f7466ae04f8bc4cbbc7e498081f3af90a9ed560fdd769a1f",
		"9e1487d13871f290fe0cb0b9b8a79f003a6000b164b839fb190f5765",
		"5fded83ef435e846dec78aa30c80bf521d9003c877c2bd4ae433cc7e",
		true,
	},
	{
		"xY4Api3GxezZaGdrGV7UIR85Qx9ehA28PN6AWCVGPwU=",
		"316ef682f18769426108a4ee80ca02dd419b438b89717b09acf6ea01",
		"84fff5821610010cc0b9e3ec2744a9f60352bf07fe2c5b93522a5dce",
		"a74122597cba74477ac4e32489b928da6b781e8cd33da5ed4ed8d8f9",
		"69aca50641e89dd028da863c5d9e7f9b4cc38a87c28891c7c3198e15",
		true,
	},
	{
		"bNqZQVOWhDb6i5HZpIA/gF2zpEkB2/9R5NqgHKU+L6o=",
		"a27d5a422b778a6d826a332c862685edf8d7cf5d526fcbd0b9f0f4ff",
		"d191ec83857cbce055b499eba738a9f383bb01e76496f1a163ddbef2",
		"6cae353c1e5b42f61ff79667e622002abe93eb2700446a9bba52e58d",
		"ca5a4e8374aaa9fafc242286d08e5b119dd8f4aa20fcac63b698ea17",
		true,
	},
	{
		"wRtVGDwbunZDTo+gD4iJGJXazpPM4bDEcL+UmmS9Bz8=",
		"57652110df7ee6e3594309796490424cb9df9f28bce9953cbc024982",
		"6b5f0cc133b1e2b2d820dc4a6ec5380696841ef7bb9ed7a8dfc439ed",
		"bd3c131acc84773d2a9b6da23b83191f66a17d7fcaffe556093e933e",
		"968ac0ae52d01059baef154abf3f6868a60c8ac72c1814f424248513",
		true,
	},
	{
		"zHfLV4XA+xfAwIk5cyFZiavzN8G4Wjj9OCNo/kgRV/Q=",
		"1e249fd0c9b986451d43b42f89021336f5a2728e72affbcc0c37f512",
		"24d136c4d9c9303d13088a7b3db0febc5ebd02c4560ff08f1d1b5d5b",
		"ebd9f93dcc2347e36d7886bf48700fa492ff13fe1d4f751429983d96",
		"867488fc76e0d32bcfa5c8171585ec5571c423b3f28e70057ae6a9d1",
		false,
	},
	{
		"fvJ0Yg8q46LnKlSnzLson8g8TC3j+wlvhT3JoYpqfTo=",
		"e8ee3171c9de606fec6f2a8adb2d3f5cb1c93acf0b5ce6a04f6cee30",
		"8e83207db5b9bbd7f9ac651c7ee4cb9b6187c11a90abfbd5de75521e",
		"ae0c7084360104d08ee6a408d09c3542f8c5d9bea5f634de24bb3df2",
		"8fe2c249caa69a4653e5b754224e750e666e664c68126237e482e691",
		false,
	},
	{
		"62SB5tn+Vcv9u60b3em4Ao+reyBcKXewWOHstA9Bo9Q=",
		"064b10c4880da85292a55a622c51be91b29190a55e7733d85d29a17c",
		"3816a5df39c25e5f4396ba1cc21119d99184510d2cf08195073fd8ba",
		"36a5c8e22accde047269f90e3ea0db20b44d980f327de733be4217f5",
		"1a0fc8c5cc20f998f9351c1b7965e8d199e9ec36a92495791071bac2",
		false,
	},
	{
		"psm3iAG5lCDNd4wD0J+r01hYkbKT3jUgffYuBuJo668=",
		"f862e75d65342ce82b3e5db791b2c538e106a42a2986e6dbb665e3d9",
		"9002f61e5ea252cdf7e19741c220233eb4d6e99a6793cf0cf581f1e2",
		"9385f393b9ea0d929e25ff0787f223fa718b68d5fdb3a02fac8c6eac",
		"752e933122b41d659c12e4922bc354fd9126466544f836d0eefb7d7d",
		false,
	},
	{
		"J8SOBOD3ANxiJG6Sy94HgpUK4PS2HoMRVrclCIYOwh8=",
		"7bc19896ea7a5e463ea26ac0fc639097698185556ef46f879ffd25ff",
		"0c9b5e55747f2dfdf55a86c9916520de36fdefb1b3e5f4c80786c393",
		"803770360232f0f3e252836bee4a2a8b7391a83d0f79e6e8a40967b2",
		"3271aae7ff9db3030d24aa60c05194b584fa9f24fb2722572974bdb7",
		false,
	},
	{
		"pQc8DsZ5JZccHzq4Re6jMl0XhbSxtDlhWbVJuy7Pk8k=",
		"f582e64838f4c34b3519607d926c80826c7b045d3c15bbc877689887",
		"c36bf1c51c2960cb1cfb88f87bc7759569c2a7bf9ae2f5b84e736c56",
		"0a2becb6f6c33b6fa34cd8eb1c00c1bc525c89de779274d7f5156995",
		"36236cc0234a6076aa7a1dbbd4f8933a36d38aea231dc0e175ad29b9",
		false,
	},
	{
		"Mz4Lq2b0qvMgxG8d2mv512PM0c9M1aSCxoi4rVZ8Gs0=",
		"d76592923ee51add3dd5131ce34d0f21a8da62bc83891c22f6e62d44",
		"7b8df34922f32d7918df2c2b1a05a60e4024a8a3a03c32c5d1be32e3",
		"69e7a2f7c9f890f013711792ebdd4783403062e19aca006185de2307",
		"20379cbe3d7054df9721734be93003c76713bd836931e75ba6b34788",
		false,
	},
	{
		"NN7r4K+UiXAcbHvrOmyYlajr+D9yMZLBCDIqIwtJNXY=",
		"a999aa5db63d7a045f3a6897201dbdc00a86308079060574263f484d",
		"0fb60c3e518c662b2663ac5261464349936aa118b2655de9dc4b3176",
		"bf8dc8e6fe8ff96ac6a817436ff5abc050161389cec54547f6207084",
		"8f17e024580a117080ed4fc2b7e01f3d7f45710d5ad9a9dc8fef3c96",
		false,
	},
	{
		"Ns9u7Vtibnlk5Txz63F+yE51J2/5jkAQLpoxE//vRTs=",
		"55385a4198dc2470cc3f9a2ddcc9e8f4bb9ed3de5907c5e01a255dbb",
		"bbee8d47fb31d31808aee7c792b9c489b49e184faa0e89cda4f6ecbc",
		"0fd7c4f8c1e51bc517e093a0513b65adb640498775850ea402bb2587",
		"e70af5385e62b9fe50ae855b788d56f5312d18d55fd2ab91c73ede3e",
		false,
	},
	{
		"l5Rb4iq5lffTHK2T4fOumrdu5OFlO33pQVcxhwPuUo0=",
		"bc1646fb050c1d463bfb01e3cba9921163eb17a6599d5650cad76528",
		"ed82f5339909463540b96629e6ac20e863f72108cdbbcba2df8a8dd3",
		"322692672ddcc36680478b080b1ebd67afb462f4293c81c1c5dd250b",
		"d30471c3cbb18fe3fbd60c4cdec73c9675e8a2b42c753fd128240c4c",
		false,
	},
	{ // From bouncycastle
		"MA3Ya9lPN6+gKqIgKY88Ih0P5LqooQMncGjjuQ==",
		"dc57c400279eff3debaa3b2069d7f1a52cae0e243d762365a53f988b",
		"e57ad223fe9ff5d9a481ec57177aa213fd2f74ef443d70c06b0946d8",
		"76ca6d809377918baa397f29e9c94bb480b49cb093944a0368f868e5",
		"7aeff445dad7f5c72ebceed45788d130f0fe105ff1fcedf0fd1bd91b",
		true,
	},
	{ // With SHA224
		"iK6Cb+JNpwVtCDbpLpYWrJxmNLD/RwdeIx94Wg==",
		"df1425299ab4c1708ca9919b6be979090e55ac4e9588c1aa687e006f",
		"3310301eda28577a271eb6bdacd2c7c3285bcb36e266989110c216e3",
		"25a774ac280a675febbf0a84f2f63a97f23623d5ca862c5becddc28d",
		"1d3e0e7594d25c841761ef8bb5ecd4d471549b0eb3de0c8b02c06787",
		true,
	},
	{
		"CYfb3NMhBVOXAatM1+G3NevQV4byA2xjIskmFw==",
		"b42d247a54ece53b3dfc2e09978f3a7579474c08d3d5e66f36544ef8",
		"d47471fdb5f82048df98545062d55191ad436da0ab4c6e113c92cd75",
		"4a3fa9e2dd5b1159c63d49e1e5fb8cd032a290a954a97463cd1c7bdd",
		"929b324879fd1c27fecb00c13acdcfd31f883c35e33005d0b77d4876",
		true,
	},
	{
		"zPeDGtE2CKlJL3iWX3Up9SBQ5e4ssevsCXdooA==",
		"480e0430ba7f560491d877deade67a1aef6d9e217f76de9854f0c472",
		"58363df81d673502f9d711d5f9756f17894c6915f988cf74c582309e",
		"82647625e44059f5070e98731708d03d3f4e724454d9a23a9f4e1d9c",
		"56947439fafedab0cd70ac20a5816f07e3f0bd02a2a9688935491ea9",
		true,
	},
	{
		"mWtQV42buoxfhJ7qiuvvfBY0IJgc0IoJXwPGxg==",
		"54727ca4098cbdf47a0720804d56572dcbd775be1242a7b9af032e88",
		"80e9ff04242c9d48c9cf76ac061e5d7b58fc2a3f3c1b76fe40640e7a",
		"e9e570ce5325109598be7e2b8f130d1cdbf53c47e7b4a27157010a3c",
		"c51a4419db67f7f1089b3dceb683eec62fec2379320484c9aa51fb2f",
		true,
	},
	{
		"hq5QRfajGJY9hHwijEYMfEemzm+HHE2r5VPG+w==",
		"499caa429e29600e4ff030436c75b3f293242d4ff3e8ccb7ec10e1b3",
		"88a9257c06b8c53fbacfbbd2320a2c655a3723443187be5bfe542ac5",
		"83a727aff472073a3721bfb8a02a2c9bd4611bd7039b8e273558b3dc",
		"87ebbb5737521a08b1c8485972d3344a3ab586ee38319cd891d21262",
		true,
	},
	{
		"73Y8mTjcHFkh67p11Gdv8aRU0UB7jg3uEL6FNA==",
		"6ec69cd380e48705109320145491c2bfa6df932edb26aa4f8ee10fca",
		"11918788a4a6440025b2fce30fdfd240f32f87d1a6d24ed8beba30d3",
		"5313cb9885e529a1960bb02b3bb9033b693c26e5e266a50d18ef03eb",
		"70c1ffd185578d87f9f53f46fcd242406daf8c2066db74dde02e2989",
		true,
	},
	{
		"fR2a4aSPZpMNgzAhCwD/lmWSDl2uUi6vies/Dw==",
		"234314bd2223f2612f7bb53054670b95b6f551107b59615e021f97f5",
		"454e9a178f98c46c4e3940b9671ee8c087743ae7a6a846b64fd59ad6",
		"93bacf7faa7781a85da85febe5b7c44b9a7d60f50e8b39c3873ba1b4",
		"d11a23a798fbdc3fd2af9b1b7d097a09ddd6ee3a2ca345d3dfa34923",
		true,
	},
	{
		"WEx0ZrJ2kqHGInDbiS0W94cQtv709JG8a/qBuQ==",
		"8ea93be28150a55aefe5fbed613ff94c260a0d0753145dd9e1e46751",
		"578ab63fabe4dbfad4726151be599e434b229f1ab242821692d31fa6",
		"2a77f32044c4def9a1d2bb3cb4efc641bd3c44451fa05541d80ce384",
		"4545711bbc462c96f191e05ae2381f01b05eb27f041f98c8fc52bcf7",
		true,
	},
	{
		"LKEDiUeQSqocG2JDHPCztAO6RCeiSYzezUpuyQ==",
		"c0820d847500215ecef7f9f423ccb04d5e884edb1d7867b15ec72cef",
		"a525064e54cae8911e9fb211ca5c782368aa75b2dc670a106901d764",
		"0bd268f34d7c9ebb699c1227f67363401f16399640fa888cd6637708",
		"6e8316c4fbe0603b37f30694297137e7bfcdb7508dcbb04737803116",
		true,
	},
	{
		"MH+UBz8oWKCgga3JepkYQ3pJmc43riFn1neo9A==",
		"a8f8ebca44d7e0997604282792eef7d4e7125a9d95a502e4292dbe56",
		"0c652a88aa3e0b0c351853b14f38987daad1ced43e074afa4d7e0add",
		"09f16c5e71dd89fb6dd65e510991163ff6f2eabc57363203d73bd6a3",
		"552761b036550f835207c2ec4364d259df81ebc23e7060e171dbda1e",
		true,
	},
	{
		"jcpCclP/LGV/7M8+3KDp9tXBw4Pw8lrrU4U5yA==",
		"27e964152d793e404366f0723ddf88bf0158598e2cbc653e834b7f14",
		"054494e937b93c2fab8698f07221a6e375285166cbf08ff4e5176551",
		"9066307646ca66b76cacc2a39ca82a9d5ba17d7519d2316782588fd9",
		"1f5ed65e8ed433916d724f9151b71024a02f1eb4bcab7530cb018945",
		false,
	},
	{
		"k0JNsD/hqOdOc4nFV6/KEP9DFLQ8Js/U9Yg2fA==",
		"1935a7a894122c5c81b2b17d9a3c56764cbb1dde32f5ccaaf051a8cd",
		"006601a65a6254615d0ab56655f2bdffe7eb9b51c8ccb1777d68bd6a",
		"031dcd89299c7ea4a180a1bd8ab37c54d632797df2c843bd99028d7e",
		"41b1c59da0e208fab5064f64d817849e6db587f2a999a4effe867735",
		false,
	},
	{
		"X3akSPEWTAeZCxgvEksKofbXZeEEs9nOH+VJvA==",
		"b369ea70c2c78688fbca324f49f7e842d9a7a48b259f8eae045683f7",
		"fdbc8aaa5fefcf2d87917258639292be7b5cd758c73dcc080d89ffa7",
		"f8ea023580d144897b318112718b87d4744a664fd8bff9bbe60a7b5c",
		"3035e98dfc71ed858503365e36356bd30cd4dd55763b33f66fa48166",
		false,
	},
	{
		"Ngsi4+dskyzDr62s3dFGLqNJSLbkylpz7NZUvQ==",
		"a98f58bb0177fc84b7f954fcc6107855b77781a214937f475bb122b5",
		"a3a647d5a07d1eff710c66f83fe2b7e52df020c9baffece81f0d9efc",
		"49074698370764d9fc16926c56f3a3c995f8236291f3f89b30aab2b1",
		"44cef38ebd300231d9d55e353ac1ea1968db3329938d1898634d05db",
		false,
	},
	{
		"7O44g55hrjN2404WK/EKL0UipdAN9oaItw8xNw==",
		"03d92a28c778ec4ae3ff512fbd3be3d9b3a8d0d358a56057af814465",
		"5a6a392078d9fc4b80ed3852bd4a4da51bef4bf6b52a49567fed07aa",
		"180667348f6f0da7e2f5969efc16de029a2e92287b683f4848f38247",
		"b16972f1b1e64efd87d2f36baffd0d1d2cafa0d2777eb8829afe694d",
		false,
	},
	{
		"iZMWig9ybYia4aqmy1riQ3WxlVYVQGxMjwzFcw==",
		"cb4e0d1997c5085e82ced1455c471ffc59b51d7cc31a9fe2cedf6570",
		"2d1c50c8fe407f5f070767e03c06ea16d113f3d8de46711f285c62ec",
		"f2da17dda55b5df219e792c354ec70d326dcb73ccd69dca44c363d6f",
		"926afcd5e523b426bccc3e86ff30f1544802e338de93b45dcc54745f",
		false,
	},
	{
		"8cTgV4In+GNbDovnMZveif/FSPkcKNKvdNQoiA==",
		"c04cf770e32f885a83fb438b0289abe661df24e4d6a57741560bd3b0",
		"21579a2b53eaaa276bc97fdcaf11244f303bcf1dbb73ff9021b646b2",
		"868269282eb994d0a925502400d26830b06c392847fb342446c81c03",
		"a7ba7ad9a681fa7bc5c52b946ee5cbb53ccf64762aa026573ec927f4",
		false,
	},
	{
		"LeIj5rhwKoO8BIILBcHGhc7hUV3FNTK8jeHT9Q==",
		"65003cb5de8b1bbde952d3f9fc9e0a3bd2946ae075ab673d5e32d9ef",
		"fea89b37b0dd4319140370f667a0130547ffa7912c653143c6d24336",
		"5100f34d400c9d177a1b57e8ad05deef2d6eb1bc1d90a1fbf62077fc",
		"a5054f958872dcbd8360f7c6dd79b1a8da89910267a977a78117dc91",
		false,
	},
	{
		"gtCRMOIfhcdn+ftzNqSDQIvq/KSPyy6iK9C9iQ==",
		"a9862ebdb846906875c482d3c9d0fe3197cec65f8e5544e2afec162c",
		"7c02aca3a65a58f8b252e7a39e347d038a5e02106b9ef1b6ce7feb28",
		"0c915f9df3a814497df4d0cc479f5b877a3428dfcd38fc38611ba0e8",
		"1fee66fa37e933b6e45212244d05ed9e76d8894ebd756f27358bb5c6",
		false,
	},
	{
		"ZRKaKoSu1CFzS60oNu4ug59KaKllkVBCJp2y3A==",
		"d9ee4f6232c129002176b4a9da2ca740fd52be22a65e15ad461945ba",
		"4e1e5b1ee68e27f93f376b83f16cfecfa1fd44a412ebc4751a83e01a",
		"53535f882c643f5937607a5e49f44082aa04b33a384e8b46bdedf395",
		"6cfccc7304111baa22f48e3a97fe8f9760de72c91d017d525fc7eff5",
		false,
	},
}

func TestVectors256(t *testing.T) {
	for i, test := range testVectors {
		pub := PublicKey{
			BitCurve: bitelliptic.S256(),
			X:        fromHex(test.Qx),
			Y:        fromHex(test.Qy),
		}
		hashed, _ := base64.StdEncoding.DecodeString(test.hash)
		r := fromHex(test.r)
		s := fromHex(test.s)
		if Verify(&pub, hashed, r, s) != test.ok {
			t.Errorf("%d: bad result", i)
		}
		if testing.Short() {
			break
		}
	}
}

func TestVectors224(t *testing.T) {
	for i, test := range testVectors224 {
		pub := PublicKey{
			BitCurve: bitelliptic.S224(),
			X:        fromHex(test.Qx),
			Y:        fromHex(test.Qy),
		}
		hashed, _ := base64.StdEncoding.DecodeString(test.hash)
		r := fromHex(test.r)
		s := fromHex(test.s)
		//		t.Logf("Comparing %v %v %v %v", pub, hashed, r, s)
		if Verify(&pub, hashed, r, s) != test.ok {
			t.Errorf("%d: bad result", i)
		}
		if testing.Short() {
			break
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	b.StopTimer()
	data := testVectors[0]
	pub := &PublicKey{
		BitCurve: bitelliptic.S256(),
		X:        fromHex(data.Qx),
		Y:        fromHex(data.Qy),
	}
	hashed, _ := base64.StdEncoding.DecodeString(data.hash)
	r := fromHex(data.r)
	s := fromHex(data.s)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		Verify(pub, hashed, r, s)
	}
}

func BenchmarkSign(b *testing.B) {
	b.StopTimer()
	priv, _ := GenerateKey(bitelliptic.S256(), rand.Reader)
	hashed := []byte("testing")
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		Sign(rand.Reader, priv, hashed)
	}
}
