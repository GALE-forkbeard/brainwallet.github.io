/*
    electrum.js : Electrum deterministic wallet implementation (public domain)
*/
//define empty coin parameters. Select coin in the list.
PUBLIC_KEY_VERSION;
PRIVATE_KEY_VERSION;
ADDRESS_URL_PREFIX;
compressed;

function electrum_extend_chain(pubKey, privKey, n, forChange, fromPrivKey
, PUBLIC_KEY_VERSION, PRIVATE_KEY_VERSION, ADDRESS_URL_PREFIX, compressed) {
    var curve = getSECCurveByName("secp256k1");
    var mode = forChange ? 1 : 0;
    var mpk = pubKey.slice(1);
    var bytes = Crypto.charenc.UTF8.stringToBytes(n + ':' + mode + ':').concat(mpk);
    var sequence = Crypto.SHA256(Crypto.SHA256(bytes, {asBytes: true}), {asBytes: true});
    var secexp = null;
    var pt = ECPointFp.decodeFrom(curve.getCurve(), pubKey);

    var A;
	
    if (fromPrivKey) {
        A = BigInteger.fromByteArrayUnsigned(sequence);
        var B = BigInteger.fromByteArrayUnsigned(privKey);
        var C = curve.getN();
        secexp = A.add(B).mod(C);
        pt = pt.add(curve.getG().multiply(A));
    } else {
        A = BigInteger.fromByteArrayUnsigned(sequence);
        pt = pt.add(curve.getG().multiply(A));
    }

    var newPriv = secexp ? secexp.toByteArrayUnsigned(): [];
    for(;newPriv.length<32;) newPriv.unshift(0x00);
    var newPub = pt.getEncoded();
	//document.write("fullpub = "+newPub+"<br>");
    var h160 = Bitcoin.Util.sha256ripe160(newPub);
	//document.write("h160 = "+h160+"<br>");	
    var addr = new Bitcoin.Address(h160);
	addr.version = PUBLIC_KEY_VERSION;
	//document.write("addr = "+addr+"<br>");								//uncompressed address

    var sec = secexp ? new Bitcoin.Address(newPriv) : '';
    if (secexp)
        sec.version = PRIVATE_KEY_VERSION.toString(10) || 128; //default 128 = 0x80 for bitcoin private keys

	if (compressed) {
		plusonebyte = newPriv;
		plusonebyte.push(0x01);												//Push 0x01 byte for compressed priv
		compressed_priv = new Bitcoin.Address(newPriv);
		compressed_priv.version = PRIVATE_KEY_VERSION.toString(10);
	}
	
		//compressing public key
	   var x = pt.getX().toBigInteger();
       var y = pt.getY().toBigInteger();
       var enc = integerToBytes(x, 32);
       if (compressed) {
         if (y.isEven()) {//byte of parity for Y-coordinate for the point on Elliptic-Curve
           enc.unshift(0x02);
         } else {
           enc.unshift(0x03);
         }
       } else {
         enc.unshift(0x04);
         enc = enc.concat(integerToBytes(y, 32));
       }
	//document.write("enc = "+enc+"<br>");	//OK
	
    var h160 = Bitcoin.Util.sha256ripe160(enc); //push the compressed public key
	//document.write("h160 = "+h160+"<br>");
    var addr = new Bitcoin.Address(h160);
	addr.version = PUBLIC_KEY_VERSION;
	//document.write("addr = "+addr+"<br><br><br>");								//Uncompressed address

	//sec - this is PRIVATE_KEY_VERSION + private_key + 4 bytes checksum
	//addr - base58Chek from the hash of compressec public key
	
    return [addr.toString(), sec.toString(), newPub, newPriv];
}

function electrum_get_pubkey(privKey) {
    var curve = getSECCurveByName("secp256k1");
    var secexp = BigInteger.fromByteArrayUnsigned(privKey);
    var pt = curve.getG().multiply(secexp);
    return pt.getEncoded();
}

var Electrum = new function () {
    var seedRounds = 100000;
    var seed;
    var oldseed;
    var pubKey;
    var privKey;
    var rounds;
    var range;
    var counter;
    var timeout;
    var onUpdate;
    var onSuccess;
    var addChange;

    function calcSeed() {
        if (rounds < seedRounds) {
            var portion = seedRounds / 100;
            onUpdate(rounds * 100 / seedRounds, seed);
            for (var i = 0; i < portion; i++)
                seed = Crypto.SHA256(seed.concat(oldseed), {asBytes: true});
            rounds += portion;
            if (rounds < seedRounds) {
                timeout = setTimeout(calcSeed, 0);
            } else {
                privKey = seed;
                pubKey = electrum_get_pubkey(privKey);
                onSuccess(privKey);
            }
        }
    }

    function calcAddr(PUBLIC_KEY_VERSION, PRIVATE_KEY_VERSION, ADDRESS_URL_PREFIX, compressed) {
        var r = electrum_extend_chain(pubKey, privKey, counter<range ? counter : counter-range, counter >= range, true
		, PUBLIC_KEY_VERSION, PRIVATE_KEY_VERSION, ADDRESS_URL_PREFIX, compressed);
        onUpdate(r);
        counter++;
        if (counter >= range+addChange) {		//from https://brainwalletX.github.io
//        if (counter >= range) {				//number of wallets is fixed,
												//but last address not corresponding
												//with address from https://brainwallet.github.io
												//even if specified "Primary Addresses"+1
												//So I leave old condition with +1 address to prevent users loss their funds.
            if (onSuccess) 
                onSuccess();
        } else {
			timeout = setTimeout(
				function(){
					calcAddr(PUBLIC_KEY_VERSION, PRIVATE_KEY_VERSION, ADDRESS_URL_PREFIX, compressed);
				},
				0
			);
		}
    }

    this.init = function(_seed, update, success) {
        seed = Crypto.charenc.UTF8.stringToBytes(_seed);
        oldseed = seed.slice(0);
        rounds = 0;
        onUpdate = update;
        onSuccess = success;
        clearTimeout(timeout);
        calcSeed();
    };

    this.gen = function(_range, update, success, useChange
	, PUBLIC_KEY_VERSION, PRIVATE_KEY_VERSION, ADDRESS_URL_PREFIX, compressed) {		
        addChange = useChange;
        range = _range;
        counter = 0;
        onUpdate = update;
        onSuccess = success;
        clearTimeout(timeout);
        calcAddr(PUBLIC_KEY_VERSION, PRIVATE_KEY_VERSION, ADDRESS_URL_PREFIX, compressed);
    };

    this.stop = function () {
        clearTimeout(timeout);
    };

    return this;
};

function electrum_test() {

    Electrum.init('12345678', function(r) {console.log(r);},
        function() {Electrum.gen(5, function(r) {console.log(r);});});

    /*
    1DLHQhEuLftmAMTiYhw4DvVWhFQ9hnbXio
    1HvoaBYqebPqFaS7GEZzywTaiTrS8cSaCF
    1KMtsVJdde66kjgaK5dcte3TiWfFBF2bC7
    159zjjZB3TadPXE3oeei5MfxTCYu5bqDCd
    1H4uQ5i3MWSiUdHLJiPop9HWw2fe96CrLR
    1EkX2PAY21FuqsKVirZS6wkLkSwbbE4EFD
    */
}
