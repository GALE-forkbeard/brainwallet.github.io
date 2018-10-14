/*
    bitcoinsig.js - sign and verify messages with bitcoin address (public domain)
*/

function msg_numToVarInt(i) {
    if (i < 0xfd) {
      return [i];
    } else if (i <= 0xffff) {
      // can't use numToVarInt from bitcoinjs, BitcoinQT wants big endian here (!)
      return [0xfd, i & 255, i >>> 8];
    } else if (i <= 0xffffffff) {
      return [0xfe, i & 255, (i >>> 8) & 255, (i >>> 16) & 255, i >>> 24];
    } else {
        throw ("message too large");
    }
}

function msg_bytes(message) {
    var b = Crypto.charenc.UTF8.stringToBytes(message);
    return msg_numToVarInt(b.length).concat(b);
}

var strMessageMagic;

function msg_digest(message, strMessageMagic) {
	//You can find the prefix string "strMessageMagic" in the source code of your altcoin.
	//This is contains inside the code of main.cpp , validation.cpp , or another
		//define default bitcoin magic prefix if undefined (not specified)
		strMessageMagic = strMessageMagic || "Bitcoin Signed Message:\n";
	var b = msg_bytes(strMessageMagic).concat(msg_bytes(message));
    return Crypto.SHA256(Crypto.SHA256(b, {asBytes:true}), {asBytes:true});
}

function verify_message(signature, message, strMessageMagic, addrtype, compressed) {

/*
	console.log('verify_message:\n',
				'signature:', signature, '\n',
				'message:', message, '\n',
				'strMessageMagic:', strMessageMagic.split('\n').join('\\n'), '\n',
				'addrtype:', addrtype, '\n',
				'compressed:', compressed
	);
*/	
	
    try {
        var sig = Crypto.util.base64ToBytes(signature);
    } catch(err) {
        return false;
    }

    if (sig.length != 65)
        return false;

    // extract r,s from signature
    var r = BigInteger.fromByteArrayUnsigned(sig.slice(1,1+32));
    var s = BigInteger.fromByteArrayUnsigned(sig.slice(33,33+32));

    // get recid
    var compressed = false;
    var p2shsegwit = false;
    var nV = sig[0];

    if (nV < 27 || nV >= 39)
        return false;
    if (nV >= 35) {
        compressed = true;
        p2shsegwit = true;
        nV -= 8;
    }
    if (nV >= 31) {
        compressed = true;
        nV -= 4;
    }
    var recid = BigInteger.valueOf(nV - 27);

    var ecparams = getSECCurveByName("secp256k1");
    var curve = ecparams.getCurve();
    var a = curve.getA().toBigInteger();
    var b = curve.getB().toBigInteger();
    var p = curve.getQ();
    var G = ecparams.getG();
    var order = ecparams.getN();

    var x = r.add(order.multiply(recid.divide(BigInteger.valueOf(2))));
    var alpha = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(p);
    var beta = alpha.modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p);
    var y = beta.subtract(recid).isEven() ? beta : p.subtract(beta);

    var R = new ECPointFp(curve, curve.fromBigInteger(x), curve.fromBigInteger(y));
    var e = BigInteger.fromByteArrayUnsigned(msg_digest(message, strMessageMagic));
    var minus_e = e.negate().mod(order);
    var inv_r = r.modInverse(order);
    var Q = (R.multiply(s).add(G.multiply(minus_e))).multiply(inv_r);

    var public_key = Q.getEncoded(compressed);
    var addr;
    if (p2shsegwit) {
        var script = Bitcoin.Util.sha256ripe160(public_key);
        script.unshift(0, 20);
        addr = new Bitcoin.Address(Bitcoin.Util.sha256ripe160(script));
        addr.version = 5;
    } else {
        addr = new Bitcoin.Address(Bitcoin.Util.sha256ripe160(public_key));
        addr.version = addrtype ? addrtype : 0;
    }
    return addr.toString();
}

function sign_message(private_key, message, strMessageMagic, compressed, addrtype) {

	//console.log("sign_message: strMessageMagic", strMessageMagic);
    if (!private_key)
        return false;

    //console.log('msg_digest(message)', msg_digest(message));
	
	var signature = private_key.sign(msg_digest(message, strMessageMagic));
    var address = new Bitcoin.Address(private_key.getPubKeyHash());
    address.version = addrtype ? addrtype : 0;

    //convert ASN.1-serialized signature to bitcoin-qt format
    var obj = Bitcoin.ECDSA.parseSig(signature);
    var sequence = [0];
    sequence = sequence.concat(obj.r.toByteArrayUnsigned());
    sequence = sequence.concat(obj.s.toByteArrayUnsigned());

    for (var i = 0; i < 4; i++) {
        var nV = 27 + i;
        if (compressed)
            nV += 4;
        sequence[0] = nV;
        var sig = Crypto.util.bytesToBase64(sequence);
        if (verify_message(sig, message, strMessageMagic, addrtype) == address)
            return sig;
    }

    return false;
}

//function to validate address by decoding base58Check and check checksum
function parseBase58Check(address) {
    var bytes = Bitcoin.Base58.decode(address);
    var end = bytes.length - 4;
    var hash = bytes.slice(0, end);
    var checksum = Crypto.SHA256(Crypto.SHA256(hash, {asBytes: true}), {asBytes: true});
    if (checksum[0] != bytes[end] ||
        checksum[1] != bytes[end+1] ||
        checksum[2] != bytes[end+2] ||
        checksum[3] != bytes[end+3])
            throw new Error("Wrong checksum");
    var version = hash.shift();
    return [version, hash]; //return prefix byte, and 160 hash - as bytearray.
}

	//function to make tests. See console.log (F12-button)
function altcoinssig_test(k, a, s, m, strMessageMagic) {
	//k - private key WIF
	//a - address Base58Check
	//s - digital signature Base58Check
	//m - message text
	//strMessageMagic - prefix string
	
	//test output in console
	console.log(
		'TEST ',
		//just escape '\n' to show. If undefined - show default parameter for bitocoin
		' strMessageMagic:',
			(
				(typeof strMessageMagic !== 'undefined')			//if not undefined
				? strMessageMagic.split('\n').join('\\n')			//show with escaped '\n'
				: "Bitcoin Signed Message:\\n"						//else, if undefined - show default with escaped '\n'
			),
		'\n', //LF
		' key:', k, '\n',
		' address:', a, '\n',
		' specified_signature:', s, '\n',
		' message_text:', m, '\n' //LF again
	);
	

	
	//working with private key
    payload = Bitcoin.Base58.decode(k); 			//parse private key to byte array
    secret = payload.slice(1, 33);					//slice first prefix byte and leave key bytes

	//uncompressed private key contains [prefix_byte + 32 bytes + (0x01, if compressed)].
	//byte array contains +4 bytes base58check checksum. this is CRC32 bytes of previous string.
	//So payload length is 1+32+4 = 37 for uncompressed private key,
	//and 1+32+1+4 = 38 for compressed priv.
	compressed = payload.length == 38;				//set compressed, if private key is compressed (37 bytes for uncompressed, and 38 for compressed)

    var eckey = new Bitcoin.ECKey(secret);			//get eckey
	eckey.setCompressed(compressed);				//set compressed, if compressed
	
	addr = parseBase58Check(a);					//get addr version from specified addr
	//console.log('addr', addr);

	console.log(
				'1. Check specified signature:\n',
				'check s =',s,'\n',
				'status:', (verify_message(s, m, strMessageMagic, addr[0], compressed)===a), '\n',
				'signer address:', verify_message(s, m, strMessageMagic, addr[0], compressed)
	);

	sig = sign_message(eckey, m, strMessageMagic, compressed);
	console.log('\n2. Try to sign again:', sig, '\n');
    
	console.log(
					'3. Check re-signed message:\n',
					' check sig =', sig, '\n',
					'status:', (verify_message(s, m, strMessageMagic, addr[0], compressed)===a), '\n',
					'signer address:', verify_message(sig, m, strMessageMagic, addr[0], compressed),
					'\n\n'
	);
}

/**
	//TESTS for different altcoins. Just uncomment this and see console.log

	//___________________________________________________________________________________________________________________________
	//1. bitcoin - uncompressed key and address
		//signed in brainwallet
		//-----BEGIN BITCOIN SIGNED MESSAGE-----
		//This is an example of a signed message.
		//-----BEGIN SIGNATURE-----
		//18w2rtYxYse12po93P1dkf8QnW8DaYqRTD
		//Gw9xyTzpE30hW596U8TVXb9ZaE38+9MQXGzezDYiAxMDjMHulUYWIVQgcFN9Q0bRZqm2TW2WWMR2xaUOZ0CeqjE=
		//-----END BITCOIN SIGNED MESSAGE-----
	
    var k = '5HsGGnRCbQ8hjjeL5Hi38vrMTzbSqzNtUjJ1JxF1qFwAzjV4KJ1';
    var a = '18w2rtYxYse12po93P1dkf8QnW8DaYqRTD';
    var s = 'Gw9xyTzpE30hW596U8TVXb9ZaE38+9MQXGzezDYiAxMDjMHulUYWIVQgcFN9Q0bRZqm2TW2WWMR2xaUOZ0CeqjE=';
    var m = 'This is an example of a signed message.';
	altcoinssig_test(k, a, s, m); 																					//run test
	//___________________________________________________________________________________________________________________________

	//___________________________________________________________________________________________________________________________
	//2. bitcoin - compressed key and address
		//signed in brainwallet
		//verified in bitcoin-qt.exe
		//verified here: https://tools.bitcoin.com/verify-message/
		
		//-----BEGIN BITCOIN SIGNED MESSAGE-----
		//This is an example of a signed message.
		//-----BEGIN SIGNATURE-----
		//15joXuxYSx9KP2quTQVFiAXbykCve3QtdL
		//HxX3bN5+IIfyWIaTjgzGfA41yPDIrtcGuHQj3tNcbqp6eT3iw4yO14BxzsMFCpLpcn1X/YoFC8v9JJYy615qb2U=
		//-----END BITCOIN SIGNED MESSAGE-----
		
    var k = 'KwSrQfTpAq6zodDmBvk8RzgqL9D35EFcDPg4NEprfzv77VyMr6Kc';
    var a = '15joXuxYSx9KP2quTQVFiAXbykCve3QtdL';
    var s = 'HxX3bN5+IIfyWIaTjgzGfA41yPDIrtcGuHQj3tNcbqp6eT3iw4yO14BxzsMFCpLpcn1X/YoFC8v9JJYy615qb2U=';
    var m = 'This is an example of a signed message.';
	altcoinssig_test(k, a, s, m); 																					//run test
	//___________________________________________________________________________________________________________________________

//altcoins test
	//___________________________________________________________________________________________________________________________
	//3. litecoin - uncompressed key and address
		//signed in brainwallet,
		//verified in brainwallet, by copy and paste (after select LiteCoin in the list),
		//verified in brainwallet, using permalink
		//verified here: https://www.litecoinpool.org/verifymessage
		
		//-----BEGIN BITCOIN SIGNED MESSAGE-----
		//This is an example of a signed message.
		//-----BEGIN SIGNATURE-----
		//LT9z86rndXt4HdVJDWzw2gCAziVVhbinxy
		//HMftz7eGSIjKy7jDL/gqO1MUrw0vAK3blLUiYDapB+rUoZk5aoFRk11Io9+5f5jcNRWd/Q5ZHpLYDAr1NgkQE0I=
		//-----END BITCOIN SIGNED MESSAGE-----
		
    var k = '5HsGGnRCbQ8hjjeL5Hi38vrMTzbSqzNtUjJ1JxF1qFwAzjV4KJ1';
    var a = 'LT9z86rndXt4HdVJDWzw2gCAziVVhbinxy';
    var s = 'HMftz7eGSIjKy7jDL/gqO1MUrw0vAK3blLUiYDapB+rUoZk5aoFRk11Io9+5f5jcNRWd/Q5ZHpLYDAr1NgkQE0I=';
    var m = 'This is an example of a signed message.';
	var strMessageMagic = "Litecoin Signed Message:\n";													//from validation.cpp

	altcoinssig_test(k, a, s, m, strMessageMagic); 																	//run test
	//___________________________________________________________________________________________________________________________

	//___________________________________________________________________________________________________________________________
	//3. DASH - uncompressed key and address
		//signed in brainwallet,
		//verified in brainwallet, by copy and paste (after select LiteCoin in the list),
		//verified in brainwallet, using permalink
		//not verified here: https://insight.dash.org/insight/messages/verify (site is lagging)
		//verified in qt-wallet
		
		//-----BEGIN BITCOIN SIGNED MESSAGE-----
		//This is an example of a signed message.
		//-----BEGIN SIGNATURE-----
		//XtPVZxrdUuMUTAbX1cD96WjdTgM4t6Zxe7
		//GxHw5X4QZwmRadRAF3UiLX5nI6xXc3uZQQ0Ty0j9YC3MPerxqywxamTLjkO2SdsGzG8c67O9EwWpeoeT9BdVQhk=
		//-----END BITCOIN SIGNED MESSAGE-----
		
    var k = '7sHFstkTbdymyjLhcFGmyhAYa4Cij91CGtWbRR9ze13FGbEyRd3';
    var a = 'XtPVZxrdUuMUTAbX1cD96WjdTgM4t6Zxe7';
    var s = 'GxHw5X4QZwmRadRAF3UiLX5nI6xXc3uZQQ0Ty0j9YC3MPerxqywxamTLjkO2SdsGzG8c67O9EwWpeoeT9BdVQhk=';
    var m = 'This is an example of a signed message.';
	var strMessageMagic = "DarkCoin Signed Message:\n";													//from validation.cpp

	altcoinssig_test(k, a, s, m, strMessageMagic); 																	//run test
	//___________________________________________________________________________________________________________________________

	//___________________________________________________________________________________________________________________________
	//5. DASH - compressed key and address
		//signed in brainwallet,
		//verified in brainwallet, by copy and paste (after select LiteCoin in the list),
		//verified in brainwallet, using permalink
		//not verified here: https://insight.dash.org/insight/messages/verify (site is lagging)
		//verified in qt-wallet
		
		//-----BEGIN BITCOIN SIGNED MESSAGE-----
		//-----BEGIN BITCOIN SIGNED MESSAGE-----
		//This is an example of a signed message.
		//-----BEGIN SIGNATURE-----
		//XfReNAcSQfMuXySVKHoUZhDPp5nckGynvp
		//IGwpHEwKeM6jjJtTvcvMb1oSLKjvI6GSBALYGBG2c8dzBX+Z/rvjbp2PHjzoiRqRelqNG2ZWwat72RS5C6IPvR0=
		//-----END BITCOIN SIGNED MESSAGE-----
		
    var k = 'XBWmrvrBUWjSrxE9DgjzwDsrFAUcX2rray1xtmA3zNCCWf3yGYNT';
    var a = 'XfReNAcSQfMuXySVKHoUZhDPp5nckGynvp';
    var s = 'IGwpHEwKeM6jjJtTvcvMb1oSLKjvI6GSBALYGBG2c8dzBX+Z/rvjbp2PHjzoiRqRelqNG2ZWwat72RS5C6IPvR0=';
    var m = 'This is an example of a signed message.';
	var strMessageMagic = "DarkCoin Signed Message:\n";													//from validation.cpp

	altcoinssig_test(k, a, s, m, strMessageMagic); 																	//run test
	//___________________________________________________________________________________________________________________________

	//6. Signatum - compressed key and address
		//signed in brainwallet
		//verified in signatum-qt.exe
		
		//-----BEGIN BITCOIN SIGNED MESSAGE-----
		//This is an example of a signed message.
		//-----BEGIN SIGNATURE-----
		//B9Bt9dQkCTjDpsL54tpDqJLGiMeWRxuH5D
		//IMq7yhsernKH4R5CjypQOGoY1pEO5WYHyYLY+evRNXSeUTSV7b1MBMlJcQswVsPNg0iWz/4X+SYfkgnhapGQY+o=
		//-----END BITCOIN SIGNED MESSAGE-----
		
    var k = 'VFyaRqAVCWpfCE4A2hcPaxeX1Ws8fbLQUDvGcrepc9PwrMWc74Ae';										//compressed priv
    var a = 'B9Bt9dQkCTjDpsL54tpDqJLGiMeWRxuH5D';														//compressed addr
    var m = 'This is an example of a signed message.';													//test message
    var s = 'IMq7yhsernKH4R5CjypQOGoY1pEO5WYHyYLY+evRNXSeUTSV7b1MBMlJcQswVsPNg0iWz/4X+SYfkgnhapGQY+o='; //signature
	var strMessageMagic = "Signatum Signed Message:\n";													//from main.cpp

	altcoinssig_test(k, a, s, m, strMessageMagic); 																	//run test
	//___________________________________________________________________________________________________________________________

	//___________________________________________________________________________________________________________________________
	//7. Signatum - uncompressed key and address
		//Signed in brainwallet:
		//verified in sinatum-qt.exe
		//-----BEGIN BITCOIN SIGNED MESSAGE-----
		//This is an example of a signed message.
		//-----BEGIN SIGNATURE-----
		//BCP7Uc1AJPDuUfHJesLbsnw5X7ZoHSGCMP
		//G0umvkaXsYPlxoBYKSaQ/P/nwFxohWvvPb+oO1gxvCK0AY4Ea6D40j0T/CA91Z1CdEnXMIK7hmGEygSQ+uhlHBM=
		//-----END BITCOIN SIGNED MESSAGE-----
    var k = '7QLAPPhDHCjyERFmBoozE8d9ABPgoMU43zkngPaVTYMc5uT1xXh';
    var a = 'BCP7Uc1AJPDuUfHJesLbsnw5X7ZoHSGCMP';
    var m = 'This is an example of a signed message.';
    var s = 'G0umvkaXsYPlxoBYKSaQ/P/nwFxohWvvPb+oO1gxvCK0AY4Ea6D40j0T/CA91Z1CdEnXMIK7hmGEygSQ+uhlHBM=';
	var strMessageMagic = "Signatum Signed Message:\n";													//from main.cpp

	altcoinssig_test(k, a, s, m, strMessageMagic); 																	//run test
	//___________________________________________________________________________________________________________________________

	//___________________________________________________________________________________________________________________________
	//8. Geertcoin. Compressed key and address:
		//Message signed in brainwallet:
		//-----BEGIN BITCOIN SIGNED MESSAGE-----
		//This is an example of a signed message.
		//-----BEGIN SIGNATURE-----
		//GNaix3HVRokcTW9CPM9N8vsVtuzmjguTrv
		//IJxHyatrfMDh2CWsh8aZSk2fz5tMV1QFPJSL6t4Brx8TE5yn3uuyevBMIDeSeK9y2utxeAIAAATmfwa1FSgH7bs=
		//-----END BITCOIN SIGNED MESSAGE-----

	var k = 'RZUp8o9zpfvDqHixCok4gcHLneqpo8ZEQBM1dVzTLBZ9p5TDnxd5';
    var a = 'GNaix3HVRokcTW9CPM9N8vsVtuzmjguTrv';
    var m = 'This is an example of a signed message.';
    var s = 'IJxHyatrfMDh2CWsh8aZSk2fz5tMV1QFPJSL6t4Brx8TE5yn3uuyevBMIDeSeK9y2utxeAIAAATmfwa1FSgH7bs=';
	var strMessageMagic = "Geertcoin Signed Message:\n";													//from main.cpp
    
	altcoinssig_test(k, a, s, m, strMessageMagic); 																	//run test
	//___________________________________________________________________________________________________________________________

	//___________________________________________________________________________________________________________________________
	//9. Vertcoin - uncompressed key and address
		//signed in brainwallet
		//verified in brainwallet by copy and paste
		//verified in brainwallet, using permalink
		//verified in vertcoin-qt.exe
		
		//-----BEGIN BITCOIN SIGNED MESSAGE-----
		//This is an example of a signed message.
		//-----BEGIN SIGNATURE-----
		//VhvrmbiQxgYD6bhHnAfGBZTGUKRC55M4u8
		//G+5YxvmTVs65s+bVurzrqe8pZ7oVvtEb+rx73aAG2MmEzfB5dwGhvspVKfJ0lCb9x4XGUtr5GDMwXbAX9JSZW/k=
		//-----END BITCOIN SIGNED MESSAGE-----
		
	var k = '5HsGGnRCbQ8hjjeL5Hi38vrMTzbSqzNtUjJ1JxF1qFwAzjV4KJ1';
    var a = 'VhvrmbiQxgYD6bhHnAfGBZTGUKRC55M4u8';
    var m = 'This is an example of a signed message.';
    var s = 'G+5YxvmTVs65s+bVurzrqe8pZ7oVvtEb+rx73aAG2MmEzfB5dwGhvspVKfJ0lCb9x4XGUtr5GDMwXbAX9JSZW/k=';
	var strMessageMagic = "Vertcoin Signed Message:\n";													//from validation.cpp
    
	altcoinssig_test(k, a, s, m, strMessageMagic); 																	//run test
	//___________________________________________________________________________________________________________________________
	
	//and also, here can be test for many other altcoins...
	//Just delete / * and * / to uncomment this.

	//___________________________________________________________________________________________________________________________
	//10. Vertcoin - compressed key and address
		//signed in brainwallet
		//verified in vertcoin-qt.exe
		//-----BEGIN BITCOIN SIGNED MESSAGE-----
		//This is an example of a signed message.
		//-----BEGIN SIGNATURE-----
		//VejdSd7zrm3XSok4CC8t94rTfZVuBwUStu
		//IFUDvvSBNlBLkTztW4SWO/FbgRgPs7PVqpIAuhexJHX9qV3kjdaRPW2vDo+eZNcXkk1Lt/Qe6tdgr4nogvpmWIM=
		//-----END BITCOIN SIGNED MESSAGE-----
		
	var k = 'KwSrQfTpAq6zodDmBvk8RzgqL9D35EFcDPg4NEprfzv77VyMr6Kc';
    var a = 'VejdSd7zrm3XSok4CC8t94rTfZVuBwUStu';
    var m = 'This is an example of a signed message.';
    var s = 'IFUDvvSBNlBLkTztW4SWO/FbgRgPs7PVqpIAuhexJHX9qV3kjdaRPW2vDo+eZNcXkk1Lt/Qe6tdgr4nogvpmWIM=';
	var strMessageMagic = "Vertcoin Signed Message:\n";													//from validation.cpp
    
	altcoinssig_test(k, a, s, m, strMessageMagic); 																	//run test
	//___________________________________________________________________________________________________________________________
	//and also, here can be test for many other altcoins...
	//Just delete / * and * / to uncomment this.
*/

if (typeof require != 'undefined' && require.main === module) {
    window = global; navigator = {}; Bitcoin = {};
    eval(require('fs').readFileSync('./bitcoinjs-min.js')+'');
    eval(require('path').basename(module.filename,'.js')+'_test()');
}