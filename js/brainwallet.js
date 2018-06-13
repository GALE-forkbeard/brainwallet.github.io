//brainwallet.js		
(function($){

    var gen_from = 'pass';
	
	var random_seed = '                                               \
	//________________________________________________________________\
	//Write here anything your,                                       \
	//it can be unique identifier, text, hash, cipher,                \
	//or another random but secret and not dynamic data.              \
	//You can use result of work TRNG here.                           \
	//This increases the cryptographic strength                       \
	//of your simple passwords to complicate any dictionary attacks.  \
	//________________________________________________________________\
	b02bd7b8ad6262d840090f4d4a79c98b609e6d86fbad41756a29caba3fcbadd5 (unique hash for my keys)	\
	';
	//symbol "\" need for multi-string data.
	//private key is base58Check of secret exponent hex.
	//secret exponent now is hash(passphrase) XOR hash(random_seed)
	//Maybe this random seed can be included to the seed parameters for armory and electrum generators.
	
	//see 
	//in armory.js
	//function armory_derive_chaincode(root,random_seed){
	//var msg = 'Derive Chaincode from Root Key';
	//and
	//function armory_decode_keys(data, random_seed)

	//and see electum chaincode derive function...
	
	//to desactivate it for using standart brainwallet, just comment all strings where is "\" and set this value - false
    //P.S. you can do not comment previous parameter. Just uncomment this:
	//var random_seed = false;
	
	//Default coin parameters.
	//Bitcoin
	

	Default_COIN_NAME = "Bitcoin";
	Default_TICKER = "BTC";
	Default_PUBLIC_KEY_VERSION = 0x00;
    Default_PRIVATE_KEY_VERSION = 0x80;
    Default_ADDRESS_URL_PREFIX = 'http://blockchain.info';
	Default_gen_compressed = false;


/*
	Default_COIN_NAME = "GeertCoin";
	Default_TICKER = "GEERT";
	Default_PUBLIC_KEY_VERSION = 0x26;
    Default_PRIVATE_KEY_VERSION = 0xa6;
    Default_ADDRESS_URL_PREFIX = 'https://prohashing.com/explorer/Geertcoin/';
	Default_gen_compressed = true;
*/
/*
To change default coin:
	1. Change this parameters;
	2. Change list <li class="dropdown" id="crCurrency">
	3. set ticker here <span id="crName">BTC</span>
	4. set default start compressed or uncompressed button as class active:
		<label class="btn btn-default active" name="uncomp" title="Uncompressed keys (reference client)">
		or <label class="btn btn-default" name="comp" title="Compressed keys (introduced in 0.5.99)">
	5. That's all.
*/

	
	//set next variable
	var coin_name = Default_COIN_NAME;
	var ticker = Default_TICKER;
	var PUBLIC_KEY_VERSION = Default_PUBLIC_KEY_VERSION;
    var PRIVATE_KEY_VERSION = Default_PRIVATE_KEY_VERSION;
    var ADDRESS_URL_PREFIX = Default_ADDRESS_URL_PREFIX;
	var gen_compressed = Default_gen_compressed;
	
	
    var gen_eckey = null;
    var gen_pt = null;
    var gen_ps_reset = false;
    var TIMEOUT = 600;
    var timeout = null;
	
	var hash_of_random_seed = Crypto.SHA256(random_seed);		//hash of random seed
	
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
        return [version, hash];
    }

    encode_length = function(len) {
        if (len < 0x80)
            return [len];
        else if (len < 255)
            return [0x80|1, len];
        else
            return [0x80|2, len >> 8, len & 0xff];
    }

    encode_id = function(id, s) {
        var len = encode_length(s.length);
        return [id].concat(len).concat(s);
    }

    encode_integer = function(s) {
        if (typeof s == 'number')
            s = [s];
        return encode_id(0x02, s);
    }

    encode_octet_string = function(s)  {
        return encode_id(0x04, s);
    }

    encode_constructed = function(tag, s) {
        return encode_id(0xa0 + tag, s);
    }

    encode_bitstring = function(s) {
        return encode_id(0x03, s);
    }

    encode_sequence = function() {
        sequence = [];
        for (var i = 0; i < arguments.length; i++)
            sequence = sequence.concat(arguments[i]);
        return encode_id(0x30, sequence);
    }

    function getEncoded(pt, compressed) {
       var x = pt.getX().toBigInteger();
       var y = pt.getY().toBigInteger();
       var enc = integerToBytes(x, 32);
       if (compressed) {
         if (y.isEven()) {
           enc.unshift(0x02);
         } else {
           enc.unshift(0x03);
         }
       } else {
         enc.unshift(0x04);
         enc = enc.concat(integerToBytes(y, 32));
       }
       return enc;
    }

    function getDER(eckey, compressed) {
        var curve = getSECCurveByName("secp256k1");
        var _p = curve.getCurve().getQ().toByteArrayUnsigned();
        var _r = curve.getN().toByteArrayUnsigned();
        var encoded_oid = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x01, 0x01];

        var secret = integerToBytes(eckey.priv, 32);
        var encoded_gxgy = getEncoded(curve.getG(), compressed);
        var encoded_pub = getEncoded(gen_pt, compressed);

        return encode_sequence(
            encode_integer(1),
            encode_octet_string(secret),
            encode_constructed(0,
                encode_sequence(
                    encode_integer(1),
                    encode_sequence(
                        encoded_oid, //encode_oid(*(1, 2, 840, 10045, 1, 1)), //TODO
                        encode_integer([0].concat(_p))
                    ),
                    encode_sequence(
                        encode_octet_string([0]),
                        encode_octet_string([7])
                    ),
                    encode_octet_string(encoded_gxgy),
                    encode_integer([0].concat(_r)),
                    encode_integer(1)
                )
            ),
            encode_constructed(1,
                encode_bitstring([0].concat(encoded_pub))
            )
        );
    }

    function pad(str, len, ch) {
        padding = '';
        for (var i = 0; i < len - str.length; i++) {
            padding += ch;
        }
        return padding + str;
    }

    function setErrorState(field, err, msg) {
        var group = field.closest('.controls').parent();
        if (err) {
            group.addClass('has-error');
            group.attr('title',msg);
        } else {
            group.removeClass('has-error');
            group.attr('title','');
        }
    }

    function genRandom() {
        $('#pass').val('');
        $('#hash').focus();
        gen_from = 'hash';
        $('#from_hash').click();
        genUpdate();
        var bytes = secureRandom(32);
        $('#hash').val(Crypto.util.bytesToHex(bytes));
        generate();
    }

	function gen_update_sec_exp() {
        $('#pass').val('');
        $('#hash').focus();
        gen_from = 'hash';
        $('#from_hash').click();
        genUpdate();
        var bytes = Crypto.util.hexToBytes($('#hash').val());
        generate();
    }
	
    function genUpdate() {
        setErrorState($('#hash'), false);
        setErrorState($('#sec'), false);
        setErrorState($('#der'), false);
        $('#pass').attr('readonly', gen_from != 'pass');
        $('#hash').attr('readonly', gen_from != 'hash');
        $('#sec').attr('readonly', gen_from != 'sec');
        $('#der').attr('readonly', gen_from != 'der');
        $('#sec').parent().parent().removeClass('error');
    }

    function genUpdateFrom() {
        gen_from = $(this).attr('id').substring(5);
        genUpdate();
        if (gen_from == 'pass') {
            if (gen_ps_reset) {
                gen_ps_reset = false;
                onChangePass();
            }
            $('#pass').focus();
        } else if (gen_from == 'hash') {
            $('#hash').focus();
        } else if (gen_from == 'sec') {
            $('#sec').focus();
			if ($('#sec').closest('.form-group').css('display') == 'none'){
				$('#toggleKeyCode').trigger("click");			
			}
        } else if (gen_from == 'der') {
            $('#der').focus();
        }
    }
	
    function generate() {
        var hash_str = pad($('#hash').val(), 64, '0');
        var hash = Crypto.util.hexToBytes(hash_str);
        eckey = new Bitcoin.ECKey(hash);
        gen_eckey = eckey;

        try {
            var curve = getSECCurveByName("secp256k1");
            gen_pt = curve.getG().multiply(eckey.priv);
            gen_eckey.pub = getEncoded(gen_pt, gen_compressed);
            gen_eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(gen_eckey.pub);
            setErrorState($('#hash'), false);
        } catch (err) {
            //console.info(err);
            setErrorState($('#hash'), true, 'Invalid secret exponent (must be non-zero value)');
            return;
        }

        gen_update();
    }
		
    function genOnChangeCompressed() {
        setErrorState($('#hash'), false);
        setErrorState($('#sec'), false);
        gen_compressed = ($(this).attr('name') == 'compressed');
        gen_eckey.pub = getEncoded(gen_pt, gen_compressed);
        gen_eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(gen_eckey.pub);
        gen_update();
    }

    function getAddressURL(addr)
    {
        if (ADDRESS_URL_PREFIX.indexOf('explorer.dot-bit.org')>=0 )
          return ADDRESS_URL_PREFIX+'/a/'+addr;
        else if (ADDRESS_URL_PREFIX.indexOf('address.dws')>=0 )
          return ADDRESS_URL_PREFIX+ "?" + addr;
        else if (ADDRESS_URL_PREFIX.indexOf('chainbrowser.com')>=0 )
          return ADDRESS_URL_PREFIX+'/address/'+addr+'/';
        else
          return ADDRESS_URL_PREFIX+'/address/'+addr;
    }

	//XOR hex strings function
	function XOR_hex(a, b) {
		var res = "",
			i = a.length,
			j = b.length;
		while (i-- >0 && j-- >0)
			res = (parseInt(a.charAt(i), 16) ^ parseInt(b.charAt(j), 16)).toString(16) + res;
		
		//document.write(res+"<br>"); //comment it
		return res;
	}
	
    function gen_update(segwit_addr) {
		segwit_addr = segwit_addr || false;
		
        var compressed = gen_compressed;
		var eckey = gen_eckey;
		//if(compressed){ //if key is compressed
		//	//push 0x01 byte from beginning - to BigInteger (priv * 0x100 + 0x01)
		//	eckey['priv'] = eckey['priv'].multiply(new BigInteger('100', 16)).add(new BigInteger('1')).toString(16);
		//}
		
		//console.log('push 0x01 to bigint: ', eckey.multiply(new BigInteger('100', 16)).add(new BigInteger('1')).toString());
		
        //eckey = eckey.setCompressed(compressed);
		//console.log('compressed.... eckey', eckey.toString());
        

        var hash_str = pad($('#hash').val(), 64, '0'); //secret exponent
        var hash = Crypto.util.hexToBytes(hash_str); //bytes
		
		
        
        
		if(segwit_addr===true){	//SegWit address
			pubkey = Crypto.util.bytesToHex(getEncoded(gen_pt, compressed));
			var hash160 = [0x00,0x14].concat(Bitcoin.Util.sha256ripe160(getEncoded(gen_pt, compressed)));
			hash160 = Bitcoin.Util.sha256ripe160(hash160);
			//add tooltip
			$('#addr').attr('title', "SegWit format Address [0x00,0x14]");
			$('#h160').attr('title', "SegWit format hash160 [0x00,0x14]");
			
			var h160 = Crypto.util.bytesToHex(hash160);
			$('#h160').val(h160);
			var addr = new Bitcoin.Address(hash160);
			addr.version = PUBLIC_KEY_VERSION;
			
		}else if(segwit_addr==='ZCash_t-addr'){
			//code...
			var hash160 = eckey.getPubKeyHash();
			hash160 = [0xb8].concat(hash160);
			//add tooltip
			$('#addr').attr('title', 'ZCash t-address [0x1c,0xb8]\n\
To convert t-addresses (ZCash, Votecoin, and another coins)\n\
to your associated bitcoin address\n\
	1. Go to Converter tab\n\
	2. Copy and paste your t-address there \n\
	3. from Base58Check -> to Hex\n\
	4. Copy this hex and discard the byte b8 at first in this hex\n\
	5. Convert the remaining hexadecimal value from hex to Base58Check.\n\
	6. Check in the bottom "B58Check ver. 0x00 (34 characters)"\n\
	7. Copy and paste your bitcoin address.');//many strings tooltip
			$('#h160').attr('title', 'ZCash byte 0xb8 inserted here');
			
			var h160 = Crypto.util.bytesToHex(hash160);
			$('#h160').val(h160);
			var addr = new Bitcoin.Address(hash160);
			addr.version = 0x1c;						//t-addressed prefix PUBLIC_KEY_VERSION byte
			
		}else{					//default address
			//а он может быть компрессед или ункомпрессед.
			
			eckey.pub = getEncoded(gen_pt, compressed);
			eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(eckey.pub);
			var hash160 = eckey.getPubKeyHash();
			//return default tooltip 
			$('#addr').attr('title', "Bitcoin Address (Base58Check of HASH160)");
			$('#h160').attr('title', "Hex-encoded address, RIPEMD160(SHA256(Public Key))");
			
			var h160 = Crypto.util.bytesToHex(hash160);
			$('#h160').val(h160);
			var addr = new Bitcoin.Address(hash160);
			addr.version = PUBLIC_KEY_VERSION;
		}

        $('#addr').val(addr);
		$('#name').val($('#addr').val()+".txt");				//addr to key file name

		var payload = hash;					//bytes of secret exponent
		if (compressed)
            payload.push(0x01);						//push 0x01 if compressed

		
        var sec = new Bitcoin.Address(payload); //correctly updated
		sec.version = PRIVATE_KEY_VERSION;
		
		$('#sec').val(sec);
		$('#sgSec').val($('#sec').val());
		$('#sgAddr').val($('#addr').val());
		
		hex_of_priv = Crypto.util.bytesToHex(payload);
		
		//$('#keyfiledata').val(hex_of_priv);	//priv_in_hex. This value is depended from set compressed or uncompressed key.
		$('#keyfiledata').val(XOR_hex(Crypto.SHA256(hex_of_priv), Crypto.SHA256(hash_of_random_seed+addr)));
		//key = sha256(priv) XOR sha256(sha256(random_seed+addr));
		//This value depended from selected coin, because prefix of public key for this coin included to dynamic seed.
		
        var pub = Crypto.util.bytesToHex(getEncoded(gen_pt, compressed));
        $('#pub').val(pub);

        var der = Crypto.util.bytesToHex(getDER(eckey, compressed));
        $('#der').val(der);

        var qrCode = qrcode(3, 'M');
        var text = $('#addr').val();
        text = text.replace(/^[\s\u3000]+|[\s\u3000]+$/g, '');
        qrCode.addData(text);
        qrCode.make();

        $('#genAddrQR').html(qrCode.createImgTag(4));
        $('#genAddrURL').attr('href', getAddressURL(addr));
        $('#genAddrURL').attr('title', addr);

        var keyQRCode = qrcode(3, 'L');
        var text = $('#sec').val();
        text = text.replace(/^[\s\u3000]+|[\s\u3000]+$/g, '');
        keyQRCode.addData(text);
        keyQRCode.make();

        $('#genKeyQR').html(keyQRCode.createImgTag(4));
        // NMC fix
        if (ADDRESS_URL_PREFIX.indexOf('explorer.dot-bit.org')>=0 )
          $('#genAddrURL').attr('href', ADDRESS_URL_PREFIX+'/a/'+addr);

        // chainbrowser fix (needs closing slash for some reason)
        if (ADDRESS_URL_PREFIX.indexOf('chainbrowser.com')>=0 )
          $('#genAddrURL').attr('href', ADDRESS_URL_PREFIX+'/address/'+addr+'/');

		
		var ticker = $('#coin_name').attr('ticker');
		var coin_name = $('#coin_name').attr('coin_name');
		$('#altcoin_name').text(coin_name || Default_COIN_NAME);
		$('#ticker').text(ticker || Default_TICKER);
		$('#coin_name').text((coin_name || Default_COIN_NAME).toUpperCase() + ' (' + (ticker || Default_TICKER) + ')');
		
		
		PubVer = parseInt(PUBLIC_KEY_VERSION);
		if(PubVer<=15){firstbyte ='0';}else{firstbyte = '';}
		$('#PubVer').text('Public key version byte: 0x'+firstbyte+PubVer.toString(16));
		
		PrivVer = parseInt(PRIVATE_KEY_VERSION);
		if(PrivVer<=15){firstbyte ='0';}else{firstbyte = '';}
		$('#PrivVer').text('Private key version byte: 0x'+firstbyte+PrivVer.toString(16));
		if(compressed==true){
			$('#compressed').text('Keys and addresses: Compressed');
		}else{
			$('#compressed').text('Keys and addresses: Uncompressed');
		}
		$('#block_explorer').text("Block-explorer: "+ADDRESS_URL_PREFIX);
		$('#block_explorer').attr('href', ADDRESS_URL_PREFIX);
	}	
			
	//sec_exponent = hash(passphrase) XOR hash(random_seed)
    function genCalcHash() {
		//document.write("<br>random_seed "+random_seed);			//test random_seed value in this function.
		
		if(random_seed == false){//if random_seed not active
			//using original brainwallet function
			var hash = Crypto.SHA256($('#pass').val());
		}else{
			//using brainwallet with specified random_seed
			//using xor at hash(random_seed). This was been defined.
			
			var hash_of_passphase = Crypto.SHA256($('#pass').val());	//this value is depending from entered passphrase.
			var hash = XOR_hex(hash_of_random_seed, hash_of_passphase); //XOR this two hashes

			//document.write("<br>hash_of_random_seed "+hash_of_random_seed); 	//print value of hash random_seed
			//0a743e5fcb375bcc6b9a044b6df5feaa309e939d9a29275265c3ecdb025bf905
			
			//you can see it in converter page
			//uncomment this two strings and press sha256-button in the section Converter
			//$('#src').val(random_seed);
			//$('#enc_to [id="to_sha256"]').addClass('active');
			//result 0a743e5fcb375bcc6b9a044b6df5feaa309e939d9a29275265c3ecdb025bf905			
		}
	
		//document.write("<br>hash is secret exponent: "+hash); //echo value of new secret exponent
		$('#hash').val(hash);		//set up hash_of_random_seed in the field of form.
		$('#hash_random_seed').val(hash_of_random_seed);		//set up secret exponent in the field of form.
		$('#chhash_random_seed').val(hash_of_random_seed);
		$('#hash_passphrase').val(hash_of_passphase);		//set up secret exponent in the field of form.
		
		//This value is a private key hex.
		//Generator -> press "Togle Key" button -> Private key WIF -> converter -> from Base58Check to hex -> is this value.
		//from Base58Check: 5KbEudEWZMr38UFxUrEww3ERKt3Pcc665cuQXBh3zoH6GZvkyBN
		//to hex: e9c4fa1d53cb47d8f161f083f49a478e1730d279feb2b41ec15675c07a094150
		//== Secret Exponent == hash value.
		
		//So when random_seed is defined and not false,
		//then private_key = Base58Check(hash(passphase) XOR hash(random_seed));
    }

    function onChangePass() {
        genCalcHash();
        clearTimeout(timeout);
        timeout = setTimeout(generate, TIMEOUT);
    }

    function onChangeHash() {
        $('#pass').val('');
        gen_ps_reset = true;
        clearTimeout(timeout);

        if (/[^0123456789abcdef]+/i.test($('#hash').val())) {
            setErrorState($('#hash'), true, 'Erroneous characters (must be 0..9-a..f)');
            return;
        } else {
            setErrorState($('#hash'), false);
        }

        timeout = setTimeout(generate, TIMEOUT);
    }

    function setCompressed(compressed) {
      gen_compressed = compressed || Default_gen_compressed; // global
      // toggle radio button without firing an event
      $('#gen_comp label input').off();
      $('#gen_comp label input[name='+(gen_compressed?'compressed':'uncompressed')+']').click();
      $('#gen_comp label input').on('change', genOnChangeCompressed);
    }
	
	function setSegwitAddr(segwit_addr) {
	  if(segwit_addr==="SegWit address"){segwit_addr=true;}
	  else if(segwit_addr==="ZCash t-address"){segwit_addr='ZCash_t-addr'}
	  else{segwit_addr=false;}
      // toggle radio button without firing an event
      //$('#gen_comp label input').off();
      //$('#gen_comp label input[name='+(gen_compressed?'compressed':'uncompressed')+']').click();
      //$('#gen_comp label input').on('change', genOnChangeCompressed);
	  //document.write(segwit_addr);
	  gen_update(segwit_addr);
    }
	
	

    function genOnChangePrivKey() {

        clearTimeout(timeout);

        $('#pass').val('');
        gen_ps_reset = true;

        var sec = $('#sec').val();

        try {
            var res = parseBase58Check(sec);
            var version = res[0];
            var payload = res[1];
        } catch (err) {
            setErrorState($('#sec'), true, 'Invalid private key checksum');
            return;
        };

        if (version != PRIVATE_KEY_VERSION) {
            setErrorState($('#sec'), true, 'Invalid private key version');
            return;
        } else if (payload.length != 32 && payload.length != 33) {
            setErrorState($('#sec'), true, 'Invalid payload (must be 32 or 33 bytes)');
            return;
        }

        setErrorState($('#sec'), false);

        if (payload.length > 32) {
            payload.pop();
            setCompressed(true);
        } else {
            setCompressed(false);
        }

        $('#hash').val(Crypto.util.bytesToHex(payload));

        timeout = setTimeout(generate, TIMEOUT);
    }

    function genUpdateDER() {
      var s = $('#der').val();
      s = s.replace(/[^A-Fa-f0-9]+/g, '');
      var bytes = Crypto.util.hexToBytes(s);
      try {
        var asn1 = ASN1.decode(bytes);
        var r = asn1.sub[1];
        if (r.length!=32)
          throw('key length mismatch');
        var ofs = r.header + r.stream.pos;
        var priv = r.stream.enc.slice(ofs, ofs + r.length);
        var hex = Crypto.util.bytesToHex(priv);
        $('#hash').val(hex);

        // get public key
        r = asn1.sub[2].sub[0].sub[3];
        ofs = r.header + r.stream.pos;
        var pub = r.stream.enc.slice(ofs, ofs + r.length);
        setCompressed(pub[0]!=0x04);

        setErrorState($('#der'), false);
        $('#pass').val('');

        generate();
      } catch (err) {
        setErrorState($('#der'), true, err);
      }
    }

    function genOnChangeDER() {
      timeout = setTimeout(genUpdateDER, TIMEOUT);
    }

    function genRandomPass() {
        // chosen by fair dice roll
        // guaranted to be random
        $('#from_pass').button('toggle');
        $('#pass').focus();
        gen_from = 'pass';
        genUpdate();
        genCalcHash();
        generate();
    }

    // --- converter ---

    var from = '';
    var to = 'hex';

    function update_enc_from() {
        $(this).addClass('active');	//add class "active" for input...
        from = $(this).attr('id').substring(5);
        translate();
    }

    function update_enc_to() {
        $(this).addClass('active');
        to = $(this).attr('id').substring(3);
        translate();
    }

	//f3e7d2655e60ab06ca99ddd187f84f49782bb47bac397e9cba677194a643b3c4 from hex -> encoded to text as
	//óçÒe^`«ÊÝÑøOIx+´{¬9~ºgq¦C³Ä
	//that's ok, here: http://www.convertstring.com/EncodeDecode/HexDecode
	//but here... http://www.endmemo.com/unicode/unicodeconverter.php
	//UTF-8 Code (e.g. 20 E2 88 9A): - give an another hex...
	
	//C3 B3 C3 A7 C3 92 65 5E 60 C2 AB 06 C3 8A C2 99 C3 9D C3 91 C2 87 C3 B8 4F 49 78 2B
	//C2 B4 7B C2 AC 39 7E C2 9C C2 BA 67 71 C2 94 C2 A6 43 C2 B3 C3 84
	//this hex in the source code of text file:
	//Offset      0  1  2  3  4  5  6  7   8  9 10 11 12 13 14 15
	//00000000   C3 B3 C3 A7 C3 92 65 5E  60 C2 AB 06 C3 8A C2 99   ГіГ§Г’e^`В« ГЉВ™
	//00000016   C3 9D C3 91 C2 87 C3 B8  4F 49 78 2B C2 B4 7B C2   ГќГ‘В‡ГёOIx+Вґ{В
	//00000032   AC 39 7E C2 9C C2 BA 67  71 C2 94 C2 A6 43 C2 B3   ¬9~ВњВєgqВ”В¦CВі
	//00000048   C3 84                                              Г„
	
	//but real hex file have this code
	//Offset      0  1  2  3  4  5  6  7   8  9 10 11 12 13 14 15
	//00000000   F3 E7 D2 65 5E 60 AB 06  CA 99 DD D1 87 F8 4F 49   узТe^`« К™ЭС‡шOI
	//00000016   78 2B B4 7B AC 39 7E 9C  BA 67 71 94 A6 43 B3 C4   x+ґ{¬9~њєgq”¦CіД
	
	
/*
Hex to ASCII text conversion table
Hexadecimal	Binary	ASCII
Character
00	00000000	NUL
01	00000001	SOH
02	00000010	STX
03	00000011	ETX
04	00000100	EOT
05	00000101	ENQ
06	00000110	ACK
07	00000111	BEL
08	00001000	BS
09	00001001	HT
0A	00001010	LF
0B	00001011	VT
0C	00001100	FF
0D	00001101	CR
0E	00001110	SO
0F	00001111	SI
10	00010000	DLE
11	00010001	DC1
12	00010010	DC2
13	00010011	DC3
14	00010100	DC4
15	00010101	NAK
16	00010110	SYN
17	00010111	ETB
18	00011000	CAN
19	00011001	EM
1A	00011010	SUB
1B	00011011	ESC
1C	00011100	FS
1D	00011101	GS
1E	00011110	RS
1F	00011111	US
20	00100000	Space
21	00100001	!
22	00100010	"
23	00100011	#
24	00100100	$
25	00100101	%
26	00100110	&
27	00100111	'
28	00101000	(
29	00101001	)
2A	00101010	*
2B	00101011	+
2C	00101100	,
2D	00101101	-
2E	00101110	.
2F	00101111	/
30	00110000	0
31	00110001	1
32	00110010	2
33	00110011	3
34	00110100	4
35	00110101	5
36	00110110	6
37	00110111	7
38	00111000	8
39	00111001	9
3A	00111010	:
3B	00111011	;
3C	00111100	<
3D	00111101	=
3E	00111110	>
3F	00111111	?
40	01000000	@
41	01000001	A
42	01000010	B
43	01000011	C
44	01000100	D
45	01000101	E
46	01000110	F
47	01000111	G
48	01001000	H
49	01001001	I
4A	01001010	J
4B	01001011	K
4C	01001100	L
4D	01001101	M
4E	01001110	N
4F	01001111	O
50	01010000	P
51	01010001	Q
52	01010010	R
53	01010011	S
54	01010100	T
55	01010101	U
56	01010110	V
57	01010111	W
58	01011000	X
59	01011001	Y
5A	01011010	Z
5B	01011011	[
5C	01011100	\
5D	01011101	]
5E	01011110	^
5F	01011111	_
60	01100000	`
61	01100001	a
62	01100010	b
63	01100011	c
64	01100100	d
65	01100101	e
66	01100110	f
67	01100111	g
68	01101000	h
69	01101001	i
6A	01101010	j
6B	01101011	k
6C	01101100	l
6D	01101101	m
6E	01101110	n
6F	01101111	o
70	01110000	p
71	01110001	q
72	01110010	r
73	01110011	s
74	01110100	t
75	01110101	u
76	01110110	v
77	01110111	w
78	01111000	x
79	01111001	y
7A	01111010	z
7B	01111011	{
7C	01111100	|
7D	01111101	}
7E	01111110	~
7F	01111111	DEL
*/

//I don't see this symbols here, so link "download as binary." was been added.

    // stringToBytes, exception-safe
    function stringToBytes(str) {
      try {
        var bytes = Crypto.chardec.UTF8.stringToBytes(str);		//char decode
      } catch (err) {
        var bytes = [];
        for (var i = 0; i < str.length; ++i)
           bytes.push(str.charCodeAt(i));
      }
      return bytes;
    }

    // bytesToString, exception-safe
    function bytesToString(bytes) {
      try {
        var str = Crypto.charenc.UTF8.bytesToString(bytes); 	//char encode
      } catch (err) {
        var str = '';
        for (var i = 0; i < bytes.length; ++i)
            str += String.fromCharCode(bytes[i]);
      }
	  
      return str;
    }
	

    function isHex(str) {
        return !/[^0123456789abcdef]+/i.test(str);
    }

    function isBase58(str) {
        return !/[^123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+/.test(str);
    }

    function isBase64(str) {
        return !/[^ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=]+/.test(str) && (str.length % 4) == 0;
    }

    function isBin(str) {
      return !/[^01 \r\n]+/i.test(str);
    }

    function isDec(str) {
      return !/[^0123456789]+/i.test(str);
    }

    function issubset(a, ssv, min_words) {
        var b = ssv.trim().split(' ');
        if (min_words>b.length)
            return false;
        for (var i = 0; i < b.length; i++) {
            if (a.indexOf(b[i].toLowerCase()) == -1
                && a.indexOf(b[i].toUpperCase()) == -1)
            return false;
        }
        return true;
    }

    function isEasy16(str) {
      return !/[^asdfghjkwertuion \r\n]+/i.test(str);
    }

    function autodetect(str) {
        var enc = [];
        var bstr = str.replace(/[ :,\n]+/g,'').trim();
        if ( isBin(bstr) )
            enc.push('bin');
        if (isDec(bstr) )
            enc.push('dec');
        if (isHex(bstr))
            enc.push('hex');
        if (isBase58(bstr)) {
            // push base58check first (higher priority)
            try {
                var res = parseBase58Check(bstr);
                enc.push('base58check');
            } catch (err) {};
        }
        if (issubset(mn_words, str, 3))
            enc.push('mnemonic');
        if (issubset(rfc1751_wordlist, str, 6))
            enc.push('rfc1751');
        if (isEasy16(bstr))
          enc.push('easy16');
        if (isBase64(bstr))
            enc.push('base64');
        if (str.length > 0) {
            enc.push('text');
            enc.push('rot13');
        }
        if (isBase58(bstr)) {
          // arbitrary text should have higher priority than base58
          enc.push('base58');
        }
		
		enc.push('raw');	//just push raw here, to don't disable this.
        return enc;
    }

    function update_toolbar(enc_list) {
        var reselect = false;

        $.each($('#enc_from').children(), function() {
            var enc = $(this).children().attr('id').substring(5);
            var disabled = (enc_list && enc_list.indexOf(enc) == -1);
            if (disabled && $(this).hasClass('active')) {
                $(this).removeClass('active');
                reselect = true;
            }
            $(this).attr('disabled', disabled);
        });

        if (enc_list && enc_list.length > 0) {
            if (reselect || from=='') {
              from = enc_list[0];
              $('#from_' + from).click();
            }
        }

		if($('#from_raw').hasClass('active')){
				$('#src').attr("readonly", "readonly");
//Here you can see a multistring commentary as multistring title.
				$('#src').attr('title', "Select the file to import RAW-data.\n\
Here will be base64-encoded file-content.\n\n\
Or select another encoding to input the text here.");
				$('#upload_source_from_file').attr('onchange', 'openFile(event, "src", "as_base64");')
		}else{
			$('#src').prop('title', false);
			$('#src').removeAttr('title');
			$('#src').removeAttr('readonly');
			$('#upload_source_from_file').attr('onchange', 'openFile(event, "src");');
		}
		
		
		if($('#to_base58check').hasClass('active') && $('#from_base58check').hasClass('active')){
			$('#dest').attr('title', "If this is a converted address for any coin, selected in the list - this is an uncompressed address.");
		}else{
			$('#dest').removeAttr('title'); //remove attribute
		}
		
    }

    function rot13(str) {
        return str.replace(/[a-zA-Z]/g, function(c) {
          return String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26);
        });
    }

    function fromEasy16(str) {
      var keys = str.split('\n');
      var res = [];
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i].replace(' ','');
        var raw = Crypto.util.hexToBytes(armory_map(k, armory_f, armory_t));
        data = raw.slice(0, 16);
        res = res.concat(data);
      }
      return res;
    }

    function toEasy16(bytes) {
        var keys = armory_encode_keys(bytes,[]);
        var lines = keys.split('\n');
        var res = [];
        for (var i in lines) {
          if (lines[i].trim(' ').split(' ').length==9)
            res.push(lines[i]);
        }
        return res.join('\n');
    }

    function toBin(bytes)
    {
      var arr = [];
      for (var i=0; i<bytes.length;i++)
      {
        var s = (bytes[i]).toString(2);
        arr.push(('0000000' + s).slice(-8));
      }
      return arr.join(' ');
    }

    function fromBin(str)
    {
      var arr = str.trim().split(/[\r\n ]+/);
      arr = [arr.join('')]; // this line actually kills separating bytes with spaces (people get confused), comment it out if you want
      var res = [];
      for (var i=0; i<arr.length; i++)
      {
        var bstr = arr[i];
        var s = ('0000000'+bstr).slice(-Math.ceil(bstr.length/8)*8); // needs padding
        var chunks = s.match(/.{1,8}/g);
         for (var j=0;j<chunks.length;j++)
          res.push(parseInt(chunks[j], 2));
      }
      return res;
    }

    function fromDec(str)
    {
        var h = new BigInteger(str).toString(16);
        return Crypto.util.hexToBytes(h.length%2?'0'+h:h);
    }

    function toDec(bytes)
    {
        var h = Crypto.util.bytesToHex(bytes);
        return new BigInteger(h,16).toString(10);
    }

    function enct(id) {
        return $('#from_'+id).parent().text();
    }

    function pad_array(bytes, n)
    {
      if (n==0) // remove padding
      {
        var res = bytes.slice(0);
        while (res.length>1 && res[0]==0)
          res.shift();
        return res;
      }

      // align to n bytes
      var len = bytes.length;
      var padding = Math.ceil(len/n)*n - len;
      var res = bytes.slice(0);
      for (i=0;i<padding;i++)
        res.unshift(0);
      return res;
    }

    function translate() {

        var str = $('#src').val();

        if (str.length == 0) {
          update_toolbar(null);
          $('#hint_from').text('');
          $('#hint_to').text('');
          $('#dest').val('');
		  
		  //hide download links if empty from src field is empty.
          $('#download_as_binary').hide();
          $('#download-converted').hide();
          
		  return;
        }

        text = str;

        var enc = autodetect(str);

        update_toolbar(enc);

        bytes = stringToBytes(str);

        var type = '';
        var addVersionByte = true; // for base58check

        if (bytes.length > 0) {
		
			if (from == 'raw') {
				var bstr = str;
				try { bytes = Crypto.util.base64ToBytes(bstr); } catch (err) {}
				var already_encoded_b64 = true;
			}
            else{
				var bstr = str.replace(/[ :,\n]+/g,'').trim();

				if (from == 'base58check') {
					try {
						var res = parseBase58Check(bstr);
						type = ' ver. 0x' + Crypto.util.bytesToHex([res[0]]);
						bytes = res[1];
						if (!addVersionByte)
						bytes.unshift(res[0]);
					} catch (err) {};
				} else if (from == 'base58') {
					bytes = Bitcoin.Base58.decode(bstr);
				} else if (from == 'hex') {
					bytes = Crypto.util.hexToBytes(bstr.length%2?'0'+bstr:bstr); // needs padding
				} else if (from == 'rfc1751') {
					try { bytes = english_to_key(str); } catch (err) { type = ' ' + err; bytes = []; };
				} else if (from == 'mnemonic') {
					bytes = Crypto.util.hexToBytes(mn_decode(str.trim()));
				} else if (from == 'base64') {
					try { bytes = Crypto.util.base64ToBytes(bstr); } catch (err) {}
				} else if (from == 'rot13') {
					bytes = stringToBytes(rot13(str));
				} else if (from == 'bin') {
					bytes = fromBin(str);
				} else if (from == 'easy16') {
					bytes = fromEasy16(str);
				} else if (from == 'dec') {
					bytes = fromDec(bstr);
				}
			}
            var ver = '';
            if (to == 'base58check') {
               var version = bytes.length <= 20 ? PUBLIC_KEY_VERSION : PRIVATE_KEY_VERSION;
               var buf = bytes.slice();
               if (!addVersionByte)
                version = buf.shift();
               var addr = new Bitcoin.Address(buf);
               addr.version = version;
               text = addr.toString();
               ver = ' ver. 0x' + Crypto.util.bytesToHex([addr.version]);
            } else if (to == 'base58') {
                text = Bitcoin.Base58.encode(bytes);
            } else if (to == 'hex') {
                text = Crypto.util.bytesToHex(bytes);
            } else if (to == 'text') {
                text = bytesToString(bytes);
				console.log(bytes);
            } else if (to == 'rfc1751') {
                text = key_to_english(pad_array(bytes,8));
            } else if (to == 'mnemonic') {
                text = mn_encode(Crypto.util.bytesToHex(pad_array(bytes,4)));
            } else if (to == 'base64') {
                text = Crypto.util.bytesToBase64(bytes);
            } else if (to == 'rot13') {
                text = rot13(bytesToString(bytes));
            } else if (to == 'bin') {
                text = toBin(bytes);
            } else if (to == 'easy16') {
                text = toEasy16(pad_array(bytes,32));
            } else if (to == 'sha256') {
                text = Crypto.SHA256(bytes);
            } else if (to == 'dec') {
                text = toDec(bytes);
            }
        }

        $('#hint_from').text(enct(from) + type + ' (' + bytes.length + ' byte' + (bytes.length == 1 ? ')' : 's)'));
        $('#hint_to').text(enct(to) + ver + ' (' + text.length + ' character' + (text.length == 1 ? ')' : 's)'));
        $('#dest').val(text);
		
		
		if(already_encoded_b64===true){
			var base64 = bstr;
			console.log('bstr', bstr);
		}else{
			var base64 = Crypto.util.bytesToBase64(bytes);
		}
			$('#download_as_binary').attr('href', "data:application/octet-stream;base64,"+base64);
		
		linkText(document.getElementById('dest'), document.getElementById('download-converted'), 'converted.txt')
		
		$('#download_as_binary').show();
		$('#download-converted').show();
    }

    function onChangeFrom() {
        clearTimeout(timeout);
        timeout = setTimeout(translate, TIMEOUT);
    }

    function onInput(id, func) {
        $(id).bind("input keyup keydown keypress change blur", function() {
            if ($(this).val() != jQuery.data(this, "lastvalue")) {
                func();
            }
            jQuery.data(this, "lastvalue", $(this).val());
        });
        $(id).bind("focus", function() {
           jQuery.data(this, "lastvalue", $(this).val());
        });
    }

    // --- chain ---
    var chMode = 'csv';
    var chAddrList = [];
    var chRange = 1;
    var chType = 'armory';

    function chOnChangeType() {
        var id = $(this).attr('id');

        if (chType != id) {
            $('#chCode').val('');
            $('#chRoot').val('');
            $('#chBackup').val('');
            $('#chMsg').text('');
            $('#chList').text('');
            chOnStop();
        }
		
        $('#chChange').attr('disabled', id != 'electrum');

        chType = id;
    }

    function chOnChangeFormat() {
        chMode = $(this).attr('id');
        chUpdate();
    }

    function chAddrToCSV(i, r) {
        return i + ', "' + r[0] +'", "' + r[1] +'"\n';
    }

    function chUpdate() {
        if (chAddrList.length == 0)
            return;
        var str = '';
        if (chMode == 'csv') {
            for (var i = 0; i < chAddrList.length; i++)
                str += chAddrToCSV(i+1, chAddrList[i]);

        } else if (chMode == 'json') {

            var w = {};
            w['keys'] = [];
            for (var i = 0; i < chAddrList.length; i++)
                w['keys'].push({'addr':chAddrList[i][0],'sec':chAddrList[i][1]});
            str = JSON.stringify(w, null, 4);
        }
        $('#chList').text(str);

        chRange = parseInt($('#chRange').val());

        var c = (chType == 'electrum') ? parseInt($('#chChange').val()) : 0;

        if (chAddrList.length >= chRange+c)
            chOnStop();

    }

    function chOnChangeCode() {
        $('#chRoot').val('');
        $('#chMsg').text('');
        chOnStop();
        $('#chBackup').val( mn_encode(chRoot) );
        clearTimeout(timeout);
        timeout = setTimeout(chGenerate, TIMEOUT);
    }

    function chUpdateBackup() {
        var str =  $('#chBackup').val();

        if (str.length == 0) {
            chOnStop();
            $('#chCode').val('');
            $('#chRoot').val('');
            $('#chBackup').val('');
            $('#chMsg').text('');
            $('#chList').text('');
            return;
        }

        if (chType == 'electrum') {
            str = str.trim();
            if (issubset(mn_words, str, 12))  {
                var seed = mn_decode(str);
                $('#chRoot').val(seed);
                var words = str.split(' ');
                if (words.length!=12)
                {
                  $('#chList').text('');
                  return;
                }
            } else {
              $('#chRoot').val('');
              $('#chCode').val('');
              chOnStop();
            }
        }

        if (chType == 'armory') {
            var keys = armory_decode_keys(str, random_seed);	
            if (keys != null) {
                var pk = keys[0];
                var cc = keys[1];				
                $('#chRoot').val(Crypto.util.bytesToHex(pk));
                $('#chCode').val(Crypto.util.bytesToHex(cc));

                var lines = str.split('\n');
                var text = lines.join(' ');
                var words = text.split(/\s+/);
                if (words.length!=9*2 && words.length!=9*4)
                {
                  $('#chList').text('');
                  return;
                }
            }
        }

        clearTimeout(timeout);
        timeout = setTimeout(chGenerate, TIMEOUT);
    }

    function chOnChangeBackup() {
        clearTimeout(timeout);
        timeout = setTimeout(chUpdateBackup, TIMEOUT);
    }

    function chOnRandom() {
        var pk = secureRandom(32);

        if (chType == 'armory') {
            var cc = armory_derive_chaincode(pk, random_seed);
            $('#chRoot').val(Crypto.util.bytesToHex(pk));
            $('#chCode').val(Crypto.util.bytesToHex(cc));
            //original seed value
			//$('#chBackup').val(armory_encode_keys(pk, cc).split('\n').slice(0,2).join('\n'));
			//two strings seed without chain code
			$('#chBackup').val(armory_encode_keys(pk, cc).split('\n').slice(0,4).join('\n'));
			//four strings seed with chain code in two last
        }

        if (chType == 'electrum') {
            var seed = Crypto.util.bytesToHex(pk.slice(0,16));
            //nb! electrum doesn't handle trailing zeros very well
            if (seed.charAt(0) == '0') seed = seed.substr(1);
            $('#chRoot').val(seed);
            $('#chBackup').val(mn_encode(seed));
        }
        chGenerate();
    }

    function chOnStop() {
        Armory.stop();
        Electrum.stop();
        if (chType == 'electrum') {
            $('#chMsg').text('');
        }
    }

    function chOnChangeRange()
    {
        if ( chAddrList.length==0 )
          return;
        clearTimeout(timeout);
        timeout = setTimeout(chUpdateRange, TIMEOUT);
    }

    function chCallback(r) {
        chAddrList.push(r);
        $('#chList').append(chAddrToCSV(chAddrList.length,r));
    }

    function chElectrumUpdate(r, seed) {
        $('#chMsg').text('key stretching: ' + r + '%');
        $('#chCode').val(Crypto.util.bytesToHex(seed));
    }

    function chElectrumSuccess(privKey) {
        $('#chMsg').text('');
        $('#chCode').val(Crypto.util.bytesToHex(privKey));
        var addChange = parseInt($('#chChange').val());
        Electrum.gen(chRange, chCallback, chUpdate, addChange
		, PUBLIC_KEY_VERSION, PRIVATE_KEY_VERSION, ADDRESS_URL_PREFIX, compressed);
    }

    function chUpdateRange() {
        chRange = parseInt($('#chRange').val());
        chAddrList = [];

        $('#chList').text('');

        if (chType == 'electrum') {
            var addChange = parseInt($('#chChange').val());
            Electrum.stop();
            Electrum.gen(chRange, chCallback, chUpdate, addChange
			, PUBLIC_KEY_VERSION, PRIVATE_KEY_VERSION, ADDRESS_URL_PREFIX, compressed);
        }

        if (chType == 'armory') {
            var codes = $('#chBackup').val();
            Armory.gen(codes, chRange, chCallback, chUpdate
			, PUBLIC_KEY_VERSION, PRIVATE_KEY_VERSION, ADDRESS_URL_PREFIX, compressed);
        }
    }

    function chGenerate() {
        clearTimeout(timeout);

        var seed = $('#chRoot').val();
        var codes = $('#chBackup').val();

        chAddrList = [];

        $('#chMsg').text('');
        $('#chList').text('');

        Electrum.stop();

        if (chType == 'electrum') {
           if (seed.length == 0)
               return;
            Electrum.init(seed, chElectrumUpdate, chElectrumSuccess);
        }

        if (chType == 'armory') {
            var uid = Armory.gen(codes, chRange, chCallback, chUpdate
			, PUBLIC_KEY_VERSION, PRIVATE_KEY_VERSION, ADDRESS_URL_PREFIX, compressed);
            if (uid)
                $('#chMsg').text('uid: ' + uid);
            else
                return;
        }
    }
    // -- transactions --

    var txType = 'txBCI';
    var txFrom = 'txFromSec';

    function txGenSrcAddr() {
        var updated = updateAddr ($('#txSec'), $('#txAddr'));

        $('#txBalance').val('0.00');

        if (updated && txFrom=='txFromSec')
            txGetUnspent();
    }

    function txOnChangeSec() {
        clearTimeout(timeout);
        timeout = setTimeout(txGenSrcAddr, TIMEOUT);
    }

    function txOnChangeAddr() {
        clearTimeout(timeout);
        timeout = setTimeout(txGetUnspent, TIMEOUT);
    }

    function txSetUnspent(text) {
        var r = JSON.parse(text);
        txUnspent = JSON.stringify(r, null, 4);
        $('#txUnspent').val(txUnspent);
        var address = $('#txAddr').val();
        TX.parseInputs(txUnspent, address);
        var value = TX.getBalance();
        var fval = Bitcoin.Util.formatValue(value);
        var fee = parseFloat($('#txFee').val());
        $('#txBalance').val(fval);
        var value = Math.floor((fval-fee)*1e8)/1e8;
        $('#txValue').val(value);
        txRebuild();
    }

    function txUpdateUnspent() {
        txSetUnspent($('#txUnspent').val());
    }

    function txOnChangeUnspent() {
        clearTimeout(timeout);
        timeout = setTimeout(txUpdateUnspent, TIMEOUT);
    }

    function txParseUnspent(text) {
        if (text=='' || text=='{}') {
            alert('No data');
            return;
        }
        txSetUnspent(text);
    }

    function txGetUnspent() {
        var addr = $('#txAddr').val();

        var url = (txType == 'txBCI') ? 'https://blockchain.info/unspent?cors=true&active=' + addr :
            'https://blockexplorer.com/q/mytransactions/' + addr;

        url = prompt('Press OK to download transaction history:', url);

        if (url != null && url != "") {

            $('#txUnspent').val('');

            $.getJSON(url, function(data) {
              txParseUnspent ( JSON.stringify(data, null, 2) );
            }).fail(function(jqxhr, textStatus, error) {
              alert( typeof(jqxhr.responseText)=='undefined' ? jqxhr.statusText
                : ( jqxhr.responseText!='' ? jqxhr.responseText : 'No data, probably Access-Control-Allow-Origin error.') );
            });

        } else {
          txSetUnspent($('#txUnspent').val());
        }
    }

    function txOnChangeJSON() {
        var str = $('#txJSON').val();
        try {
          var sendTx = TX.fromBBE(str);
          $('txJSON').removeClass('has-error');
          var bytes = sendTx.serialize();
          var hex = Crypto.util.bytesToHex(bytes);
          $('#txHex').val(hex);
          if (!TX.getBalance().equals(BigInteger.ZERO))
            $('#txFee').val(Bitcoin.Util.formatValue(TX.getFee(sendTx)));
          setErrorState($('#txJSON'), false, '');
        } catch (err) {
          setErrorState($('#txJSON'), true, 'syntax error');
        }

        $('#txSend').attr('disabled', $('#txHex').val()=="");
    }

    function txOnChangeHex() {
        var str = $('#txHex').val();
        str = str.replace(/[^0-9a-fA-f]/g,'');
        $('#txHex').val(str);
        var bytes = Crypto.util.hexToBytes(str);
        var sendTx = TX.deserialize(bytes);
        var text = TX.toBBE(sendTx);
        $('#txJSON').val(text);
        $('#txSend').attr('disabled', $('#txHex').val()=="");
    }

    function txOnAddDest() {
        var list = $(document).find('.txCC');
        var clone = list.last().clone();
        clone.find('.help-inline').empty();
        clone.find('.control-label').text('Cc');
        var dest = clone.find('#txDest');
        var value = clone.find('#txValue');
        clone.insertAfter(list.last());
        onInput(dest, txOnChangeDest);
        onInput(value, txOnChangeDest);
        dest.val('');
        value.val('');
        $('#txRemoveDest').attr('disabled', false);
        return false;
    }

    function txOnRemoveDest() {
        var list = $(document).find('.txCC');
        if (list.size() == 2)
            $('#txRemoveDest').attr('disabled', true);
        list.last().remove();
        return false;
    }

    function txSent(text) {
        alert(text ? text : 'No response!');
    }

    function txSend() {
        var txAddr = $('#txAddr').val();

        var r = '';
        if (txAddr!='' && txAddr!=TX.getAddress())
            r += 'Warning! Source address does not match private key.\n\n';

        var tx = $('#txHex').val();

        url = 'https://blockchain.info/pushtx?cors=true';

        // alternatives are:
        // http://eligius.st/~wizkid057/newstats/pushtxn.php (supports non-standard transactions)
        // https://btc.blockr.io/tx/push
        // http://bitsend.rowit.co.uk (defunct)

        url = prompt(r + 'Press OK to send transaction to:', url);

        if (url != null && url != "") {

            $.post(url, { tx: tx }, function(data) {
              txSent(data.responseText);
            }).fail(function(jqxhr, textStatus, error) {
              alert( typeof(jqxhr.responseText)=='undefined' ? jqxhr.statusText
                : ( jqxhr.responseText!='' ? jqxhr.responseText : 'No data, probably Access-Control-Allow-Origin error.') );
            });

        }

        return false;
    }

    function txRebuild() {
        var sec = $('#txSec').val();
        var addr = $('#txAddr').val();
        var unspent = $('#txUnspent').val();
        var balance = parseFloat($('#txBalance').val());
        var fee = parseFloat('0'+$('#txFee').val());

        try {
            var res = parseBase58Check(sec);
            var version = res[0];
            var payload = res[1];
        } catch (err) {
            $('#txJSON').val('');
            $('#txHex').val('');
            return;
        }

        var compressed = false;
        if (payload.length > 32) {
            payload.pop();
            compressed = true;
        }

        var eckey = new Bitcoin.ECKey(payload);

        eckey.setCompressed(compressed);

        TX.init(eckey);

        var fval = 0;
        var o = txGetOutputs();
        for (i in o) {
            TX.addOutput(o[i].dest, o[i].fval);
            fval += o[i].fval;
        }

        // send change back or it will be sent as fee
        if (balance > fval + fee) {
            var change = balance - fval - fee;
            TX.addOutput(addr, change);
        }

        try {
            var sendTx = TX.construct();
            var txJSON = TX.toBBE(sendTx);
            var buf = sendTx.serialize();
            var txHex = Crypto.util.bytesToHex(buf);
            setErrorState($('#txJSON'), false, '');
            $('#txJSON').val(txJSON);
            $('#txHex').val(txHex);
        } catch(err) {
            $('#txJSON').val('');
            $('#txHex').val('');
        }
        $('#txSend').attr('disabled', $('#txHex').val()=="");
    }

    function txSign() {
        if (txFrom=='txFromSec')
        {
          txRebuild();
          return;
        }

        var str = $('#txJSON').val();
        TX.removeOutputs();
        var sendTx = TX.fromBBE(str);

        try {
            sendTx = TX.resign(sendTx);
            $('#txJSON').val(TX.toBBE(sendTx));
            $('#txHex').val(Crypto.util.bytesToHex(sendTx.serialize()));
            $('#txFee').val(Bitcoin.Util.formatValue(TX.getFee(sendTx)));
        } catch(err) {
            $('#txJSON').val('');
            $('#txHex').val('');
        }
        $('#txSend').attr('disabled', $('#txHex').val()=="");
    }

    function txOnChangeDest() {
        var balance = parseFloat($('#txBalance').val());
        var fval = parseFloat('0'+$('#txValue').val());
        var fee = parseFloat('0'+$('#txFee').val());

        if (fval + fee > balance) {
            fee = balance - fval;
            $('#txFee').val(fee > 0 ? fee : '0.00');
        }

        clearTimeout(timeout);
        timeout = setTimeout(txRebuild, TIMEOUT);
    }

    function txShowUnspent() {
        var div = $('#txUnspentForm');

        if (div.hasClass('hide')) {
            div.removeClass('hide');
            $('#txShowUnspent').text('Hide Outputs');
        } else {
            div.addClass('hide');
            $('#txShowUnspent').text('Show Outputs');
        }
    }

    function txChangeType() {
        txType = $(this).attr('id');
    }

    function txChangeFrom() {
      txFrom = $(this).attr('id');
      var bFromKey = txFrom=='txFromSec' || txFrom=='txFromPass';
      $('#txJSON').attr('readonly', txFrom!='txFromJSON');
      $('#txHex').attr('readonly', txFrom!='txFromRaw');
      $('#txFee').attr('readonly', !bFromKey);
      $('#txAddr').attr('readonly', !bFromKey);

      $.each($(document).find('.txCC'), function() {
        $(this).find('#txDest').attr('readonly', !bFromKey);
        $(this).find('#txValue').attr('readonly', !bFromKey);
      });

      if ( txFrom=='txFromRaw' )
        $('#txHex').focus();
      else if ( txFrom=='txFromJSON' )
        $('#txJSON').focus();
      else if ( bFromKey )
        $('#txSec').focus();
    }

    function txOnChangeFee() {

        var balance = parseFloat($('#txBalance').val());
        var fee = parseFloat('0'+$('#txFee').val());

        var fval = 0;
        var o = txGetOutputs();
        for (i in o) {
            TX.addOutput(o[i].dest, o[i].fval);
            fval += o[i].fval;
        }

        if (fval + fee > balance) {
            fval = balance - fee;
            $('#txValue').val(fval < 0 ? 0 : fval);
        }

        if (fee == 0 && fval == balance - 0.0001) {
            $('#txValue').val(balance);
        }

        clearTimeout(timeout);
        timeout = setTimeout(txRebuild, TIMEOUT);
    }

    function txGetOutputs() {
        var res = [];
        $.each($(document).find('.txCC'), function() {
            var dest = $(this).find('#txDest').val();
            var fval = parseFloat('0' + $(this).find('#txValue').val());
            res.push( {"dest":dest, "fval":fval } );
        });
        return res;
    }

    // -- sign --	
    function updateAddr(from, to, bUpdate) {
        setErrorState(from, false);
        var sec = from.val();
        var addr = '';
        var eckey = null;
        var compressed = false;
        try {
            var res = parseBase58Check(sec);
            var privkey_version = res[0];
            var payload = res[1];

            if (payload.length!=32 && payload.length!=33)
              throw ('Invalid payload (must be 32 or 33 bytes)');

            if (payload.length > 32) {
                payload.pop();
                compressed = true;
            }
            eckey = new Bitcoin.ECKey(payload);
            var curve = getSECCurveByName("secp256k1");
            var pt = curve.getG().multiply(eckey.priv);
            eckey.pub = getEncoded(pt, compressed);
            eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(eckey.pub);
            addr = new Bitcoin.Address(eckey.getPubKeyHash());
            addr.version = PUBLIC_KEY_VERSION;

            if (privkey_version!=PRIVATE_KEY_VERSION)
            {
                var wif = new Bitcoin.Address(payload);
                wif.version = PRIVATE_KEY_VERSION;
                from.val(wif.toString());
            }
        } catch (err) {
            if (from.val())
              setErrorState(from, true, err);
            return false;
        }
        to.val(addr);
        return {"key":eckey, "compressed":compressed, "addrtype":PUBLIC_KEY_VERSION, "address":addr};
    }

    function sgGenAddr() {
        updateAddr($('#sgSec'), $('#sgAddr'));
    }

    function sgOnChangeSec() {
        $('#sgSig').val('');
        $('#sgLabel').html('');
        clearTimeout(timeout);
        timeout = setTimeout(sgGenAddr, TIMEOUT);
    }

    function sgOnChangeMsg() {
        $('#sgSig').val('');
        $('#sgLabel').html('');
    }

    function fullTrim(message)
    {
        message = message.replace(/^\s+|\s+$/g, '');
        message = message.replace(/^\n+|\n+$/g, '');
        return message;
    }

    var sgHdr = [
      "-----BEGIN BITCOIN SIGNED MESSAGE-----",
      "-----BEGIN SIGNATURE-----",
      "-----END BITCOIN SIGNED MESSAGE-----"
    ];

    var qtHdr = [
      "-----BEGIN BITCOIN SIGNED MESSAGE-----",
      "-----BEGIN BITCOIN SIGNATURE-----",
      "-----END BITCOIN SIGNATURE-----"
    ];

    function joinMessage(type, addr, msg, sig)
    {
      if (type=='inputs_io')
        return sgHdr[0]+'\n'+msg +'\n'+sgHdr[1]+'\n'+addr+'\n'+sig+'\n'+sgHdr[2];
      else if (type=='multibit')
        return qtHdr[0]+'\n'+msg +'\n'+qtHdr[1]+'\nVersion: Bitcoin-qt (1.0)\nAddress: '+addr+'\n\n'+sig+'\n'+qtHdr[2];
      else
        return sig;
    }

    function sgSign() {
      var sgType = $('#sgType input:radio:checked').attr('value');
      var sgMsg = $('#sgMsg').val();

      var p = updateAddr($('#sgSec'), $('#sgAddr'));

      if ( !sgMsg || !p )
        return;

      sgMsg = fullTrim(sgMsg);

      var label = '';

      if (sgType=='armory_base64' || sgType=='armory_clearsign' || sgType=='armory_hex') {
        $('#sgSig').val(armory_sign_message (p.key, p.address, sgMsg, p.compressed, p.addrtype, sgType));
      } else {
        var sgSig = sign_message(p.key, sgMsg, p.compressed, p.addrtype);
        $('#sgSig').val(joinMessage(sgType, p.address, sgMsg, sgSig));
        label = '(<a href="#verify'+vrPermalink(p.address, sgMsg, sgSig)+'" target=_blank>permalink</a>)';
      }

      $('#sgLabel').html(label);
	  linkText(document.getElementById('sgSig'), document.getElementById('download-signed'), 'signed.txt')
		$('#download-signed').show();
	  
    }

    // -- verify --

    function vrPermalink(addr,msg,sig)
    {
      return '?vrAddr='+encodeURIComponent(addr)+'&vrMsg='+encodeURIComponent(msg)+'&vrSig='+encodeURIComponent(sig);
    }

    function splitSignature(s)
    {
      var addr = '';
      var sig = s;
      if ( s.indexOf('\n')>=0 )
      {
        var a = s.split('\n');
        addr = a[0];

        // always the last
        sig = a[a.length-1];

        // try named fields
        var h1 = 'Address: ';
        for (i in a) {
          var m = a[i];
          if ( m.indexOf(h1)>=0 )
            addr = m.substring(h1.length, m.length);
        }

        // address should not contain spaces
        if (addr.indexOf(' ')>=0)
          addr = '';

        // some forums break signatures with spaces
        sig = sig.replace(" ","");
      }
      return { "address":addr, "signature":sig };
    }

    function splitMessage(s)
    {
      var p = armory_split_message(s);
      if (p)
        return p;

      s = s.replace('\r','');

      for (var i=0; i<2; i++ )
      {
        var hdr = i==0 ? sgHdr : qtHdr;
        var type = i==0 ? "inputs_io" : "multibit";

        var p0 = s.indexOf(hdr[0]);
        if ( p0>=0 )
        {
          var p1 = s.indexOf(hdr[1]);
          if ( p1>p0 )
          {
            var p2 = s.indexOf(hdr[2]);
            if ( p2>p1 )
            {
              var msg = s.substring(p0+hdr[0].length+1, p1-1);
              var sig = s.substring(p1+hdr[1].length+1, p2-1);
              var m = splitSignature(sig);
              msg = fullTrim(msg); // doesn't work without this
              return { "message":msg, "address":m.address, "signature":m.signature, "type":type };
            }
          }
        }
      }
      return false;
    }

    function vrVerify() {

        var vrMsg = $('#vrMsg').val();
        var vrAddr = $('#vrAddr').val();
        var vrSig = $('#vrSig').val();

        var vrVer = PUBLIC_KEY_VERSION;

        var bSplit = $('#vrFromMessage').parent().hasClass('active');

        if (bSplit && !vrMsg)
          return;

        if (!bSplit && (!vrMsg || !vrSig))
          return;

        var addr = null;
        var p = null;

        if (bSplit) {
          p = splitMessage(vrMsg);
          vrAddr = p.address;
          vrMsg = p.message;
          vrSig = p.signature;

          // try armory first
          addr = armory_verify_message(p
		  ,PUBLIC_KEY_VERSION, PRIVATE_KEY_VERSION, ADDRESS_URL_PREFIX, compressed);
        } else {
          p = { "type": "bitcoin_qt", "address":vrAddr, "message": vrMsg, "signature": vrSig };
        }

        if (!addr) {
          try { vrVer = parseBase58Check(vrAddr)[0]; } catch (err) {};
          addr = verify_message(vrSig, vrMsg, vrVer);
        }

        var armoryMsg = "";
        if (p.type=="armory_base64" && p.message) {
          armoryMsg = p.message;
          console.log(armoryMsg);
        }

        $('#vrAlert').empty();

        var clone = $('#vrError').clone();

        // also check address was mentioned somewhere in the message (may be unsafe)
        if (!vrAddr && addr && vrMsg.search(addr)!=-1)
          vrAddr = addr;

        if (addr && (vrAddr==addr || !vrAddr)) {
          clone = vrAddr==addr ? $('#vrSuccess').clone() : $('#vrWarning').clone();

          var label = addr;

          // insert link here
          if (vrAddr==addr && p.type!="armory_hex")
            label = vrAddr +
              ' (<a href="#verify'+vrPermalink(vrAddr,vrMsg,vrSig)+'" target=_blank>permalink</a>)';

          clone.find('#vrAddrLabel').html(label);
        }

        clone.appendTo($('#vrAlert'));

        //if (armoryMsg) alert(armoryMsg);

        return false;
    }

    function vrOnInput() {
        $('#vrAlert').empty();
        vrVerify();
    }


    function vrOnChange() {
        clearTimeout(timeout);
        timeout = setTimeout(vrOnInput, TIMEOUT);
    }

    function crChange()
    {
      var p = $(this).attr('data-target').split(',',3);	  
	  //using default parameters if not all was been specified
	  /*
		compressed, pubVer;		privVer - default;
		pubVer, privVer;		compressed = false - by default;
		pubVer;					privVer and compressed - by default;
		compressed only;		privVer, pubVer - by default.
	  */
	  
	  if (p.length>0)
	  //use compressed private key and compressed address or need to use uncompressed both???
		if(p[0] == 'compressed'){compressed = true;}
		else{
			if(p[0] == 'uncompressed'){compressed = false;}
			else{//uncompressed as default format for private keys and addresses
				compressed = Default_gen_compressed;
			}
		}
		if(p.length==1){
			if(p[0] == 'compressed'){
					compressed = true;
					PUBLIC_KEY_VERSION = Default_PUBLIC_KEY_VERSION;
					PRIVATE_KEY_VERSION = Default_PRIVATE_KEY_VERSION;
			}
			else if(p[0] == 'uncompressed'){
				compressed = false;
				PUBLIC_KEY_VERSION = parseInt(p[1]);
				PRIVATE_KEY_VERSION = Default_PRIVATE_KEY_VERSION;
			}
			else{//if first specified value is byte, then it public key version
				compressed = Default_gen_compressed;
				PUBLIC_KEY_VERSION = parseInt(p[0]);
				PRIVATE_KEY_VERSION = Default_PRIVATE_KEY_VERSION;
			}
		}else if(p.length==2){
			if(p[0] == 'compressed'){
					compressed = true;
					PUBLIC_KEY_VERSION = parseInt(p[1]);
					PRIVATE_KEY_VERSION = Default_PRIVATE_KEY_VERSION;
			}
			else if(p[0] == 'uncompressed'){
				compressed = false;
				PUBLIC_KEY_VERSION = parseInt(p[1]);
				PRIVATE_KEY_VERSION = Default_PRIVATE_KEY_VERSION;
			}
			else{//uncompressed as default format for private keys and addresses
				compressed = Default_gen_compressed;
				PUBLIC_KEY_VERSION = parseInt(p[0]);
				PRIVATE_KEY_VERSION = parseInt(p[1]);
			}
		}else if(p.length==3){
			PUBLIC_KEY_VERSION = parseInt(p[1]);
			PRIVATE_KEY_VERSION = parseInt(p[2]);
		}
		else{
			PUBLIC_KEY_VERSION = Default_PUBLIC_KEY_VERSION;		//default bitcoin public key version
			PRIVATE_KEY_VERSION = Default_PRIVATE_KEY_VERSION;		//default bitcoin private key version
		}
		//for private key there was been an another formula:
		//PRIVATE_KEY_VERSION = p.length>1 ? parseInt(p[2]) : ((PUBLIC_KEY_VERSION+128) & 255);

		ADDRESS_URL_PREFIX = $(this).attr('href');
		//if(ADDRESS_URL_PREFIX==""){ADDRESS_URL_PREFIX==Default_PRIVATE_KEY_VERSION;} //not working
	  
      var name = $(this).text();
      var child = $(this).children();
      if (child.length)
        name = child.text();

		ticker = $(this).find('span').text();
		coin_name = $(this).text().split(ticker)[1];
		$('#coin_name').attr('ticker', ticker);
		$('#coin_name').attr('coin_name', coin_name);
		
		//console.log(
		//	'p[0]', p[0], 'p[1]', p[1], 'p[2]', p[2],
		//	'\n compressed', compressed, 'PUBLIC_KEY_VERSION', PUBLIC_KEY_VERSION, 'PRIVATE_KEY_VERSION', PRIVATE_KEY_VERSION
		//);
		
      $('#crName').text(name);	  
      $('#crSelect').dropdown('toggle');
      //gen_update();
      translate();
		
	  	//compressed=null;
		gen_compressed=compressed;
		
		//compressed=true;	//test
		//compressed=false;
		//compressed=null;
		if(compressed===true){
			$('#gen_comp label input').off();
			$('#gen_comp [name=comp]').addClass('active');
			$('#gen_comp [name=uncomp]').removeClass('active');
		}
		else{
			if(compressed===false){
				$('#gen_comp label input').off();
				$('#gen_comp [name=uncomp]').addClass('active');
				$('#gen_comp [name=comp]').removeClass('active');
			}
			else{
				$('#gen_comp label input').off();
				$('#gen_comp [name=uncomp]').addClass('active');
				$('#gen_comp [name=comp]').removeClass('active');
			}
		}
/*
index.html
              <div class="form-group">
                <label class="col-lg-2 control-label">Point Conversion</label>
                <div class="col-lg-10 controls">
                  <div class="btn-group" data-toggle="buttons" id="gen_comp">
                    <label class="btn btn-default" name="uncomp" title="Uncompressed keys (reference client)">
					<input name="uncompressed" type="radio" />Uncompressed</label>
					<label class="btn btn-default" name="comp" title="Compressed keys (introduced in 0.5.99)">
					<input name="compressed" type="radio" />Compressed</label>
                  </div>
                </div>
              </div>
*/
		setCompressed(compressed);
		//gen_update();
		chOnRandom();

		var segwit_addr = $(this).attr('title');
		setSegwitAddr(segwit_addr);
		
      return false;
    }

    $(document).ready( function() {

        if ((window.location.host=='brainwallet.github.io' || window.location.host=='brainwallet.org') && window.location.protocol!="https:")
            window.location.protocol = "https";

        if (window.location.hash)
          $('#tab-' + window.location.hash.substr(1).split('?')[0]).tab('show');

        $('a[data-toggle="tab"]').on('click', function (e) {
            window.location.hash = $(this).attr('href');
        });


        $('#tab-gen').on('shown.bs.tab', function() { $('#'+gen_from).focus(); });
        $('#tab-chains').on('shown.bs.tab', function() { $('#chBackup').focus(); });
        $('#tab-tx').on('shown.bs.tab', function() { $('#txSec').focus(); });
        $('#tab-converter').on('shown.bs.tab', function() { $('#src').focus(); });
        $('#tab-sign').on('shown.bs.tab', function() { $('#sgSec').focus(); });
        $('#tab-verify').on('shown.bs.tab', function() { $('#vrMsg').focus(); });
		$('#tab-xor').on('shown.bs.tab', function() { $('#xor').focus(); });
		$('#tab-t_addr').on('shown.bs.tab', function() { $('#taddr').focus(); });

        // generator
		
        onInput('#pass', onChangePass);
        onInput('#hash', onChangeHash);
        onInput('#sec', genOnChangePrivKey);
        onInput('#der', genOnChangeDER);

        $('#genRandom').click(genRandom);

        $('#gen_from label input').on('change', genUpdateFrom );
        $('#gen_comp label input').on('change', genOnChangeCompressed);
		

        genRandomPass();

        // chains

        $('#chRandom').click(chOnRandom);

        $('#chType label input').on('change', chOnChangeType);
        $('#chFormat label input').on('change', chOnChangeFormat);

        onInput($('#chRange'), chOnChangeRange);
        onInput($('#chCode'), chOnChangeCode);
        onInput($('#chBackup'), chOnChangeBackup);
        onInput($('#chChange'), chOnChangeRange);
        chRange = parseInt($('#chRange').val());

        // transactions

        //$('#txSec').val(tx_sec);
        //$('#txAddr').val(tx_addr);
        //$('#txDest').val(tx_dest);

        //txSetUnspent(tx_unspent);

        $('#txGetUnspent').click(txGetUnspent);
        $('#txType label input').on('change', txChangeType);
        $('#txFrom label input').on('change', txChangeFrom);

        onInput($('#txSec'), txOnChangeSec);
        onInput($('#txAddr'), txOnChangeAddr);
        onInput($('#txUnspent'), txOnChangeUnspent);
        onInput($('#txHex'), txOnChangeHex);
        onInput($('#txJSON'), txOnChangeJSON);
        onInput($('#txDest'), txOnChangeDest);
        onInput($('#txValue'), txOnChangeDest);
        onInput($('#txFee'), txOnChangeFee);

        $('#txAddDest').click(txOnAddDest);
        $('#txRemoveDest').click(txOnRemoveDest);
        $('#txSend').click(txSend);
        $('#txSign').click(txSign);
        $('#txSign').attr('disabled', true);
        $('#txSend').attr('disabled', true);

        // converter

        onInput('#src', onChangeFrom);

        $('#enc_from label input').on('change', update_enc_from );
        $('#enc_to label input').on('change', update_enc_to );

        // sign

        $('#sgSec').val($('#sec').val());
		
        $('#sgAddr').val($('#addr').val());
        $('#sgMsg').val("This is an example of a signed message.");

        onInput('#sgSec', sgOnChangeSec);
        onInput('#sgMsg', sgOnChangeMsg);

        $('#sgType label input').on('change', function() { if ($('#sgSig').val()!='') sgSign(); } );

        $('#sgSign').click(sgSign);
        $('#sgForm').submit(sgSign);

        // verify

        $('#vrVerify').click(vrVerify);

        $('#vrFrom label input').on('change', function() {
          var bJoin = $(this).attr('id')=="vrFromMessage";
          $('.vrAddr').attr('hidden', bJoin);
          $('.vrSig').attr('hidden', bJoin);
          $('#vrMsg').attr('rows', bJoin ? 14:9);

          // convert from Bitcoin-QT to signed message and vice-versa
          if (bJoin) {
            var p = { "address": $('#vrAddr').val(), "message":$('#vrMsg').val(), "signature":$('#vrSig').val() };
            if (p.message && p.signature && $('#vrMsg'))
              $('#vrMsg').val(joinMessage("inputs_io", p.address, p.message, p.signature));
          } else {
            var p = splitMessage($('#vrMsg').val());
            if (p) {

              if (p.type=="armory_hex") {
                $('#vrAlert').empty();
                console.log('impossible to convert signature, message digest is incompatible with bitcoin-qt');
                p = { "message": $('#vrMsg').val() };
              }

              $('#vrAddr').val(p.address)
              $('#vrMsg').val(p.message)
              $('#vrSig').val(p.signature);
            }
          }

        });

        onInput($('#vrAddr'), vrOnChange);
        
		onInput($('#vrMsg'), vrOnChange);
		$("#vrMsg").on('mouseenter', vrOnChange);	//verify if mouse enter
		$("#vrMsg").on('click', vrOnChange);		//verify if user clicking by textarea
        $("#vrMsg").on("focusin", vrOnChange);		//verify if focus in this textarea, without mouse
		
		onInput($('#vrSig'), vrOnChange);
		
        // permalink support
        if ( window.location.hash && window.location.hash.indexOf('?')!=-1 ) {
          var args = window.location.hash.split('?')[1].split('&');
          var p = {};
          for ( var i=0; i<args.length; i++ ) {
            var arg = args[i].split('=');
            p[arg[0]] = decodeURIComponent(arg[1]);
          }
          if (p.vrMsg && p.vrSig) {
            $('#vrMsg').val(joinMessage( "inputs_io", (p.vrAddr||"<insert address here>"), p.vrMsg, p.vrSig ));
            vrVerify();
          }
        }

        // currency select

        $('#crCurrency ul li a').on('click', crChange);


        // init secure random
        try {
          var r = secureRandom(32);
          $('#genRandom').attr('enabled', false);
          $('#chRandom').attr('disabled', false);
        } catch (err) {
          console.log ('secureRandom is not supported');
        }

        $('#toggleKeyCode').on('click', function() {
            $('#genKeyQR').slideToggle();
            $('#sec').closest('.form-group').slideToggle();
			
			var toogled = $('#toggleKeyCode').attr('toogled');
            toogled = (toogled === 'true' ? 'false' : 'true');
            $('#toggleKeyCode').attr('toogled', toogled);
			
			var text = (toogled === 'true' ? 'Hide private key': 'Show private key');
            $('#toggleKeyCode').html(text);
        });

        $('#togglePass').on('click', function(){
            var type = $('#pass').attr('type');
            type = (type === 'text' ? 'password' : 'text');
            $('#pass').attr('type', type);
			
			var text = (type === 'text' ? 'PASS' : 'TEXT');
            $('#togglePass').html(text);
        });
		
		$('#toggleKeyfiledata').on('click', function(){
            var type = $('#keyfiledata').attr('type');
            type = (type === 'text' ? 'password' : 'text');
            $('#keyfiledata').attr('type', type);
			
			var text = (type === 'text' ? 'PASS' : 'TEXT');
            $('#toggleKeyfiledata').html(text);
 
        });
		
		
		if(random_seed==false){
			$('#hash_random_seed_form').hide();
			$('#hash_random_seed').hide();
			$('#XOR').hide();
			
			$('#chain_hash_of_random_seed').hide();			
			$('#chhash_random_seed').hide();			
			$('#chXOR').hide();
		}
		
		$('#XOR').on('click', function(){
				var XOR = $('#hash').attr('XOR');
				XOR = (XOR === 'true' ? 'false' : 'true');
				$('#hash').attr('XOR', XOR);
				//attribute can be checked in the source code of html page
				
				$('#hash').val(XOR_hex($('#hash').val(),$('#hash_random_seed').val()));
				var text = (XOR === 'true' ? 'unXOR' : 'XOR');
				$('#XOR').text(text);
		
				gen_update_sec_exp();
        });
		$('#chXOR').on('click', function(){

			$('#chRoot').val(XOR_hex($('#chRoot').val(),$('#chhash_random_seed').val()));
			$('#chCode').val(XOR_hex($('#chCode').val(),$('#chhash_random_seed').val()));
			root_key = Crypto.util.hexToBytes($('#chRoot').val());
			chaincode = Crypto.util.hexToBytes($('#chCode').val())
				
			if (chType == 'armory'){
				$('#chBackup').val(armory_encode_keys(root_key, chaincode).split('\n').slice(0,4).join('\n'));
			}
			if (chType == 'electrum'){
				var seed = $('#chRoot').val();
				$('#chBackup').val(mn_encode(seed));
			}
			chUpdateBackup();
        });
		
		
		$('#xorRand').on('click', function(){
			var a = secureRandom(32);
			var b = secureRandom(32);
			$('#a').val(Crypto.util.bytesToHex(a));
			$('#b').val(Crypto.util.bytesToHex(b));
        });
		
		$('#xorXOR').on('click', function(){
			$('#c').val(XOR_hex($('#a').val(),$('#b').val()));
        });	
        
		$('#SegWit_address').on('click', function(){
				var type = $('#addr').attr('SegWit_address');
				//SegWit_address = (SegWit_address === "SegWit address" ? "Default address" : "SegWit address");
				switch (type) {
					case "SegWit address": type = "ZCash t-address"; break;
					case "ZCash t-address": type = "Default address"; break;
					case "Default address": type = "SegWit address"; break;
					default: type = "SegWit address";
				}//	console.log(SegWit_address);		
			
				$('#addr').attr('SegWit_address', type);
				$('#SegWit_address').text(type);

				setSegwitAddr(type);
        });
		
    });
})(jQuery);


//JS functions, not JQuery
//function to download text as file.
var as_text = false; //default download as binary data.
function download(filename, text) {
	console.log(text);
	var element = document.createElement('a');
		var hex = text, // = "375771", // ASCII HEX: 37="7", 57="W", 71="q"
		bytes = [],
		str;
		
	for(var i=0; i< hex.length-1; i+=2){
		bytes.push(parseInt(hex.substr(i, 2), 16));
	}
	
	var sampleBytes = new Uint8Array(bytes);
	var saveByteArray = (function () {
		var a = document.createElement("a");
		document.body.appendChild(a);
		a.style = "display: none";
		return function (data, name) {
			console.log('as_text: '+as_text);
			if(as_text){
				var blob = new Blob([hex], {type: "text/plain"});
				console.log('text: ', blob);
			} else{
				var blob = new Blob(data, {type: "application/octet-stream"});
				console.log('data: ', blob);
			}
			var url = window.URL.createObjectURL(blob);
			a.href = url;
			console.log('url', url);
			a.download = name;
			a.click();
			window.URL.revokeObjectURL(url);
		};
	}());
		saveByteArray([sampleBytes], filename);
}

function download_as_binary(src){
	download(filename, src)
}

//Load the textareas from the text files.
var openFile = function(event, id, as_base64) {
	var input = event.target;
		var reader = new FileReader();
		reader.onload = function(){
			var text = reader.result;
			if(text.indexOf(String.fromCharCode(65533))!==-1){
				as_base64='as_base64';
				console.log('Unsigned character found. Next uploading as base64.');
				openFile(event, id, as_base64);
document.getElementById('src').setAttribute('title',
'Unsigned character was been found in the source code.\n\
Now this content was been uploaded as base64.\n\
You can decode this from base64. Just select this source encoding.');
			}
			var node = document.getElementById(id);
			if(as_base64==='as_base64'){
				node.value = text.split(';base64,')[1];
			}
			else{
				node.value = text;
			}//console.log(reader.result.substring(0, 200));
		};
		if(as_base64==='as_base64'){
			reader.readAsDataURL(input.files[0]);
		}else{
			reader.readAsText(input.files[0]);
		}
};
	  
//function to generate download links for buttons.
function updateLink(input, link) {
  link.hidden = !input.value;
  //if($('#enc_to [id="to_text"]').hasClass('active')){	//хочу что сохранялись байты а не утф.
  
  link.href = "data:text/plain;charset=UTF-8," + encodeURI(input.value); //<-- data in href, as UTF-8 text.
  link.onclick = '';
  link.style.display = (input.value==='') ? 'none' : 'block';
}

//funtion to show and hide download link (button) for empty or filled readonly textarea's
function linkText(input, link, fileName) { //IDs and filename
  link.style.display = 'none' ? 'block': 'block';
  updateLink(input, link)
  link.download = fileName;
  
  function onInput() {
    updateLink(input, link);
  }
  
  input.addEventListener("input", onInput);
  return onInput;
}
