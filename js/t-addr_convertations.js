/**
 * Converts a ZCash t-address (transparent address) to a Bitcoin
 * "Pay To Public Key Hash" (P2PKH) address. 
 * 
 * The same private key (aka "spending key") that generated 
 * the ZCash t-address can be used to control funds associated
 * with the Bitcoin address. (This requires a Bitcoin wallet system 
 * which allows that private key to be imported. For example, 
 * bitcoin-core/bitcoind with its `importprivkey` function.)
 */
 
 
  //bitcoin address to ZCash t-address
	function baddr_to_taddr(baddr_str) {
    var baddr = new Bitcoin.Base58.decode(baddr_str).slice(1);  // decode base58check to bytes
	//and discard bitcoin prefix byte [0x00] (symbol 1)
	
	// set zcash type two bytes [1c,b8] (28, 184) at first.
    var taddr = new Uint8Array(baddr.length+1);					//new uint array
    taddr.set(baddr, 1);										//fill it + 1 byte
    taddr.set([0xb8], 0);  			 //insert second 0xb8 byte here;

	taddr = Crypto.util.bytesToHex(taddr);		//hex b8+bitcoin_payload+checksum
	taddr = taddr.substring(0,taddr.length-8)	//discard checksum
	taddr = Crypto.util.hexToBytes(taddr);		//hex b8+bitcoin_payload
	
	taddr = new Bitcoin.Address(taddr);			//new bitcoin address with new checksum
	taddr.version = 0x1c;						//set t prefix in address. first 0x1c byte
	taddr = taddr.toString();					//to string
	
	return taddr;								//return it encoded in Base58Check
	}

function taddr_to_baddr(taddr_str) {
    var taddr = new Bitcoin.Base58.decode(taddr_str).slice(2);  // discard two first type bytes [1c,b8]

	taddr = Crypto.util.bytesToHex(taddr);						//hex bitcoin_payload+checksum
	taddr = taddr.substring(0,taddr.length-8)					//discard checksum
	taddr = Crypto.util.hexToBytes(taddr);						//hex bitcoin_payload
	
	var baddr = new Bitcoin.Address(taddr);						//new bitcoin address with default prefix "1" (0x00)
	baddr = baddr.toString();									//to string
	
	return baddr;												//return it encoded in Base58Check
}

// a couple famous addresses for testing convertor
//var bitcoin_address = '1NFEViMdeYT4CcH5XLzPzsjwBiNPq8uRpg';
//document.write("bitcoin_address: "+bitcoin_address+"<br>");

//var t_addr_from_bitcoin_address = baddr_to_taddr(bitcoin_address);
//document.write("ZCash t-addr : "+t_addr_from_bitcoin_address+"<br>");		//t1f7qW3mmcsEeoFKyTmoX8gqrSNZUaDv6c6

//var bitcoin_address_from_t_addr = taddr_to_baddr(t_addr_from_bitcoin_address);
//document.write("recovered bitcoin addr : "+bitcoin_address_from_t_addr+"<br>");	//1NFEViMdeYT4CcH5XLzPzsjwBiNPq8uRpg




/**
	Вот здесь, через ссылку - передаются несколько get-параметров
*/
var query_string = (function(a) {		//get-parameters in url
    if (a == "") return {};

    var b = {};
    for (var i = 0; i < a.length; ++i)
    {
        var p=a[i].split('=', 2);
        if (p.length == 1)
            b[p[0]] = "";
        else
            b[p[0]] = decodeURIComponent(p[1].replace(/\+/g, " "));
			b[p[0]] = b[p[0]].replace('#t_addr', '');
    }
    return b;
})(window.location.search.substr(1).split('&'));

//ссылка, содержащая get-запрос может содержать более одного параметра
//index.html?address=1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN&name=query+string	

//вывод параметров переданных через get-запрос:
//document.write("address: "+query_string["address"]+"<br>");								// 1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN
//document.write("address: "+query_string["name"]+"<br>");								// 1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN





//convert address by type
function changeaddress(address){
	if(address.charAt(0)=='1'){												//if bitcoin address
		var result = baddr_to_taddr(address);			//to t-address
		result = 'ZCash t-address: '+result+' <a href="?address='+result+'#t_addr">convert back (permalink)</a>';		
	}
	else if(address.charAt(0)=='t'){										//if t-address
		var result = taddr_to_baddr(address);			//to bitcoin address
		result = 'Bitcoin address: '+result+' <a href="?address='+result+'#t_addr">convert back (permalink)</a>';
	}
	else {//else
		var result = "t-address from 'unknown coin or incorrect address': "+baddr_to_taddr(address);	
		//discard first prefix and return t-address
	}
	return result;										//return converted address.
}

var address;
var focus_second_field = false; //default focus on "Source text" textarea

function focus_2(f){
	focus_second_field = f;
	if (focus_second_field){
		$("input[id='miner_address']").focus();
	}
}

function checkaddr(){
	if(typeof address!=='undefined'){
		focus_2(true); //focus on the second input
	}
	else{
		if(typeof query_string['address'] !== 'undefined'){
			address = query_string['address'];
			focus_2(true); //focus on the second input
		}else{
			if(document.getElementById("miner_address")!==null){
				if (typeof document.getElementById("miner_address").value !== 'undefined'){
					address = query_string['address'] = document.getElementById("miner_address").value;
					focus_2(true); //focus on the second input
				}
				else{
					console.log('No any value on input...');
				}
			}else{
				address = query_string['address'] = '1NFEViMdeYT4CcH5XLzPzsjwBiNPq8uRpg'; //default address
			}
		}
	}
} checkaddr();

//get value from input and add this as get-parameter in link
var getValue = function (){
    var address = document.getElementById("miner_address").value;	//from input field
	
	var result = changeaddress(address);							//convert address
	
	location.href = '?address='+address+'#t_addr';					//change get-parameter in link + redirect
	focus_second_field = true; focus_2(true);
	return result;													//return converted address
}

var validate_address = function(address) {							//validate Base58Check checksum
    var address = address || document.getElementById("miner_address").value;	//from input if not specified
	var text, type_address;	//define var


	//recalculate checksum
	var addr_bytes = new Bitcoin.Base58.decode(address);											//decode to bytes
	var hex_addr = Crypto.util.bytesToHex(addr_bytes);												//hex
	var pref_payload = hex_addr.substring(0,hex_addr.length-8);										//discard checksum
	var checksum = hex_addr.substring(hex_addr.length-8,hex_addr.length);							//checksum hex
	var bytes_pref_payload = Crypto.util.hexToBytes(pref_payload);									//bytes prefix + payload
	var shasha_pref_payload = Crypto.SHA256(Crypto.SHA256(bytes_pref_payload, {asBytes: true}));	//double sha256 from this
	var first_fourbytes = shasha_pref_payload.substring(0,8);										//first 4 bytes is checksum
	
	//verify type of address
	if(addr_bytes[0]===0x00){type_address = "Bitcoin address";}										//bitcoin
	else if((addr_bytes[0]===0x1c)&&(addr_bytes[1]===0xb8)){type_address = "ZCash t-address";}		//t-address
	else{type_address = "unknown_coin address"}														//unknown address
	
	//validation
	if(first_fourbytes===checksum){text = type_address+" OK";}										//if checksum correct
	else{text = type_address+" NOT OK. Invalid Base58Check checksum!";}								//if incorrect
	
	return text;																					//return validation result
}  

var result = changeaddress(query_string["address"]);												//run convertation
var validation = validate_address(query_string["address"]);											//run validation