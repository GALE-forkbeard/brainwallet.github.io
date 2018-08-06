Brainwallet
===========

JavaScript Client-Side Bitcoin Address Generator

Notable features
----------------

* Online converter, including Base58 decoder and encoder
* OpenSSL point conversion and compressed keys support
* Armory and Electrum deterministic wallets implementation
* RFC 1751 JavaScript implementation
* Bitcoin transactions editor
* Signing and verifying messages with bitcoin address
* Litecoin support
___________________________________________________________________________________________________________
- New changes available on this page: https://username1565.github.io/brainwallet.github.io/
- Source code - here: https://github.com/username1565/brainwallet.github.io
___________________________________________________________________________________________________________
Changes:
- Add "javascript-file-encrypter".
- Add there option to upload keyfile with password as text inside.
- Add openFile-function there to load text field by file text-content.
...
See changes in javascript-file-encryptor, by comparing the code,
or read README.md here: https://github.com/username1565/javascript-file-encrypter/blob/master/README.md
or see changes.txt, here: https://github.com/username1565/brainwallet.github.io/blob/master/javascript-file-encrypter/changes.txt
___________________________________________________________________________________________________________
index.html changes:
- Add key-file tab for downloading 32 bytes key, which can be using as password to encryption and decryption.
- This value is available in separate field "passphrase" and generating as:
- this = SHA256(priv_hex) XOR sha256(hash_of_random_seed + current_addr);
- downloading as text and as file. This function in beginning of brainwallet.js
- Come back the tab "Important Security Update!"
- Add XOR page to do XOR values.
- Add new tab t-addr. Conversion between transparent-addr <-> bitcoin-addr.
___________________________________________________________________________________________________________
Brainwallet.js:
- Add multistring variable "var random_seed" to specify custom random-seed.
- Dynamic text, for toggle buttons - added.
- Generator update:
- Add field "Coin parameters".
- Add toogle-button for "passphrase".
- Add "hash of random_seed" field.
- Add XOR button to get generated private key, XORed by "hash of random_seed".
- Now the same password with different random_seed - give different private keys.
- Add "Secure Random button" for generating "secret exponent" (private key HEX).
- Add button to switch type of address (Default address, SegWit and transparent t-addr).
- Add toogle trigger when "private key" selected.
- "Toogle key" button triggered to do show private key, when private key selected.
___________________________________________________________________________________________________________
"Chains" update:
- add "hash of random seed" and XOR button. Generated keys and specified keys can be xored to this.
- add two strings in Paper Backup - to encode "Chain Code" and this is compatible with previous brainwallet.
___________________________________________________________________________________________________________
Converter update:
- Add SHA-256 to converter.
- Add converting bitocoin address to ZCash t-addr and t-addr to bitcoin address.
- Using locally Get-queries there (separate function).
- Uploading files, for textarea - added.
- download textarea, as binary - added.
- download result as UTF-8 encoded text - added.
- RAW encoding for source code of files - added.
- Now, you can see hex-code of file, for example. Also you can download the same file as binary.
- Now, you can upload any binary file, as RAW-data, see base64 or hex, sign this, verify, then decode this from hex -> to base64 and download as binary. This is the same file, and this opened after renaming, with add extension.
___________________________________________________________________________________________________________
"Sign" and "Verify" update:
- Fix. Armory HEX now give the verified status, after message signed, in the case when another coin selected in the list.
- ARCH -> Sign -> Armory HEX -> Sign message -> verify -> Signed message -> MESSAGE VERIFIED.
___________________________________________________________________________________________________________
Coins list update:
- Now list with the coins is scrollable. Height is limited.
- Add separate parameter to array with coins.
- Now can be specified is coin using compressed or uncompressed keys and addresess.
- Add autoswitching for the status of "Compressed" button, when coin selected in the list.
- Add autoswitching public key byte when coin selected in list.
- Chains-tab: Armory and Electrum now supporting compressed keys and addresses.
- EmerCoin - added. Domain coin: https://explorer.emercoin.com/nvs
- SixEleven - added. Good coin for domain names, where is supporting CNAME, for dynamic dns.
- Here you can see old version of this brainwallet: https://brain.611.to
- VertCoin - added. https://www.coinexplorer.net/VTC
- GeertCoin - added. Only 9.6 million total coins, short blockchain. Cheap coin.
- Waves - added just for google. They have DEX with many different tokens traded each for each.
___________________________________________________________________________________________________________
-This code need to be optimized and compress. So many comments there.
__________________________
What need to fix?
Check and verify signatures for another altcoins, using compressed private keys...
For example, Geertcoin have compressed private keys and address...
1. Go to https://username1565.github.io/brainwallet.github.io/
2. Select Geertcoin in the list.
3. Default private key in generator: RZUp8o9zpfvDqHixCok4gcHLneqpo8ZEQBM1dVzTLBZ9p5TDnxd5
address corresponded for this private key is GNaix3HVRokcTW9CPM9N8vsVtuzmjguTrv - both are compressed...
4. Go to "Sign" tab, and press the button "Sign Message".
5. Signed message can be [verified now, in brainwallet](https://username1565.github.io/brainwallet.github.io/#verify?vrAddr=GNaix3HVRokcTW9CPM9N8vsVtuzmjguTrv&vrMsg=This%20is%20an%20example%20of%20a%20signed%20message.&vrSig=HzRtqv21fSm%2F6LBmFX57ppSddO4GXihI60rDRAET1baSt1D9fGsGIie75xgBJfcDZOF6bLZKjKA9odKzobsaRHY%3D)
bitcoin-qt version of this message, can be verified too, and only in brainwallet...

But in geertcoin-qt.exe this message cann't be verified!
Also, message, signed in geertcoin-qt.exe cannt be verified in brainwallet...
This need to test for all altcoins, where using compressed and uncompressed keys.

Best regards...
