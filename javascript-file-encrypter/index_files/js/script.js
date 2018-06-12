	//Load the keys to textareas from the text files, containing PGP keys as text.
var openFile = function(event, id) {
	var input = event.target;
		var reader = new FileReader();
		reader.onload = function(){
			var text = reader.result;
			var node = document.getElementById(id);
			node.value = text;
			//console.log(reader.result.substring(0, 200));
		};
		reader.readAsText(input.files[0]);
};


$(function(){

	var body = $('body'),
		stage = $('#stage'),
		back = $('a.back');

	/* Step 1 */

	$('#step1 .encrypt').click(function(){
		body.attr('class', 'encrypt');

		// Go to step 2
		step(2);
	});

	$('#step1 .decrypt').click(function(){
		body.attr('class', 'decrypt');
		step(2);
	});


	/* Step 2 */


	$('#step2 .button').click(function(){
		// Trigger the file browser dialog
		$(this).parent().find('input').click();
	});


	// Set up events for the file inputs

	var file = null;

	$('#step2').on('change', '#encrypt-input', function(e){

		// Has a file been selected?

		if(e.target.files.length!=1){
			alert('Please select a file to encrypt!');
			return false;
		}

		file = e.target.files[0];

		if(file.size > 1024*1024){
			alert('Please choose files smaller than 1mb, otherwise you may crash your browser. \nThis is a known issue. See the tutorial.');
			return;
		}

		step(3);
	});

	$('#step2').on('change', '#decrypt-input', function(e){

		if(e.target.files.length!=1){
			alert('Please select a file to decrypt!');
			return false;
		}

		file = e.target.files[0];
		step(3);
	});


	/* Step 3 */


	$('a.button.process').click(function(){

		var input = $(this).parent().find('input[type=password]'),
			a = $('#step4 a.download'),
			password = input.val();

		input.val('');

		if(password.length<5){
			alert('Please choose a longer password!');
			return;
		}

		// The HTML5 FileReader object will allow us to read the 
		// contents of the	selected file.

		var reader = new FileReader();

		if(body.hasClass('encrypt')){

			// Encrypt the file!

			reader.onload = function(e){ //e.target.result - DataURL, base64 encoded

				// Use the CryptoJS library and the AES cypher to encrypt the 
				// contents of the file, held in e.target.result, with the password

				var b64_file_content = e.target.result.split(';base64,')[1]; //copy file content, base64-encoded
				var file_type = e.target.result.split(';base64,')[0]; //copy file type from DataURL
				var pure_file_content = file_type+';base64,'+window.atob(b64_file_content); //make file type + file source. This contains binary data.
				var encrypted = CryptoJS.AES.encrypt(pure_file_content, password); 	//Encrypt file. encrypted - base64 encoded.

				// The download attribute will cause the contents of the href
				// attribute to be downloaded when clicked. The download attribute
				// also holds the name of the file that is offered for download.

				a.attr('href', 'data:application/octet-stream;base64,' + encrypted); //write encrypted as binary data, from base64 encoded.
				a.attr('download', file.name + '.encrypted');	//downloaded Salted__... binary.

				step(4);
			};

			// This will encode the contents of the file into a data-uri.
			// It will trigger the onload handler above, with the result

			reader.readAsDataURL(file);
		}
		else {

			// Decrypt it!

			reader.onload = function(e){//e.target.result - DataURL, base64 encoded
				var file_content = e.target.result.split(';base64,')[1]; //copy base64 content of encrypted file

				if(!/^U2FsdGVkX1/.test(file_content)){//check "Salted__" base64 encoded
					alert("Invalid encrypted file! 'Salted__'-prefix not found in base64 encoded file.");
					return false;
				}
				//if ok - decrypt
				var decrypted = CryptoJS.AES.decrypt(file_content, password) //file type + file source.
											.toString(CryptoJS.enc.Utf8); // -> to UTF-8
				
				if(!/^data:/.test(decrypted)){//check dataURL
					alert("Invalid pass phrase or file! Please try again.");
					return false;
				}
				//if ok: 
				var decrypted_file_content = decrypted.split(';base64,')[1]; //copy decrypted file content
				var file_type = decrypted.split(';base64,')[0]; //and file type. This need to auto-open file, after saving this.

				var decrypted_b64 = btoa(decrypted_file_content); //encode decrypted file content to base64
				
				//make href with dataURL
				var DataURL = file_type+';base64,'+decrypted_b64; //file type + base encoded source.
				//or
				//var DataURL = 'data:application/octet-stream;base64,'+decrypted_b64; //just write this as binary data, without file type.

				a.attr('href', DataURL); //push dataURL to href
				a.attr('download', file.name.replace('.encrypted','')); //download binary bile - OK.

				step(4);
			};

			reader.readAsDataURL(file);//read file as data-url, base64-encoded
		}
	});


	/* The back button */


	back.click(function(){

		// Reinitialize the hidden file inputs,
		// so that they don't hold the selection 
		// from last time

		$('#step2 input[type=file]').replaceWith(function(){
			return $(this).clone();
		});

		step(1);
	});


	// Helper function that moves the viewport to the correct step div

	function step(i){

		if(i == 1){
			back.fadeOut();
		}
		else{
			back.fadeIn();
		}

		// Move the #stage div. Changing the top property will trigger
		// a css transition on the element. i-1 because we want the
		// steps to start from 1:

		stage.css('top',(-(i-1)*100)+'%');
	}

});
