//decrypts a page
function decrypt_page(url_to_file, container_id, password_id) {
    let url = url_to_file;

    let xmlHttp = new XMLHttpRequest();
    xmlHttp.onreadystatechange = function() {
	if (xmlHttp.readyState == 4 && xmlHttp.status == 200) // if ready state is completed, and we recieved an HTTP OK
	    decrypt_page_callback(xmlHttp.responseText, container_id, password_id); // process html content
    }

    xmlHttp.open("GET", url, true); //asynchronous request
    xmlHttp.send(null); //start the request
}

function utf8_to_arraybuffer(string) {
    let arraybuffer = new Uint8Array(string.length);
    for (let i = 0; i < string.length; i++)
	arraybuffer[i] = string.charCodeAt(i);
    return arraybuffer;
}

//will attempt to get the iv from the url
//the iv will be in arraybuffer form
function get_iv() {
    let iv = null;
    location.search.substr(1).split("&").forEach( (item) => { //substr returns everything from ? on, so we start from index 1, after ?
	let tmp = item.split("="); //split paramter and value
	if (tmp[0] === "iv") iv = decodeURIComponent(tmp[1]); //finds the iv parameter, return decoded uri
    });

    if (iv !== null) //if IV is not null, we convert the string from base64 to arraybuffer
	iv = utf8_to_arraybuffer(atob(iv));

    return iv; //returns null if iv is not found
};

//callback function to decrypt a page, and dumps the content into id
//note: UTF-8 strings only.
function decrypt_page_callback(encrypted_html, container_id, password_id) {
    encrypted_html = utf8_to_arraybuffer(atob(encrypted_html)) //get an array buffer version of the encrypted information
    let iv = get_iv(), cleartext = ""; //gets the iv, and creates a variable
    let page = document.getElementById(container_id); //gets the container to store the cleartext
    const password = utf8_to_arraybuffer(document.getElementById(password_id).value); //gets the ArrayBuffer of the password

    if (iv === null) {
	page.innerHTML = "Invalid or missing IV vector. If you have been given the link to this page, please copy and paste the entire link.";
	return;
    } else {
	window.crypto.subtle.importKey(
	    "raw",
	    password,
	    "PBKDF2",
	    false,
	    ["deriveKey"]
	).then( (key) => { //we now have a CryptoKey
	    window.crypto.subtle.deriveKey(
		{
		    name: "PBKDF2",
		    hash: "SHA-256",
		    salt: iv,
		    iterations: 1000
		},
		key,
		{
		    name: "AES-GCM",
		    length: 256
		},
		false,
		["decrypt"]
	    ).then( (key) => {
		window.crypto.subtle.decrypt( //decrypt the contents of encrypted_html with the key
		    {
			name: "AES-GCM",
			iv: iv
		    },
		    key,
		    encrypted_html
		).then( (cleartext) => { //cleartext
		    let textDecoder = new TextDecoder();
		    page.innerHTML = textDecoder.decode(cleartext);
		}, (err_msg) => { //decryption failed, either invalid key or invalid operation
		    page.innerHTML = "Cannot decrypt your file. Is your password valid?";
		    console.log("Decryption error: " + err_msg);
		});
	    }, (err_msg) => { //can't derive key
		page.innerHTML = "Cannot derive a key from your password. Is your password valid?";
		console.log("Key derivation failed: " + err_msg);
	    });
	}, (err_msg) => { //key generation failed, probably due to invalid key format
	    page.innerHTML = "Cannot generate a key. Is your password valid?";
	    console.log("Key generation failed: " + err_msg);
	});
    }
};
