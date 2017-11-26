document.addEventListener("DOMContentLoaded", (e) => { 

	// Levenstein distance between two strings
	// used to replace non-dictionary words for BIP-39
	levensteinDistance = function(a, b){
	  if(a.length == 0) return b.length; 
	  if(b.length == 0) return a.length; 

	  var matrix = [];

	  // increment along the first column of each row
	  var i;
	  for(i = 0; i <= b.length; i++){
	    matrix[i] = [i];
	  }

	  // increment each column in the first row
	  var j;
	  for(j = 0; j <= a.length; j++){
	    matrix[0][j] = j;
	  }

	  // Fill in the rest of the matrix
	  for(i = 1; i <= b.length; i++){
	    for(j = 1; j <= a.length; j++){
	      if(b.charAt(i-1) == a.charAt(j-1)){
	        matrix[i][j] = matrix[i-1][j-1];
	      } else {
	        matrix[i][j] = Math.min(matrix[i-1][j-1] + 1, // substitution
	                                Math.min(matrix[i][j-1] + 1, // insertion
	                                         matrix[i-1][j] + 1)); // deletion
	      }
	    }
	  }

	  return matrix[b.length][a.length];
	};

	function bip39verify(seed){
		// checks if the seed is in BIP-39 format
		return new Promise( (resolve, reject) => {
			// getting 11-bit values encoded in the seed words
			var words = seed.trim().split(" ").map( word => {
				return english.indexOf(word);
			});
			// checks if all words are in the dictionary
			if(words.includes(-1)){
				reject("Invalid BIP-39 seed, unknown words");
				return false;
			}
			// checks if the length is correct
			if(words.length % 3 != 0){
				reject("Invalid length of the seed");
				return false;
			}

			var csLen = words.length/3; // checksum length in bits
			var payloadLen = words.length*11 - csLen;

			// converting array of 11-bit values to normal Uint8Array
			var arr = new Uint8Array(payloadLen/8);
			for(let i = 0; i < arr.length; i++){
				let startWord = Math.floor(i*8/11);
				let startPos = i*8 % 11;
				let endWord = Math.floor((i+1)*8/11);
				let endPos = (i+1)*8 % 11;
				arr[i] = (words[startWord] << (startPos-3)) | (words[endWord] >> (11-endPos));
			}

			// checksum check
			var ccs = words[words.length-1] & (2**csLen-1); // checksum from the seed
			window.crypto.subtle.digest({name: "SHA-256"}, arr).then(function (hash) {
				var h = new Uint8Array(hash);
				var cs = h[0] >> (8 - csLen); // first csLen bits of the sha256(payload)
				if(cs == ccs){
					resolve(true);
				}else{
					reject("Checksum is wrong");
				}
			});
		});
	}

	function bip39fix(seed){
		// fixes the seed
		return new Promise( (resolve, reject) => {
			// getting 11-bit values encoded in the seed words
			var words = seed.trim().split(" ").map( word => {
				let ind = english.indexOf(word);
				// replacing word with a closest one
				if(ind == -1){
					ind = 0;
					let distance = Infinity;
					for (let i = 0; i < english.length; i++) {
						let curDistance = levensteinDistance(word, english[i]);
						if(curDistance < distance){
							distance = curDistance;
							ind = i;
						}
					}
				}
				return ind;
			});			
			// checks if the length is correct
			// adding extra words if not
			if(words.length % 3 != 0){
				// for now just add last word a few more times
				// better to rewrite with hash later
				let extraWords = 3 - words.length % 3;
				for(let i = 0; i < extraWords; i++){
					words.push(words[words.length-1]);
				}
			}

			var csLen = words.length/3; // checksum length in bits
			var payloadLen = words.length*11 - csLen;

			// converting array of 11-bit values to normal Uint8Array
			var arr = new Uint8Array(payloadLen/8);
			for(let i = 0; i < arr.length; i++){
				let startWord = Math.floor(i*8/11);
				let startPos = i*8 % 11;
				let endWord = Math.floor((i+1)*8/11);
				let endPos = (i+1)*8 % 11;
				arr[i] = (words[startWord] << (startPos-3)) | (words[endWord] >> (11-endPos));
			}

			// checksum
			var ccs = words[words.length-1] & (2**csLen-1); // checksum from the seed
			window.crypto.subtle.digest({name: "SHA-256"}, arr).then(function (hash) {
				var h = new Uint8Array(hash);
				var cs = h[0] >> (8 - csLen); // first csLen bits of the sha256(payload)
				words[words.length-1] = words[words.length-1] - ccs + cs;
				var newSeed = words.map( w => { return english[w]; }).join(" ");
				resolve(newSeed);
			});
		});
	}

	function checkElectrumHash(prefix){
		return function(hash){
			return hash.startsWith(prefix);
		};
	}

	var seedInput = document.getElementById("seed");

	var formats = [
	/*  {
			name: name of the seed for detection,
			element: DOM element to place a seed of this format,
			verify: function that checks if the seed is in this format (should return promise),
			verifyHash: the same as above, but accepts HMAC instead of the seed itself
			fix: function that converts the seed to this format. if not set - random change will be applied
		},  */
		{
			name: "BIP-39",
			element: document.getElementById("bip39"),
			verify: bip39verify,
			fix: bip39fix // for bip39 we can make seed compatible in one run
		},
		{
			name: "Electrum standart",
			element: document.getElementById("el-standart"),
			verifyHash: checkElectrumHash("01")
		},
		{
			name: "Electrum segwit",
			element: document.getElementById("el-segwit"),
			verifyHash: checkElectrumHash("100")
		},
		{
			name: "Electrum 2FA",
			element: document.getElementById("el-2fa"),
			verifyHash: checkElectrumHash("101")
		}
	]

	var prefix = "01";
	var segwitPrefix = "100";

	// console.log(english.length);

	var enc = new TextEncoder("utf-8");
	var key;

	// creating a key for electrum HMAC
	window.crypto.subtle.importKey(
		"raw", enc.encode("Seed version"), { name: "HMAC", hash: {name: "SHA-512"} }, false, ["sign", "verify"]
	).then( k => {
		key = k;
		checkSeed();
	});

	function getHash(str){
		return window.crypto.subtle.sign("HMAC", key, enc.encode(str)).then(signature => {
			var b = new Uint8Array(signature);
			var hash = Array.prototype.map.call(b, x => ('00'+x.toString(16)).slice(-2)).join("")
			return {str: str, hash: hash};
		});
	}

	function showSeed(element, seed, oldSeed){
		var oldWords = oldSeed.trim().split(" ");
		var newWords = seed.trim().split(" ");
		newWords = newWords.map( (word, i) => {
			if(i >= oldWords.length){
				return "<span class='added'>"+word+"</span>";
			}
			if(oldWords[i] != word){
				return "<span class='modified'>"+word+"</span>";
			}
			return word;
		})
		element.innerHTML = newWords.join(" ");
	}

	function tryWord(seed, hashFormats, j=0){
		hashFormats = hashFormats.slice();
		if(hashFormats.length == 0){
			return;
		}

		var words = seed.trim().split(" ");
		var promises = [];
		for(let i = 0; i < english.length; i++){
			let str = words.slice(0,-1-j).join(" ") + " " + english[i] + " " + words.slice(-1-j).slice(1).join(" ");
			str = str.trim();
			promises.push(getHash(str));
		}
		Promise.all(promises).then( values => {
			var success = false;
			values.forEach( (e, i) => {
				hashFormats.forEach( (f, j) => {
					if(("verifyHash" in f) && f.verifyHash(e.hash)){
						showSeed(f.element, e.str, seed);
						hashFormats[j] = {};
					}
				});
			});
			// removing ones that already succeded
			hashFormats = hashFormats.filter( f => { return ("verifyHash" in f);})
			if(j < words.length){
				tryWord(seed, hashFormats, j+1);
			}else{
				// for now it can replace only one word, it's usually enough.
				// refactor later to try two or more words
				f.element.innerHTML = "<span class='error'>Error: unable to find matching seed</span>";
			}
		});
	}

	// checks type of the seed
	function checkSeed(){
		var seedNote = document.getElementById("seed-note");
		seedNote.innerHTML = "";
		seedInput.className = "is-invalid";

		getHash(seedInput.value.trim()).then( o => { 
			document.getElementById("hmac").innerHTML = o.hash;
			formats.forEach( format => {
				if("verifyHash" in format){
					let isValid = format.verifyHash(o.hash);
					if(isValid){
						seedNote.innerHTML += format.name + " seed<br>";
						seedInput.className = "is-valid";
					}
				}else{
					if("verify" in format){
						format.verify(o.str).then( res => {
							seedNote.innerHTML += format.name + " seed<br>";
							seedInput.className = "is-valid";
						}, err => {
							console.log(err);
						})
					}
				}
			});
		});
	}

    document.getElementById("seed").addEventListener('input', e => {
		checkSeed();
	});
	document.getElementById("generate").addEventListener("click", e => {
		bip39fix(seedInput.value).then( seed => {
			showSeed(document.getElementById("bip39"), seed, seedInput.value);
		}, err => {
			document.getElementById("bip39").innerHTML = "<span class='error'>Error: " + err + "</span>";
		});
		tryWord(seedInput.value, formats.filter( f => { return ("verifyHash" in f); }));
	});
});
