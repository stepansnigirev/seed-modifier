document.addEventListener("DOMContentLoaded", (e) => { 

	function bip39verify(seed){
		return new Promise( (resolve, reject) => {
			var words = seed.trim().split(" ").map( word => {
				return english.indexOf(word);
			});
			if(words.includes(-1)){
				reject("Invalid BIP-39 seed, unknown words");
				return false;
			}
			if(words.length % 3 != 0){
				reject("Invalid length of the seed");
				return false;
			}
			var csLen = words.length/3; // checksum length in bits
			var payloadLen = words.length*11 - csLen;

			var arr = new Uint8Array(payloadLen/8);
			for(let i = 0; i < arr.length; i++){
				let startWord = Math.floor(i*8/11);
				let startPos = i*8 % 11;
				let endWord = Math.floor((i+1)*8/11);
				let endPos = (i+1)*8 % 11;
				arr[i] = (words[startWord] << (startPos-3)) | (words[endWord] >> (11-endPos));
			}

			var ccs = words[words.length-1] & (2**csLen-1);
			window.crypto.subtle.digest({name: "SHA-256"}, arr).then(function (hash) {
				var h = new Uint8Array(hash);
				var cs = h[0] >> (8 - csLen);
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
	}

	function checkElectrumSeed(prefix){
		return function(seed){
			console.log(seed, prefix);
		};
	}
	var formats = [
		{
			name: "BIP-39",
			verify: bip39verify,
			fix: bip39fix // for bip39 we can make seed compatible in one run
		},
		{
			name: "Electrum standart",
			verify: checkElectrumSeed("01")
		},
		{
			name: "Electrum segwit",
			verify: checkElectrumSeed("100")
		},
		{
			name: "Electrum 2FA",
			verify: checkElectrumSeed("101")
		}
	]
	var prefix = "01";
	var segwitPrefix = "100";

	// console.log(english.length);

	var enc = new TextEncoder("utf-8");
	var key;

	window.crypto.subtle.importKey(
		"raw", enc.encode("Seed version"), { name: "HMAC", hash: {name: "SHA-512"} }, false, ["sign", "verify"]
	).then( k => {
		key = k;
		checkSeed();
		var seed = document.getElementById("seed").value;
		bip39verify(seed).then( e => {
			console.log("BIP-39 compatible seed");
		}, err => {
			console.log(err);
		});
	});

	function getHash(str){
		return window.crypto.subtle.sign("HMAC", key, enc.encode(str)).then(signature => {
			var b = new Uint8Array(signature);
			var hash = Array.prototype.map.call(b, x => ('00'+x.toString(16)).slice(-2)).join("")
			return {str: str, hash: hash};
		});
	}

	function tryWord(j, seed){
		var str = seed.split(" ").slice(0,-1-j).join(" ") + " " + "xxx" + " " + seed.split(" ").slice(-1-j).slice(1).join(" ");
		str = str.trim();
		console.log(str);
		var promises = [];
		for(var i = 0; i < english.length; i++){
			str = seed.split(" ").slice(0,-1-j).join(" ") + " " + english[i] + " " + seed.split(" ").slice(-1-j).slice(1).join(" ");
			str = str.trim();
			promises.push(getHash(str));
		}
		Promise.all(promises).then( values => {
			var success = false;
			values.forEach( (e, i) => {
			    if(e.hash.startsWith(segwitPrefix)){
			    	document.getElementById("seed2").value = e.str;
					document.getElementById("hmac2").innerHTML = e.hash;
					success = true;
				}
			});
			if(!success){
				if(j < seed.split(" ").length){
					tryWord(j+1, seed);
				}else{
					console.log("FAIL");
				}
			}else{
				console.log("SUCCESS on round ", j+1)
			}
		});
	}

	function checkSeed(){
		var seed = document.getElementById("seed").value;
		getHash(seed).then( o => { 
			document.getElementById("hmac").innerHTML = o.hash;

			if(o.hash.startsWith(prefix)){
				document.getElementById("seed").className = "form-control is-valid";
			}else{
				document.getElementById("seed").className = "form-control is-invalid";
			}
		});
	}

    document.getElementById("seed").addEventListener('input', e => {
		var seed = document.getElementById("seed").value;
		checkSeed();
		bip39verify(seed).then( e => {
			console.log("BIP-39 compatible seed");
		}, err => {
			console.log(err);
		});
	});
	document.getElementById("generate").addEventListener("click", e => {
		var seed = document.getElementById("seed").value;
		tryWord(0, seed);
	});
});
