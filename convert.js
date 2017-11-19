$(document).ready( () => {

	var prefix = "01";
	var segwitPrefix = "100";

	// console.log(english.length);

	var enc = new TextEncoder("utf-8");
	var key;

	window.crypto.subtle.importKey(
		"raw", enc.encode("Seed version"), { name: "HMAC", hash: {name: "SHA-512"} }, false, ["sign", "verify"]
	).then( k => {
		key = k;
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
			    	$("#seed2").val(e.str);
					$("#hmac2").html(e.hash);
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

	$("input").on("input", e => {
		var seed = $("#seed").val();
		getHash(seed).then( o => { 
			$("#hmac").html(o.hash);

			if(o.hash.startsWith(prefix)){
				$("#seed").addClass("is-valid");
				$("#seed").removeClass("is-invalid");
			}else{
				$("#seed").addClass("is-invalid");
				$("#seed").removeClass("is-valid");
			}
		});
	});
	$("#generate").on("click", e => {
		var seed = $("#seed").val();
		tryWord(0, seed);
	});
});
