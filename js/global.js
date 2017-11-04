function toggleView($id) {
	if(document.getElementById($id).type == "password") {
		document.getElementById($id).type = "text";
	} else if(document.getElementById($id).type == "text") {
		document.getElementById($id).type = "password";
	}
}
function toClipboard($id) {
	// convert input to text, because copy from password input is not allowed
	$convertback = false;
	if(document.getElementById($id).type == "password") {
		document.getElementById($id).type = "text";
		$convertback = true;
	}

	// copy
	var copyText = document.getElementById($id);
	copyText.select();
	document.execCommand("Copy");

	// convert input back to password field
	if($convertback == true) {
		document.getElementById($id).type = "password";
	}
}
