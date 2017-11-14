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

function showRows($classname) {
	var x = document.getElementsByClassName("group"+$classname);
	var i;
	for(i = 0; i < x.length; i++) {
		x[i].style.display = "table-row";
	}
	document.getElementById("btnminus"+$classname).style.display = "inline-block";
	document.getElementById("btnplus"+$classname).style.display = "none";
}

function hideRows($classname) {
	var x = document.getElementsByClassName("group"+$classname);
	var i;
	for(i = 0; i < x.length; i++) {
		x[i].style.display = "none";
	}
	document.getElementById("btnminus"+$classname).style.display = "none";
	document.getElementById("btnplus"+$classname).style.display = "inline-block";
}

function checkSearchBarHide() {
	// check if searchresults object is available and hide search box if not
	if(document.getElementById('searchresults') === null) {
		if(document.getElementById('searchbar') !== null) {
			document.getElementById('searchbar').style.display = "none";
		}
	}
}
if(window.addEventListener) {
	window.addEventListener('load', checkSearchBarHide, false); //W3C
} else {
	window.attachEvent('onload', checkSearchBarHide); //IE
}

function search($q) {
	// check if searchresults object is available (only on index.php)
	if(document.getElementById('searchresults') === null) {
		return;
	}

	// empty query means display all entries (default state)
	if($q == "") {
		// hide all entries
		var x = document.getElementsByClassName("entry");
		var i;
		for(i = 0; i < x.length; i++) {
			x[i].style.display = "none";
		}
		// show entries without group
		x = document.getElementsByClassName("entry_without_group");
		i = 0;
		for(i = 0; i < x.length; i++) {
			x[i].style.display = "table-row";
		}
		// hide all hide group entries buttons
		x = document.getElementsByClassName("btnminus");
		i = 0;
		for(i = 0; i < x.length; i++) {
			x[i].style.display = "none";
		}
		// show all show all group entries buttons
		x = document.getElementsByClassName("btnplus");
		i = 0;
		for(i = 0; i < x.length; i++) {
			x[i].style.display = "inline-block";
		}
		// hide results text
		document.getElementById("searchresults").style.display = "none";
		return;
	}

	var filter = $q.toUpperCase();
	var x = document.getElementsByClassName("entry");
	var i;
	var result_count = 0;
	// loop trough all entries
	for(i = 0; i < x.length; i++) {
		var match = false;
		var c = x[i].getElementsByTagName("*"); // get all sub-elements
		var j;
		// loop trough all fields of this entry
		for(j = 0; j < c.length; j++) {
			// check entry contents if they match the search query
			if(hasClass(c[j], "title") || hasClass(c[j], "description") || hasClass(c[j], "url")) {
				if(c[j].innerHTML.toUpperCase().indexOf(filter) > -1) {
					match = true;
				}
			}
			if(hasClass(c[j], "username") || hasClass(c[j], "password")) {
				if(c[j].value.toUpperCase().indexOf(filter) > -1) {
					match = true;
				}
			}
		}
		// show or hide entry
		if(match == true) {
			x[i].style.display = "table-row";
			result_count ++;
		} else {
			x[i].style.display = "none";
		}
	}

	// hide all show/hide group entries buttons
	x = document.getElementsByClassName("btnplusminus");
	i = 0;
	for(i = 0; i < x.length; i++) {
		x[i].style.display = "none";
	}

	// echo result count
	document.getElementById("searchresults").style.display = "block";
	document.getElementById("searchresultcount").innerHTML = result_count;
}

function clearSearch() {
	document.getElementById("searchbar").value = "";
	search("");
}

/* helper functions for setting and removing style classes from objects */
function hasClass(el, className) {
	if (el.classList)
		return el.classList.contains(className)
	else
		return !!el.className.match(new RegExp('(\\s|^)' + className + '(\\s|$)'))
}
function addClass(el, className) {
	if (el.classList)
		el.classList.add(className)
	else if (!hasClass(el, className)) el.className += " " + className
}
function removeClass(el, className) {
	if (el.classList)
		el.classList.remove(className)
	else if (hasClass(el, className)) {
		var reg = new RegExp('(\\s|^)' + className + '(\\s|$)')
		el.className=el.className.replace(reg, ' ')
	}
}
