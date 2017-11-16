function obj($id) {
	return document.getElementById($id);
}

function toggleView($id) {
	if(obj($id).type == "password") {
		obj($id).type = "text";
	} else if(obj($id).type == "text") {
		obj($id).type = "password";
	}
}
function toClipboard($id) {
	// convert input to text, because copy from password input is not allowed
	$convertback = false;
	if(obj($id).type == "password") {
		obj($id).type = "text";
		$convertback = true;
	}

	// copy
	var copyText = obj($id);
	copyText.select();
	document.execCommand("Copy");

	// convert input back to password field
	if($convertback == true) {
		obj($id).type = "password";
	}
}

function showRows($groupid) {
	var x = document.getElementsByClassName("entry");
	var i;
	for(i = 0; i < x.length; i++) {
		if(x[i].getAttribute("group") == $groupid)
			x[i].style.display = "table-row";
	}
	obj("btnminus"+$groupid).style.display = "inline-block";
	obj("btnplus"+$groupid).style.display = "none";
}

function hideRows($groupid) {
	var x = document.getElementsByClassName("entry");
	var i;
	for(i = 0; i < x.length; i++) {
		if(x[i].getAttribute("group") == $groupid)
			x[i].style.display = "none";
	}
	obj("btnminus"+$groupid).style.display = "none";
	obj("btnplus"+$groupid).style.display = "inline-block";
}

function checkSearchBarHide() {
	// check if searchresults object is available and hide search box if not
	if(obj('searchresults') === null) {
		if(obj('searchbar') !== null) {
			obj('searchbar').style.display = "none";
		}
	}
}
// register checkSearchBarHide function on load event
if(window.addEventListener) {
	window.addEventListener('load', checkSearchBarHide, false); //W3C
} else {
	window.attachEvent('onload', checkSearchBarHide); //IE
}

function search($q) {
	// check if searchresults object is available (only on index.php)
	if(obj('searchresults') === null) {
		return;
	}

	// empty query means display all entries (default state)
	if($q == "") {
		// hide all entries
		var x = document.getElementsByClassName("entry");
		var i;
		for(i = 0; i < x.length; i++) {
			if(hasClass(x[i], "entry_without_group"))
				x[i].style.display = "table-row";
			else
				x[i].style.display = "none";
		}

		// restore group header visibility
		showGroupHeader();

		// hide results text
		obj("searchresults").style.display = "none";

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

	// hide group header if there are no results in this group
	showHideGroupHeader();

	// echo result count
	obj("searchresults").style.display = "block";
	obj("searchresultcount").innerHTML = result_count;
}

function showGroupHeader() {
	// show all group headers
	x = document.getElementsByClassName("groupheader");
	i = 0;
	for(i = 0; i < x.length; i++) {
		x[i].style.display = "table-cell";
	}

	// hide all "hide group entries" buttons, show all "show group entries" button
	x = document.getElementsByClassName("btnplusminus");
	i = 0;
	for(i = 0; i < x.length; i++) {
		if(hasClass(x[i], "btnplus"))
			x[i].style.display = "inline-block";
		if(hasClass(x[i], "btnminus"))
			x[i].style.display = "none";
	}
}

function showHideGroupHeader() {
	// hide group header if there are no results in this group
	x = document.getElementsByClassName("groupheader");
	i = 0;
	for(i = 0; i < x.length; i++) {
		var currentgroup = x[i].getAttribute("group");
		var hidegroup = true;
		y = document.getElementsByClassName("entry");
		j = 0;
		for(j = 0; j < y.length; j++) {
			if(y[j].getAttribute("group") == currentgroup && y[j].style.display != "none")
				hidegroup = false;
		}
		if(hidegroup == true)
			x[i].style.display = "none";
		else
			x[i].style.display = "table-cell";
	}
}

function clearSearch() {
	obj("searchbar").value = "";
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
