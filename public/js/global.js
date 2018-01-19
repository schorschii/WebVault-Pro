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

function search($q) {
	// check if searchresults object is available (only on index.php)
	if(obj('searchresults') === null) {
		return;
	}

	// empty query means display all entries (default state)
	if($q == "") {
		// show all entries
		var x = document.getElementsByClassName("entry");
		for(var i = 0; i < x.length; i++) {
			//if(hasClass(x[i], "entry_without_group"))
				x[i].style.display = "list-item";
			//else
			//	x[i].style.display = "none";
		}

		// restore group header visibility
		showGroupHeader();

		// hide results text
		obj("searchresults").style.display = "none";

		return;
	}

	var filter = $q.toUpperCase();
	var x = document.getElementsByClassName("entry");
	var result_count = 0;
	// iterate over all entries
	for(var i = 0; i < x.length; i++) {
		var match = false;
		var c = x[i].getElementsByTagName("*"); // get all sub-elements
		// iterate over all fields of this entry
		for(var j = 0; j < c.length; j++) {
			// check entry contents if they match the search query
			if(c[j].innerHTML.toUpperCase().indexOf(filter) > -1) {
				match = true;
			}
		}
		// show or hide entry
		if(match == true) {
			x[i].style.display = "list-item";
			result_count ++;
		} else {
			x[i].style.display = "none";
		}
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
		x[i].style.opacity = 1;
	}
}

function showHideGroupHeader() {
	// hide group header if there are no results in this group
	x = document.getElementsByClassName("groupheader");
	for(var i = 0; i < x.length; i++) {
		var currentgroup = x[i].getAttribute("group");
		var hidegroup = true;
		y = document.getElementsByClassName("entry");
		for(var j = 0; j < y.length; j++) {
			if(y[j].getAttribute("group") == currentgroup && y[j].style.display != "none")
				hidegroup = false;
		}
		if(hidegroup == true)
			x[i].style.opacity = 0.25;
		else
			x[i].style.opacity = 1;
	}
}

function clearSearch() {
	obj("searchbar").value = "";
	search("");
}

function expandOrCollapseGroup(obj) {
	var group = obj.getElementsByTagName('ul')[0];
	if(group.style.display != "none") {
		group.style.display = "none";
		addClass(obj, "dirclosed");
	} else {
		group.style.display = "block";
		removeClass(obj, "dirclosed");
	}
}

function onFileChanged(fileInputObj, keepFilesInputObj) {
	if(fileInputObj.value == "")
		keepFilesInputObj.setAttribute('checked', 'true');
	else
		keepFilesInputObj.removeAttribute('checked');
}

function ajaxInnerHTML(obj, url) {
	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function() {
		if (this.readyState == 4 && this.status == 200) {
			obj.innerHTML = this.responseText;
			// empty title means session timed out, because title cannot be empty
			if(this.responseText == "" && obj.id == "detail_title")
				window.location.replace("login");
			// empty download file name means there is no file saved in this record
			if(this.responseText == "" && obj.id == "downloadbutton") {
				obj.innerHTML = obj.getAttribute('nofile');
				obj.setAttribute('disabled', 'true');
			} else {
				obj.removeAttribute('disabled');
			}
		}
	};
	xhttp.open("GET", url, true);
	xhttp.send();
}
function ajaxValue(obj, url) {
	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function() {
		if (this.readyState == 4 && this.status == 200) {
			obj.value = this.responseText;
		}
	};
	xhttp.open("GET", url, true);
	xhttp.send();
}
function ajaxHref(obj, url) {
	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function() {
		if (this.readyState == 4 && this.status == 200) {
			obj.href = this.responseText;
		}
	};
	xhttp.open("GET", url, true);
	xhttp.send();
}

function hideDetails() {
	obj('detail_title').innerHTML = "";
	obj('detail_group').innerHTML = "";
	obj('detail_url').innerHTML = "";
	obj('detail_url').href = "";
	obj('username').value = "";
	obj('password').value = "";
	obj('download').href = "";
	obj('downloadbutton').innerHTML = "...";
	obj('detail_id_edit').value = "";
	obj('detail_id_remove').value = "";
	obj('detail_description').innerHTML = "";
	obj('entrydetailscontainer').style.display = "none";
}
function showDetails(id) {
	let pre = "ajax" + "?id="+id;
	ajaxInnerHTML(obj('detail_title'), pre+"&param=title");
	ajaxInnerHTML(obj('detail_group'), pre+"&param=group");
	ajaxInnerHTML(obj('detail_url'), pre+"&param=url");
	ajaxHref(obj('detail_url'), pre+"&param=url");
	ajaxValue(obj('username'), pre+"&param=username");
	ajaxValue(obj('password'), pre+"&param=password");
	ajaxHref(obj('download'), pre+"&param=download");
	ajaxInnerHTML(obj('downloadbutton'), pre+"&param=filename");
	ajaxValue(obj('detail_id_edit'), pre+"&param=id");
	ajaxValue(obj('detail_id_remove'), pre+"&param=id");
	ajaxInnerHTML(obj('detail_description'), pre+"&param=description");
	obj('entrydetailscontainer').style.display = "block";
}
function popupCenter(url, title, w, h) {
	// Fixes dual-screen position                         Most browsers      Firefox
	var dualScreenLeft = window.screenLeft != undefined ? window.screenLeft : screen.left;
	var dualScreenTop = window.screenTop != undefined ? window.screenTop : screen.top;

	var width = window.innerWidth ? window.innerWidth : document.documentElement.clientWidth ? document.documentElement.clientWidth : screen.width;
	var height = window.innerHeight ? window.innerHeight : document.documentElement.clientHeight ? document.documentElement.clientHeight : screen.height;

	var left = ((width / 2) - (w / 2)) + dualScreenLeft;
	var top = ((height / 2) - (h / 2)) + dualScreenTop;
	var newWindow = window.open(url, title, 'scrollbars=yes, width=' + w + ', height=' + h + ', top=' + top + ', left=' + left);

	// Puts focus on the newWindow
	if (window.focus) {
		newWindow.focus();
	}
}

function setGroupOldValues() {
	let grouplist = obj('grouplist');
	obj('new_title').value = grouplist.options[grouplist.selectedIndex].innerHTML;
	obj('new_description').value = grouplist.options[grouplist.selectedIndex].getAttribute('description');
	obj('new_superior_group_id').value = "NULL";
	let superior_group_id = grouplist.options[grouplist.selectedIndex].getAttribute('superior_group_id');
	if(superior_group_id != "") obj('new_superior_group_id').value = superior_group_id;
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
