// global session variables
var sessionKeys = {
	'private': null, 'public': null
};
var sessionVaultContent = {
	'groups': {}, 'passwords': {}
};
var sessionEnvironment = {
	'userId': -1, 'users': {}, 'groups': {}
};
var sessionCheckTimer;


// set up event listeners
document.addEventListener('DOMContentLoaded', (event) => {
	btnLogin.addEventListener('click', () => login());
	txtSearch.addEventListener('input', () => search(txtSearch.value));
	btnNewPassword.addEventListener('click', () => showPasswordDetails());
	btnNewGroup.addEventListener('click', () => showGroupDetails());
	btnUserGroups.addEventListener('click', () => showUserGroupsManagement());
	btnReload.addEventListener('click', () => {
		imgReload.classList.add('rotating');
		divVault.classList.add('loading');
		loadVault().then(() => {
			imgReload.classList.remove('rotating');
			divVault.classList.remove('loading');
		})
	});
	btnLogout.addEventListener('click', () => logout());
	let loginAction = function(event) {
		event.preventDefault();
		if(event.keyCode === 13) btnLogin.click();
	};
	txtUsername.addEventListener('keyup', loginAction);
	txtPassword.addEventListener('keyup', loginAction);
	txtOldPassword.addEventListener('keyup', loginAction);
	activateMouseDragForParent(divVaultTitlebar);
});


class PrivateKeyDecryptionError extends Error {}

function jsonRequest(method, url, data) {
	return new Promise(function(resolve, reject) {
		var xhttp = new XMLHttpRequest();
		xhttp.onreadystatechange = function() {
			if(this.readyState == 4) {
				if(this.status == 200) {
					resolve(JSON.parse(this.responseText));
				} else if(this.status == 401) {
					logout();
					reject('Session expired');
				} else {
					reject('HTTP '+this.status+' '+this.responseText);
				}
			}
		};
		xhttp.open(method, url, true);
		xhttp.setRequestHeader('Content-type', 'application/json');
		if(data) {
			xhttp.send(JSON.stringify(data));
		} else {
			xhttp.send();
		}
	});
}

function login() {
	if(!crypto.subtle) {
		alert(strings.crypto_api_unavailable);
		return;
	}

	let username = txtUsername.value;
	let password = txtPassword.value;
	let oldPassword = password;
	if(txtOldPassword.value !== '') {
		oldPassword = txtOldPassword.value;
	}

	btnLogin.classList.add('loading');
	btnLogin.disabled = true;
	jsonRequest(
		'POST', 'user/login',
		{'username':username, 'password':password}
	).then((response) => {
		if(response.private_key) {
			// store users and groups for sharing options
			sessionEnvironment['userId'] = response.id;
			response.users.forEach((item) => {
				sessionEnvironment['users'][item.id] = {'display_name': item.display_name, 'public_key': item.public_key};
			});
			response.groups.forEach((item) => {
				sessionEnvironment['groups'][item.id] = {'title': item.title, 'members': item.members};
			});
			// try to decrypt private key with password
			return importPrivateKey(response.private_key, oldPassword, response.salt, response.iv)
				.then((key) => {
					let promiseChain = Promise.resolve();
					if(oldPassword !== password) {
						// re-encrypt private key with new password
						console.log('Re-encrypted private key with new password');
						promiseChain = exportPrivateKey(key, password)
							.then((exportedPrivKey) => jsonRequest(
								'POST', 'user/keys',
								{'private_key':exportedPrivKey.key, 'salt':exportedPrivKey.salt, 'iv':exportedPrivKey.iv}
							));
					}
					return promiseChain.then(() => loadVault(key))
					.then(() => loginToVaultAnimation());
				}).catch((error) => {
					infobox(divLoginInfoBox, 'yellow', strings.private_key_decryption_error);
					divLoginInfoBox.classList.remove('invisible');
					txtOldPassword.classList.remove('invisible');
					throw new PrivateKeyDecryptionError('Unable to decrypt private key: '+error); // trigger the outer error handler
				});
		} else {
			// generate a private key, encrypt with password
			let _keys;
			return generateKey(encryptAlgorithm, scopesEncryptDecrypt)
				.then((pair) => exportPemKeys(pair, password))
				.then((keys) => {
					console.log('Keypair generated');
					//console.log(keys.privateKey); console.log(keys.publicKey);
					// store the generated key on the server
					_keys = keys;
					return jsonRequest(
						'POST', 'user/keys',
						{'public_key':keys.publicKey, 'private_key':keys.privateKey, 'salt':keys.salt, 'iv':keys.iv}
					);
				})
				.then(() => login());
		}
	}).then(() => {
		txtUsername.value = '';
		txtPassword.value = '';
		txtOldPassword.value = '';
		txtOldPassword.classList.add('invisible');
		divLoginInfoBox.classList.add('invisible');

		clearInterval(sessionCheckTimer);
		sessionCheckTimer = setInterval(checkSession, 5000);
	}).catch((error) => {
		console.error(error);
		txtPassword.value = '';
		txtOldPassword.value = '';
		btnLogin.classList.remove('loading');
		btnLogin.disabled = false;
		if(!(error instanceof PrivateKeyDecryptionError)) {
			infobox(divLoginInfoBox, 'red', strings.login_failed);
			divLoginInfoBox.classList.remove('invisible');
		}
	});
}

function checkSession() {
	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function() {
		if(this.readyState == 4) {
			// not not log out if status code is 0, which means connection lost
			// it should be able to still view passwords offline
			if(this.status >= 400 && this.status <= 499) {
				console.log('Session timed out');
				logout();
			}
		}
	};
	xhttp.open('GET', 'user/session', true);
	xhttp.send();
}

function loadVault(privKey=null, pubKey=null) {
	if(privKey) sessionKeys['private'] = privKey;
	if(pubKey) sessionKeys['public'] = pubKey;

	sessionVaultContent = {
		'groups': {}, 'passwords': {}
	};

	return jsonRequest(
		'GET', 'vault/entries', null
	).then((response) => {
		// parse groups
		response.groups.forEach((group) => {
			sessionVaultContent['groups'][group.id] = {
				'group':group.parent_password_group_id,
				'title':group.title,
				'share_users':group.share_users, 'share_groups':group.share_groups
			};
		});
		// decrypt all passwords
		let promiseChain = Promise.resolve();
		response.passwords.forEach((password) => {
			promiseChain = promiseChain.then(() =>
				decryptData(base64StringToArrayBuffer(password.iv), sessionKeys['private'], base64StringToArrayBuffer(password.secret))
				.then((decrypted) => {
					let decryptedData = JSON.parse(arrayBufferToText(decrypted));
					sessionVaultContent['passwords'][password.id] = {
						'revision':password.revision,
						'group':password.password_group_id, 'title':decryptedData.title,
						'username':decryptedData.username, 'password':decryptedData.password,
						'url':decryptedData.url, 'description':decryptedData.description,
						'share_users':password.share_users, 'share_groups':password.share_groups
					};
				})
			);
		});
		return promiseChain;
	})
	.then(() => populateVaultWindowEntries())
	.catch((error) => {
		console.error(error);
	});
}
function populateVaultWindowEntries() {
	ulEntriesTree.innerHTML = '';
	if(!Object.keys(sessionVaultContent['passwords']).length
	&& !Object.keys(sessionVaultContent['groups']).length) {
		ulEntriesTree.innerHTML = strings.empty_vault_placeholder;
		return;
	}
	addGroupsHtmlOfParent(null);
	for(let key in sessionVaultContent['passwords']) {
		let password = sessionVaultContent['passwords'][key];
		let temporaryParentGroupId = password['group'];
		if(password['group'] !== null && !(password['group'] in sessionVaultContent['groups'])) {
			// we don't have permission to this parent group
			temporaryParentGroupId = null;
			console.log('added password '+key+' to vault root because permissions for parent group missing');
		}
		let groupUl = temporaryParentGroupId ? sessionVaultContent['groups'][temporaryParentGroupId]['ul'] : ulEntriesTree;
		addPasswordHtml(groupUl, key, password);
	}
	restoreGroupState();
}
function addGroupsHtmlOfParent(parentGroupId) {
	for(let key in sessionVaultContent['groups']) {
		let group = sessionVaultContent['groups'][key];
		let temporaryParentGroupId = group['group'];
		if(group['group'] !== null && !(group['group'] in sessionVaultContent['groups'])) {
			// we don't have permission to this parent group
			temporaryParentGroupId = null;
			console.log('added group '+key+' to vault root because permissions for parent group missing');
		}
		if(temporaryParentGroupId == parentGroupId) {
			let groupUl = temporaryParentGroupId ? sessionVaultContent['groups'][temporaryParentGroupId]['ul'] : ulEntriesTree;
			sessionVaultContent['groups'][key]['ul'] = addGroupHtml(groupUl, key, group);
			addGroupsHtmlOfParent(key);
		}
	}
}
function addPasswordHtml(parentUl, id, passwordItem) {
	let openDetailsAction = function(e) {
		showPasswordDetails(id);
		e.preventDefault();
		e.stopPropagation();
	};
	let li = document.createElement('LI');
	li.classList.add('password');
	li.setAttribute('passwordid', id);
	li.addEventListener('click', openDetailsAction);
	parentUl.appendChild(li);
	let divCont = document.createElement('DIV');
	li.appendChild(divCont);
	let a = document.createElement('A');
	a.href = '#';
	a.addEventListener('click', openDetailsAction);
	divCont.appendChild(a);
	let spanTitle = document.createElement('SPAN');
	spanTitle.innerText = truncate(passwordItem.title);
	a.appendChild(spanTitle);
	let spanUsername = document.createElement('SPAN');
	spanUsername.classList.add('username');
	spanUsername.innerText = truncate(passwordItem.username);
	a.appendChild(spanUsername);
	let divDesc = document.createElement('DIV');
	divDesc.classList.add('entrydescription');
	divCont.appendChild(divDesc);
	if(passwordItem.url) {
		let aUrl = document.createElement('A');
		aUrl.href = passwordItem.url;
		aUrl.innerText = truncate(passwordItem.url);
		aUrl.target = '_blank';
		aUrl.addEventListener('click', (e) => e.stopPropagation());
		divDesc.appendChild(aUrl);
	}
	let spanDesc = document.createElement('SPAN');
	spanDesc.innerText = (passwordItem.url&&passwordItem.description ? ' - ' : '') + truncate(passwordItem.description.replace('\n', ' '));
	divDesc.appendChild(spanDesc);
	if(passwordItem['share_users'].length > 1 || passwordItem['share_groups'].length > 0) {
		let spanShares = document.createElement('SPAN');
		spanShares.classList.add('shares');
		spanShares.innerText = passwordItem['share_users'].length+' Benutzer, '+passwordItem['share_groups'].length+' Gruppe(n)';
		divDesc.appendChild(spanShares);
	}
}
function addGroupHtml(parentUl, id, groupItem) {
	let li = document.createElement('LI');
	let openDetailsAction = function(e) {
		li.classList.toggle('closed');
		saveGroupState();
		e.preventDefault();
		e.stopPropagation();
	};
	li.classList.add('group');
	li.classList.add('closed');
	li.setAttribute('groupid', id);
	li.addEventListener('click', openDetailsAction);
	parentUl.appendChild(li);
	let divCont = document.createElement('DIV');
	divCont.classList.add('groupheader');
	li.appendChild(divCont);
	let a = document.createElement('A');
	a.href = '#';
	a.innerText = groupItem.title;
	a.addEventListener('click', openDetailsAction);
	divCont.appendChild(a);
	let btnEdit = document.createElement('BUTTON');
	let imgEdit = document.createElement('IMG');
	imgEdit.src = 'img/edit.svg';
	btnEdit.appendChild(imgEdit);
	btnEdit.addEventListener('click', function(e){
		showGroupDetails(id);
		e.stopPropagation();
	});
	divCont.appendChild(btnEdit);
	let divDesc = document.createElement('DIV');
	divDesc.classList.add('groupdescription');
	divCont.appendChild(divDesc);
	if(groupItem['share_users'].length > 1 || groupItem['share_groups'].length > 0) {
		let spanShares = document.createElement('SPAN');
		spanShares.classList.add('shares');
		spanShares.innerText = groupItem['share_users'].length+' Benutzer, '+groupItem['share_groups'].length+' Gruppe(n)';
		divDesc.appendChild(spanShares);
	}
	let ulSub = document.createElement('UL');
	li.appendChild(ulSub);
	return ulSub;
}
function infobox(div, color, text) {
	div.classList.remove('red');
	div.classList.remove('yellow');
	div.classList.remove('green');
	div.classList.remove('blue');
	div.classList.add(color);
	div.innerText = text;
}

function logout() {
	sessionKeys = {
		'private': null, 'public': null
	};
	sessionVaultContent = {
		'groups': {}, 'passwords': {}
	};
	sessionEnvironment = {
		'users': {}, 'groups': {}
	};

	jsonRequest(
		'POST', 'user/logout', null
	).then(() => {
		let childWindows = document.getElementsByClassName('childWindow');
		for(var i=0; i<childWindows.length; i++) {
			childWindows[i].getElementsByClassName('btnClose')[0].click();
		}
		vaultToLoginAnimation();
	})
	.catch((error) => {
		console.error(error);
	});
	clearInterval(sessionCheckTimer);
}

const STORAGE_KEY_GROUP_STATE = 'group-states';
function saveGroupState() {
	let groupStates = {};
	var elements = ulEntriesTree.querySelectorAll('li.group');
	for(var i = 0; i < elements.length; i++) {
		let groupId = elements[i].getAttribute('groupid');
		groupStates[groupId] = !elements[i].classList.contains('closed');
	}
	localStorage.setItem(STORAGE_KEY_GROUP_STATE, JSON.stringify(groupStates));
}
function restoreGroupState() {
	let groupStates = JSON.parse(localStorage.getItem(STORAGE_KEY_GROUP_STATE));
	if(!groupStates) return;
	var elements = ulEntriesTree.querySelectorAll('li.group');
	for(var i = 0; i < elements.length; i++) {
		let groupId = elements[i].getAttribute('groupid');
		if(groupStates[groupId]) {
			elements[i].classList.remove('closed');
		} else {
			elements[i].classList.remove('add');
		}
	}
}

function generateRandomPassword(length=12) {
	var charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
	var generated = '';
	for(var i = 0, n = charset.length; i < length; ++i) {
		generated += charset.charAt(Math.floor(Math.random() * n));
	}
	return generated;
}
function togglePasswordInput(input) {
	if(input.type == 'password') {
		input.type = 'text';
	} else if(input.type == 'text') {
		input.type = 'password';
	}
}
function copyInputValueToClipboard(input) {
	// select all text
	input.select();
	input.setSelectionRange(0, 99999); // For mobile devices
	// copy the text inside the text field
	navigator.clipboard.writeText(input.value);
}

function search(q) {
	var entries = divVault.querySelectorAll('.password, .group');
	// empty query means display all entries (default state)
	if(q == '') {
		// show all entries again
		for(var i = 0; i < entries.length; i++) {
			entries[i].style.display = '';
		}
		// restore group header visibility
		showGroupHeader();
		return;
	}
	// do the search
	var filter = q.toUpperCase();
	for(var i = 0; i < entries.length; i++) {
		let match = false;
		let passwordId = entries[i].getAttribute('passwordid');
		let groupId = entries[i].getAttribute('groupid');
		var item;
		if(passwordId) item = sessionVaultContent['passwords'][passwordId];
		else if(groupId) item = sessionVaultContent['groups'][groupId];
		// iterate over all fields and check if contents match the search query
		for(let key in item) {
			if(!item[key] || typeof item[key] !== 'string') continue;
			match = (item[key].toUpperCase().indexOf(filter) > -1);
			if(match) break;
		}
		// show or hide password
		if(match) {
			entries[i].classList.add('searchresult');
			if(entries[i].classList.contains('password'))
				entries[i].style.display = '';
			// open all parent folders
			let parent = entries[i].parentNode;
			while(parent.id != 'ulEntriesTree') {
				if(parent.classList.contains('group'))
					parent.classList.remove('closed');
				parent = parent.parentNode;
			}
		} else {
			entries[i].classList.remove('searchresult');
			if(entries[i].classList.contains('password'))
				entries[i].style.display = 'none';
		}
	}
	// hide group header if there are no results in this group
	showHideGroupHeader();
}

function showGroupHeader() {
	// show all group headers
	let items = ulEntriesTree.getElementsByClassName('groupheader');
	for(var i = 0; i < items.length; i++) {
		items[i].style.opacity = 1;
	}
}
function showHideGroupHeader() {
	// hide group header if there are no results in this group
	let items = ulEntriesTree.getElementsByClassName('groupheader');
	for(var i = 0; i < items.length; i++) {
		var hidegroup = true;
		var subItems = items[i].getElementsByClassName('password');
		for(var j = 0; j < subItems.length; j++) {
			if(subItems[j].classList.contains('searchresult'))
				hidegroup = false;
		}
		if(hidegroup) {
			items[i].style.opacity = 0.25;
		} else {
			items[i].style.opacity = 1;
		}
	}
}

function populateUserGroups() {
	let tblGroups = divUserGroupsContainer.querySelectorAll('.groups')[0];
	tblGroups.innerHTML = '';
	for(let groupId in sessionEnvironment['groups']) {
		addUserGroupRow(tblGroups, groupId, function(){
			showUserGroupManagement(groupId);
		});
	}
	if(!Object.keys(sessionEnvironment['groups']).length) {
		let tr = document.createElement('TR');
		tblGroups.appendChild(tr);
		let td = document.createElement('TD');
		td.innerText = strings.no_user_groups_placeholder;
		tr.appendChild(td);
	}
}
function showUserGroupManagement(id=null) {
	// create details window on current main window position
	const clone = divUserGroupTemplateContainer.cloneNode(true);
	clone.removeAttribute('id');
	clone.style.top = (parseInt(divVaultContainer.style.top)+35) + 'px';
	clone.style.left = (parseInt(divVaultContainer.style.left)+35) + 'px';
	// identify inputs
	let txtTitle = clone.querySelectorAll('[name=txtTitle]')[0];
	let sltGroupUser = clone.querySelectorAll('[name=sltGroupUser]')[0];
	let tblMembers = clone.querySelectorAll('.members')[0];
	// populate select boxes
	sltGroupUser.innerHTML = '';
	for(let userId in sessionEnvironment['users']) {
		let option = document.createElement('OPTION');
		option.value = userId;
		option.innerText = sessionEnvironment['users'][userId]['display_name'];
		if(!sessionEnvironment['users'][userId]['public_key']) option.disabled = true;
		sltGroupUser.appendChild(option);
	}
	// add actions
	activateMouseDragForParent(clone.querySelectorAll('.titlebar')[0]);
	let closeAnimation = windowCloseAction(clone);
	clone.querySelectorAll('.btnAddGroupUser')[0].addEventListener('click', function(){
		addShareUserRow(tblMembers, sltGroupUser.value);
	});
	clone.querySelectorAll('.btnSave')[0].addEventListener('click', function(){
		// get all member ids
		let newGroupMemberIds = [];
		let userEntries = clone.querySelectorAll('.members tr');
		for(let i=0; i<userEntries.length; i++) {
			if(userEntries[i].getAttribute('userid')) {
				newGroupMemberIds.push(userEntries[i].getAttribute('userid'));
			}
		}
		// re-encrypt all passwords which are shared with the edited group
		let promiseChain = [];
		var encryptedPasswords = {};
		if(id) {
			for(let passwordId in sessionVaultContent['passwords']) {
				if(sessionVaultContent['passwords'][passwordId]['share_groups'].includes(parseInt(id))) {
					let targetPublicKeys = {};
					sessionVaultContent['passwords'][passwordId]['share_users'].forEach((userId) => {
						targetPublicKeys[userId] = sessionEnvironment['users'][userId]['public_key'];
					});
					sessionVaultContent['passwords'][passwordId]['share_groups'].forEach((groupId) => {
						let newMembers = (id==groupId) ? newGroupMemberIds : sessionEnvironment['groups'][groupId]['members'];
						newMembers.forEach((groupUserId) => {
							targetPublicKeys[groupUserId] = sessionEnvironment['users'][groupUserId]['public_key'];
						});
					});
					let secret = {
						'title': sessionVaultContent['passwords'][passwordId].title,
						'username': sessionVaultContent['passwords'][passwordId].username,
						'password': sessionVaultContent['passwords'][passwordId].password,
						'url': sessionVaultContent['passwords'][passwordId].url,
						'description': sessionVaultContent['passwords'][passwordId].description,
					};
					for(let userId in targetPublicKeys) {
						promiseChain.push(
							importPublicKey(targetPublicKeys[userId], userId, passwordId)
							.then((result) => {
								let iv = getRandomCryptoValues(16);
								if(!(result.passwordId in encryptedPasswords)) {
									encryptedPasswords[result.passwordId] = {
										'revision': sessionVaultContent['passwords'][passwordId].revision,
										'share_users': sessionVaultContent['passwords'][passwordId].share_users,
										'share_groups': sessionVaultContent['passwords'][passwordId].share_groups
									};
								}
								encryptedPasswords[result.passwordId][result.userId] = {
									'iv': arrayBufferToBase64String(iv),
									'secret': null, // filled in next step
								};
								return encryptData(iv, result.key, JSON.stringify(secret), result.userId, result.passwordId);
							})
							.then((result) => {
								encryptedPasswords[result.passwordId][result.userId]['secret'] = arrayBufferToBase64String(result.encrypted);
								return Promise.resolve();
							})
						);
					}
				}
			}
		}
		// send request
		Promise.all(promiseChain)
		.then(() => jsonRequest(
			'POST', (id==null ? 'user/group' : 'user/group/'+encodeURIComponent(id)),
			{'title':txtTitle.value, 'members':newGroupMemberIds, 'passwords':encryptedPasswords}
		)).then((response) => {
			sessionEnvironment['groups'][response.id] = {'title':txtTitle.value, 'members':newGroupMemberIds};
			populateUserGroups();
			closeAnimation();
		}).catch((error) => {
			console.warn(error);
			alert(error);
		});
	});
	clone.querySelectorAll('.btnDelete')[0].addEventListener('click', function(){
		if(confirm(strings.are_you_sure)) {
			jsonRequest(
				'DELETE', 'user/group/'+encodeURIComponent(id), null
			).then((response) => {
				delete sessionEnvironment['groups'][id];
				populateUserGroups();
				closeAnimation();
			}).catch((error) => {
				console.warn(error);
				alert(error);
			});
		}
	});
	clone.querySelectorAll('.btnClose')[0].addEventListener('click', closeAnimation);
	if(id == null) {
		clone.querySelectorAll('.btnDelete')[0].remove();
		// add self by default since it is necessary
		addShareUserRow(tblMembers, sessionEnvironment['userId']);
	} else {
		// load members
		sessionEnvironment['groups'][id]['members'].forEach((userId) => {
			addShareUserRow(tblMembers, userId);
		});
		txtTitle.value = sessionEnvironment['groups'][id]['title'];
	}
	// show with animation
	document.body.appendChild(clone);
	windowOpenAnimation(clone);
	txtTitle.focus();
}
function showUserGroupsManagement() {
	divUserGroupsContainer.style.top = (parseInt(divVaultContainer.style.top)+35) + 'px';
	divUserGroupsContainer.style.left = (parseInt(divVaultContainer.style.left)+35) + 'px';
	// populate select boxes
	populateUserGroups();
	// add actions
	activateMouseDragForParent(divUserGroupsContainer.querySelectorAll('.titlebar')[0]);
	divUserGroupsContainer.querySelectorAll('.btnAdd')[0].onclick = function(){showUserGroupManagement()};
	divUserGroupsContainer.querySelectorAll('.btnClose')[0].onclick = windowCloseAction(divUserGroupsContainer,false);
	// show with animation
	windowOpenAnimation(divUserGroupsContainer);
}

function showGroupDetails(id=null) {
	// create details window on current main window position
	const clone = divGroupTemplateContainer.cloneNode(true);
	clone.removeAttribute('id');
	clone.style.top = (parseInt(divVaultContainer.style.top)+35) + 'px';
	clone.style.left = (parseInt(divVaultContainer.style.left)+35) + 'px';
	// identify inputs
	let sltGroup = clone.querySelectorAll('[name=sltGroup]')[0];
	let txtTitle = clone.querySelectorAll('[name=txtTitle]')[0];
	let sltShareUser = clone.querySelectorAll('[name=sltShareUser]')[0];
	let sltShareUserGroup = clone.querySelectorAll('[name=sltShareUserGroup]')[0];
	let tblShares = clone.querySelectorAll('.shares')[0];
	// populate select boxes
	populateGroupSelectBox(sltGroup, null, id);
	for(let userId in sessionEnvironment['users']) {
		let option = document.createElement('OPTION');
		option.value = userId;
		option.innerText = sessionEnvironment['users'][userId]['display_name'];
		if(!sessionEnvironment['users'][userId]['public_key']) option.disabled = true;
		sltShareUser.appendChild(option);
	}
	for(let userGroupId in sessionEnvironment['groups']) {
		let option = document.createElement('OPTION');
		option.value = userGroupId;
		option.innerText = sessionEnvironment['groups'][userGroupId]['title'];
		sltShareUserGroup.appendChild(option);
	}
	// add actions
	activateMouseDragForParent(clone.querySelectorAll('.titlebar')[0]);
	let closeAnimation = windowCloseAction(clone);
	if(id == null) {
		clone.querySelectorAll('.btnDelete')[0].remove();
	} else {
		let group = sessionVaultContent['groups'][id];
		sltGroup.value = group['group'];
		txtTitle.value = group['title'];
		clone.querySelectorAll('.btnDelete')[0].addEventListener('click', function(e){
			if(confirm(strings.are_you_sure)) {
				jsonRequest(
					'DELETE', 'vault/group/'+encodeURIComponent(id), null
				).then((response) => {
					delete sessionVaultContent['groups'][id];
					populateVaultWindowEntries();
					closeAnimation(e);
				}).catch((error) => {
					console.warn(error);
					alert(error);
				});
			}
		});
		group['share_groups'].forEach((shareGroupId) => {
			addShareGroupRow(tblShares, shareGroupId);
		});
		group['share_users'].forEach((shareUserId) => {
			addShareUserRow(tblShares, shareUserId);
		});
	}
	sltGroup.addEventListener('change', function(e) {
		// apply permissions from parent folder
		if(sltGroup.value != '' && sltGroup.value != '-') {
			let permissionEntries = clone.querySelectorAll('.shares tr');
			for(let i=0; i<permissionEntries.length; i++) {
				if(permissionEntries[i].getAttribute('userid') || permissionEntries[i].getAttribute('groupid')) {
					permissionEntries[i].remove();
				}
			}
			sessionVaultContent['groups'][sltGroup.value]['share_groups'].forEach((shareGroupId) => {
				addShareGroupRow(tblShares, shareGroupId);
			});
			sessionVaultContent['groups'][sltGroup.value]['share_users'].forEach((shareUserId) => {
				addShareUserRow(tblShares, shareUserId);
			});
		}
	});
	clone.querySelectorAll('.btnAddUserShare')[0].addEventListener('click', function(e){
		addShareUserRow(tblShares, sltShareUser.value);
	});
	clone.querySelectorAll('.btnAddUserGroupShare')[0].addEventListener('click', function(e){
		addShareGroupRow(tblShares, sltShareUserGroup.value);
	});
	clone.querySelectorAll('.btnContents')[0].addEventListener('click', function(e){
		clone.querySelectorAll('.box.contents')[0].classList.remove('invisible');
		clone.querySelectorAll('.box.share')[0].classList.add('invisible');
	});
	clone.querySelectorAll('.btnShare')[0].addEventListener('click', function(e){
		clone.querySelectorAll('.box.contents')[0].classList.add('invisible');
		clone.querySelectorAll('.box.share')[0].classList.remove('invisible');
	});
	clone.querySelectorAll('.btnClose')[0].addEventListener('click', closeAnimation);
	clone.querySelectorAll('.btnSave')[0].addEventListener('click', function(e){
		let shareUsers = [];
		let shareGroups = [];
		let targetPublicKeys = {};
		// add logged in user
		let myUserId = sessionEnvironment['userId'];
		shareUsers.push(myUserId);
		targetPublicKeys[myUserId] = sessionEnvironment['users'][myUserId]['public_key'];
		// add all other users
		tblShares.querySelectorAll('tr').forEach(function(item){
			let userId = item.getAttribute('userid') ? parseInt(item.getAttribute('userid')) : null;
			let groupId = item.getAttribute('groupid') ? parseInt(item.getAttribute('groupid')) : null;
			if(userId && !shareUsers.includes(userId)) {
				targetPublicKeys[userId] = sessionEnvironment['users'][userId]['public_key'];
				shareUsers.push(userId);
			}
			if(groupId && !shareGroups.includes(groupId)) {
				sessionEnvironment['groups'][groupId]['members'].forEach((groupUserId) => {
					targetPublicKeys[groupUserId] = sessionEnvironment['users'][groupUserId]['public_key'];
				});
				shareGroups.push(groupId);
			}
		});
		// change permissions and re-encrypt all subitems
		let entriesToUpdate = {'passwords':{}, 'groups':{}};
		var encryptedPasswords = {};
		let promiseChain = [];
		if(id) {
			entriesToUpdate = getAllSubentriesOfGroup(id);
			for(let passwordId in entriesToUpdate.passwords) {
				let secret = {
					'title': entriesToUpdate.passwords[passwordId].title,
					'username': entriesToUpdate.passwords[passwordId].username,
					'password': entriesToUpdate.passwords[passwordId].password,
					'url': entriesToUpdate.passwords[passwordId].url,
					'description': entriesToUpdate.passwords[passwordId].description,
				};
				for(let userId in targetPublicKeys) {
					promiseChain.push(
						importPublicKey(targetPublicKeys[userId], userId, passwordId)
						.then((result) => {
							let iv = getRandomCryptoValues(16);
							if(!(result.passwordId in encryptedPasswords)) {
								encryptedPasswords[result.passwordId] = {
									'revision': entriesToUpdate.passwords[passwordId].revision,
								};
							}
							encryptedPasswords[result.passwordId][result.userId] = {
								'iv': arrayBufferToBase64String(iv),
								'secret': null, // filled in next step
							};
							return encryptData(iv, result.key, JSON.stringify(secret), result.userId, result.passwordId);
						})
						.then((result) => {
							encryptedPasswords[result.passwordId][result.userId]['secret'] = arrayBufferToBase64String(result.encrypted);
							return Promise.resolve();
						})
					);
				}
			}
		}
		// send update request
		let group = (id && !sltGroup.value) ? sessionVaultContent['groups'][id]['group'] : sltGroup.value;
		if(group == '' || group == '-') group = null;
		Promise.all(promiseChain)
		.then(() => jsonRequest(
			'POST', (id==null ? 'vault/group' : 'vault/group/'+encodeURIComponent(id)),
			{
				'parent_password_group_id': group, 'title': txtTitle.value,
				'share_users': shareUsers, 'share_groups': shareGroups,
				'passwords': encryptedPasswords
			}
		)).then((response) => {
			// append to session vault
			sessionVaultContent['groups'][response.id] = {
				'group':group, 'title':txtTitle.value,
				'share_users':shareUsers, 'share_groups':shareGroups
			};
			// update share info of updated passwords
			for(let passwordId in entriesToUpdate.passwords) {
				sessionVaultContent['passwords'][passwordId]['share_users'] = shareUsers;
				sessionVaultContent['passwords'][passwordId]['share_groups'] = shareGroups;
			}
			populateVaultWindowEntries();
			closeAnimation(e);
		})
		.catch((error) => {
			console.warn(error);
			alert(error);
		});
	});
	// show with animation
	document.body.appendChild(clone);
	windowOpenAnimation(clone);
	txtTitle.focus();
}
function showPasswordDetails(id=null) {
	// create details window on current main window position
	const clone = divPasswordTemplateContainer.cloneNode(true);
	clone.removeAttribute('id');
	clone.style.top = (parseInt(divVaultContainer.style.top)+35) + 'px';
	clone.style.left = (parseInt(divVaultContainer.style.left)+35) + 'px';
	// identify inputs
	let txtRevision = clone.querySelectorAll('[name=txtRevision]')[0];
	let sltGroup = clone.querySelectorAll('[name=sltGroup]')[0];
	let txtTitle = clone.querySelectorAll('[name=txtTitle]')[0];
	let txtUrl = clone.querySelectorAll('[name=txtUrl]')[0];
	let txtUsername = clone.querySelectorAll('[name=txtUsername]')[0];
	let txtPassword = clone.querySelectorAll('[name=txtPassword]')[0];
	let txtDescription = clone.querySelectorAll('[name=txtDescription]')[0];
	let sltShareUser = clone.querySelectorAll('[name=sltShareUser]')[0];
	let sltShareUserGroup = clone.querySelectorAll('[name=sltShareUserGroup]')[0];
	let tblShares = clone.querySelectorAll('.shares')[0];
	// populate select boxes
	populateGroupSelectBox(sltGroup);
	for(let userId in sessionEnvironment['users']) {
		let option = document.createElement('OPTION');
		option.value = userId;
		option.innerText = sessionEnvironment['users'][userId]['display_name'];
		if(!sessionEnvironment['users'][userId]['public_key']) option.disabled = true;
		sltShareUser.appendChild(option);
	}
	for(let userGroupId in sessionEnvironment['groups']) {
		let option = document.createElement('OPTION');
		option.value = userGroupId;
		option.innerText = sessionEnvironment['groups'][userGroupId]['title'];
		sltShareUserGroup.appendChild(option);
	}
	// add actions
	activateMouseDragForParent(clone.querySelectorAll('.titlebar')[0]);
	let closeAnimation = windowCloseAction(clone);
	if(id == null) {
		clone.querySelectorAll('.btnDelete')[0].remove();
	} else {
		let password = sessionVaultContent['passwords'][id];
		txtRevision.value = password['revision'];
		sltGroup.value = password['group'];
		txtTitle.value = password['title'];
		txtUsername.value = password['username'];
		txtPassword.value = password['password'];
		txtUrl.value = password['url'];
		txtDescription.value = password['description'];
		clone.querySelectorAll('.btnDelete')[0].addEventListener('click', function(e){
			if(confirm(strings.are_you_sure)) {
				jsonRequest(
					'DELETE', 'vault/password/'+encodeURIComponent(id), null
				).then((response) => {
					delete sessionVaultContent['passwords'][id];
					populateVaultWindowEntries();
					closeAnimation(e);
				}).catch((error) => {
					console.warn(error);
					alert(error);
				});
			}
		});
		password['share_groups'].forEach((shareGroupId) => {
			addShareGroupRow(tblShares, shareGroupId);
		});
		password['share_users'].forEach((shareUserId) => {
			addShareUserRow(tblShares, shareUserId);
		});
	}
	sltGroup.addEventListener('change', function(e) {
		// apply permissions from parent folder
		if(sltGroup.value != '' && sltGroup.value != '-') {
			let permissionEntries = clone.querySelectorAll('.shares tr');
			for(let i=0; i<permissionEntries.length; i++) {
				if(permissionEntries[i].getAttribute('userid') || permissionEntries[i].getAttribute('groupid')) {
					permissionEntries[i].remove();
				}
			}
			sessionVaultContent['groups'][sltGroup.value]['share_groups'].forEach((shareGroupId) => {
				addShareGroupRow(tblShares, shareGroupId);
			});
			sessionVaultContent['groups'][sltGroup.value]['share_users'].forEach((shareUserId) => {
				addShareUserRow(tblShares, shareUserId);
			});
		}
	});
	clone.querySelectorAll('.btnAddUserShare')[0].addEventListener('click', function(e){
		addShareUserRow(tblShares, sltShareUser.value);
	});
	clone.querySelectorAll('.btnAddUserGroupShare')[0].addEventListener('click', function(e){
		addShareGroupRow(tblShares, sltShareUserGroup.value);
	});
	clone.querySelectorAll('.btnCopyUsername')[0].addEventListener('click', function(e){
		copyInputValueToClipboard(txtUsername);
	});
	clone.querySelectorAll('.btnCopyPassword')[0].addEventListener('click', function(e){
		copyInputValueToClipboard(txtPassword);
	});
	clone.querySelectorAll('.btnGeneratePassword')[0].addEventListener('click', function(e){
		txtPassword.value = generateRandomPassword();
		txtPassword.type = 'text';
	});
	clone.querySelectorAll('.btnShowHidePassword')[0].addEventListener('click', function(e){
		togglePasswordInput(txtPassword);
	});
	clone.querySelectorAll('.btnContents')[0].addEventListener('click', function(e){
		clone.querySelectorAll('.box.contents')[0].classList.remove('invisible');
		clone.querySelectorAll('.box.share')[0].classList.add('invisible');
	});
	clone.querySelectorAll('.btnShare')[0].addEventListener('click', function(e){
		clone.querySelectorAll('.box.contents')[0].classList.add('invisible');
		clone.querySelectorAll('.box.share')[0].classList.remove('invisible');
	});
	clone.querySelectorAll('.btnClose')[0].addEventListener('click', closeAnimation);
	clone.querySelectorAll('.btnSave')[0].addEventListener('click', function(e){
		let group = (id && !sltGroup.value) ? sessionVaultContent['passwords'][id]['group'] : sltGroup.value;
		if(group == '' || group == '-') group = null;
		let secret = {
			'title': txtTitle.value,
			'username': txtUsername.value,
			'password': txtPassword.value,
			'url': txtUrl.value,
			'description': txtDescription.value,
		};

		let shareUsers = [];
		let shareGroups = [];
		let targetPublicKeys = {};
		// add logged in user
		let myUserId = sessionEnvironment['userId'];
		shareUsers.push(myUserId);
		targetPublicKeys[myUserId] = sessionEnvironment['users'][myUserId]['public_key'];
		// add all other users and compile target keys
		tblShares.querySelectorAll('tr').forEach(function(item){
			let userId = item.getAttribute('userid') ? parseInt(item.getAttribute('userid')) : null;
			let groupId = item.getAttribute('groupid') ? parseInt(item.getAttribute('groupid')) : null;
			if(userId && !shareUsers.includes(userId)) {
				targetPublicKeys[userId] = sessionEnvironment['users'][userId]['public_key'];
				shareUsers.push(userId);
			}
			if(groupId && !shareGroups.includes(groupId)) {
				sessionEnvironment['groups'][groupId]['members'].forEach((groupUserId) => {
					targetPublicKeys[groupUserId] = sessionEnvironment['users'][groupUserId]['public_key'];
				});
				shareGroups.push(groupId);
			}
		});
		// encrypt to all target keys
		let encrypted = {};
		let promiseChain = [];
		for(let userId in targetPublicKeys) {
			promiseChain.push(
				importPublicKey(targetPublicKeys[userId], userId)
				.then((result) => {
					let iv = getRandomCryptoValues(16);
					encrypted[result.userId] = {
						'iv': arrayBufferToBase64String(iv),
						'secret': null, // filled in next step
					};
					return encryptData(iv, result.key, JSON.stringify(secret), result.userId);
				})
				.then((result) => {
					encrypted[result.userId]['secret'] = arrayBufferToBase64String(result.encrypted);
					return Promise.resolve();
				})
			);
		}
		Promise.all(promiseChain)
		.then(() => jsonRequest(
			'POST', (id==null ? 'vault/password' : 'vault/password/'+encodeURIComponent(id)),
			{
				'password_group_id': group, 'password_data': encrypted,
				'share_users': shareUsers, 'share_groups': shareGroups,
				'revision': txtRevision.value
			}
		))
		.then((response) => {
			// append to session vault
			sessionVaultContent['passwords'][response.id] = {
				'revision':response.revision,
				'group':group, 'title':secret.title,
				'username':secret.username, 'password':secret.password,
				'url':secret.url, 'description':secret.description,
				'share_users':shareUsers, 'share_groups':shareGroups
			};
			populateVaultWindowEntries();
			closeAnimation(e);
		})
		.catch((error) => {
			console.warn(error);
			alert(error);
		});
	});
	// show with animation
	document.body.appendChild(clone);
	windowOpenAnimation(clone);
	txtTitle.focus();
}

function getAllSubentriesOfGroup(groupId) {
	let subPasswords = {};
	let subGroups = {};
	for(let key in sessionVaultContent['passwords']) {
		if(sessionVaultContent['passwords'][key]['group'] == groupId) {
			subPasswords[key] = sessionVaultContent['passwords'][key];
		}
	}
	for(let key in sessionVaultContent['groups']) {
		if(sessionVaultContent['groups'][key]['group'] == groupId) {
			subGroups[key] = sessionVaultContent['groups'][key];
			let subs = getAllSubentriesOfGroup(key);
			Object.assign(subGroups, subs.groups);
			Object.assign(subPasswords, subs.passwords);
		}
	}
	return {'passwords':subPasswords, 'groups':subGroups};
}
function populateGroupSelectBox(sltGroup, groupId=null, hideGroupId=null, depth=0) {
	for(let key in sessionVaultContent['groups']) {
		if(sessionVaultContent['groups'][key]['group'] == groupId) {
			let option = document.createElement('OPTION');
			option.value = key;
			option.innerText = ('-'.repeat(depth) + ' ' + sessionVaultContent['groups'][key]['title']).trim();
			if(key == hideGroupId) option.disabled = true;
			sltGroup.appendChild(option);
			populateGroupSelectBox(sltGroup, key, hideGroupId, depth+1);
		}
	}
}

function addUserGroupRow(groupTable, userGroupId, editAction) {
	let group = sessionEnvironment['groups'][userGroupId];
	let tr = document.createElement('TR');
	tr.setAttribute('usergroupid', userGroupId);
	let td1 = document.createElement('TD');
	td1.setAttribute('colspan', '2');
	td1.innerText = group['title'];
	tr.appendChild(td1);
	let td2 = document.createElement('TD');
	let btn = document.createElement('BUTTON');
	btn.addEventListener('click', editAction);
	let img = document.createElement('IMG');
	img.src = 'img/edit.svg';
	btn.appendChild(img);
	td2.appendChild(btn);
	tr.appendChild(td2);
	groupTable.appendChild(tr);
}
function addShareUserRow(shareTable, userId) {
	let user = sessionEnvironment['users'][userId];
	let tr = document.createElement('TR');
	tr.setAttribute('userid', userId);
	let td1 = document.createElement('TD');
	td1.setAttribute('colspan', '2');
	td1.innerText = user['display_name'];
	tr.appendChild(td1);
	let td2 = document.createElement('TD');
	let btn = document.createElement('BUTTON');
	btn.addEventListener('click', function(e){
		this.parentNode.parentNode.remove();
	});
	let img = document.createElement('IMG');
	img.src = 'img/minus.svg';
	btn.appendChild(img);
	td2.appendChild(btn);
	tr.appendChild(td2);
	shareTable.appendChild(tr);
}
function addShareGroupRow(shareTable, groupId) {
	let group = sessionEnvironment['groups'][groupId];
	let tr = document.createElement('TR');
	tr.setAttribute('groupid', groupId);
	let td1 = document.createElement('TD');
	td1.setAttribute('colspan', '2');
	td1.innerText = group['title'];
	tr.appendChild(td1);
	let td2 = document.createElement('TD');
	let btn = document.createElement('BUTTON');
	btn.addEventListener('click', function(e){
		this.parentNode.parentNode.remove();
	});
	let img = document.createElement('IMG');
	img.src = 'img/minus.svg';
	btn.appendChild(img);
	td2.appendChild(btn);
	tr.appendChild(td2);
	shareTable.appendChild(tr);
}

function truncate(str, n=25){
	return (str.length > n) ? str.slice(0, n-1) + '…' : str;
}
function onlyUnique(value, index, array) {
	return array.indexOf(value) === index;
}
