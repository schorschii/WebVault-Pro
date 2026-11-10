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
var sessionLastUserActivity = Date.now();


// set up event listeners
document.addEventListener('DOMContentLoaded', (event) => {
	btnLogin.addEventListener('click', () => login());
	txtSearch.addEventListener('input', () => search(txtSearch.value));
	btnNewPassword.addEventListener('click', () => showPasswordDetails());
	btnNewGroup.addEventListener('click', () => showGroupDetails());
	btnMore.addEventListener('click', () => showMore());
	btnUserGroups.addEventListener('click', () => showUserGroupsManagement());
	btnImport.addEventListener('click', () => showImport());
	btnTotp.addEventListener('click', () => showTotp());
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
	txtTotp.addEventListener('keyup', loginAction);
	// changed credentials require the first login step again
	txtUsername.addEventListener('input', () => txtTotp.classList.add('invisible'));
	txtPassword.addEventListener('input', () => txtTotp.classList.add('invisible'));
	activateWindowMouseDrag(divVaultContainer, divVaultTitlebar);
	document.addEventListener('keydown', () => sessionLastUserActivity = Date.now());
	document.addEventListener('mousedown', () => sessionLastUserActivity = Date.now());
});


class PrivateKeyDecryptionError extends Error {}
class TotpRequiredError extends Error {}

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
	let request;
	if(!txtTotp.classList.contains('invisible')) {
		// second step: the password was already checked, only the one-time code is required
		request = jsonRequest('POST', 'user/login/totp', {'code':txtTotp.value});
	} else {
		request = jsonRequest('POST', 'user/login', {'username':username, 'password':password});
	}
	request.then((response) => {
		if(response.totp_required) {
			throw new TotpRequiredError();
		}
		sessionEnvironment['totp'] = response.totp;
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
			let isPasswordChange = (oldPassword !== password);
			return importPrivateKey(response.private_key, oldPassword, response.salt, response.iv, isPasswordChange)
				.then((key) => {
					let promiseChain = [];
					if(isPasswordChange) {
						// re-encrypt private key with new password
						console.log('Re-encrypt private key with new password');
						promiseChain.push(
							exportPrivateKey(key, password)
							.then((exportedPrivKey) => {
								console.log('Upload re-encrypted private key');
								return jsonRequest(
									'POST', 'user/keys',
									{'private_key':exportedPrivKey.key, 'salt':exportedPrivKey.salt, 'iv':exportedPrivKey.iv}
								)
							})
						);
					}
					return Promise.all(promiseChain)
					.then(() => loadVault(key))
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
		txtTotp.value = '';
		txtTotp.classList.add('invisible');
		divLoginInfoBox.classList.add('invisible');

		clearInterval(sessionCheckTimer);
		sessionCheckTimer = setInterval(checkSession, 5000);
	}).catch((error) => {
		btnLogin.classList.remove('loading');
		btnLogin.disabled = false;
		if(error instanceof TotpRequiredError) {
			txtTotp.classList.remove('invisible');
			txtTotp.focus();
			return;
		}
		console.error(error);
		if(txtTotp.classList.contains('invisible')) {
			txtPassword.value = '';
			txtOldPassword.value = '';
		} else if(String(error).includes('Invalid session')) {
			// too many wrong codes, start again with the password
			txtTotp.classList.add('invisible');
		}
		txtTotp.value = ''; // keep the password in the second step, it is needed to decrypt the private key
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
	// keep the session alive while the user is working, e.g. typing a long entry
	let active = (Date.now() - sessionLastUserActivity < 5000);
	xhttp.open('GET', 'user/session'+(active ? '?active=1' : ''), true);
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
				'title':group.title, 'icon':group.icon, 'permission':group.permission,
				'share_users':group.share_users, 'share_groups':group.share_groups,
				'share_user_permissions':group.share_user_permissions, 'share_group_permissions':group.share_group_permissions,
				'share_user_expires':group.share_user_expires, 'share_group_expires':group.share_group_expires
			};
		});
		// decrypt all passwords
		let promiseChain = Promise.resolve();
		response.passwords.forEach((password) => {
			promiseChain = promiseChain.then(() =>
				decryptData(sessionKeys['private'], password.aes_key, password.aes_iv, password.rsa_iv, password.secret)
				.then((decrypted) => {
					let decryptedData = JSON.parse(decrypted);
					sessionVaultContent['passwords'][password.id] = {
						'revision':password.revision,
						'group':password.password_group_id, 'title':decryptedData.title,
						'username':decryptedData.username, 'password':decryptedData.password,
						'url':decryptedData.url, 'description':decryptedData.description,
						'icon':decryptedData.icon, 'fields':decryptedData.fields || [], 'files':decryptedData.files || [],
						'permission':password.permission,
						'share_users':password.share_users, 'share_groups':password.share_groups,
						'share_user_permissions':password.share_user_permissions, 'share_group_permissions':password.share_group_permissions,
						'share_user_expires':password.share_user_expires, 'share_group_expires':password.share_group_expires
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
	addIconHtml(li, passwordItem.icon);
	let divCont = document.createElement('DIV');
	divCont.classList.add('passwordheader');
	li.appendChild(divCont);
	let a = document.createElement('A');
	a.href = '#';
	a.addEventListener('click', openDetailsAction);
	divCont.appendChild(a);
	let spanTitle = document.createElement('SPAN');
	setTruncatedText(spanTitle, passwordItem.title);
	a.appendChild(spanTitle);
	let spanUsername = document.createElement('SPAN');
	spanUsername.classList.add('username');
	setTruncatedText(spanUsername, passwordItem.username);
	a.appendChild(spanUsername);
	let divDesc = document.createElement('DIV');
	divDesc.classList.add('entrydescription');
	divCont.appendChild(divDesc);
	if(passwordItem.url) {
		let aUrl = document.createElement('A');
		if(passwordItem.url.startsWith('http://')
		|| passwordItem.url.startsWith('https://')
		|| passwordItem.url.startsWith('ftp://')) {
			aUrl.href = passwordItem.url;
		}
		setTruncatedText(aUrl, passwordItem.url);
		aUrl.target = '_blank';
		aUrl.addEventListener('click', (e) => e.stopPropagation());
		divDesc.appendChild(aUrl);
	}
	let spanDesc = document.createElement('SPAN');
	setTruncatedText(spanDesc, passwordItem.description.replaceAll('\n', ' '), (passwordItem.url&&passwordItem.description ? ' - ' : ''));
	divDesc.appendChild(spanDesc);
	let shareText = compileShareText(passwordItem['share_users'], passwordItem['share_groups']);
	if(shareText) {
		let divShares = document.createElement('DIV');
		divShares.classList.add('shares');
		divShares.innerText = shareText
		divDesc.appendChild(divShares);
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
	addIconHtml(li, groupItem.icon);
	let divCont = document.createElement('DIV');
	divCont.classList.add('groupheader');
	li.appendChild(divCont);
	let a = document.createElement('A');
	a.href = '#';
	a.innerText = groupItem.title;
	a.addEventListener('click', openDetailsAction);
	divCont.appendChild(a);
	let btnEdit = document.createElement('BUTTON');
	btnEdit.title = strings.edit;
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
	let shareText = compileShareText(groupItem['share_users'], groupItem['share_groups']);
	if(shareText) {
		let divShares = document.createElement('DIV');
		divShares.classList.add('shares');
		divShares.innerText = shareText;
		divDesc.appendChild(divShares);
	}
	let ulSub = document.createElement('UL');
	li.appendChild(ulSub);
	return ulSub;
}
function getIconUrl(icon) {
	// only icons offered by the server and small uploaded PNG images are allowed since the value could be manipulated by another user
	if(!icon) return null;
	if(/^data:image\/png;base64,[A-Za-z0-9+\/]+=*$/.test(icon) && icon.length <= 20000) return icon;
	if(/^[a-z_]+$/.test(icon) && divIconPickerTemplateContainer.querySelector('.icons button[value="'+icon+'"]')) return 'img/icon/'+icon+'.svg';
	return null;
}
function addIconHtml(li, icon) {
	let url = getIconUrl(icon);
	if(!url) return;
	li.classList.add('customicon');
	let img = document.createElement('IMG');
	img.classList.add('icon');
	img.src = url;
	li.appendChild(img);
}
function compileShareText(shareUsers, shareGroups) {
	let infos = [];
	if(shareUsers.length > 1) infos.push(shareUsers.length+' '+strings.users);
	if(shareGroups.length > 0) infos.push(shareGroups.length+' '+strings.groups);
	return infos.join(', ');
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
		}
	}
}

const STORAGE_KEY_SETTINGS = 'settings';
function getSetting(name, def=null) {
	let settings = JSON.parse(localStorage.getItem(STORAGE_KEY_SETTINGS));
	if(!settings) return def;
	return settings[name] || def;
}
function setSetting(name, value) {
	let settings = JSON.parse(localStorage.getItem(STORAGE_KEY_SETTINGS));
	if(!settings) settings = {};
	settings[name] = value;
	localStorage.setItem(STORAGE_KEY_SETTINGS, JSON.stringify(settings));
}

function generateRandomPassword(length=13, charset='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') {
	let generated = '';
	let n = charset.length;
	if(!n) return generated;
	let random = new Uint32Array(1);
	while(generated.length < length) {
		crypto.getRandomValues(random);
		// rejection sampling to avoid modulo bias
		if(random[0] < 0x100000000 - (0x100000000 % n)) {
			generated += charset.charAt(random[0] % n);
		}
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
	input.setSelectionRange(0, 99999); // for mobile devices
	// copy the text inside the text field
	navigator.clipboard.writeText(input.value);
}
function clearClipboardIfMatchesInput(input) {
	navigator.clipboard.readText().then((text) => {
		if(text == input.value) {
			navigator.clipboard.writeText('');
		}
	}).catch((exception) => {});
}

function search(q) {
	var entries = divVault.querySelectorAll('.password, .group');
	// empty query means display all entries (default state)
	if(q == '') {
		// restore password/group visibility
		ulEntriesTree.classList.remove('searchresults');
		divNoSearchResults.classList.add('invisible');
		return;
	}
	// do the search
	ulEntriesTree.classList.add('searchresults');
	var matches = 0;
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
			if(key == 'password') continue; // do not leak passwords via search
			if(!item[key] || typeof item[key] !== 'string') continue;
			match = (item[key].toUpperCase().indexOf(filter) > -1);
			if(match) break;
		}
		(item['fields'] || []).forEach((field) => {
			if(field.name.toUpperCase().indexOf(filter) > -1
			|| (field.type != 'password' && field.value.toUpperCase().indexOf(filter) > -1)) match = true;
		});
		// show or hide password
		if(match) {
			matches ++;
			entries[i].classList.add('searchresult');
		} else {
			entries[i].classList.remove('searchresult');
		}
	}
	if(matches) {
		divNoSearchResults.classList.add('invisible');
	} else {
		divNoSearchResults.classList.remove('invisible');
	}
	// open/close parent folders
	let groups = ulEntriesTree.getElementsByClassName('group');
	for(var i = 0; i < groups.length; i++) {
		var subResults = groups[i].querySelectorAll('.searchresult');
		if(subResults.length) {
			let parent = groups[i];
			while(parent.id != 'ulEntriesTree') {
				parent.classList.remove('closed');
				parent = parent.parentNode;
			}
		} else {
			groups[i].classList.add('closed');
		}
	}
}

function populateUserGroups() {
	let tblGroups = divUserGroupsContainer.querySelectorAll('.groups')[0];
	tblGroups.innerHTML = '';
	for(let groupId in sessionEnvironment['groups']) {
		if(!sessionEnvironment['groups'][groupId]['members'].includes(sessionEnvironment['userId'])) continue;
		addUserGroupRow(tblGroups, groupId, function(){
			showUserGroupManagement(groupId);
		});
	}
	if(!tblGroups.rows.length) {
		let tr = document.createElement('TR');
		tblGroups.appendChild(tr);
		let td = document.createElement('TD');
		td.innerText = strings.no_user_groups_placeholder;
		tr.appendChild(td);
	}
}
function showUserGroupManagement(id=null) {
	const clone = divUserGroupTemplateContainer.cloneNode(true);
	clone.removeAttribute('id');
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
	activateWindowMouseDrag(clone, clone.querySelectorAll('.titlebar')[0], divUserGroupsContainer);
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
				newGroupMemberIds.push(parseInt(userEntries[i].getAttribute('userid')));
			}
		}
		// re-encrypt all passwords which are shared with the edited group
		let promiseChain = [];
		var encryptedPasswords = {};
		if(id) {
			for(let passwordId in sessionVaultContent['passwords']) {
				if(sessionVaultContent['passwords'][passwordId]['share_groups'].includes(parseInt(id))
				&& !(sessionVaultContent['passwords'][passwordId]['permission'] & SHARE_PERMISSION_READ_ONLY)) { // read only passwords cannot be re-encrypted
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
						'icon': sessionVaultContent['passwords'][passwordId].icon,
						'fields': sessionVaultContent['passwords'][passwordId].fields,
						'files': sessionVaultContent['passwords'][passwordId].files,
					};
					promiseChain.push(
						encryptData(targetPublicKeys, JSON.stringify(secret), passwordId)
						.then((result) => {
							encryptedPasswords[result.password_id] = {
								'secret': result.secret,
								'aes_iv': result.aes_iv,
								'password_user': result.password_user,
								'revision': sessionVaultContent['passwords'][result.password_id].revision,
							};
						})
					);
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
			for(let passwordId in encryptedPasswords) {
				sessionVaultContent['passwords'][passwordId]['revision'] += 1;
			}
			populateUserGroups();
			closeAnimation();
		}).catch((error) => {
			console.warn(error);
			alert(error);
		});
	});
	clone.querySelectorAll('.btnDelete')[0].addEventListener('click', function(){
		if(confirm(strings.are_you_sure_delete)) {
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
	// populate select boxes
	populateUserGroups();
	// add actions
	activateWindowMouseDrag(divUserGroupsContainer, divUserGroupsContainer.querySelectorAll('.titlebar')[0], divVaultContainer);
	divUserGroupsContainer.querySelectorAll('.btnAdd')[0].onclick = function(){showUserGroupManagement()};
	divUserGroupsContainer.querySelectorAll('.btnClose')[0].onclick = windowCloseAction(divUserGroupsContainer,false);
	// show with animation
	document.body.appendChild(divUserGroupsContainer);
	windowOpenAnimation(divUserGroupsContainer);
}
function showMore() {
	divMore.classList.toggle('invisible');
	// hide when sub-button clicked
	divMore.onclick = function(e) {
		divMore.classList.toggle('invisible');
	};
}
function showTotp() {
	let divNotes = divTotpContainer.querySelectorAll('.notes')[0];
	let txtSecret = divTotpContainer.querySelectorAll('[name=txtSecret]')[0];
	let txtUri = divTotpContainer.querySelectorAll('[name=txtUri]')[0];
	let imgQrCode = divTotpContainer.querySelectorAll('[name=imgQrCode]')[0];
	let txtCode = divTotpContainer.querySelectorAll('[name=txtCode]')[0];
	let btnEnable = divTotpContainer.querySelectorAll('.btnEnable')[0];
	let btnDisable = divTotpContainer.querySelectorAll('.btnDisable')[0];
	let trRecovery = divTotpContainer.querySelectorAll('tr.recovery')[0];
	let preRecoveryCodes = divTotpContainer.querySelectorAll('[name=preRecoveryCodes]')[0];
	let setupRows = divTotpContainer.querySelectorAll('tr.setup');
	let codeRows = divTotpContainer.querySelectorAll('tr.code');
	// reset state
	txtCode.value = '';
	trRecovery.classList.add('invisible');
	codeRows.forEach((tr) => tr.classList.remove('invisible'));
	if(sessionEnvironment['totp']) {
		divNotes.innerText = strings.totp_enabled_notes;
		setupRows.forEach((tr) => tr.classList.add('invisible'));
		btnEnable.classList.add('invisible');
		btnDisable.classList.remove('invisible');
	} else {
		divNotes.innerText = strings.totp_setup_notes;
		setupRows.forEach((tr) => tr.classList.remove('invisible'));
		btnEnable.classList.remove('invisible');
		btnDisable.classList.add('invisible');
		jsonRequest('POST', 'user/totp', {}).then((response) => {
			txtSecret.value = response.secret;
			txtUri.value = response.uri;
			let qr = qrcode(0, 'M');
			qr.addData(response.uri);
			qr.make();
			imgQrCode.src = qr.createDataURL(4);
		}).catch((error) => {
			console.warn(error);
			alert(error);
		});
	}
	// add actions
	let closeAction = windowCloseAction(divTotpContainer, false);
	activateWindowMouseDrag(divTotpContainer, divTotpContainer.querySelectorAll('.titlebar')[0], divVaultContainer);
	btnEnable.onclick = function(){
		jsonRequest('POST', 'user/totp/enable', {'code':txtCode.value}).then((response) => {
			sessionEnvironment['totp'] = true;
			// show the recovery codes once
			setupRows.forEach((tr) => tr.classList.add('invisible'));
			codeRows.forEach((tr) => tr.classList.add('invisible'));
			preRecoveryCodes.innerText = response.recovery_codes.join('\n');
			trRecovery.classList.remove('invisible');
		}).catch((error) => {
			console.warn(error);
			alert(error);
		});
	};
	btnDisable.onclick = function(){
		jsonRequest('POST', 'user/totp/disable', {'code':txtCode.value}).then((response) => {
			sessionEnvironment['totp'] = false;
			closeAction();
		}).catch((error) => {
			console.warn(error);
			alert(error);
		});
	};
	divTotpContainer.querySelectorAll('.btnClose')[0].onclick = closeAction;
	// show with animation
	document.body.appendChild(divTotpContainer);
	windowOpenAnimation(divTotpContainer);
	txtCode.focus();
}
function showImport() {
	// add actions
	let closeAction = windowCloseAction(divImportContainer,false);
	activateWindowMouseDrag(divImportContainer, divImportContainer.querySelectorAll('.titlebar')[0], divVaultContainer);
	divImportContainer.querySelectorAll('.btnImport')[0].onclick = function(){
		importCsvFile(divImportContainer.querySelectorAll('[name=fleInputFile]')[0].files[0])
		.then((rows) => {
			rows = rows.slice(1); // cut header row
			importEntries(rows)
			.then(() => {
				divImportContainer.querySelectorAll('.btnImport')[0].classList.remove('loading');
				divImportContainer.querySelectorAll('.btnImport')[0].disabled = false;
				loadVault(); // reload to get the complete share and permission info of the imported entries
				closeAction();
			})
			.catch((error) => {
				console.warn(error);
				alert(error);
			});
		});
		this.classList.add('loading');
		this.disabled = true;
	};
	divImportContainer.querySelectorAll('.btnClose')[0].onclick = closeAction;
	// show with animation
	document.body.appendChild(divImportContainer);
	windowOpenAnimation(divImportContainer);
}
function getGroupId(name, parent) {
	for(let groupId in sessionVaultContent['groups']) {
		if(sessionVaultContent['groups'][groupId]['title'] == name
		&& sessionVaultContent['groups'][groupId]['group'] == parent) {
			return groupId;
		}
	}
}
async function importEntries(rows) {
	return new Promise(async function(resolve, reject){
		for(let i=0; i<rows.length; i++) {
			let row = rows[i];
			if(row.length < 6) continue;
			let path = row[0].split('/');
			let groupId = null;
			// get existing group or create a new one
			if(path.length > 1 || path[0] != '') {
				for(let n=0; n<path.length; n++) {
					let existingGroupId = getGroupId(path[n], groupId);
					if(existingGroupId) {
						groupId = existingGroupId;
					} else {
						await jsonRequest('POST', 'vault/group',
						{
							'parent_password_group_id': groupId, 'title': path[n],
							'share_users': [sessionEnvironment['userId']], 'share_groups': [],
						})
						.then((response) => {
							// append to session vault
							sessionVaultContent['groups'][response.id] = {
								'group':groupId, 'title':path[n],
								'share_users':[sessionEnvironment['userId']], 'share_groups':[]
							};
							groupId = response.id;
						});
					}
				}
			}
			// create the password entry
			let secret = {
				'title': row[1],
				'username': row[2],
				'password': row[3],
				'url': row[4],
				'description': row[5],
			};
			let userId = sessionEnvironment['userId'];
			let targetPublicKeys = {};
			targetPublicKeys[userId] = sessionEnvironment['users'][userId]['public_key'];
			await encryptData(targetPublicKeys, JSON.stringify(secret))
			.then((result) => jsonRequest(
				'POST', 'vault/password',
				{
					'password_group_id': groupId,
					'secret': result.secret,
					'aes_iv': result.aes_iv,
					'password_user': result.password_user,
					'share_users': [sessionEnvironment['userId']], 'share_groups': []
				}
			))
			.then((response) => {
				// append to session vault
				sessionVaultContent['passwords'][response.id] = {
					'revision': response.revision,
					'group': groupId, 'title': secret.title,
					'username': secret.username, 'password': secret.password,
					'url': secret.url, 'description': secret.description,
					'share_users':[sessionEnvironment['userId']], 'share_groups':[]
				};
			}).catch((error) => console.warn(error))
		}
		resolve();
	});
}

function showGroupDetails(id=null) {
	const clone = divGroupTemplateContainer.cloneNode(true);
	clone.removeAttribute('id');
	// identify inputs
	let sltGroup = clone.querySelectorAll('[name=sltGroup]')[0];
	let txtTitle = clone.querySelectorAll('[name=txtTitle]')[0];
	let txtIcon = clone.querySelectorAll('[name=txtIcon]')[0];
	let btnIcon = clone.querySelectorAll('.btnIcon')[0];
	let sltShareUser = clone.querySelectorAll('[name=sltShareUser]')[0];
	let sltShareUserGroup = clone.querySelectorAll('[name=sltShareUserGroup]')[0];
	let chkInheritPermissions = clone.querySelectorAll('[name=chkInheritPermissions]')[0];
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
		// only members can add a group share
		if(!sessionEnvironment['groups'][userGroupId]['members'].includes(sessionEnvironment['userId'])) continue;
		let option = document.createElement('OPTION');
		option.value = userGroupId;
		option.innerText = sessionEnvironment['groups'][userGroupId]['title'];
		sltShareUserGroup.appendChild(option);
	}
	// add actions
	activateWindowMouseDrag(clone, clone.querySelectorAll('.titlebar')[0], divVaultContainer);
	let closeAnimation = windowCloseAction(clone);
	if(id == null) {
		clone.querySelectorAll('.btnDelete')[0].remove();
	} else {
		let group = sessionVaultContent['groups'][id];
		sltGroup.value = group['group'];
		txtTitle.value = group['title'];
		txtIcon.value = group['icon'] || '';
		btnIcon.querySelectorAll('img')[0].src = getIconUrl(txtIcon.value) || 'img/folder.svg';
		clone.querySelectorAll('.btnDelete')[0].addEventListener('click', function(e){
			let subItems = getAllSubentriesOfGroup(id);
			if(Object.keys(subItems['passwords']).length || Object.keys(subItems['groups']).length) {
				alert(strings.cannot_delete_group_contains_items);
				return;
			}
			if(confirm(strings.are_you_sure_delete)) {
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
			addShareGroupRow(tblShares, shareGroupId, group['share_group_permissions'][shareGroupId], group['share_group_expires'][shareGroupId]);
		});
		group['share_users'].forEach((shareUserId) => {
			addShareUserRow(tblShares, shareUserId, group['share_user_permissions'][shareUserId], group['share_user_expires'][shareUserId]);
		});
	}
	sltGroup.addEventListener('change', function(e) {
		// reset shares
		let permissionEntries = clone.querySelectorAll('.shares tr');
		for(let i=0; i<permissionEntries.length; i++) {
			if(permissionEntries[i].getAttribute('userid') || permissionEntries[i].getAttribute('groupid')) {
				permissionEntries[i].remove();
			}
		}
		if(sltGroup.value != '' && sltGroup.value != '-') {
			// apply permissions from parent folder
			let parentGroup = sessionVaultContent['groups'][sltGroup.value];
			parentGroup['share_groups'].forEach((shareGroupId) => {
				addShareGroupRow(tblShares, shareGroupId, parentGroup['share_group_permissions'][shareGroupId], parentGroup['share_group_expires'][shareGroupId]);
			});
			parentGroup['share_users'].forEach((shareUserId) => {
				addShareUserRow(tblShares, shareUserId, parentGroup['share_user_permissions'][shareUserId], parentGroup['share_user_expires'][shareUserId]);
			});
		} else {
			// add self only
			addShareUserRow(tblShares, sessionEnvironment['userId'], 0);
		}
	});
	clone.querySelectorAll('.btnAddUserShare')[0].addEventListener('click', function(e){
		addShareUserRow(tblShares, sltShareUser.value, 0);
	});
	clone.querySelectorAll('.btnAddUserGroupShare')[0].addEventListener('click', function(e){
		addShareGroupRow(tblShares, sltShareUserGroup.value, 0);
	});
	btnIcon.addEventListener('click', function(e){
		showIconPicker(txtIcon, btnIcon, 'img/folder.svg', clone);
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
		let shareUserPermissions = {};
		let shareGroupPermissions = {};
		let shareUserExpires = {};
		let shareGroupExpires = {};
		let targetPublicKeys = {};
		// add all other users
		tblShares.querySelectorAll('tr').forEach(function(item){
			let userId = item.getAttribute('userid') ? parseInt(item.getAttribute('userid')) : null;
			let groupId = item.getAttribute('groupid') ? parseInt(item.getAttribute('groupid')) : null;
			if(userId && !shareUsers.includes(userId)) {
				targetPublicKeys[userId] = sessionEnvironment['users'][userId]['public_key'];
				shareUsers.push(userId);
				shareUserPermissions[userId] = parseInt(item.querySelector('select.permission').value);
				shareUserExpires[userId] = localDateTimeInputToUtc(item.querySelector('input.expires').value);
			}
			if(groupId && !shareGroups.includes(groupId)) {
				shareGroupPermissions[groupId] = parseInt(item.querySelector('select.permission').value);
				shareGroupExpires[groupId] = localDateTimeInputToUtc(item.querySelector('input.expires').value);
				sessionEnvironment['groups'][groupId]['members'].forEach((groupUserId) => {
					targetPublicKeys[groupUserId] = sessionEnvironment['users'][groupUserId]['public_key'];
				});
				shareGroups.push(groupId);
			}
		});
		if(!isOwnUserIdIncluded(shareUsers, shareGroups)) {
			let myUserId = sessionEnvironment['userId'];
			shareUsers.push(myUserId);
			shareUserPermissions[myUserId] = 0;
			shareUserExpires[myUserId] = null;
			targetPublicKeys[myUserId] = sessionEnvironment['users'][myUserId]['public_key'];
		}
		// change permissions and re-encrypt all subitems
		let entriesToUpdate = {'passwords':{}, 'groups':{}};
		var encryptedPasswords = {};
		let promiseChain = [];
		if(id && chkInheritPermissions.checked) {
			entriesToUpdate = getAllSubentriesOfGroup(id);
			for(let passwordId in entriesToUpdate.passwords) {
				let secret = {
					'title': entriesToUpdate.passwords[passwordId].title,
					'username': entriesToUpdate.passwords[passwordId].username,
					'password': entriesToUpdate.passwords[passwordId].password,
					'url': entriesToUpdate.passwords[passwordId].url,
					'description': entriesToUpdate.passwords[passwordId].description,
					'icon': entriesToUpdate.passwords[passwordId].icon,
					'fields': entriesToUpdate.passwords[passwordId].fields,
					'files': entriesToUpdate.passwords[passwordId].files,
				};
				promiseChain.push(
					encryptData(targetPublicKeys, JSON.stringify(secret), passwordId)
					.then((result) => {
						encryptedPasswords[result.password_id] = {
							'secret': result.secret,
							'aes_iv': result.aes_iv,
							'password_user': result.password_user,
							'revision': sessionVaultContent['passwords'][result.password_id].revision,
						};
					})
				);
			}
		}
		// send update request
		let group = (id && !sltGroup.value) ? sessionVaultContent['groups'][id]['group'] : sltGroup.value;
		if(group == '' || group == '-') group = null;
		Promise.all(promiseChain)
		.then(() => jsonRequest(
			'POST', (id==null ? 'vault/group' : 'vault/group/'+encodeURIComponent(id)),
			{
				'parent_password_group_id': group, 'title': txtTitle.value, 'icon': txtIcon.value,
				'share_users': shareUsers, 'share_groups': shareGroups,
				'share_user_permissions': shareUserPermissions, 'share_group_permissions': shareGroupPermissions,
				'share_user_expires': shareUserExpires, 'share_group_expires': shareGroupExpires,
				'passwords': encryptedPasswords, 'groups': entriesToUpdate.groups
			}
		)).then((response) => {
			// append to session vault
			sessionVaultContent['groups'][response.id] = {
				'group':group, 'title':txtTitle.value, 'icon':txtIcon.value,
				'permission': (id ? sessionVaultContent['groups'][id]['permission'] : 0),
				'share_users':shareUsers, 'share_groups':shareGroups,
				'share_user_permissions':shareUserPermissions, 'share_group_permissions':shareGroupPermissions,
				'share_user_expires':shareUserExpires, 'share_group_expires':shareGroupExpires
			};
			// update share info of updated entries
			for(let groupId in entriesToUpdate.groups) {
				sessionVaultContent['groups'][groupId]['share_users'] = shareUsers;
				sessionVaultContent['groups'][groupId]['share_groups'] = shareGroups;
				sessionVaultContent['groups'][groupId]['share_user_permissions'] = shareUserPermissions;
				sessionVaultContent['groups'][groupId]['share_group_permissions'] = shareGroupPermissions;
				sessionVaultContent['groups'][groupId]['share_user_expires'] = shareUserExpires;
				sessionVaultContent['groups'][groupId]['share_group_expires'] = shareGroupExpires;
			}
			for(let passwordId in entriesToUpdate.passwords) {
				sessionVaultContent['passwords'][passwordId]['revision'] += 1;
				sessionVaultContent['passwords'][passwordId]['share_users'] = shareUsers;
				sessionVaultContent['passwords'][passwordId]['share_groups'] = shareGroups;
				sessionVaultContent['passwords'][passwordId]['share_user_permissions'] = shareUserPermissions;
				sessionVaultContent['passwords'][passwordId]['share_group_permissions'] = shareGroupPermissions;
				sessionVaultContent['passwords'][passwordId]['share_user_expires'] = shareUserExpires;
				sessionVaultContent['passwords'][passwordId]['share_group_expires'] = shareGroupExpires;
			}
			populateVaultWindowEntries();
			closeAnimation(e);
		})
		.catch((error) => {
			console.warn(error);
			alert(error);
		});
	});
	if(id && (sessionVaultContent['groups'][id]['permission'] & SHARE_PERMISSION_READ_ONLY)) {
		disableEditing(clone);
	}
	if(id && (sessionVaultContent['groups'][id]['permission'] & SHARE_PERMISSION_NO_RESHARE)) {
		clone.querySelectorAll('.btnShare')[0].classList.add('invisible');
	}
	// show with animation
	document.body.appendChild(clone);
	windowOpenAnimation(clone);
	txtTitle.focus();
}
function showPasswordDetails(id=null) {
	const clone = divPasswordTemplateContainer.cloneNode(true);
	clone.removeAttribute('id');
	// identify inputs
	let txtRevision = clone.querySelectorAll('[name=txtRevision]')[0];
	let sltGroup = clone.querySelectorAll('[name=sltGroup]')[0];
	let txtTitle = clone.querySelectorAll('[name=txtTitle]')[0];
	let txtIcon = clone.querySelectorAll('[name=txtIcon]')[0];
	let btnIcon = clone.querySelectorAll('.btnIcon')[0];
	let txtUrl = clone.querySelectorAll('[name=txtUrl]')[0];
	let txtUsername = clone.querySelectorAll('[name=txtUsername]')[0];
	let txtPassword = clone.querySelectorAll('[name=txtPassword]')[0];
	let divPasswordStrength = clone.querySelectorAll('.passwordStrength > .bar')[0];
	let txtDescription = clone.querySelectorAll('[name=txtDescription]')[0];
	let trAddField = clone.querySelectorAll('.btnAddField')[0].parentNode.parentNode;
	let trFiles = clone.querySelectorAll('tr.files')[0];
	let tblFiles = clone.querySelectorAll('table.files')[0];
	let fleUpload = clone.querySelectorAll('[name=fleUpload]')[0];
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
		// only members can add a group share
		if(!sessionEnvironment['groups'][userGroupId]['members'].includes(sessionEnvironment['userId'])) continue;
		let option = document.createElement('OPTION');
		option.value = userGroupId;
		option.innerText = sessionEnvironment['groups'][userGroupId]['title'];
		sltShareUserGroup.appendChild(option);
	}
	// add actions
	activateWindowMouseDrag(clone, clone.querySelectorAll('.titlebar')[0], divVaultContainer);
	let closeAnimation = windowCloseAction(clone);
	let updatePasswordStrength = function(e) {
		divPasswordStrength.classList.remove('score0', 'score1', 'score2', 'score3', 'score4');
		if(txtPassword.value != '')
			divPasswordStrength.classList.add(
				'score'+zxcvbn(txtPassword.value, [txtTitle.value, txtUsername.value]).score
			);
	};
	txtTitle.addEventListener('input', updatePasswordStrength);
	txtUsername.addEventListener('input', updatePasswordStrength);
	txtPassword.addEventListener('input', updatePasswordStrength);
	if(id == null) {
		clone.querySelectorAll('.btnDelete')[0].remove();
		trFiles.classList.add('invisible'); // files can only be attached to saved entries
	} else {
		let password = sessionVaultContent['passwords'][id];
		txtRevision.value = password['revision'];
		sltGroup.value = password['group'];
		txtTitle.value = password['title'];
		txtUsername.value = password['username'];
		txtPassword.value = password['password'];
		updatePasswordStrength();
		txtUrl.value = password['url'];
		txtDescription.value = password['description'];
		txtIcon.value = password['icon'] || '';
		btnIcon.querySelectorAll('img')[0].src = getIconUrl(txtIcon.value) || 'img/key.svg';
		password['fields'].forEach((field) => {
			addCustomFieldRow(trAddField, field.name, field.value, field.type);
		});
		password['files'].forEach((file) => {
			addFileRow(tblFiles, id, file);
		});
		fleUpload.addEventListener('change', function(e){
			// encrypt and upload immediately, the file meta data is saved with the entry
			let file = fleUpload.files[0];
			if(!file) return;
			let fileInfo = {'name': file.name, 'size': file.size};
			file.arrayBuffer()
			.then((data) => encryptFile(data))
			.then((result) => {
				fileInfo['key'] = result.key;
				fileInfo['iv'] = result.iv;
				return jsonRequest('POST', 'vault/password/'+encodeURIComponent(id)+'/file', {'data': arrayBufferToBase64String(result.data)});
			})
			.then((response) => {
				fileInfo['id'] = response.id;
				addFileRow(tblFiles, id, fileInfo);
				fleUpload.value = '';
			})
			.catch((error) => {
				console.warn(error);
				alert(error);
			});
		});
		clone.querySelectorAll('.btnDelete')[0].addEventListener('click', function(e){
			if(confirm(strings.are_you_sure_delete)) {
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
			addShareGroupRow(tblShares, shareGroupId, password['share_group_permissions'][shareGroupId], password['share_group_expires'][shareGroupId]);
		});
		password['share_users'].forEach((shareUserId) => {
			addShareUserRow(tblShares, shareUserId, password['share_user_permissions'][shareUserId], password['share_user_expires'][shareUserId]);
		});
	}
	sltGroup.addEventListener('change', function(e) {
		// reset shares
		let permissionEntries = clone.querySelectorAll('.shares tr');
		for(let i=0; i<permissionEntries.length; i++) {
			if(permissionEntries[i].getAttribute('userid') || permissionEntries[i].getAttribute('groupid')) {
				permissionEntries[i].remove();
			}
		}
		if(sltGroup.value != '' && sltGroup.value != '-') {
			// apply permissions from parent folder
			let parentGroup = sessionVaultContent['groups'][sltGroup.value];
			parentGroup['share_groups'].forEach((shareGroupId) => {
				addShareGroupRow(tblShares, shareGroupId, parentGroup['share_group_permissions'][shareGroupId], parentGroup['share_group_expires'][shareGroupId]);
			});
			parentGroup['share_users'].forEach((shareUserId) => {
				addShareUserRow(tblShares, shareUserId, parentGroup['share_user_permissions'][shareUserId], parentGroup['share_user_expires'][shareUserId]);
			});
		} else {
			// add self only
			addShareUserRow(tblShares, sessionEnvironment['userId'], 0);
		}
	});
	clone.querySelectorAll('.btnAddUserShare')[0].addEventListener('click', function(e){
		addShareUserRow(tblShares, sltShareUser.value, 0);
	});
	clone.querySelectorAll('.btnAddUserGroupShare')[0].addEventListener('click', function(e){
		addShareGroupRow(tblShares, sltShareUserGroup.value, 0);
	});
	clone.querySelectorAll('.btnAddField')[0].addEventListener('click', function(e){
		addCustomFieldRow(trAddField).focus();
	});
	clone.querySelectorAll('.btnCopyUsername')[0].addEventListener('click', function(e){
		copyInputValueToClipboard(txtUsername);
	});
	clone.querySelectorAll('.btnCopyPassword')[0].addEventListener('click', function(e){
		copyInputValueToClipboard(txtPassword);
	});
	clone.querySelectorAll('.btnGeneratePassword')[0].addEventListener('click', function(e){
		showPasswordGenerator(txtPassword, clone);
	});
	clone.querySelectorAll('.btnShowHidePassword')[0].addEventListener('click', function(e){
		togglePasswordInput(txtPassword);
	});
	btnIcon.addEventListener('click', function(e){
		showIconPicker(txtIcon, btnIcon, 'img/key.svg', clone);
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
			'icon': txtIcon.value,
			'fields': [],
		};
		clone.querySelectorAll('tr.field').forEach((tr) => {
			let txtValue = tr.querySelectorAll('.fieldvalue')[0];
			secret.fields.push({'name': tr.querySelectorAll('.fieldname')[0].value, 'value': txtValue.value, 'type': txtValue.type});
		});
		secret.files = [];
		tblFiles.querySelectorAll('tr').forEach((tr) => {
			secret.files.push(tr.fileInfo);
		});

		// collect selected users and groups and compile target keys
		let shareUsers = [];
		let shareGroups = [];
		let shareUserPermissions = {};
		let shareGroupPermissions = {};
		let shareUserExpires = {};
		let shareGroupExpires = {};
		let targetPublicKeys = {};
		tblShares.querySelectorAll('tr').forEach(function(item){
			let userId = item.getAttribute('userid') ? parseInt(item.getAttribute('userid')) : null;
			let groupId = item.getAttribute('groupid') ? parseInt(item.getAttribute('groupid')) : null;
			if(userId && !shareUsers.includes(userId)) {
				targetPublicKeys[userId] = sessionEnvironment['users'][userId]['public_key'];
				shareUsers.push(userId);
				shareUserPermissions[userId] = parseInt(item.querySelector('select.permission').value);
				shareUserExpires[userId] = localDateTimeInputToUtc(item.querySelector('input.expires').value);
			}
			if(groupId && !shareGroups.includes(groupId)) {
				shareGroupPermissions[groupId] = parseInt(item.querySelector('select.permission').value);
				shareGroupExpires[groupId] = localDateTimeInputToUtc(item.querySelector('input.expires').value);
				sessionEnvironment['groups'][groupId]['members'].forEach((groupUserId) => {
					targetPublicKeys[groupUserId] = sessionEnvironment['users'][groupUserId]['public_key'];
				});
				shareGroups.push(groupId);
			}
		});
		if(!isOwnUserIdIncluded(shareUsers, shareGroups)) {
			let myUserId = sessionEnvironment['userId'];
			shareUsers.push(myUserId);
			shareUserPermissions[myUserId] = 0;
			shareUserExpires[myUserId] = null;
			targetPublicKeys[myUserId] = sessionEnvironment['users'][myUserId]['public_key'];
		}

		// encrypt to all target keys and send to server
		encryptData(targetPublicKeys, JSON.stringify(secret))
		.then((result) => jsonRequest(
			'POST', (id==null ? 'vault/password' : 'vault/password/'+encodeURIComponent(id)),
			{
				'password_group_id': group,
				'secret': result.secret,
				'aes_iv': result.aes_iv,
				'revision': txtRevision.value,
				'password_user': result.password_user,
				'share_users': shareUsers, 'share_groups': shareGroups,
				'share_user_permissions': shareUserPermissions, 'share_group_permissions': shareGroupPermissions,
				'share_user_expires': shareUserExpires, 'share_group_expires': shareGroupExpires,
				'file_ids': secret.files.map((file) => file.id),
			}
		))
		.then((response) => {
			// append to session vault
			sessionVaultContent['passwords'][response.id] = {
				'revision': response.revision,
				'group': group, 'title': secret.title,
				'username': secret.username, 'password': secret.password,
				'url': secret.url, 'description': secret.description,
				'icon': secret.icon, 'fields': secret.fields, 'files': secret.files,
				'permission': (id ? sessionVaultContent['passwords'][id]['permission'] : 0),
				'share_users': shareUsers, 'share_groups': shareGroups,
				'share_user_permissions': shareUserPermissions, 'share_group_permissions': shareGroupPermissions,
				'share_user_expires': shareUserExpires, 'share_group_expires': shareGroupExpires
			};
			populateVaultWindowEntries();
			closeAnimation(e);
		})
		.catch((error) => {
			console.warn(error);
			alert(error);
		});
	});
	if(id && (sessionVaultContent['passwords'][id]['permission'] & SHARE_PERMISSION_READ_ONLY)) {
		disableEditing(clone);
	}
	if(id && (sessionVaultContent['passwords'][id]['permission'] & SHARE_PERMISSION_NO_RESHARE)) {
		clone.querySelectorAll('.btnShare')[0].classList.add('invisible');
	}
	// show with animation
	document.body.appendChild(clone);
	windowOpenAnimation(clone);
	txtTitle.focus();
}
function showIconPicker(txtIcon, btnIcon, defaultIcon, divParentWindow) {
	const clone = divIconPickerTemplateContainer.cloneNode(true);
	clone.removeAttribute('id');
	// identify inputs
	let txtSearch = clone.querySelectorAll('[name=txtSearch]')[0];
	let fleIcon = clone.querySelectorAll('[name=fleIcon]')[0];
	let btnIcons = clone.querySelectorAll('.icons button');
	btnIcons[0].querySelectorAll('img')[0].src = defaultIcon;
	// add actions
	activateWindowMouseDrag(clone, clone.querySelectorAll('.titlebar')[0], divParentWindow);
	let closeAnimation = windowCloseAction(clone);
	let applyIcon = function(icon) {
		txtIcon.value = icon;
		btnIcon.querySelectorAll('img')[0].src = getIconUrl(icon) || defaultIcon;
		closeAnimation();
	};
	btnIcons.forEach((btn) => {
		btn.addEventListener('click', function(e){
			applyIcon(btn.value);
		});
	});
	txtSearch.addEventListener('input', function(e){
		btnIcons.forEach((btn) => {
			btn.classList.toggle('invisible', !btn.title.toUpperCase().includes(txtSearch.value.toUpperCase()));
		});
	});
	fleIcon.addEventListener('change', function(e){
		// re-encode the uploaded image as small PNG so that only plain image data is stored
		let img = new Image();
		img.onload = function() {
			let canvas = document.createElement('CANVAS');
			canvas.width = 48;
			canvas.height = 48;
			canvas.getContext('2d').drawImage(img, 0, 0, canvas.width, canvas.height);
			URL.revokeObjectURL(img.src);
			applyIcon(canvas.toDataURL('image/png'));
		};
		img.onerror = function() {
			alert(strings.invalid_image);
		};
		img.src = URL.createObjectURL(fleIcon.files[0]);
	});
	clone.querySelectorAll('.btnClose')[0].addEventListener('click', closeAnimation);
	// show with animation
	document.body.appendChild(clone);
	windowOpenAnimation(clone);
	txtSearch.focus();
}
function showPasswordGenerator(input, divParentWindow) {
	const clone = divPasswordGeneratorTemplateContainer.cloneNode(true);
	clone.removeAttribute('id');
	// identify inputs
	let txtCharCount = clone.querySelectorAll('[name=txtCharCount]')[0];
	let txtCharset = clone.querySelectorAll('[name=txtCharset]')[0];
	let txtGeneratedPassword = clone.querySelectorAll('[name=txtGeneratedPassword]')[0];
	let btnGeneratePassword = clone.querySelectorAll('.btnGeneratePassword')[0];
	// set defaults
	txtCharCount.value = getSetting('generatorCharCount', '13');
	txtCharset.value = getSetting('generatorCharset', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');
	txtCharset.title = txtCharset.value; // the charset is usually longer than the input field
	txtCharset.addEventListener('input', function(e){ txtCharset.title = txtCharset.value; });
	// add actions
	activateWindowMouseDrag(clone, clone.querySelectorAll('.titlebar')[0], divParentWindow);
	let closeAnimation = windowCloseAction(clone);
	clone.querySelectorAll('.btnGeneratePassword')[0].addEventListener('click', function(e){
		txtGeneratedPassword.value = generateRandomPassword(parseInt(txtCharCount.value), txtCharset.value);
	});
	clone.querySelectorAll('.btnGeneratePassword')[0].click();
	clone.querySelectorAll('.btnApply')[0].addEventListener('click', function(e){
		input.value = txtGeneratedPassword.value;
		input.type = 'text';
		closeAnimation();
		setSetting('generatorCharCount', txtCharCount.value);
		setSetting('generatorCharset', txtCharset.value);
	});
	clone.querySelectorAll('.btnClose')[0].addEventListener('click', closeAnimation);
	// show with animation
	document.body.appendChild(clone);
	windowOpenAnimation(clone);
	btnGeneratePassword.focus();
}

function isOwnUserIdIncluded(userIds, groupIds) {
	let myUserId = sessionEnvironment['userId'];
	if(userIds.includes(myUserId)) {
		return true;
	}
	for(let i=0; i<groupIds.length; i++) {
		if(sessionEnvironment['groups'][groupIds[i]]['members'].includes(myUserId)) {
			return true;
		}
	}
	return false;
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
	btn.title = strings.edit;
	btn.addEventListener('click', editAction);
	let img = document.createElement('IMG');
	img.src = 'img/edit.svg';
	btn.appendChild(img);
	td2.appendChild(btn);
	tr.appendChild(td2);
	groupTable.appendChild(tr);
}
const SHARE_PERMISSION_READ_ONLY = 1;
const SHARE_PERMISSION_NO_RESHARE = 2;
const SHARE_PERMISSIONS = {0:'full_access', 2:'no_resharing', 3:'read_only'};
function createPermissionCell(permission, expires) {
	let td = document.createElement('TD');
	let slt = document.createElement('SELECT');
	slt.classList.add('permission');
	for(let value in SHARE_PERMISSIONS) {
		let option = document.createElement('OPTION');
		option.value = value;
		option.innerText = strings[SHARE_PERMISSIONS[value]];
		slt.appendChild(option);
	}
	slt.value = permission || 0;
	td.appendChild(slt);
	let input = document.createElement('INPUT');
	input.type = 'datetime-local';
	input.classList.add('expires');
	input.title = strings.expires;
	input.value = utcToLocalDateTimeInput(expires);
	td.appendChild(input);
	return td;
}
// expiry dates are transferred as UTC 'YYYY-MM-DD HH:MM:SS' and displayed in local time
function utcToLocalDateTimeInput(utc) {
	if(!utc) return '';
	let date = new Date(utc.replace(' ', 'T')+'Z');
	let pad = (n) => String(n).padStart(2, '0');
	return date.getFullYear()+'-'+pad(date.getMonth()+1)+'-'+pad(date.getDate())+'T'+pad(date.getHours())+':'+pad(date.getMinutes());
}
function localDateTimeInputToUtc(local) {
	if(!local) return null;
	return new Date(local).toISOString().slice(0, 19).replace('T', ' ');
}
function disableEditing(divWindow) {
	// read only permission: hide save/delete and make all inputs read only
	divWindow.querySelectorAll('.btnSave, .btnDelete, .btnAddField').forEach((btn) => btn.remove());
	divWindow.querySelectorAll('input, textarea').forEach((input) => input.readOnly = true);
	divWindow.querySelectorAll('input[type=file]').forEach((input) => input.disabled = true);
	divWindow.querySelectorAll('select, .btnIcon').forEach((select) => select.disabled = true);
}
function addFileRow(fileTable, passwordId, fileInfo) {
	let tr = document.createElement('TR');
	tr.fileInfo = fileInfo; // {id, name, size, key, iv} - stored inside the encrypted secret
	let td1 = document.createElement('TD');
	let a = document.createElement('A');
	a.href = '#';
	a.innerText = fileInfo.name+' ('+Math.max(1, Math.round(fileInfo.size/1024))+' KB)';
	a.addEventListener('click', function(e){
		e.preventDefault();
		downloadFile(passwordId, fileInfo);
	});
	td1.appendChild(a);
	tr.appendChild(td1);
	let td2 = document.createElement('TD');
	let btn = document.createElement('BUTTON');
	btn.title = strings.remove;
	btn.addEventListener('click', function(e){
		tr.remove();
	});
	let img = document.createElement('IMG');
	img.src = 'img/minus.svg';
	btn.appendChild(img);
	td2.appendChild(btn);
	tr.appendChild(td2);
	fileTable.appendChild(tr);
}
function downloadFile(passwordId, fileInfo) {
	var xhttp = new XMLHttpRequest();
	xhttp.responseType = 'arraybuffer';
	xhttp.onreadystatechange = function() {
		if(this.readyState != 4) return;
		if(this.status != 200) {
			alert('HTTP '+this.status);
			return;
		}
		decryptFile(fileInfo.key, fileInfo.iv, this.response).then((decrypted) => {
			let a = document.createElement('A');
			a.href = URL.createObjectURL(new Blob([decrypted]));
			a.download = fileInfo.name;
			a.click();
			URL.revokeObjectURL(a.href);
		}).catch((error) => {
			console.warn(error);
			alert(error);
		});
	};
	xhttp.open('GET', 'vault/password/'+encodeURIComponent(passwordId)+'/file/'+encodeURIComponent(fileInfo.id), true);
	xhttp.send();
}
function addCustomFieldRow(trAddField, name='', value='', type='text') {
	// custom fields are stored inside the encrypted secret as {name, value, type}
	let tr = document.createElement('TR');
	tr.classList.add('field');
	let th = document.createElement('TH');
	let txtName = document.createElement('INPUT');
	txtName.type = 'text';
	txtName.classList.add('fieldname');
	txtName.placeholder = strings.field_name;
	txtName.value = name;
	th.appendChild(txtName);
	tr.appendChild(th);
	let td = document.createElement('TD');
	let div = document.createElement('DIV');
	div.classList.add('with2button');
	let txtValue = document.createElement('INPUT');
	txtValue.type = (type == 'password') ? 'password' : 'text';
	txtValue.classList.add('fieldvalue');
	txtValue.placeholder = strings.value;
	txtValue.value = value;
	div.appendChild(txtValue);
	let btnToggle = document.createElement('BUTTON');
	btnToggle.title = strings.show_hide_password;
	btnToggle.addEventListener('click', function(e){
		togglePasswordInput(txtValue);
	});
	let imgToggle = document.createElement('IMG');
	imgToggle.src = 'img/eye.svg';
	btnToggle.appendChild(imgToggle);
	div.appendChild(btnToggle);
	let btnRemove = document.createElement('BUTTON');
	btnRemove.title = strings.remove;
	btnRemove.addEventListener('click', function(e){
		tr.remove();
	});
	let imgRemove = document.createElement('IMG');
	imgRemove.src = 'img/minus.svg';
	btnRemove.appendChild(imgRemove);
	div.appendChild(btnRemove);
	td.appendChild(div);
	tr.appendChild(td);
	trAddField.parentNode.insertBefore(tr, trAddField);
	return txtName;
}
function addShareUserRow(shareTable, userId, permission=null, expires=null) {
	if(!(userId in sessionEnvironment['users'])) return;
	let user = sessionEnvironment['users'][userId];
	let tr = document.createElement('TR');
	tr.setAttribute('userid', userId);
	let td1 = document.createElement('TD');
	td1.innerText = user['display_name'];
	tr.appendChild(td1);
	// permission is null for user group member rows
	if(permission === null) {
		td1.setAttribute('colspan', '2');
	} else {
		tr.appendChild(createPermissionCell(permission, expires));
	}
	let td2 = document.createElement('TD');
	let btn = document.createElement('BUTTON');
	btn.title = strings.remove;
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
function addShareGroupRow(shareTable, groupId, permission=0, expires=null) {
	if(!(groupId in sessionEnvironment['groups'])) return;
	let group = sessionEnvironment['groups'][groupId];
	let tr = document.createElement('TR');
	tr.setAttribute('groupid', groupId);
	let td1 = document.createElement('TD');
	td1.innerText = group['title'];
	tr.appendChild(td1);
	tr.appendChild(createPermissionCell(permission, expires));
	let td2 = document.createElement('TD');
	let btn = document.createElement('BUTTON');
	btn.title = strings.remove;
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

function truncate(str, n=null){
	if(!n) n = getSetting('truncateChars', 60);
	return (str.length > n) ? str.slice(0, n-1) + '…' : str;
}
function setTruncatedText(element, str, prefix='') {
	let truncated = truncate(str);
	element.innerText = prefix + truncated;
	// show the full text as tooltip if it was truncated
	if(truncated !== str) element.title = str;
}
function onlyUnique(value, index, array) {
	return array.indexOf(value) === index;
}

function importCsvFile(file) {
	if(!file) return;
	return new Promise(function(resolve, reject) {
		var reader = new FileReader();
		reader.readAsText(file, 'UTF-8');
		reader.onload = function(evt) {
			resolve(parseCsvToArray(evt.target.result));
		}
		reader.onerror = function(evt) {
			alert('Error reading CSV import file');
			reject();
		}
	});
}
function parseCsvToArray(strData, strDelimiter=',') {
	var objPattern = new RegExp(
		(
			"(\\" + strDelimiter + "|\\r?\\n|\\r|^)" + // delimiters
			"(?:\"([^\"]*(?:\"\"[^\"]*)*)\"|" + // quoted fields
			"([^\"\\" + strDelimiter + "\\r\\n]*))" // standard fields
		),
		"gi"
	);
	var arrData = [[]];
	var arrMatches = null;
	while(arrMatches = objPattern.exec( strData )) {
		var strMatchedDelimiter = arrMatches[ 1 ];

		// Check to see if the given delimiter has a length
		// (is not the start of string) and if it matches
		// field delimiter. If id does not, then we know
		// that this delimiter is a row delimiter.
		if(
			strMatchedDelimiter.length &&
			strMatchedDelimiter !== strDelimiter
		) {
			// Since we have reached a new row of data,
			// add an empty row to our data array.
			arrData.push( [] );
		}

		// Now that we have our delimiter out of the way,
		// let's check to see which kind of value we
		// captured (quoted or unquoted).
		var strMatchedValue;
		if(arrMatches[ 2 ]) {
			// We found a quoted value. When we capture
			// this value, unescape any double quotes.
			strMatchedValue = arrMatches[ 2 ].replace(
				new RegExp( "\"\"", "g" ),
				"\""
			);
		} else {
			// We found a non-quoted value.
			strMatchedValue = arrMatches[ 3 ] ?? '';
		}

		// Now that we have our value string, let's add
		// it to the data array.
		arrData[ arrData.length - 1 ].push( strMatchedValue );
	}
	return arrData;
}
