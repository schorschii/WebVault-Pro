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
	btnImport.addEventListener('click', () => showImport());
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
	activateWindowMouseDrag(divVaultContainer, divVaultTitlebar);
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
				decryptData(sessionKeys['private'], password.aes_key, password.aes_iv, password.rsa_iv, password.secret)
				.then((decrypted) => {
					let decryptedData = JSON.parse(decrypted);
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
		} else {
			elements[i].classList.remove('add');
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
	// populate select boxes
	populateUserGroups();
	// add actions
	activateWindowMouseDrag(divUserGroupsContainer, divUserGroupsContainer.querySelectorAll('.titlebar')[0], divVaultContainer);
	divUserGroupsContainer.querySelectorAll('.btnAdd')[0].onclick = function(){showUserGroupManagement()};
	divUserGroupsContainer.querySelectorAll('.btnClose')[0].onclick = windowCloseAction(divUserGroupsContainer,false);
	// show with animation
	windowOpenAnimation(divUserGroupsContainer);
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
				populateVaultWindowEntries();
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
		// reset shares
		let permissionEntries = clone.querySelectorAll('.shares tr');
		for(let i=0; i<permissionEntries.length; i++) {
			if(permissionEntries[i].getAttribute('userid') || permissionEntries[i].getAttribute('groupid')) {
				permissionEntries[i].remove();
			}
		}
		if(sltGroup.value != '' && sltGroup.value != '-') {
			// apply permissions from parent folder
			sessionVaultContent['groups'][sltGroup.value]['share_groups'].forEach((shareGroupId) => {
				addShareGroupRow(tblShares, shareGroupId);
			});
			sessionVaultContent['groups'][sltGroup.value]['share_users'].forEach((shareUserId) => {
				addShareUserRow(tblShares, shareUserId);
			});
		} else {
			// add self only
			addShareUserRow(tblShares, sessionEnvironment['userId']);
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
		if(!isOwnUserIdIncluded(shareUsers, shareGroups)) {
			let myUserId = sessionEnvironment['userId'];
			shareUsers.push(myUserId);
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
				'parent_password_group_id': group, 'title': txtTitle.value,
				'share_users': shareUsers, 'share_groups': shareGroups,
				'passwords': encryptedPasswords, 'groups': entriesToUpdate.groups
			}
		)).then((response) => {
			// append to session vault
			sessionVaultContent['groups'][response.id] = {
				'group':group, 'title':txtTitle.value,
				'share_users':shareUsers, 'share_groups':shareGroups
			};
			// update share info of updated entries
			for(let groupId in entriesToUpdate.groups) {
				sessionVaultContent['groups'][groupId]['share_users'] = shareUsers;
				sessionVaultContent['groups'][groupId]['share_groups'] = shareGroups;
			}
			for(let passwordId in entriesToUpdate.passwords) {
				sessionVaultContent['passwords'][passwordId]['revision'] += 1;
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
	const clone = divPasswordTemplateContainer.cloneNode(true);
	clone.removeAttribute('id');
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
	activateWindowMouseDrag(clone, clone.querySelectorAll('.titlebar')[0], divVaultContainer);
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
		// reset shares
		let permissionEntries = clone.querySelectorAll('.shares tr');
		for(let i=0; i<permissionEntries.length; i++) {
			if(permissionEntries[i].getAttribute('userid') || permissionEntries[i].getAttribute('groupid')) {
				permissionEntries[i].remove();
			}
		}
		if(sltGroup.value != '' && sltGroup.value != '-') {
			// apply permissions from parent folder
			sessionVaultContent['groups'][sltGroup.value]['share_groups'].forEach((shareGroupId) => {
				addShareGroupRow(tblShares, shareGroupId);
			});
			sessionVaultContent['groups'][sltGroup.value]['share_users'].forEach((shareUserId) => {
				addShareUserRow(tblShares, shareUserId);
			});
		} else {
			// add self only
			addShareUserRow(tblShares, sessionEnvironment['userId']);
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
		showPasswordGenerator(txtPassword, clone);
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

		// collect selected users and groups and compile target keys
		let shareUsers = [];
		let shareGroups = [];
		let targetPublicKeys = {};
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
		if(!isOwnUserIdIncluded(shareUsers, shareGroups)) {
			let myUserId = sessionEnvironment['userId'];
			shareUsers.push(myUserId);
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
			}
		))
		.then((response) => {
			// append to session vault
			sessionVaultContent['passwords'][response.id] = {
				'revision': response.revision,
				'group': group, 'title': secret.title,
				'username': secret.username, 'password': secret.password,
				'url': secret.url, 'description': secret.description,
				'share_users': shareUsers, 'share_groups': shareGroups
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
	btn.addEventListener('click', editAction);
	let img = document.createElement('IMG');
	img.src = 'img/edit.svg';
	btn.appendChild(img);
	td2.appendChild(btn);
	tr.appendChild(td2);
	groupTable.appendChild(tr);
}
function addShareUserRow(shareTable, userId) {
	if(!(userId in sessionEnvironment['users'])) return;
	let user = sessionEnvironment['users'][userId];
	let tr = document.createElement('TR');
	tr.setAttribute('userid', userId);
	let td1 = document.createElement('TD');
	td1.setAttribute('colspan', '2');
	td1.innerText = user['display_name'];
	tr.appendChild(td1);
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
function addShareGroupRow(shareTable, groupId) {
	if(!(groupId in sessionEnvironment['groups'])) return;
	let group = sessionEnvironment['groups'][groupId];
	let tr = document.createElement('TR');
	tr.setAttribute('groupid', groupId);
	let td1 = document.createElement('TD');
	td1.setAttribute('colspan', '2');
	td1.innerText = group['title'];
	tr.appendChild(td1);
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
