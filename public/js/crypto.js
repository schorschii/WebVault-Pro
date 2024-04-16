var scopesSignVerify = ['sign', 'verify'];
var signAlgorithm = {
	name: 'RSASSA-PKCS1-v1_5',
	modulusLength: 4096,
	publicExponent: new Uint8Array([1, 0, 1]),
	extractable: false,
	hash: { name: 'SHA-256' }
};
var scopesEncryptDecrypt = ['encrypt', 'decrypt'];
var encryptAlgorithm = {
	name: 'RSA-OAEP',
	modulusLength: 4096,
	publicExponent: new Uint8Array([1, 0, 1]),
	extractable: false,
	hash: { name: 'SHA-256' }
};

function arrayBufferToBase64String(arrayBuffer) {
	var byteArray = new Uint8Array(arrayBuffer);
	var byteString = '';
	for(var i=0; i<byteArray.byteLength; i++) {
		byteString += String.fromCharCode(byteArray[i]);
	}
	return btoa(byteString);
}
function base64StringToArrayBuffer(b64str) {
	var byteStr = atob(b64str);
	var bytes = new Uint8Array(byteStr.length);
	for(var i = 0; i < byteStr.length; i++) {
		bytes[i] = byteStr.charCodeAt(i);
	}
	return bytes.buffer;
}

function textToArrayBuffer(str) {
	return new TextEncoder().encode(str);
}
function arrayBufferToText(arrayBuffer) {
	return new TextDecoder().decode(arrayBuffer);
}

function convertBinaryToPem(binaryData, label=null) {
	var base64Cert = arrayBufferToBase64String(binaryData);
	var pemCert = '';
	if(label) pemCert += '-----BEGIN ' + label + '-----'+"\r\n";
	var nextIndex = 0;
	while(nextIndex < base64Cert.length) {
		if(nextIndex + 64 <= base64Cert.length) {
			pemCert += base64Cert.substr(nextIndex, 64) + "\r\n";
		} else {
			pemCert += base64Cert.substr(nextIndex) + "\r\n";
		}
		nextIndex += 64;
	}
	if(label) pemCert += '-----END ' + label + '-----'+"\r\n";
	return pemCert;
}
function convertPemToBinary(pem) {
	var lines = pem.split('\n');
	var encoded = '';
	for(var i = 0;i < lines.length;i++){
		if(lines[i].trim().length > 0 &&
				lines[i].indexOf('-BEGIN PRIVATE KEY-') < 0 &&
				lines[i].indexOf('-BEGIN ENCRYPTED PRIVATE KEY-') < 0 &&
				lines[i].indexOf('-BEGIN RSA PRIVATE KEY-') < 0 &&
				lines[i].indexOf('-BEGIN RSA PUBLIC KEY-') < 0 &&
				lines[i].indexOf('-END PRIVATE KEY-') < 0 &&
				lines[i].indexOf('-END ENCRYPTED PRIVATE KEY-') < 0 &&
				lines[i].indexOf('-END RSA PRIVATE KEY-') < 0 &&
				lines[i].indexOf('-END RSA PUBLIC KEY-') < 0) {
			encoded += lines[i].trim();
		}
	}
	return base64StringToArrayBuffer(encoded);
}

function importPublicKey(pemKey, userId=null, passwordId=null) {
	return new Promise(function(resolve) {
		crypto.subtle.importKey(
			'spki', convertPemToBinary(pemKey), encryptAlgorithm, false, ['encrypt']
		).then(function(key) {
			resolve({'key':key, 'userId':userId, 'passwordId':passwordId});
		});
	});
}
function importPrivateKey(pemKey, passphrase=null, saltb64=null, ivb64=null) {
	return new Promise(function(resolve, reject) {
		if(passphrase) {
			const enc = new TextEncoder();
			crypto.subtle.importKey(
				'raw',
				enc.encode(passphrase),
				{ name: 'PBKDF2' },
				false,
				['deriveBits', 'deriveKey'],
			).then((keyMaterial) => {
				return crypto.subtle.deriveKey(
					{ name: 'PBKDF2', salt: base64StringToArrayBuffer(saltb64), iterations: 100000, hash: 'SHA-256' },
					keyMaterial,
					{ name: 'AES-GCM', length: 256 },
					false,
					['wrapKey', 'unwrapKey'],
				);
			}).then((unwrappingKey) => {
				return crypto.subtle.unwrapKey(
					'pkcs8', convertPemToBinary(pemKey), unwrappingKey,
					{ name: 'AES-GCM', iv: base64StringToArrayBuffer(ivb64) },
					encryptAlgorithm, false, ['decrypt'],
				);
			}).then((key) => {
				resolve(key);
			}).catch((error) => {
				reject(error);
			});
		} else {
			crypto.subtle.importKey(
				'pkcs8', convertPemToBinary(pemKey), encryptAlgorithm, false, ['decrypt']
			).then(function(key) {
				resolve(key)
			}).catch((error) => {
				reject(error);
			});
		}
	});
}

function exportPublicKey(keys) {
	return new Promise(function(resolve) {
		crypto.subtle.exportKey(
			'spki', keys
		).then(function(spki) {
			resolve(convertBinaryToPem(spki));
		});
	});
}
function exportPrivateKey(keys, passphrase=null) {
	return new Promise(function(resolve, reject) {
		if(passphrase) {
			var saltb64, ivb64;
			const enc = new TextEncoder();
			crypto.subtle.importKey(
				'raw',
				enc.encode(passphrase),
				{ name: 'PBKDF2' },
				false,
				['deriveBits', 'deriveKey'],
			).then((keyMaterial) => {
				let salt = getRandomCryptoValues(16);
				saltb64 = arrayBufferToBase64String(salt);
				return crypto.subtle.deriveKey(
					{ name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
					keyMaterial,
					{ name: 'AES-GCM', length: 256 },
					false,
					['wrapKey', 'unwrapKey'],
				)
			}).then((wrappingKey) => {
				let iv = getRandomCryptoValues(12);
				ivb64 = arrayBufferToBase64String(iv);
				return crypto.subtle.wrapKey(
					'pkcs8', keys, wrappingKey, {name: 'AES-GCM', iv}
				)
			}).then(function(pkcs8) {
				resolve({key:convertBinaryToPem(pkcs8), salt:saltb64, iv:ivb64})
			}).catch((error) => {
				reject(error);
			});
		} else {
			crypto.subtle.exportKey(
				'pkcs8', keys
			).then(function(pkcs8) {
				resolve(convertBinaryToPem(pkcs8))
			}).catch((error) => {
				reject(error);
			});
		}
	})
}
function exportPemKeys(keys, passphrase=null) {
	return new Promise(function(resolve) {
		exportPublicKey(keys.publicKey).then(function(pubKey) {
			exportPrivateKey(keys.privateKey, passphrase).then(function(privKey) {
				resolve({publicKey:pubKey, privateKey:privKey.key, salt:privKey.salt, iv:privKey.iv});
			});
		});
	});
}

function getRandomCryptoValues(length) {
	return crypto.getRandomValues(new Uint8Array(length));
}

function generateKey(alg, scope) {
	return new Promise(function(resolve) {
		crypto.subtle.generateKey(
			alg, true, scope
		).then(function (pair) {
			resolve(pair);
		});
	});
}

function signData(key, data) {
	return crypto.subtle.sign(signAlgorithm, key, textToArrayBuffer(data));
}
function testVerifySig(pub, sig, data) {
	return crypto.subtle.verify(signAlgorithm, pub, sig, data);
}

// RSA can not directly encrypt data larger than the used key.
// We need to use a symmetric cipher, encrypt the large data with it using a secure mode (GCM).
// Then, encrypt the symmetric key with the RSA public key.
function encryptData(rsaPubKey, data, userId=null, passwordId=null) {
	let _rsaIv = getRandomCryptoValues(16);
	let _aesIv = getRandomCryptoValues(12);
	let _aesKey;
	let _aesEncrypted;
	return window.crypto.subtle.generateKey(
		{ name: 'AES-GCM', length: 256 },
		true,
		['encrypt', 'decrypt'],
	).then((aesKey) => {
		_aesKey = aesKey;
		return crypto.subtle.encrypt(
			{ name: 'AES-GCM', iv: _aesIv },
			aesKey,
			textToArrayBuffer(data)
		)
	}).then((aesEncrypted) => {
		_aesEncrypted = aesEncrypted;
		return crypto.subtle.exportKey('raw', _aesKey);
	}).then((exportedAesKey) => crypto.subtle.encrypt(
		{ name: 'RSA-OAEP', iv: _rsaIv },
		rsaPubKey,
		exportedAesKey
	)).then((rsaEncrypted) => {
		return Promise.resolve({
			'encrypted':  arrayBufferToBase64String(_aesEncrypted), 'encryptedAesKey':  arrayBufferToBase64String(rsaEncrypted),
			'rsaIv':  arrayBufferToBase64String(_rsaIv), 'aesIv':  arrayBufferToBase64String(_aesIv),
			'userId': userId, 'passwordId': passwordId
		});
	});
}
function decryptData(rsaPrivKey, encryptedAesKey, aesIv, rsaIv, data) {
	return crypto.subtle.decrypt(
		{ name: 'RSA-OAEP', iv: base64StringToArrayBuffer(rsaIv) },
		rsaPrivKey,
		base64StringToArrayBuffer(encryptedAesKey)
	).then((aesKeyBytes) => crypto.subtle.importKey(
		'raw', aesKeyBytes, 'AES-GCM', true, scopesEncryptDecrypt
	)).then((aesKey) => crypto.subtle.decrypt(
		{ name: 'AES-GCM', iv: base64StringToArrayBuffer(aesIv) },
		aesKey,
		base64StringToArrayBuffer(data)
	)).then((decrypted) => {
		return Promise.resolve(arrayBufferToText(decrypted));
	});
}

function testEncryptDecrypt() {
	let text = 'Lorem ipsum dolor sit amet';
	let keyPair;
	generateKey(encryptAlgorithm, scopesEncryptDecrypt)
	.then((pair) => {
		keyPair = pair;
		return encryptData(pair.publicKey, text);
	})
	.then((result) => {
		console.log(result);
		return decryptData(result.rsaIv, result.aesIv, keyPair.privateKey, result.encryptedAesKey, result.encrypted)
	})
	.then((decrypted) => console.log(decrypted));
}
