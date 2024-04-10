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
	var buf = unescape(encodeURIComponent(str)); // 2 bytes for each char
	var bufView = new Uint8Array(buf.length);
	for(var i=0; i < buf.length; i++) {
		bufView[i] = buf.charCodeAt(i);
	}
	return bufView;
}
function arrayBufferToText(arrayBuffer) {
	var byteArray = new Uint8Array(arrayBuffer);
	var str = '';
	for(var i=0; i<byteArray.byteLength; i++) {
		str += String.fromCharCode(byteArray[i]);
	}
	return str;
}

function convertBinaryToPem(binaryData, label) {
	var base64Cert = arrayBufferToBase64String(binaryData);
	var pemCert = '-----BEGIN ' + label + '-----'+"\r\n";
	var nextIndex = 0;
	while(nextIndex < base64Cert.length) {
		if(nextIndex + 64 <= base64Cert.length) {
			pemCert += base64Cert.substr(nextIndex, 64) + "\r\n";
		} else {
			pemCert += base64Cert.substr(nextIndex) + "\r\n";
		}
		nextIndex += 64;
	}
	pemCert += '-----END ' + label + '-----'+"\r\n";
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
			'spki', convertPemToBinary(pemKey), encryptAlgorithm, true, ['encrypt']
		).then(function(key) {
			resolve({'key':key, 'userId':userId, 'passwordId':passwordId});
		});
	})
}
function importPrivateKey(pemKey, passphrase=null, saltb64=null, ivb64=null) {
	return new Promise(function(resolve, reject) {
		if(passphrase) {
			const enc = new TextEncoder();
			window.crypto.subtle.importKey(
				'raw',
				enc.encode(passphrase),
				{ name: 'PBKDF2' },
				false,
				['deriveBits', 'deriveKey'],
			).then((keyMaterial) => {
				return window.crypto.subtle.deriveKey(
					{ name: 'PBKDF2', salt: base64StringToArrayBuffer(saltb64), iterations: 100000, hash: 'SHA-256' },
					keyMaterial,
					{ name: 'AES-GCM', length: 256 },
					true,
					['wrapKey', 'unwrapKey'],
				);
			}).then((unwrappingKey) => {
				return window.crypto.subtle.unwrapKey(
					'pkcs8', convertPemToBinary(pemKey), unwrappingKey,
					{ name: 'AES-GCM', iv: base64StringToArrayBuffer(ivb64) },
					encryptAlgorithm, true, ['decrypt'],
				);
			}).then((key) => {
				resolve(key);
			}).catch((error) => {
				reject(error);
			});
		} else {
			crypto.subtle.importKey(
				'pkcs8', convertPemToBinary(pemKey), encryptAlgorithm, true, ['decrypt']
			).then(function(key) {
				resolve(key)
			}).catch((error) => {
				reject(error);
			});
		}
	})
}

function exportPublicKey(keys) {
	return new Promise(function(resolve) {
		window.crypto.subtle.exportKey(
			'spki', keys
		).then(function(spki) {
			resolve(convertBinaryToPem(spki, 'RSA PUBLIC KEY'));
		})
	})
}
function exportPrivateKey(keys, passphrase=null) {
	return new Promise(function(resolve) {
		if(passphrase) {
			var saltb64, ivb64;
			const enc = new TextEncoder();
			window.crypto.subtle.importKey(
				'raw',
				enc.encode(passphrase),
				{ name: 'PBKDF2' },
				false,
				['deriveBits', 'deriveKey'],
			).then((keyMaterial) => {
				let salt = getRandomCryptoValues(16);
				saltb64 = arrayBufferToBase64String(salt);
				return window.crypto.subtle.deriveKey(
					{ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
					keyMaterial,
					{ name: 'AES-GCM', length: 256 },
					true,
					['wrapKey', 'unwrapKey'],
				)
			}).then((wrappingKey) => {
				let iv = getRandomCryptoValues(12);
				ivb64 = arrayBufferToBase64String(iv);
				return window.crypto.subtle.wrapKey(
					'pkcs8', keys, wrappingKey, {name: 'AES-GCM', iv}
				)
			}).then(function(pkcs8) {
				resolve({key:convertBinaryToPem(pkcs8, 'ENCRYPTED PRIVATE KEY'), salt:saltb64, iv:ivb64})
			}).catch((error) => {
				reject(error);
			});
		} else {
			window.crypto.subtle.exportKey(
				'pkcs8', keys
			).then(function(pkcs8) {
				resolve(convertBinaryToPem(pkcs8, 'RSA PRIVATE KEY'))
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
				resolve({publicKey:pubKey, privateKey:privKey.key, salt:privKey.salt, iv:privKey.iv})
			})
		})
	})
}

function getRandomCryptoValues(length) {
	window.crypto.getRandomValues(new Uint8Array(length))
}

function generateKey(alg, scope) {
	return new Promise(function(resolve) {
		crypto.subtle.generateKey(
			alg, true, scope
		).then(function (pair) {
			resolve(pair);
		});
	})
}

function signData(key, data) {
	return window.crypto.subtle.sign(signAlgorithm, key, textToArrayBuffer(data));
}
function testVerifySig(pub, sig, data) {
	return crypto.subtle.verify(signAlgorithm, pub, sig, data);
}

function encryptData(vector, key, data, userId=null, passwordId=null) {
	return crypto.subtle.encrypt(
		{ name: 'RSA-OAEP', iv: vector },
		key,
		textToArrayBuffer(data)
	).then((encrypted) => {
		return Promise.resolve({'encrypted':encrypted, 'userId':userId, 'passwordId':passwordId});
	})
}
function decryptData(vector, key, data) {
	return crypto.subtle.decrypt(
		{ name: 'RSA-OAEP', iv: vector },
		key,
		data
	)
}
