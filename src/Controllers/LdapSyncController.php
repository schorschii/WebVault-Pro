<?php
namespace WebVault\Controllers;

use \Exception as Exception;

class LdapSyncController {

	private $db;
	private $settings;
	private /*bool*/ $debug;

	function __construct($settings, $db, bool $debug=false) {
		$this->db = $db;
		$this->settings = $settings;
		$this->debug = $debug;
	}

	private static function GUIDtoStr($binary_guid) {
		$unpacked = @unpack('Va/v2b/n2c/Nd', $binary_guid);
		if(!$unpacked) {
			// fallback string representation (base64) if we got unexpected input
			return base64_encode($binary_guid);
		}
		return sprintf('%08x-%04x-%04x-%04x-%04x%08x', $unpacked['a'], $unpacked['b1'], $unpacked['b2'], $unpacked['c1'], $unpacked['c2'], $unpacked['d']);
	}

	private static function applyDefaultLdapAttrs($attrs) {
		$attrs['uid'] = $attrs['uid'] ?? 'objectguid';
		$attrs['username'] = $attrs['username'] ?? 'samaccountname';
		$attrs['first_name'] = $attrs['first_name'] ?? 'givenname';
		$attrs['last_name'] = $attrs['last_name'] ?? 'sn';
		$attrs['display_name'] = $attrs['display_name'] ?? 'displayname';
		$attrs['email'] = $attrs['email'] ?? 'mail';
		$attrs['phone'] = $attrs['phone'] ?? 'telephonenumber';
		$attrs['mobile'] = $attrs['mobile'] ?? 'mobile';
		$attrs['description'] = $attrs['description'] ?? 'description';
		return $attrs;
	}

	public function sync() {
		// get configuration
		if(empty($this->settings) || !is_array($this->settings)) {
			throw new Exception('LDAP sync not configured!');
		}

		// for each configured server
		$foundLdapUsers = [];
		foreach($this->settings as $serverIdentifier => $details) {
			$attributes = self::applyDefaultLdapAttrs($details['attribute-matching'] ?? []);
			if(!is_int($serverIdentifier) || intval($serverIdentifier) < 1 || empty($details['address']) || empty($details['username']) || empty($details['password']) || empty($details['query-root']) || empty($details['queries']) || !is_array($details['queries'])) {
				if($this->debug) echo '===> '.($details['address']??$serverIdentifier).': missing configuration values, skipping!'."\n";
				continue;
			}

			// connect to server
			$ldapconn = ldap_connect($details['address']);
			if(!$ldapconn) {
				throw new Exception($details['address'].': ldap_connect failed');
			}
			if($this->debug) echo '===> '.$details['address'].': ldap_connect OK'."\n";

			// set options and authenticate
			ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
			ldap_set_option($ldapconn, LDAP_OPT_NETWORK_TIMEOUT, 5);
			ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, 0);
			$ldapbind = ldap_bind($ldapconn, $details['username'], $details['password']);
			if(!$ldapbind) {
				throw new Exception('ldap_bind failed: '.ldap_error($ldapconn));
			}
			if($this->debug) echo '===> ldap_bind OK'."\n";

			foreach($details['queries'] as $query) {
				// ldap search with paging support
				$data = [];
				$cookie = null;
				do {
					$result = ldap_search(
						$ldapconn, $details['query-root'], $query,
						[] /*attributes*/, 0 /*attributes_only*/, -1 /*sizelimit*/, -1 /*timelimit*/, LDAP_DEREF_NEVER,
						[ ['oid' => LDAP_CONTROL_PAGEDRESULTS, 'value' => ['size' => 750, 'cookie' => $cookie]] ]
					);
					if(!$result) {
						throw new Exception('ldap_search failed: '.ldap_error($ldapconn));
					}
					ldap_parse_result($ldapconn, $result, $errcode, $matcheddn, $errmsg, $referrals, $controls);
					$data = array_merge($data, ldap_get_entries($ldapconn, $result));
					if(isset($controls[LDAP_CONTROL_PAGEDRESULTS]['value']['cookie'])) {
						$cookie = $controls[LDAP_CONTROL_PAGEDRESULTS]['value']['cookie'];
					} else {
						$cookie = null;
					}
				} while(!empty($cookie));
				if($this->debug) echo '===> ldap_search OK - processing entries...'."\n";

				// iterate over results array
				foreach($data as $key => $account) {
					if(!is_numeric($key)) continue; // skip "count" entry
					#var_dump($account); die(); // debug

					if(empty($account[$attributes['uid']][0])) {
						continue;
					}
					$uid = self::GUIDtoStr($account[$attributes['uid']][0]);
					if(array_key_exists($uid, $foundLdapUsers)) {
						if($this->debug) echo '-> duplicate UID '.$uid.', skipping!'."\n";
						continue;
					}

					// parse LDAP values
					$username    = $account[$attributes['username']][0];
					$firstname   = '?';
					$lastname    = '?';
					$displayname = '?';
					$mail        = null;
					$description = null;
					if(isset($account[$attributes['first_name']][0]))
						$firstname = $account[$attributes['first_name']][0];
					if(isset($account[$attributes['last_name']][0]))
						$lastname = $account[$attributes['last_name']][0];
					if(isset($account[$attributes['display_name']][0]))
						$displayname = $account[$attributes['display_name']][0];
					if(isset($account[$attributes['email']][0]))
						$mail = $account[$attributes['email']][0];
					if(isset($account[$attributes['description']][0]))
						$description = $account[$attributes['description']][0];

					// add to found array
					$foundLdapUsers[$uid] = $username;

					// check if user already exists
					$id = null;
					$checkResult = $this->db->selectUserByUid($uid);
					if($checkResult !== null) {
						$id = $checkResult->id;
						if($this->debug) echo '--> '.$username.': found in db - update id: '.$id;

						// update into db
						if($this->db->updateUser($id, $uid, $username, $displayname, null/*password*/, intval($serverIdentifier), $mail, $description, 0/*locked*/))
							if($this->debug) echo '  OK'."\n";
						else throw new Exception('Error updating: '.$this->db->getLastStatement()->error);
					} else {
						if($this->debug) echo '--> '.$username.': not found in db - creating';

						// insert into db
						if($this->db->insertUser($uid, $username, $displayname, null/*password*/, intval($serverIdentifier), $mail, $description, 0/*locked*/))
							if($this->debug) echo '  OK'."\n";
						else throw new Exception('Error inserting: '.$this->db->getLastStatement()->error);
					}
				}
			}
			ldap_close($ldapconn);
		}

		if($this->debug) echo '===> Check for deleted users...'."\n";
		foreach($this->db->selectAllUser() as $dbUser) {
			if($dbUser->ldap < 1) continue;
			$found = false;
			foreach($foundLdapUsers as $uid => $username) {
				if($dbUser->uid == $uid) {
					$found = true;
				}
				if($dbUser->username == $username) { // fallback for old DB schema without uid
					$found = true;
				}
			}
			if(!$found) {
				if(!empty($details['lock-deleted-users'])) {
					if($this->db->updateUser($dbUser->id, $dbUser->uid, $dbUser->username, $dbUser->display_name, null/*password*/, $dbUser->ldap, $dbUser->email, $dbUser->description, 1/*locked*/)) {
						if($this->debug) echo '--> '.$dbUser->username.': locking  OK'."\n";
					}
					else throw new Exception('Error locking '.$dbUser->username.': '.$this->db->getLastStatement()->error);
				} else {
					if($this->db->deleteUser($dbUser->id)) {
						if($this->debug) echo '--> '.$dbUser->username.': deleting  OK'."\n";
					}
					else throw new Exception('Error deleting '.$dbUser->username.': '.$this->db->getLastStatement()->error);
				}
			}
		}
	}

	public function checkPassword($user, $checkPassword) {
		// do not allow anonymous binds
		if(empty($checkPassword)) return false;

		if(empty($this->settings) || !is_array($this->settings)) {
			throw new Exception('LDAP sync not configured!');
		}
		foreach($this->settings as $serverIdentifier => $details) {
			if(intval($user->ldap) !== intval($serverIdentifier)) continue;
			$username = $user->username;

			// get DN for LDAP auth check if configured
			$binddnQuery = empty($details['login-binddn-query']) ? '(&(objectClass=user)(samaccountname=%s))' : $details['login-binddn-query'];
			if($binddnQuery) {
				$ldapconn1 = ldap_connect($details['address']);
				if(!$ldapconn1) continue;
				ldap_set_option($ldapconn1, LDAP_OPT_PROTOCOL_VERSION, 3);
				ldap_set_option($ldapconn1, LDAP_OPT_NETWORK_TIMEOUT, 3);
				$ldapbind = ldap_bind($ldapconn1, $details['username'], $details['password']);
				if(!$ldapbind) continue;
				$result = ldap_search($ldapconn1, $details['query-root'], str_replace('%s', ldap_escape($user->username), $binddnQuery), ['dn']);
				if(!$result) continue;
				$data = ldap_get_entries($ldapconn1, $result);
				if(!empty($data[0]['dn'])) $username = $data[0]['dn'];
			}

			// try user authentication
			$ldapconn2 = ldap_connect($details['address']);
			if(!$ldapconn2) continue;
			ldap_set_option($ldapconn2, LDAP_OPT_PROTOCOL_VERSION, 3);
			ldap_set_option($ldapconn2, LDAP_OPT_NETWORK_TIMEOUT, 3);
			$ldapbind = @ldap_bind($ldapconn2, $username, $checkPassword);
			if($ldapbind) return true;

			return false;
		}

		error_log($user->username.': no LDAP logon server found for identifier '.$serverIdentifier);
		return false;
	}

}
