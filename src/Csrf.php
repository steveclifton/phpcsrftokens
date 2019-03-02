<?php

namespace steveclifton\phpcsrftokens;

class Csrf
{

	const EXPIRY     = 1800; // 30 minutes
	const POST_NAME  = 'csrftoken';
	const HTTPS_ONLY = false;


	/**
	 * Generates a new token
	 * @return [object]   token
	 */
	protected static function setNewToken(string $page) {

		$token = new \stdClass();
		$token->page = $page;
		$token->expiry = time() + self::EXPIRY; // 30 minutes
		$token->sessiontoken  = base64_encode(random_bytes(32));
		$token->cookietoken   = md5(base64_encode(random_bytes(32)));

		setcookie(self::makeCookieName($page), $token->cookietoken, $token->expiry);

		return $_SESSION['csrftokens'][$page] = $token;
	}


	/**
	 * Returns a session token for a page
	 * @param  [string]   page name
	 * @return [object]   token
	 */
	protected static function getSessionToken(string $page) {

		$token = !empty($_SESSION['csrftokens'][$page]) ? $_SESSION['csrftokens'][$page] : null;

		// make sure the time is set, and is within the window
		if (empty($token->expiry) || time() > $token->expiry) {
			return self::setNewToken($page);
		}

		return $token;
	}


	/**
	 * [getCookieToken description]
	 * @param  [string]   page name
	 * @return [string]   token string / empty string
	 */
	protected static function getCookieToken(string $page) : string {
		$value = self::makeCookieName($page);

		return !empty($_COOKIE[$value]) ? $_COOKIE[$value] : '';
	}


	/**
	 * Centralised method to make the cookie name
	 * @param  [string]   page name
	 * @return [string]   cookie token name / empty string
	 */
	protected static function makeCookieName(string $page) : string {

		if (empty($page)) {
			return '';
		}

		return 'csrftoken-' . substr(md5($page), 0, 10);
	}

	/**
	 * Confirms that the superglobal $_SESSION exists
	 * @return [bool]  Whether the session exists or not
	 */
	protected static function confirmSessionStarted() : bool {
		if (empty($_SESSION)) {
			trigger_error('Session has not been started.', E_USER_ERROR);
			return false;
		}

		return true;
	}

	/**
	 * Confirms whether the request was made using HTTPS
	 * @return [bool]
	 */
	protected static function isHttps() : bool {

		return (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on');
	}

	/**
	 * Returns a page's token
	 * @param  [string]   page name
	 * @return [string]   markup to be used in the form
	 */
	public static function getInputToken(string $page) {

		self::confirmSessionStarted();

		if (empty($page)) {
			trigger_error('Page is missing.', E_USER_ERROR);
			return false;
		}

		$token = self::getSessionToken($page);

		return '<input type="hidden" id="csrftoken" name="'.self::POST_NAME.'" value="'. $token->sessiontoken .'">';
	}


	/**
	 * Verify's a request token against a session token
	 * @param  [string]    page name
	 * @param  [string]    token from the request
	 * @return [bool]      whether the request submission is valid or not
	 */
	public static function verifyToken(string $page, $removeToken = false, $requestToken = null) : bool {

		self::confirmSessionStarted();

		if (self::HTTPS_ONLY && empty(self::isHttps())) {
			return false;
		}

		// if the request token has not been passed, check POST
		$requestToken = $requestToken ?? $_POST[self::POST_NAME] ?? null;

		if (empty($page) || empty($requestToken)) {
			trigger_error('Page alias is missing', E_USER_WARNING);
			return false;
		}

		$token = self::getSessionToken($page);

		// if the time is greater than the expiry form submission window
		if (time() > (int) $token->expiry) {
			return false;
		}

		// check the hash matches the Session / Cookie
		$sessionConfirm = hash_equals($token->sessiontoken, $requestToken);
		$cookieConfirm  = hash_equals($token->cookietoken, self::getCookieToken($page));

		// remove the token
		if ($removeToken) {
			self::removeToken($page);
		}

		if ($sessionConfirm && $cookieConfirm) {
			return true;
		}

		return false;
	}


	/**
	 * Removes a token from the session
	 * @param  [string] $page    page name
	 * @return [bool]            successfully removed or not
	 */
	public static function removeToken(string $page) {

		self::confirmSessionStarted();

		if (empty($page)) {
			return false;
		}

		unset($_COOKIE[self::makeCookieName($page)], $_SESSION['csrftokens'][$page]);

		return true;
	}



} // Csrf