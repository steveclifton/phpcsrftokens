<?php

namespace steveclifton\phpcsrftokens;

class Csrf
{

	/**
	 * Generates a new token
	 * @return [object]   token
	 */
	protected static function setNewToken(string $page, int $expiry) {

		$token = new \stdClass();
		$token->page   = $page;
		$token->expiry = time() + $expiry;
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

		return !empty($_SESSION['csrftokens'][$page]) ? $_SESSION['csrftokens'][$page] : null;
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

		if (!isset($_SESSION)) {
			trigger_error('Session has not been started.', E_USER_ERROR);
			return false;
		}

		return true;
	}

	/**
	 * Returns a page's token.
	 * - Page name is required so that users can browse to multiple pages and allows for each
	 *   page to have its own unique token
	 *
	 * @param  [string]   page name
	 * @param  [int]      expiry time
	 * @return [mixed]    markup to be used in the form, false on data missing
	 */
	public static function getInputToken(string $page, int $expiry = 1800) {

		self::confirmSessionStarted();

		if (empty($page)) {
			trigger_error('Page is missing.', E_USER_ERROR);
			return false;
		}

		$token = (self::getSessionToken($page) ?? self::setNewToken($page, $expiry));

		return '<input type="hidden" id="csrftoken" name="csrftoken" value="'. $token->sessiontoken .'">';
	}


	/**
	 * Verify's a request token against a session token
	 * @param  [string]    page name
	 * @param  [string]    token from the request
	 * @return [bool]      whether the request submission is valid or not
	 */
	public static function verifyToken(string $page, $removeToken = false, $requestToken = null) : bool {

		self::confirmSessionStarted();

		// if the request token has not been passed, check POST
		$requestToken = ($requestToken ?? $_POST['csrftoken'] ?? null);

		if (empty($page)) {
			trigger_error('Page alias is missing', E_USER_WARNING);
			return false;
		}
		else if (empty($requestToken)) {
			trigger_error('Token is missing', E_USER_WARNING);
			return false;
		}

		$token = self::getSessionToken($page);

		// if the time is greater than the expiry form submission window
		if (empty($token) || time() > (int) $token->expiry) {
			self::removeToken($page);
			return false;
		}

		// check the hash matches the Session / Cookie
		$sessionConfirm = hash_equals($token->sessiontoken, $requestToken);
		$cookieConfirm  = hash_equals($token->cookietoken, self::getCookieToken($page));

		// remove the token
		if ($removeToken) {
			self::removeToken($page);
		}

		// both session and cookie match
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
	public static function removeToken(string $page) : bool {

		self::confirmSessionStarted();

		if (empty($page)) {
			return false;
		}

		unset($_COOKIE[self::makeCookieName($page)], $_SESSION['csrftokens'][$page]);

		return true;
	}



} // Csrf