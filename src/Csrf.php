<?php

namespace SteveClifton;

class Csrf
{

	public function __construct()
	{

	}

	const EXPIRY = 1800;


	/**
	 * Generates a new token
	 * @return [string]   page name
	 */
	private static function getNewToken($page) {

		$token = new stdClass();
		$token->page = $page;
		$token->expiry = time() + self::EXPIRY; // 30 minutes
		$token->value  = base64_encode(random_bytes(32)); // create random token

		return $_SESSION['csrftokens'][$page] = $token;
	}


	/**
	 * Returns a token for a page
	 * @param  [string]   page name
	 * @return [string]   token
	 */
	private static function getToken($page) {

		$token = !empty($_SESSION['csrftokens'][$page]) ? $_SESSION['csrftokens'][$page] : null;

		// make sure the time is set, and is within the window
		if (empty($token->expiry) || time() > $token->expiry) {
			return self::getNewToken($page);
		}

		return $token;

	}


	/**
	 * Returns a page's token
	 * @param  [string]   page name
	 * @return [string]   markup to be used in the form
	 */
	public static function getInputToken($page) {


		if (empty($page)) {
			trigger_error('Page is missing', E_USER_ERROR);
			return false;
		}

		$token = self::getToken($page);

		return '<input type="hidden" id="csrftoken" name="token" value="'. $token->value .'">';
	}


	/**
	 * Verify's a request token against a session token
	 * @param  [string]    page name
	 * @param  [string]    token from the request
	 * @return [bool]      whether the request submission is valid or not
	 */
	public static function verifyToken($page, $requestToken, $removeToken = false) : bool {

		$requestToken = $requestToken ?? $_POST['csrftoken'] ?? null;

		if (empty($page) || empty($requestToken)) {
			trigger_error('Page alias is missing', E_USER_WARNING);
			return false;
		}

		$token = self::getToken($page);

		// if the time is greater than the 30 minute form submission window
		if (time() > (int) $token->expiry) {
			return false;
		}

		// check the hash matches
		if (hash_equals($token->value, $requestToken)) {

			if ($removeToken) {
				self::removeToken($page);
			}
			return true;
		}

		return false;
	}

	/**
	 * Removes a token from the session
	 * @param  [string] $page    page name
	 * @return [bool]            successfully removed or not
	 */
	public static function removeToken($page) {

		if (empty($page)) {
			return false;
		}

		unset($_SESSION['csrftokens'][$page]);
		return true;
	}



} // csrf