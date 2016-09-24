<?php

require_once('AbstractAuthProvider.php');

class GoogleAuthProvider extends AbstractAuthProvider {

	public function __construct() {
		parent::__construct('OAuth2');

		$this->key = Configure::read('ExtAuth.Provider.Google.key');
		$this->secret = Configure::read('ExtAuth.Provider.Google.secret');

		$this->AuthDialogURL = 'https://accounts.google.com/o/oauth2/auth';
		$this->AuthDialogParameters = array(
			'client_id'     => $this->key,
			'response_type' => 'code',
			'scope'         => 'email',
			'redirect_uri'  => '{CALLBACK_URL}',
			'display'		=> 'popup'
			//'state'         => '{STATE}',
		);

		$this->accessTokenURL = 'https://accounts.google.com/o/oauth2/token';
		$this->accessTokenParameters = array(
			'client_id'     => $this->key,
			'client_secret' => $this->secret,
			'redirect_uri'  => '{CALLBACK_URL}',
			'grant_type'    => 'authorization_code'
		);

		$this->profileURL = 'https://www.googleapis.com/oauth2/v1/userinfo';
		$this->profileParameters = array('alt' => 'json');
	}

	public function getAccessTokenParameters($params = null) {
		$parameters = parent::getAccessTokenParameters($params);
		$parameters['code'] = $_GET['code'];
		return $parameters;
	}

	public function normalizeProfile($raw_profile) {
		$profile = json_decode($raw_profile, TRUE);


		// mapped items
		$map = array(
			// ExtAuth => FB
			'oid'      => 'id',
			'birthday'  => 'dob',
			'email'			=> 'email',
		);

		// do mapping
		foreach($map as $source => $dest) {
			if (isset($profile[$dest]) && !isset($profile[$source]) ) {
				$profile[$source] = $profile[$dest];
			}
		}

		$profile['raw'] = $raw_profile;
		$profile['provider'] = OAUTH_PROVIDER_GOOGLE;
		unset($profile['id']);
		return array(
			'success'   => true,
			'data'      => $profile
		);
	}
}
