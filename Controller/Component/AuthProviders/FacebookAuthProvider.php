	<?php

require_once('AbstractAuthProvider.php');

class FacebookAuthProvider extends AbstractAuthProvider {

	public function __construct() {
		parent::__construct('OAuth2');

		$this->key = Configure::read('ExtAuth.Provider.Facebook.key');
		$this->secret = Configure::read('ExtAuth.Provider.Facebook.secret');

		$this->AuthDialogURL            = 'https://www.facebook.com/dialog/oauth/';
		$this->AuthDialogParameters = array(
			'client_id'         => $this->key,
			'redirect_uri'      => '{CALLBACK_URL}',
			'scope'        		=> 'email',
			//'state'           => '{STATE}',
		);

		$this->accessTokenURL           = 'https://graph.facebook.com/oauth/access_token';
		$this->accessTokenRequestMethod = 'GET';
		$this->accessTokenParameters = array(
			'client_id'     => $this->key,
			'client_secret' => $this->secret,
			'redirect_uri'  => '{CALLBACK_URL}',
		);

		$this->profileURL = 'https://graph.facebook.com/me';
	}

	public function getAccessTokenParameters($params = null) {
		$parameters = parent::getAccessTokenParameters($params);
		if (isset($_GET['code'])) $parameters['code'] = $_GET['code'];
		return $parameters;
	}

	public function normalizeProfile($raw_profile) {
		$profile = json_decode($raw_profile, TRUE);
		// mapped items
		$map = array(
			// ExtAuth => FB
			'email'			=> 'email',
			'given_name'        => 'first_name',
			'family_name'         => 'last_name',
			//	'link'              => 'oid',
			'oid'				=> 'id'
		);

		// do mapping
		foreach($map as $source => $dest) {
			if (isset($profile[$dest]) && !isset($profile[$source]) ) {
				$profile[$source] = $profile[$dest];
			}
		}
		// special cases
		$profile['picture'] = str_replace('www.facebook.com', 'graph.facebook.com', $profile['link']) . '/picture?type=large';
		$profile['raw'] = $raw_profile;
		$profile['provider'] = OAUTH_PROVIDER_FACEBOOK;
		unset($profile['id']);
		return array(
			'success'   => true,
			'data'      => $profile
		);
	}
}
