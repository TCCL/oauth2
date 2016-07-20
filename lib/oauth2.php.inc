<?php

/**
 * This file contains functionality to perform OAuth2 operations. It uses the
 * PHP-builtin socket stream functionality to communicate with a foreign API.
 *
 * @package oauth2
 */

require_once("http.php.inc");

/**
 * Define a specialized exception type to support exceptions that we want users
 * to potentially handle
 */
class OAuth2Exception extends Exception {
    function __construct() {
        // forward arguments to base class constructor
        call_user_func_array("parent::__construct",func_get_args());
    }
}

/**
 * Enumerate exceptions that occur in this library that we want users to
 * potentially handle
 */
define('OAUTH_EXCEPTION_BAD_REQUEST',101);
define('OAUTH_EXCEPTION_FAILED_REQUEST',102);
define('OAUTH_EXCEPTION_INVALID_OPERATION',103);
define('OAUTH_EXCEPTION_BAD_RESPONSE',104);

/**
 * Defines the string used to key the access token cache
 */
define('OAUTH_CACHE_KEY_PREFIX','oauth2/oauth2_client');

abstract class OAuth2 {
    /**
     * Unique identifier for this oauth instance
     * @var string
     */
    private $id;

    /**
     * Parameters provided by user to this object
     *  - client_id :: registered client id
     *  - client_secret :: registered client secret
     *  - token_endpoint :: the remote OAuth2 token resource identifier
     *  - auth_endpoint :: the remote OAuth2 authorization resource identifier
     *  - redirect_uri :: the redirect_uri to use for the authorization_code
     *  workflow; the user specifies this so that the uri can be hardcoded when
     *  used in this library
     *  - scope :: a user-defined scope identifier value
     *  - token_cache_callback :: a function that handles caching an access token;
     *  if called with 1 parameter, then it looks up an access token by id; if
     *  called with 2 parameters, then it stores an access token by key; the key
     *  is structured in the format: "level1/level2/.../levelN/id"; if the key is
     *  not found then the function should return either 'false' or an empty array
     * @var array
     */
    private $params = array(
        'client_id' => null,
        'client_secret' => null,
        'token_endpoint' => null,
        'auth_endpoint' => null,
        'redirect_uri' => null,
        'scope' => null,
        'token_cache_callback' => 'self::defaultCacheHandler'
    );

    /**
     * Response fields for access token data from remote server
     * @var array
     */
    private $token = array(
        'access_token' => null,
        'expires_in' => null,
        'token_type' => null,
        'scope' => null,
        'refresh_token' => null,
        'expiration_time' => null
    );

    /**
     * Construct a new OAuth session; derived classes should forward their
     * constructor arguments to this base class constructor
     * @param string $url    The full url of the token resource server
     * @param array $params OAuth parameters
     */
    function __construct($url,array $params = array()) {
        // unionize user params with existing params (the user should specify
        // most of them)
        $this->params = $params + $this->params;

        // assign user-specified url as token_endpoint property
        $this->params['token_endpoint'] = $url;

        // generate unique id for this instance
        $this->id = md5($this->params['token_endpoint']
                    . $this->params['client_id']
                    . $this->getFlowId());

        // attempt to load the access token from cache
        $tok = $this->cacheItemRetrieve('token');
        if (!empty($tok)) {
            $this->token = $tok;
        }
    }

    /**
     * Get the string access token representation
     * @return string   access token
     */
    function getAccessToken() {
        // do the hard work...
        $this->getAccessTokenImpl();

        // return the actual access token string
        return $this->token['access_token'];
    }

    /**
     * Get the full access token information
     * @return array    the full access token information
     */
    function getAccessTokenFull() {
        // do the hard work
        $this->getAccessTokenImpl();

        // return the token information in full
        return $this->token;
    }

    /**
     * Request an access token from the remote server; this is an implementation
     * function to be called by interface functions
     */
    private function getAccessTokenImpl() {
        // use the current token if it hasn't yet expired
        $t = time() + 10;
        if ($this->token['expiration_time'] > $t) {
            return; // we already have a current token
        }

        // otherwise attempt to use the refresh token
        try {
            $this->token = $this->getTokenRefresh();
        }
        catch (Exception $e) {
            // else try to get a new token using the derived class's
            // implementation
            $this->token = $this->getTokenNew($this->params);
        }

        // update the cache to remember the access token
        $this->cacheItemStore('token',$this->token);
    }

    /**
     * Preform a generic API call; alternatively users can use the 'http' library
     * directly to make api calls
     * @param  string $url      request url
     * @param  string $method   the request method to specify
     * @param  array  $params   query string parameters
     * @return object           The response encoded as a PHP object
     */
    function apiCall($url,$method,array $params = array()) {
        // always attempt to get an access token; if we already have one, then
        // the getAccessTokenImpl() will simply return the cached token
        $this->getAccessTokenImpl();

        // handle the API call based on token type
        if (strtolower($this->token['token_type']) == 'bearer') {
            // include the authorization header and other needed request parameters
            $data = array(
                'headers' => array(
                    'Authorization' => "Bearer {$this->token['access_token']}"
                ),
                'request_method' => $method,
                'query' => $params
            );

            // make an HTTP request to perform the API call
            $request = new HTTPRequest($url,$data);
            return $request->makeRequest();
        }

        // token type is not supported at this time
        throw new OAuth2Exception(__FUNCTION__
            . ": cannot understand token_type={$this->token['token_type']} field",
            OAUTH_EXCEPTION_INVALID_OPERATION);
    }

    /**
     * Dervied classes implement this to specify which grant type they implement
     * @return string       the flow identifier string (e.g. 'client_credentials')
     */
    abstract function getFlowId();

    /**
     * Return one of the OAuth parameters for this session.
     * @param  string $key The key name of the desired parameter
     * @return variant  The parameter value
     */
    final protected function getOAuthParam($key) {
        if (!array_key_exists($key,$this->params))
            return false;
        return $this->params[$key];
    }

    final protected function getSessionKey() {
        return 'oauth2_client/' . $this->id;
    }

    /**
     * Gets a cached variable using the user-defined cache function
     * @param  scalar $key the key that identifies the cached variable
     * @return variant      the cached variable
     */
    final protected function cacheItemRetrieve($key) {
        $tok = call_user_func($this->params['token_cache_callback'],
                OAUTH_CACHE_KEY_PREFIX."/$this->id/$key");
        return $tok;
    }

    /**
     * Cache a variable using the user-defined cache function; every attempt is
     * made to make sure the key is unique while ensuring the key is a scalar
     * @param  scalar $key   the key to use when caching
     * @param  variant $value the value to cache
     */
    final protected function cacheItemStore($key,$value) {
        call_user_func($this->params['token_cache_callback'],
            OAUTH_CACHE_KEY_PREFIX."/$this->id/$key",$value);
    }

    /**
     * This function implements the generic request procedure for an access token
     * @param array $data   the data payload to include in the request
     * @return array        the requested token structure
     */
    final protected function requestToken(array $data) {
        // produce the authorization string; we only support using the HTTP
        // basic authentication scheme and WILL NOT send the client credentials
        // in the request body
        $auth = base64_encode("{$this->params['client_id']}:{$this->params['client_secret']}");

        // set parameters for the http request
        $httpParams = array(
            'request_method' => HTTP_POST,
            'data' => $data + array(
                'grant_type' => $this->getFlowId(),
                'scope' => $this->params['scope']
            ),
            'headers' => array(
                'Connection' => 'close',
                'Content-type' => 'application/x-www-form-urlencoded',
                'Authorization' => "Basic $auth"
            ),
        );

        // make the http request and return the response as a PHP array (decoded)
        // from JSON
        try {
            $request = new HTTPRequest($this->params['token_endpoint'],$httpParams);
            $response = $request->makeRequest();
        } catch (Exception $e) {
            throw new OAuth2Exception($e->getMessage(),OAUTH_EXCEPTION_BAD_REQUEST);
        }
        if ($response->statusCode != 200) {
            throw new OAuth2Exception(__FUNCTION__.": remote server did not grant access token: "
                                . "got $response->statusCode: $response->error",
                                OAUTH_EXCEPTION_FAILED_REQUEST);
        }

        // decode the response payload as a PHP array
        $tok = json_decode($response->data,true);

        // calculate the token's expiration time
        $tok['expiration_time'] = $_SERVER['REQUEST_TIME'] + $tok['expires_in'];

        return $tok;
    }

    /**
     * Derived classes should implement this method to request a new access token
     * in some implementation-specific way; the implementation should always call
     * getToken() at some point to perform the actual request
     * @param array $params         the oauth2 parameters
     * @return array    the access token structure
     */
    abstract protected function getTokenNew(array $params);

    /**
     * Gets a new access token based on the current refresh token
     */
    private function getTokenRefresh() {
        if (!array_key_exists('refresh_token',$this->token) || empty($this->token['refresh_token'])) {
            throw new Exception(__FUNCTION__.": access refresh token was not specified");
        }


    }

    /**
     * The default cache handler that uses the user session to record tokens
     * @return string       returns the access token if only 1 argument was
     * passed to the function
     */
    private static function defaultCacheHandler() {
        // by default we will store the access token in the user session
        list($key,$tok) = func_get_args() + array('','');

        // testing environments don't have session set necessarily
        if (!isset($_SESSION))
            return false;

        // lookup and return the access token
        if (empty($tok)) {
            if (!array_key_exists($key,$_SESSION))
                return false;
            return $_SESSION[$key];
        }

        // otherwise just assign the token to the session
        $_SESSION[$key] = $tok;
    }
}

/**
 * An OAuth2 type that handles the 'client_credentials' authorization flow
 * (i.e. grant type)
 */
class OAuth2ClientCredentials extends OAuth2 {
    /**
     * Construct a new OAuth2 object that handles the 'client_credentials' flow
     */
    function __construct() {
        // forward arguments to parent constructor
        call_user_func_array('parent::__construct',func_get_args());
    }

    /**
     * Returns the flow-id for this derivation
     */
    final function getFlowId() {
        return 'client_credentials';
    }

    /**
     * Implements 'getTokenNew' to request an access token from the remote server
     * using the 'client_credentials' authorization flow
     * @param array $params         the oauth2 parameters
     * @return array                the access token
     */
    protected function getTokenNew(array $params) {
        // this is really simple: just do a request
        return $this->requestToken(array());
    }
}

/**
 * An OAuth2 type that handles the 'authorization_code' authorization flow
 */
class OAuth2AuthorizationCode extends OAuth2 {
    /**
     * Construct a new OAuth2 object that handles the 'authorization_code' flow
     */
    function __construct($url,$authUrl,array $params) {
        if (!array_key_exists('redirect_uri',$params)) {
            throw new Exception(__FUNCTION__.": expected a redirect_uri parameter");
        }

        // save auth_endpoint parameter
        $params['auth_endpoint'] = $authUrl;

        // check for testing hostname; we'll use this as a substitute for a
        // local hostname that a remote server might refuse
        if (array_key_exists('test_host',$params)) {
            $replace = @preg_replace("/^(https?:\/\/)(?:[a-zA-Z0-9_\-]+(?:\.(?:[a-zA-Z0-9_\-]+))*)(\/.*)$/",
                        "$1{$params['test_host']}$2",$params['redirect_uri']);
            if (is_string($replace))
                $params['redirect_uri'] = $replace;
            unset($params['test_host']);
        }

        // forward arguments to parent constructor
        parent::__construct($url,$params);
    }

    /**
     * Returns the flow-id for this derivation
     */
    final function getFlowId() {
        return 'authorization_code';
    }

    /**
     * Implements 'getTokenNew' to request an access token from the remote server
     * using the 'authorization_code' authorization flow; this flow works in three
     * steps:
     * 		1. request an authorization code from authorization endpoint
     * 		2. receive the authorization code (or error if client failed auth.)
     * 		3. request an access token (and cache it), then redirect back to the
     * 		    original page
     * @param array $params         the oauth2 parameters
     * @return array                the access token
     */
    protected function getTokenNew(array $params) {
        $key = $this->getSessionKey();

        // if $_GET[code] is defined then we have (nearly) completed the
        // three-step flow
        if (isset($_GET['code'])) {
            // lookup the redirect_uri and state from the user session
            if (!array_key_exists('state',$_REQUEST)) {
                throw new OAuth2Exception(__FUNCTION__.": no state parameter",
                    OAUTH_EXCEPTION_BAD_RESPONSE);
            }
            $state = $_REQUEST['state'];
            if (!isset($_SESSION[$key]['redirect'][$state])
                || !isset($_SESSION[$key]['redirect']['state'])
                || $_SESSION[$key]['redirect']['state'] != $state)
            {
                throw new OAuth2Exception(__FUNCTION__.": invalid state parameter",
                    OAUTH_EXCEPTION_BAD_RESPONSE);
            }
            $uri = $_SESSION[$key]['redirect'][$state];
            unset($_SESSION[$key]['redirect']);

            // prepare the data parameters we will include in the POST request
            // for the access token; these are combined with the default values
            // that 'requestToken()' already handles
            $data = array(
                'code' => $_GET['code'],
                'redirect_uri' => $uri,
            );

            // request the access token
            $tok = $this->requestToken($data);

            // since the redirect will terminate the script, we must save the token
            // to the cache before the script terminates
            $this->cacheItemStore('token',$tok);

            // redirect back to the original url to complete the flow; this will
            // lookup the redirect uri from the current user session; we do this
            // so that we remove any query parameters that were introduced by the
            // remote server
            if (!array_key_exists('state',$_REQUEST)) {
                // the server should have returned the state parameter back to
                // us; we throw an exception in this case since we didn't get
                // the required parameter back
                throw new OAuth2Exception(__FUNCTION__.": server did not send back 'state'",
                    OAUTH_EXCEPTION_BAD_RESPONSE);
            }
            $this->redirect($uri);
            // (control no longer in this script)
        }
        // otherwise we start from the beginning of the flow

        // generate a random state id for maintaining state between us and the
        // authorization server; this is an opaque value
        $state = md5(uniqid(rand(),true));

        // obtain redirect_uri parameter for remote server
        $uri = $params['redirect_uri'];

        // generate the uri to which we will redirect the user-agent
        $queryParams = array(
            'response_type' => 'code',
            'client_id' => $params['client_id'],
            'redirect_uri' => $uri,
            'state' => $state
        );
        if (!empty($params['scope'])) {
            $queryParams['scope'] = $params['scope'];
        }
        $authUri = $params['auth_endpoint'] . '?' . http_build_query($queryParams);

        // save the redirect uri in the session alongside the state parameter;
        // this uri will be the original uri that we want to return to later on
        if (isset($_SESSION[$key]['redirect'])) {
            unset($_SESSION[$key]['redirect']);
        }
        $_SESSION[$key]['redirect']['state'] = $state;
        $_SESSION[$key]['redirect'][$state] = $uri;

        // redirect the user to the authorization endpoint; this will terminate
        // the script
        $this->redirect($authUri);
        // (control no longer in this script)
    }

    /**
     * Derived classes may override this to do a redirect in some application-specific
     * way; by default we simply insert a 'Location' header into the response
     * @param  string $uri      the redirect uri
     */
    protected function redirect($uri) {
        header("Location: $uri");
        exit;
    }
}

/**
 * Provides an authorization_code grant type flow that employs Drupal functions
 * for redirection and redirect_uri configuration
 */
class OAuth2AuthorizationCode_Drupal extends OAuth2AuthorizationCode {
    function __construct($url,$authUrl,array $params) {
        $redirectUri = drupal_get_destination()['destination'];
        $redirectUri = url($redirectUri,array('query'=>$_REQUEST,'absolute'=>true));

        parent::__construct($url,$authUrl,$params + array('redirect_uri'=>$redirectUri));
    }

    protected function redirect($uri) {
        // note: this will call drupal_exit() which will use the 'exit' construct
        // to stop the script
        drupal_goto($uri);
    }
}
