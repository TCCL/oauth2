<?php

/**
 * This file contains functionality to perform OAuth2 operations. It uses the
 * PHP-builtin socket stream functionality to communicate with a foreign API.
 *
 * @package oauth2
 */

require_once("http.php.inc");

/**
 * Enumerate exceptions that occur in this library
 */
define('OAUTH_EXCEPTION_BAD_REQUEST',101);
define('OAUTH_EXCEPTION_FAILED_REQUEST',102);

/**
 * Defines the string used to key the access token cache
 */
define('OAUTH_CACHE_KEY','oauth2/oauth2_client');

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
     *  - token_endpoint :: the remote OAuth2 server
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
     * Construct a new OAuth session; derivce classes should forward their constructor
     * arguments to this base class constructor
     * @param string $url    The full url of the resource server
     * @param array $params OAuth parameters
     */
    function __construct($url,$params = null) {
        // unionize user params with existing params (the user should specify
        // most of them)
        if (!is_null($params)) {
            $this->params = $params + $this->params;
        }

        // assign user-specified url as token_endpoint property
        $this->params['token_endpoint'] = $url;

        // generate unique id for this instance
        $this->id = md5($this->params['token_endpoint']
                    . $this->params['client_id']);

        // attempt to load the access token from cache
        $tok = call_user_func($this->params['token_cache_callback'],
                OAUTH_CACHE_KEY."/".$this->id);
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
            // parameters
            $this->token = $this->getTokenNew($this->getTokenRequestParams());
        }

        // calculate the token's expiration time
        $this->token['expiration_time'] = $_SERVER['REQUEST_TIME'] + $this->token['expires_in'];

        // update the cache to remember the access token
        call_user_func($this->params['token_cache_callback'],
            OAUTH_CACHE_KEY."/".$this->id,$this->token);
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
        // if we don't already have an access token, then attempt to get one
        if (is_null($this->token['access_token'])) {
            $this->getAccessTokenImpl();
        }

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
        throw new Exception(__FUNCTION__.": cannot understand token_type field");
    }

    /**
     * Return one of the OAuth parameters for this session.
     * @param  string $key The key name of the desired parameter
     * @return variant  The parameter value
     */
    protected function getOAuthParam($key) {
        if (!array_key_exists($key,$this->params))
            return false;
        return $this->params[$key];
    }

    /**
     * Derived classes should implement this method and return the parameters
     * required for their specific auth. flow kind (i.e. grant type).
     * @return [type] [description]
     */
    abstract protected function getTokenRequestParams();

    /**
     * Gets a new access token based on the current refresh token
     * @return [type] [description]
     */
    private function getTokenRefresh() {
        if (!array_key_exists('refresh_token',$this->token) || empty($this->token['refresh_token'])) {
            throw new Exception(__FUNCTION__.": access refresh token was not specified");
        }


    }

    /**
     * Request an access token from the remote server using the 'client_id' and
     * 'client_secret' parameters
     * @param array $data the data parameters for the token request
     * @return array    the access token
     */
    private function getTokenNew(array $data) {
        // produce the authorization string; we only support using the HTTP
        // basic authentication scheme and WILL NOT send the client credentials
        // in the request body
        $auth = base64_encode("{$this->params['client_id']}:{$this->params['client_secret']}");

        // set parameters for the http request
        $httpParams = array(
            'request_method' => HTTP_POST,
            'data' => $data,
            'headers' => array(
                'Connection' => 'close',
                'Content-type' => 'application/x-www-form-urlencoded',
                'Authorization' => "Basic $auth"
            )
        );

        // make the http request and return the response as a PHP array (decoded)
        // from JSON
        try {
            $request = new HTTPRequest($this->params['token_endpoint'],$httpParams);
            $response = $request->makeRequest();
        } catch (Exception $e) {
            throw new Exception($e->getMessage(),OAUTH_EXCEPTION_BAD_REQUEST);
        }
        if ($response->statusCode != 200) {
            throw new Exception(__FUNCTION__.": remote server did not grant access token: "
                                . "got $response->statusCode",OAUTH_EXCEPTION_FAILED_REQUEST);
        }

        return (Array) json_decode($response->data);
    }

    /**
     * The default cache handler which uses the user session
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
    function __construct() {
        call_user_func_array('parent::__construct',func_get_args());
    }

    protected function getTokenRequestParams() {
        return array(
            'grant_type' => 'client_credentials',
            'scope' => $this->getOAuthParam('scope')
        );
    }
}
