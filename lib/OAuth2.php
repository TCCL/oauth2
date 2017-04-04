<?php

/**
 * OAuth2.php
 *
 * This file is a part of tccl/oauth2.
 */

namespace TCCL\OAuth2;

use Exception;

/**
 * OAuth2 provides a base class that represents the OAuth2 client-side state. It
 * is used to implement the specific authorization grants.
 */
abstract class OAuth2 {
    /**
     * Defines the string used to key the access token cache.
     */
    const OAUTH_CACHE_KEY_PREFIX = 'oauth2/oauth2_client';

    /**
     * A unique identifier for this oauth instance.
     *
     * @var string
     */
    private $id;

    /**
     * Parameters provided by user to this object:
     *  - client_id
     *      The registered client id.
     *  - client_secret
     *      The registered client secret.
     *  - token_endpoint
     *      The remote OAuth2 token resource identifier.
     *  - auth_endpoint
     *      The remote OAuth2 authorization resource identifier.
     *  - redirect_uri
     *      The redirect_uri to use for the authorization_code workflow; the
     *      user specifies this so that the uri can be hardcoded when used in
     *      this library.
     *  - scope
     *      A user-defined scope identifier value.
     *  - token_cache_callback
     *      A function that handles caching an access token. If called with 1
     *      parameter, then it looks up an access token by id. If called with 2
     *      parameters, then it stores an access token by key. The key is
     *      structured in the format:
     *        "level1/level2/.../levelN/id"
     *      If the key is not found then the function should return either
     *      'false' or an empty array.
     *
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
     * Response fields for access token data from remote server.
     *
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
     * Reference counter for closing inet connections.
     *
     * @var integer
     */
    static private $ref = 1;

    /**
     * Construct a new OAuth session; derived classes should forward their
     * constructor arguments to this base class constructor.
     *
     * @param string $url
     *  The full url of the token resource server
     * @param array  $params
     *  OAuth parameters
     */
    function __construct($url,array $params = array()) {
        // Unionize user params with existing params (the user should specify
        // most of them).
        $this->params = $params + $this->params;

        // Assign user-specified url as token_endpoint property.
        $this->params['token_endpoint'] = $url;

        // Generate unique id for this instance.
        $this->id = md5($this->params['token_endpoint']
                        . $this->params['client_id']
                        . $this->getFlowId());

        // Attempt to load the access token from cache.
        $tok = $this->cacheItemRetrieve('token');
        if (!empty($tok)) {
            $this->token = $tok;
        }

        // Up reference counter for new potential connector.
        self::$ref += 1;
    }

    /**
     * When an instance is garbage-collected, we want to close any cached
     * connections used by the instance. We use a reference counter to ensure
     * the last instance closes any connections (so we limit the number of
     * reconnections but not necessarily new connections).
     */
    function __destruct() {
        self::$ref -= 1;
        if (self::$ref <= 0) {
            HTTPRequest::closeCachedConnections();
            self::$ref = 0;
        }
    }

    /**
     * Get the string access token representation.
     *
     * @return string
     *  The access token component (i.e. its ID)
     */
    function getAccessToken() {
        // Do the hard work...
        $this->getAccessTokenImpl();

        // Return the actual access token as string.
        return $this->token['access_token'];
    }

    /**
     * Get the full access token information.
     *
     * @return array
     *  The full access token information
     */
    function getAccessTokenFull() {
        // Do the hard work...
        $this->getAccessTokenImpl();

        // Return the token information in full.
        return $this->token;
    }

    /**
     * Request an access token from the remote server. This is an implementation
     * function to be called by interface functions.
     */
    private function getAccessTokenImpl() {
        // Use the current token if it hasn't yet expired.
        $t = time() + 10;
        if ($this->token['expiration_time'] > $t) {
            // We already have a current token.
            return;
        }

        // Otherwise attempt to use the refresh token.
        try {
            $this->token = $this->getTokenRefresh();
        }
        catch (Exception $e) {
            // Else try to get a new token using the derived class's
            // implementation.
            $this->token = $this->getTokenNew($this->params);
        }

        // Update the cache to remember the access token.
        $this->cacheItemStore('token',$this->token);
    }

    /**
     * Preform a generic API call. Alternatively users can use the 'http'
     * library directly to make api calls and configure the access token
     * themselves.
     *
     * @param string $url
     *  The request url
     * @param string $method
     *  The request method to specify
     * @param array $params
     *  Any extra HTTP request parameters; see HTTPRequest::__construct in
     *  http.php.inc for more details.
     *
     * @return object
     *  The HTTP response encoded as a PHP object. Check the 'data' member for
     *  the response payload.
     */
    function apiCall($url,$method,array $params = array()) {
        // Always attempt to get and set $this->token with a new access
        // token. If we already have one, then the getAccessTokenImpl()
        // functionality will simply assign the cached token.
        $this->getAccessTokenImpl();

        // Handle the API call based on token type.
        if (strtolower($this->token['token_type']) == 'bearer') {
            // Include the authorization header and other needed request
            // parameters.
            $data = array(
                'headers' => array(
                    'Authorization' => "Bearer {$this->token['access_token']}"
                ) + (isset($params['headers']) ? $params['headers'] : array()),
                'request_method' => $method
            ) + $params;

            // Make an HTTP request to perform the API call.
            $request = new HTTPRequest($url,$data);
            return $request->makeRequest();
        }

        // Token type is incorrect or not supported at this time.
        throw new OAuth2Exception(
            __METHOD__
            . ": cannot understand token_type={$this->token['token_type']} field",
            OAuth2Exception::OAUTH_EXCEPTION_INVALID_OPERATION);
    }

    /**
     * Dervied classes implement this to specify which grant type they
     * implement.
     *
     * @return string
     *  The string identifying the grant type (e.g. 'client_credentials')
     */
    abstract function getFlowId();

    /**
     * Return one of the OAuth parameters for this session.
     *
     * @param string $key
     *  The key name of the desired parameter
     *
     * @return mixed
     *  The parameter value
     */
    final protected function getOAuthParam($key) {
        if (!array_key_exists($key,$this->params))
            return false;
        return $this->params[$key];
    }

    /**
     * Get the unique key that can be used when caching values in a database
     * or session table
     *
     * @return string
     */
    final protected function getSessionKey() {
        return 'oauth2_client/' . $this->id;
    }

    /**
     * Gets a cached variable using the user-defined cache function.
     *
     * @param string $key
     *  The key that identifies the cached variable.
     *
     * @return mixed
     *  The cached variable
     */
    final protected function cacheItemRetrieve($key) {
        $tok = call_user_func(
            $this->params['token_cache_callback'],
            self::OAUTH_CACHE_KEY_PREFIX."/$this->id/$key");
        return $tok;
    }

    /**
     * Cache a variable using the user-defined cache function. Every attempt is
     * made to make sure the key is unique while ensuring the key remains a
     * scalar.
     *
     * @param string $key
     *  The key used to identify the cached resource
     * @param mixed $value
     *  The value to place into the cache
     */
    final protected function cacheItemStore($key,$value) {
        call_user_func($this->params['token_cache_callback'],
            self::OAUTH_CACHE_KEY_PREFIX."/$this->id/$key",$value);
    }

    /**
     * This function implements the generic request procedure for an access token
     *
     * @param array $data
     *  The data payload to include in the request
     *
     * @return array
     *  The requested token structure
     */
    final protected function requestToken(array $data) {
        // Produce the authorization string. We only support using the HTTP
        // basic authentication scheme and WILL NOT send the client credentials
        // in the request body.
        $auth = base64_encode("{$this->params['client_id']}:{$this->params['client_secret']}");

        // Set parameters for the http request.
        $httpParams = array(
            'request_method' => HTTPRequest::HTTP_POST,
            'data' => $data + array(
                'grant_type' => $this->getFlowId(),
                'scope' => $this->params['scope']
            ),
            'headers' => array(
                'Content-type' => 'application/x-www-form-urlencoded',
                'Authorization' => "Basic $auth"
            ),
        );

        // Make the http request and return the response as a PHP array
        // (decoded) from JSON.
        try {
            $request = new HTTPRequest($this->params['token_endpoint'],$httpParams);
            $response = $request->makeRequest();
        } catch (Exception $e) {
            throw new OAuth2Exception(
                $e->getMessage(),
                OAuth2Exception::OAUTH_EXCEPTION_BAD_REQUEST);
        }
        if ($response->statusCode != 200) {
            $errorData = json_decode($response->data);
            throw new OAuth2Exception(
                __METHOD__.": remote server did not grant access token: "
                  . "got $response->statusCode: $errorData->description",
                OAuth2Exception::OAUTH_EXCEPTION_FAILED_REQUEST);
        }

        // Decode the response payload as a PHP array.
        $tok = json_decode($response->data,true);

        // Calculate the token's expiration time.
        $tok['expiration_time'] = $_SERVER['REQUEST_TIME'] + $tok['expires_in'];

        return $tok;
    }

    /**
     * Derived classes should implement this method to request a new access
     * token in some implementation-specific way. The implementation should
     * always call getToken() at some point to perform the actual request.
     *
     * @param array $params
     *  An associative array containing the oauth2 parameters.
     *
     * @return array
     *  The access token structure
     */
    abstract protected function getTokenNew(array $params);

    /**
     * Gets a new access token based on the current refresh token.
     *
     * @return array
     *  The refreshed access token structure
     */
    private function getTokenRefresh() {
        if (!array_key_exists('refresh_token',$this->token)
            || empty($this->token['refresh_token']))
        {
            throw new Exception(__METHOD__.": access refresh token was not specified");
        }

        // TODO: implement refresh token functionality...
    }

    /**
     * The default cache handler that employs user session to record tokens.
     *
     * @param string $key
     *  The key that identifies the cached resource
     * @param mixed $value
     *  The value to store into the cache (optional)
     *
     * @return mixed
     *  Returns the cache value if no value was given
     */
    private static function defaultCacheHandler(/* $key, [$value] */) {
        // By default we will store the value in the user session.
        list($key,$value) = func_get_args() + array('','');

        // Testing environments don't have session set necessarily; in this case
        // we do nothing and the cache fails.
        if (!isset($_SESSION)) {
            return false;
        }

        // Lookup and return the cached value if no store value was specified.
        if (empty($value)) {
            if (!array_key_exists($key,$_SESSION))
                return false;
            return $_SESSION[$key];
        }

        // Otherwise just assign the value to the session.
        $_SESSION[$key] = $value;
        return $value;
    }
}
