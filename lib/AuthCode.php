<?php

/**
 * AuthCode.php
 *
 * This file is a part of tccl/oauth2.
 */

namespace TCCL\OAuth2;

use Exception;

/**
 * An OAuth2 type that handles the 'authorization_code' grant type. This kind of
 * authorization flow involves redirecting the user-agent to the authorization
 * server. Following, the remote host redirects back to our host with the access
 * token.
 */
class AuthCode extends OAuth2 {
    /**
     * Construct a new OAuth2 object that handles the 'authorization_code' flow.
     *
     * @param string $url
     *  The remote token request endpoint
     * @param string $authUrl
     *  The remote authorization endpoint
     * @param array $params
     *  Additional protocol parameters (must include 'redirect_uri')
     */
    function __construct($url,$authUrl,array $params) {
        // Verify that the caller provided a redirection URI required by the
        // OAuth2 protocol.
        if (!array_key_exists('redirect_uri',$params)) {
            throw new Exception(__METHOD__.": expected a redirect_uri parameter");
        }

        // Save auth_endpoint parameter.
        $params['auth_endpoint'] = $authUrl;

        // Check for testing hostname. We'll use this as a substitute for a
        // local hostname that a remote server might refuse. You should add the
        // test hostname to your /etc/hosts file so everything is routed back
        // correctly to your testing site.
        if (array_key_exists('test_host',$params)) {
            $replace = @preg_replace(
                "/^(https?:\/\/)(?:[a-zA-Z0-9_\-]+(?:\.(?:[a-zA-Z0-9_\-]+))*)(\/.*)$/",
                "$1{$params['test_host']}$2",
                $params['redirect_uri']);
            if (is_string($replace)) {
                $params['redirect_uri'] = $replace;
            }
            unset($params['test_host']);
        }

        // Forward arguments to parent constructor.
        parent::__construct($url,$params);
    }

    /**
     * Returns the flow-id for this derivation.
     *
     * @return string
     *  The identifier as defined by the OAauth2 protocol
     */
    final function getFlowId() {
        return 'authorization_code';
    }

    /**
     * Implements getTokenNew() to request an access token from the remote
     * server using the 'authorization_code' grant type. This flow works in
     * three steps:
     *
     * 	1. Request an authorization code from authorization endpoint.
     *
     * 	2. Receive the authorization code (or error if client failed auth).
     *
     * 	3. Request an access token (and cache it), then redirect back to the
     * 	   original page.
     *
     * @return array
     *  The access token structure
     */
    protected function getTokenNew() {
        $key = $this->getSessionKey();

        // If $_GET[code] is defined then we have completed step 2 of three
        // steps. Now we must request an access token using the authorization
        // code.
        if (isset($_GET['code'])) {
            // Lookup the redirect_uri and state from the user session. Use the
            // state value to verify the response from the server. We'll use the
            // redirect_uri value in the token request to perform a final
            // redirect to clean up the user-agent's url heading.
            if (!array_key_exists('state',$_REQUEST)) {
                throw new OAuth2Exception(
                    __METHOD__.": no state parameter",
                    OAuth2Exception::OAUTH_EXCEPTION_BAD_RESPONSE);
            }
            $state = $_REQUEST['state'];
            if (!isset($_SESSION[$key]['redirect'][$state])
                || !isset($_SESSION[$key]['redirect']['state'])
                || $_SESSION[$key]['redirect']['state'] != $state)
            {
                throw new OAuth2Exception(
                    __METHOD__.": invalid state parameter",
                    OAuth2Exception::OAUTH_EXCEPTION_BAD_RESPONSE);
            }
            $uri = $_SESSION[$key]['redirect'][$state];
            unset($_SESSION[$key]['redirect']); // cleanup session

            // Prepare the data parameters we will include in the POST request
            // for the access token. These are combined with the default values
            // that requestToken() already handles.
            $this->params['token_request_data']['code'] = $_GET['code'];
            $this->params['token_request_data']['redirect_uri'] = $uri;

            // Request the access token.
            $tok = $this->requestToken();

            // Since the redirect will terminate the script, we must save the
            // token to the cache before the script terminates.
            $this->cacheItemStore('token',$tok);

            // Remove 'code' and 'state' from the query parameters; then url
            // encode whatever is left over so that we save any original query
            // parameters.
            unset($_GET['code']);
            unset($_GET['state']);
            if (!empty($_GET)) {
                $uri .= "?" . http_build_query($_GET);
            }

            // Redirect back to the original url (from the user session) to
            // complete the flow. We do this to remove any query parameters that
            // were introduced by the remote server.
            $this->redirect($uri);
            exit; // just in case

            // (control no longer in this script)
        }

        // Otherwise we start from the beginning of the flow.

        // Generate a random state id for maintaining state between us and the
        // authorization server. This is an opaque value.
        $state = md5(uniqid(rand(),true));

        // Obtain redirect_uri parameter for remote server.
        $uri = $this->params['redirect_uri'];

        // Generate the URI to which we will redirect the user-agent.
        $queryParams = array(
            'response_type' => 'code',
            'client_id' => $this->params['client_id'],
            'redirect_uri' => $uri,
            'state' => $state,
        );
        if (!empty($params['scope'])) {
            $queryParams['scope'] = $this->params['scope'];
        }
        $authUri = $this->params['auth_endpoint'] . '?'
            . http_build_query($queryParams);

        // Save the redirect URI in the session alongside the state parameter.
        // This URI will be the original URI to which we want to return later.
        if (isset($_SESSION[$key]['redirect'])) {
            unset($_SESSION[$key]['redirect']);
        }
        $_SESSION[$key]['redirect']['state'] = $state;
        $_SESSION[$key]['redirect'][$state] = $uri;

        // Redirect the user to the authorization endpoint. This will terminate
        // the script.
        $this->redirect($authUri);
        exit; // just in case

        // (control no longer in this script)
    }

    /**
     * Derived classes may override this to do a redirect in some
     * application-specific way. By default we simply insert a 'Location' header
     * into the response to redirect the user-agent to the specified resource.
     *
     * @param string $uri
     *  The redirect URI (this should preferably be an absolute path)
     */
    protected function redirect($uri) {
        header("Location: $uri");
        exit;
    }
}
