<?php

/**
 * ClientCredentials.php
 *
 * This file is a part of tccl/oauth2.
 */

namespace TCCL\OAuth2;

/**
 * This class provides an OAuth2 implementation type that handles the
 * 'client_credentials' authorization grant.
 */
class ClientCredentials extends OAuth2 {
    /**
     * Construct a new OAuth2 object that handles the 'client_credentials' flow.
     *
     * Parameters to this function are the same as the base class; I have a
     * constructor here in case I want to add anything later...
     */
    function __construct() {
        // Forward arguments to parent constructor.
        call_user_func_array('parent::__construct',func_get_args());
    }

    /**
     * Returns the flow-id for this derivation.
     *
     * @return string
     *  The identifier as defined by the OAuth2 protocol
     */
    final function getFlowId() {
        return 'client_credentials';
    }

    /**
     * Implements getTokenNew() to request an access token from the remote
     * server using the 'client_credentials' authorization flow.
     *
     * @return array
     *  The access token structure
     */
    protected function getTokenNew() {
        // This is really simple: just do a request.
        return $this->requestToken();
    }
}
