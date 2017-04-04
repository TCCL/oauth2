<?php

/**
 * OAuth2Exception.php
 *
 * This file is a part of tccl/oauth2.
 */

namespace TCCL\OAuth2;

/**
 * Define a specialized exception type to support exceptions that we want users
 * to potentially handle.
 */
class OAuth2Exception extends Exception {
    /**
     * Enumerate exceptions that occur in this library that we want users to
     * potentially handle.
     */
    const OAUTH_EXCEPTION_BAD_REQUEST = 101;
    const OAUTH_EXCEPTION_FAILED_REQUEST = 102;
    const OAUTH_EXCEPTION_INVALID_OPERATION = 103;
    const OAUTH_EXCEPTION_BAD_RESPONSE = 104;

    /**
     * Creates a new OAuth2Exception instance.
     */
    function __construct($message,$code) {
        parent::__construct("in function $message",$code);
    }
}
