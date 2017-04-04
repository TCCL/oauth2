<?php

/**
 * HTTPException.php
 *
 * This file is a part of tccl/oauth2.
 */

namespace TCCL\OAuth2;

/**
 * Define an exception type and exception code constants for exceptions
 * generated in this module that we potentially want users to handle.
 */
class HTTPException extends Exception {
    /**
     * Enumerate the various exception codes.
     */
    const HTTP_EXCEPTION_CANNOT_CONNECT = 101;
    const HTTP_EXCEPTION_BAD_RESPONSE = 102;
    const HTTP_EXCEPTION_CONNECTION_TIMED_OUT = 103;

    /**
     * Creates a new HTTPException instance.
     */
    function __construct($message,$code) {
        parent::__construct("in function $message",$code);
    }
}
