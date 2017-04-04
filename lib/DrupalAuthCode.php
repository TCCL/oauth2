<?php

/**
 * DrupalAuthCode.php
 *
 * This file is a part of tccl/oauth2.
 */

namespace TCCL\OAuth2;

/**
 * Provides an authorization_code grant type flow that employs Drupal functions
 * for redirection and redirect_uri configuration.
 */
class DrupalAuthCode extends AuthCode {
    /**
     * Constructs a new Drupal-based OAuth2 object that handles the
     * 'authorization_code' OAuth2 grant type.
     *
     * @param string $url
     *  The remote token endpoint URL
     * @param string $authUrl
     *  The remote authorization endpoint URL
     * @param array $params
     *  Additional protocol parameters (must include 'redirect_uri')
     */
    function __construct($url,$authUrl,array $params) {
        $redirectUri = drupal_get_destination()['destination'];
        $redirectUri = url($redirectUri,array('query'=>$_REQUEST,'absolute'=>true));

        parent::__construct($url,$authUrl,$params + array('redirect_uri'=>$redirectUri));
    }

    /**
     * Override redirect() to use drupal_goto() as Drupal performs some
     * additional processing when redirecting.
     *
     * @param string $uri
     *  The URI to which to redirect.
     */
    protected function redirect($uri) {
        // Note: this will call drupal_exit() which will use the 'exit'
        // construct to stop the script.
        drupal_goto($uri);
    }
}
