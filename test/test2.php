<?php

/**
 * This file tests the OAuth2 functionality using Innovative's PATRON API. We
 * use the provider's test sandbox site at https://sandbox.iii.com
 */

require_once("../lib/oauth2.php.inc");
session_id("test2"); // test a session
session_start();

define('TOKEN_API',"https://sandbox.iii.com/iii/sierra-api/v2/token");
define('AUTHORITY_API',"https://sandbox.iii.com/iii/sierra-api/v2/authorities");
define('BIBS_API',"https://sandbox.iii.com/iii/sierra-api/v2/bibs");
define('PATRONS_API',"https://sandbox.iii.com/iii/sierra-api/v2/patrons");

$params = array(
    'client_id' => 'WO0rS+IFzwLnso/kmPGM6S9h5Lv8',
    'client_secret' => 'pleaseletmein'
);

$session = new OAuth2ClientCredentials(TOKEN_API,$params);
$token = $session->getAccessTokenFull();

var_dump($token);

// play around with the Sierra sandbox

$a = $session->apiCall(BIBS_API,HTTP_GET,array('query'=>(array("deleted"=>false,"suppressed"=>false,"limit"=>10))));
var_dump($a);

$b = $session->apiCall(AUTHORITY_API,HTTP_GET,array('query'=>array("limit"=>10)));
var_dump($b);

$patrons = $session->apiCall(PATRONS_API,HTTP_GET,array('query'=>array("id"=>1000001,"fields"=>"names,addresses,barcodes")));
var_dump($patrons);
