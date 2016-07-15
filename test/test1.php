<?php

/**
 * This file tests the 'http' library functionality.
 */

require_once("../lib/http.php.inc");

$params = array(
    'request_method' => HTTP_GET,
    'headers' => array(
        'Connection' => 'close'
    )
);

try {
    $request = new HTTPRequest("http://www.google.com/thing",$params);
    echo "Requesting " . $request->getURL() . PHP_EOL;
    var_dump($request->makeRequest());
} catch (Exception $e) {
    echo "Failed request to " . $request->getURL() . ": " . $e->getMessage() . PHP_EOL;
}

try {
    $request = new HTTPRequest("http://www.geemediaanddesign.com/",$params);
    echo "Requesting " . $request->getURL() . PHP_EOL;
    var_dump($request->makeRequest());
} catch (Exception $e) {
    echo "Failed request to " . $request->getURL() . ": " . $e->getMessage() . PHP_EOL;
}

try {
    $request = new HTTPRequest("https://www.google.com/search",['query'=>['q'=>'apple']]+$params);
    echo "Requesting " . $request->getURL() . PHP_EOL;
    var_dump($request->makeRequest());
} catch (Exception $e) {
    echo "Failed request to " . $request->getURL() . ": " . $e->getMessage() . PHP_EOL;
}

/*try {
    $request = new HTTPRequest("http://rserver.us:8080/strlength/roger",$params);
    echo "Requesting " . $request->getURL() . PHP_EOL;
    var_dump($request->makeRequest());
} catch (Exception $e) {
    echo "Failed request to " . $request->getURL() . ": " . $e->getMessage() . PHP_EOL;
}*/

try {
    $request = new HTTPRequest("https://api.github.com/users/RogerGee/repos",$params);
    echo "Requesting " . $request->getURL() . PHP_EOL;
    var_dump($request->makeRequest());
} catch (Exception $e) {
    echo "Failed request to " . $request->getURL() . ": " . $e->getMessage() . PHP_EOL;
}
