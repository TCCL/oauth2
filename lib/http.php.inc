<?php

/**
 * This file provides simple HTTP/HTTPS request interaction
 * @package oauth2
 */

/**
 * Define an exception type and exception code constants for exceptions generated
 * in this module that we potentially want users to handle
 */
class HTTPException extends Exception {
    function __construct() {
        // forward arguments to parent class
        call_user_func_array('parent::__construct',func_get_args());
    }
}
define('HTTP_EXCEPTION_CANNOT_CONNECT',101);
define('HTTP_EXCEPTION_BAD_RESPONSE',102);

/**
 * Define protocol kinds and ports along with HTTP methods
 */
define('HTTP','tcp:80');
define('HTTPS','ssl:443');
define('HTTP_GET','GET');
define('HTTP_POST','POST');
define('HTTP_PUT','PUT');
define('HTTP_DELETE','DELETE');

/**
 * Misc. defines
 */
define('CRLF',"\r\n");
define('HTTP_CONNECTION_TIMEOUT',5);

/**
 * Represents and performs an HTTP request
 */
class HTTPRequest {
    /**
     * The original url
     * @var string
     */
    private $url;

    /**
     * The parameters used to make the request
     *  - remote_host :: the host name or IP address of the remote host
     *  - request_uri :: the resource to request on the remote server
     *  - protocol :: either HTTP or HTTPS constant
     *  - request_method :: one of the HTTP_* constants
     *  - headers :: headers to include in the request
     *  - data :: associative array of data payload fields; these are
     *  interpreted into a query string
     *  -- query :: associative array of data fields to include as a query
     *  string; this will be passed to http_build_query()
     * @var array
     */
    private $params = array(
        /* these first three fields should be set automatically */
        'remote_host' => null,
        'request_uri' => null,
        'protocol' => null,

        /* user can provide these themself */
        'request_method' => HTTP_POST,
        'headers' => array(
            'User-Agent' => 'lib-oauth2-client/1.0'
        ),
        'data' => null,
        'query' => null
    );

    /**
     * The cached request string and socket address (in case the same request
     * is made again)
     * @var array
     */
    private $cache = array(
        'request' => null,
        'sockaddr' => null
    );

    /**
     * Create a new HTTPRequest object
     * @param string $url    the url of the request
     * @param array $params parameters to customize the request
     * @param boolean $secure if true then force https
     */
    function __construct($url,$params = null,$secure = false) {
        // remember original url string
        $this->url = $url;

        // parse the url to deduce the uri, host and protocol parameters
        $uri = @parse_url($url);
        if (!isset($uri['scheme'])) {
            throw new Exception(__FUNCTION__.": url must specify protocol");
        }
        if (strtolower($uri['scheme']) == 'https') {
            $this->params['protocol'] = HTTPS;
        }
        else if ($secure) {
            throw new Exception(__FUNCTION__.": url scheme must be https by user option in '$url'");
        }
        else {
            $this->params['protocol'] = HTTP;
        }
        $this->params['remote_host'] = $uri['host'];
        $this->params['request_uri'] = $uri['path'];

        // unionize with user-specified parameters; this may override some of
        // the parameters we just deduced and/or the defaults
        if (is_array($params)) {
            if (array_key_exists('headers',$params))
                $params['headers'] = $params['headers'] + $this->params['headers'];
            $this->params = $params + $this->params;
        }
    }

    function getURL() {
        return $this->url;
    }

    function makeRequest() {
        if (!empty($this->cache['request']) && !empty($this->cache['sockaddr'])) {
            return self::http($this->cache['sockaddr'],$this->cache['request']);
        }

        // construct the socket address string used to connect to the remote host
        list($proto,$port) = explode(':',$this->params['protocol']);
        $sockaddr = "$proto://{$this->params['remote_host']}:$port";

        // construct the request string
        $query = "";
        if (!empty($this->params['query'])) {
            $query = '?' . http_build_query($this->params['query']);
        }
        $request = "{$this->params['request_method']} {$this->params['request_uri']}$query HTTP/1.1\r\n"
                    . "Host: {$this->params['remote_host']}\r\n";
        if (!empty($this->params['headers'])) {
            foreach ($this->params['headers'] as $k => $v) {
                $request .= "$k: $v\r\n";
            }
        }
        $dataBody = "";
        if (!empty($this->params['data'])) {
            if (is_array($this->params['data'])) {
                foreach ($this->params['data'] as $k => $v) {
                    if (!empty($v)) {
                        if (!empty($dataBody))
                            $dataBody .= "&";
                        $dataBody .= htmlentities($k) . "=" . htmlentities($v);
                    }
                }
            }
            else {
                $dataBody .= "{$this->params['data']}";
            }
        }
        if (!empty($dataBody)) {
            $request .= "Content-Length: " . strlen($dataBody) . CRLF;
        }
        $request .= CRLF;
        $request .= $dataBody;

        // cache the socket address and request strings
        $this->cache['sockaddr'] = $sockaddr;
        $this->cache['request'] = $request;

        // perform the request
        return self::http($sockaddr,$request);
    }

    /**
     * Perform a generic HTTP request
     * @param  string $sockaddr the socket connect address
     * @param  string $request  the entire request message (headers & body)
     * @return array           A PHP object containing the headers as properties
     *  and a 'data' property; the 'data' payload will not be modified
     */
    private static function http($sockaddr,$request) {
        // create socket connection to remote host
        $sock = stream_socket_client($sockaddr,$errno,$errmsg,HTTP_CONNECTION_TIMEOUT);
        if ($sock === false) {
            throw new HTTPException(__FUNCTION__
                    .": failed to open stream socket to $sockaddr: $errmsg",
                    HTTP_EXCEPTION_CANNOT_CONNECT);
        }

        // write the request and close our end of the connection
        fwrite($sock,$request);
        stream_set_timeout($sock,10);
        stream_socket_shutdown($sock,STREAM_SHUT_WR); // for writing

        // read the response until all bytes have been read
        $response = "";
        while (true) {
            $newbytes = fread($sock,4096);
            $info = stream_get_meta_data($sock);
            if (empty($newbytes) || $info['timed_out'])
                break;
            $response .= $newbytes;
        }
        fclose($sock);

        // parse the response into a PHP object
        $result = array();
        $i = 0;
        foreach (explode(CRLF,$response) as $line) {
            $i += strlen($line) + 2;
            if (empty($line))
                break;

            if (empty($result)) {
                if (!preg_match("/^HTTP\/1\.(?:1|0)\s+([0-9]+)\s+(.+)\s*$/i",$line,$matches)) {
                    throw new HTTPException(__FUNCTION__
                            .": first response line was unexpected: '$line'",
                            HTTP_EXCEPTION_BAD_RESPONSE);
                }

                $result['statusCode'] = $matches[1];
                $result['statusMessage'] = $matches[2];
            }
            else {
                if (!preg_match("/(.+?):\s*(.+)\s*/",$line,$matches)) {
                    throw new HTTPException(__FUNCTION__
                            .": bad header field in response: '$line'",
                            HTTP_EXCEPTION_BAD_RESPONSE);
                }

                // add the header; normalize keys to lower case values (note:
                // HTTP says header keys are case-insensitive)
                $result[strtolower($matches[1])] = $matches[2];
            }
        }
        if ($i < strlen($response)) {
            // parse the rest of the response string; truncate it if Content-Length
            // was specified
            $result['data'] = substr($response,$i);
            if (array_key_exists('content-length',$result)) {
                $clength = intval($result['content-length']);
                if (strlen($result['data']) > $clength)
                    $result['data'] = substr($result['data'],0,$clength);
            }

            // if chunked transfer occurred, decode the chunks into a proper payload
            if (array_key_exists('transfer-encoding',$result)
                && strtolower($result['transfer-encoding']) == 'chunked')
            {
                $result['data'] = self::chunkedTransferDecode($result['data']);
            }
        }
        return (object) $result;
    }

    /**
     * Decodes a message payload sent with Transfer-Encoding: chunked
     * @param  string $message Message payload string
     * @return string          The decoded message string
     */
    private static function chunkedTransferDecode($message) {
        // Note: the HTTP/1.1 spec (i.e. rfc2616 sec-3.6.1) details a chunk-extension
        // syntax and trailer syntax (for additional headers); we do not handle
        // these here

        $offset = 0;
        $length = strlen($message);
        $payload = "";
        while (true) {
            // grab the first CRLF delimited line; this should be a hexadecimal-encoded
            // number representing the number of bytes to read
            $i = strpos($message,CRLF,$offset);
            if ($i === false) {
                break;
            }
            $hlen = $i - $offset;
            $bcount = hexdec(substr($message,$offset,$hlen));

            // seek ahead to the chunk data and grab the chunk data
            $offset += $hlen + 2; // length of hex string plus CRLF
            $s = substr($message,$offset,$bcount);
            if ($s === false) {
                throw new HTTPException(__FUNCTION__.": chunked transfer not encoded correctly",
                    HTTP_EXCEPTION_BAD_RESPONSE);
            }
            $payload .= $s;

            // seek ahead to next chunk header
            $offset += $bcount + 2; // +2 bytes for CRLF

            // verify that a CLRF sequence was found after the chunk data
            if (substr($message,$offset-2,2) != CRLF) {
                throw new Exception(__FUNCTION__.": chunked transfer not encoded correctly",
                    HTTP_EXCEPTION_BAD_RESPONSE);
            }
        }
        // note: there should be a trailing CRLF sequence at $offset

        return $payload;
    }
}
