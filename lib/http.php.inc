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
define('HTTP_EXCEPTION_CONNECTION_TIMED_OUT',103);

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
 * HTTPRequest represents and performs an HTTP request
 */
class HTTPRequest {
    /**
     * The original url string
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
        'port' => null,

        /* user can provide these themself */
        'request_method' => HTTP_POST,
        'headers' => array(
            'Connection' => 'keep-alive',
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
     * Cache connections to remote host so we can improve performance by making
     * less connections; the cached object is an array whose first element is the
     * socket stream resource and whose second is the connection input buffer
     * @var array('host name' => array(socket_stream,string))
     */
    static private $conns = array();
    static private $register = false;

    /**
     * Create a new HTTPRequest object
     *
     * @param string  $url    The url of the request
     * @param array   $params Parameters to customize the request
     * @param boolean $secure If TRUE then force ssl on connection
     */
    function __construct($url,$params = null,$secure = false) {
        if (!self::$register) {
            self::$register = true;
            register_shutdown_function("HTTPRequest::closeCachedConnections");
        }

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
        if (isset($uri['port'])) {
            $this->params['port'] = $uri['port'];
        }

        // unionize with user-specified parameters; this may override some of
        // the parameters we just deduced and/or the defaults
        if (is_array($params)) {
            if (array_key_exists('headers',$params))
                $params['headers'] = $params['headers'] + $this->params['headers'];
            $this->params = $params + $this->params;
        }
    }

    /**
     * Close cached connections; I'm pretty sure PHP would destroy these at some
     * point but it's nice to be able to do it ourselves
     */
    static function closeCachedConnections() {
        foreach (self::$conns as list($sock,$_)) {
            fclose($sock);
        }
        self::$conns = array();
    }

    /**
     * Returns the original request URL provided when the request was created
     *
     * @return string
     */
    function getURL() {
        return $this->url;
    }

    /**
     * Performs the actual HTTP request and returns the response
     *
     * The response object's properties represent response header fields
     * (e.g. $response->contentLength)
     *
     * @return object The PHP object representing the response
     */
    function makeRequest() {
        if (!empty($this->cache['request']) && !empty($this->cache['sockaddr'])) {
            return self::http($this->cache['sockaddr'],$this->cache['request']);
        }

        // construct the socket address string used to connect to the remote host
        list($proto,$port) = explode(':',$this->params['protocol']);
        if (!is_null($this->params['port'])) {
            $port = $this->params['port'];
        }
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
     *
     * @param  string $sockaddr The socket connect address
     * @param  string $request  The entire request message (headers & body)
     *
     * @return array A PHP object representing the response
     */
    private static function http($sockaddr,$request) {
        // try to load an existing connection from the remote host; since we
        // send keep-alives to the Web server then there is a chance the
        // conneciton is still good
        $sock = false;
        $response = "";
        if (isset(self::$conns[$sockaddr])) {
            list($sock,$response) = self::$conns[$sockaddr];
            // check to make sure the remote host didn't shutdown the connection
            if (feof($sock)) {
                unset(self::$conns[$sockaddr]);
                fclose($sock);
                $sock = false;
            }
        }

        // if we don't already have a connection, then we connect to the specified
        // socket address
        if (!is_resource($sock)) {
            // create socket connection to remote host
            $sock = @stream_socket_client($sockaddr,$errno,$errmsg,HTTP_CONNECTION_TIMEOUT);
            if ($sock === false) {
                throw new HTTPException(__FUNCTION__
                    .": failed to open stream socket to $sockaddr: $errmsg",
                    HTTP_EXCEPTION_CANNOT_CONNECT);
            }
            stream_set_timeout($sock,10);
        }

        // write the request
        fwrite($sock,$request);

        // read the response until the end of an HTTP response message
        $iterator = false;
        while ($iterator === false) {
            // attempt to read some more bytes; we consider the connection shut
            // down if we read the conventional EOF (i.e. empty read) OR if the
            // read operation timed out
            $newbytes = fread($sock,4096);
            $info = stream_get_meta_data($sock);
            if (empty($newbytes) || $info['timed_out'])
                break;
            $response .= $newbytes;

            // attempt to parse the response so far; I hope that most if not all
            // of the message was sent at once; this would mean calls to the
            // following method would be limited; however, some servers will
            // sent data in small increments; to that end the following method
            // will cache its progress in $_ until it can read a whole response
            $result = self::parseHttpMessage($response,$iterator,$_);
        }

        // if $iter is false then we never got a complete message (at least within
        // the requisite timeout)
        if ($iterator === false) {
            fclose($sock);
            unset(self::$conns[$sockaddr]);
            throw new HTTPException(__FUNCTION__.": the remote host either took "
                . "too long to respond or shut down the connection",
                    HTTP_EXCEPTION_CONNECTION_TIMED_OUT);
        }

        // cache the socket connection and any remaining bytes from the input
        // buffer (hopefully this should nearly always be empty) unless the
        // server intends to close the connection
        if (isset($result['connection']) && strcasecmp($result['connection'],"close") == 0) {
            fclose($sock);
            unset(self::$conns[$sockaddr]);
        }
        else {
            $remain = substr($response,$iterator);
            self::$conns[$sockaddr] = array($sock,$remain === false ? "" : $remain);
        }

        // map any "dashed" key names to Camel-case
        foreach ($result as $k => $v) {
            $r = preg_replace_callback('/(-)(.)/',function($m){return strtoupper($m[2]);},$k);
            if ($r != $k) {
                unset($result[$k]);
                $result[$r] = $v;
            }
        }

        // parse the response into a PHP object and return it
        return (object) $result;
    }

    /**
     * This function parses an HTTP response message, including the response line,
     * headers and data payload (if any). If returns an array that represents
     * the HTTP response.
     *
     * @param string  $response The HTTP response body
     * @param integer $iterator The function will write the offset in $response after the logical
     *                          end of the message OR 'false' if the end of the message was not reached
     * @param array   $progress Used to speed up parsing if this is a subsequent parse attempt; this is
     *                          used internally by the function's implementation
     *
     * @return array An associative array containing the response headers, status
     *               code, status message and data payload
     */
    private static function parseHttpMessage($response,&$iterator,&$progress) {
        // check to see if we've already parsed the header fields
        if (!isset($progress['header-state'])) {
            $result = array(); // the result array
            $iterator = 0; // rolling offset into response message

            // process the response line/header fields
            foreach (explode(CRLF,$response) as $line) {
                // compute rolling offset into $response
                $iterator += strlen($line) + 2;

                // if we get an empty line, we have reached the end of the headers
                // section of the HTTP response
                if (empty($line)) {
                    // flag that we have reached the end of the headers section
                    $progress['header-state'] = $result;
                    $progress['iterator'] = $iterator;
                    break;
                }

                // parse the first line if we haven't processed any lines yet
                if (empty($result)) {
                    if (!preg_match("/^HTTP\/1\.(?:1|0)\s+([0-9]+)\s+(.+)\s*$/i",$line,$matches)) {
                        throw new HTTPException(__FUNCTION__
                                .": response line was incorrectly formatted: '$line'",
                                HTTP_EXCEPTION_BAD_RESPONSE);
                    }

                    $result['statusCode'] = $matches[1];
                    $result['statusMessage'] = $matches[2];
                }

                // otherwise parse a header line
                else {
                    if (!preg_match("/(.+?):\s*(.+)\s*/",$line,$matches)) {
                        throw new HTTPException(__FUNCTION__
                                .": bad header field in response: '$line'",
                                HTTP_EXCEPTION_BAD_RESPONSE);
                    }

                    // add the header; normalize keys to lower case values
                    // (note: HTTP says header keys are case-insensitive)
                    $result[strtolower($matches[1])] = $matches[2];
                }
            }
        }
        else {
            // otherwise we already parsed the headers and can restore them
            $result = $progress['header-state'];
            $iterator = $progress['iterator'];
        }

        // if the header's haven't been parsed, then the response is incomplete;
        // otherwise we can move on to reading the data payload (if any)
        if (!isset($progress['header-state'])) {
            $iterator = false;
        }
        else {
            // handle the data payload; I assume that no HEAD or CONNECT
            // requests are made by this library (therefore I don't have to
            // worry about not having a data payload in those cases)

            // handle 'Transfer-Encoding: chunked' (preferred, unfortunately by
            // serveral of the services I use...)
            if (isset($result['transfer-encoding'])
                && strtolower($result['transfer-encoding']) == 'chunked')
            {
                $data = self::chunkedTransferDecode($response,$iterator,$progress);
                if ($iterator !== false) {
                    $result['data'] = $data;
                }
            }

            // handle case where Content-Length header is set
            else if (isset($result['content-length'])) {
                $contentLength = intval($result['content-length']);
                if ($contentLength > 0) {
                    $data = substr($response,$iterator,$contentLength);
                    if ($data === false || strlen($data) < $contentLength) {
                        $iterator = false;
                    }
                    else {
                        $result['data'] = $data;
                        $iterator += $contentLength;
                    }
                }
            }
        }

        return $result;
    }

    /**
     * Decodes a message payload sent with 'Transfer-Encoding: chunked' option
     *
     * @param string  $response The complete response message
     * @param integer $offset   The current offset into the response message; if
     *                          the payload is incomplete, then we will set this
     *                          to false
     * @param array   $progress Saves the progress state for efficiency
     *
     * @return string           The decoded response payload
     */
    private static function chunkedTransferDecode($message,&$offset,&$progress) {
        // Note: the HTTP/1.1 spec (i.e. rfc2616 sec-3.6.1) details a chunk-extension
        // syntax and trailer syntax (for additional headers); we do not handle
        // these here

        // load any values from a previous iteration of this routine
        $payload = isset($progress['payload']) ? $progress['payload'] : "";
        $stage = isset($progress['stage']) ? $progress['stage'] : 1;

        // enter a loop to read data chunks
        while (true) {
            // restore previous context only once (I know, this is nasty! But
            // it's quick (unfortunately PHP doesn't let me jump into a loop...)
            if (isset($stage)) {
                $cpy = $stage;
                unset($stage);
                if ($cpy == 1)
                    goto one;
                else if ($cpy == 2)
                    goto two;
                else if ($cpy == 3)
                    goto three;
                else
                    goto four;
            }

        one:
            // grab the first CRLF delimited line; this should be a
            // hexadecimal-encoded number representing the number of bytes to
            // read after the CRLF
            $i = strpos($message,CRLF,$offset);
            if ($i === false) {
                $stage = 1;
                break; // incomplete chunk size line
            }
            $hlen = $i - $offset; // length of hex string
            $progress['bcount'] = hexdec(substr($message,$offset,$hlen));
            $offset += $hlen + 2; // seek length of hex string plus CRLF
            if ($progress['bcount'] == 0) {
                // the server should have sent a zero length chunk to indicate
                // that it has finished sending the chunked data payload
                $stage = 4;
                break;
            }

        two:
            // grab the chunk data
            $s = substr($message,$offset,$progress['bcount']);
            if ($s === false || strlen($s) < $progress['bcount']) {
                $stage = 2;
                break; // not enough bytes
            }
            $payload .= $s;
            // seek ahead to next chunk header
            $offset += $progress['bcount'] + 2; // +2 bytes for CRLF

        three:
            // verify that a CLRF sequence was found after the chunk data
            if (($test = substr($message,$offset-2,2)) != CRLF) {
                if ($test === false) {
                    $stage = 3;
                    break; // not enough bytes
                }

                // otherwise the payload was not formatted correctly
                throw new Exception(__FUNCTION__.": chunked transfer not encoded correctly",
                    HTTP_EXCEPTION_BAD_RESPONSE);
            }
        }

    four:
        // if $stage < 4, then an error occurred somewhere in stages 1-3 and we
        // need to quit; otherwise we verify the trailing CRLF sequence
        if ($stage < 4 || substr($message,$offset,2) != CRLF) {
            // save state in progress variable so we can restore it on the next
            // call (note: $offset should be restored by the caller)
            $progress['payload'] = $payload;
            $progress['iterator'] = $offset;
            $progress['stage'] = isset($stage) ? $stage : 4;
            $offset = false; // flag that we failed
        }
        else {
            $offset += 2;
        }

        return $payload;
    }
}
