<?php
/*
 * ================================================================================
 * Copyright 2022-present Srpopty
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ================================================================================
 * @Copyright: Copyright (c) 2022-present by Srpopty. All rights reserved.
 * @Author: Srpopty
 * @Email: srpopty@outlook.com
 * @Project: Corax
 * @Filename: CoraxHTTPClient.php
 * @Description: 
 *   HTTP request interface in for Corax by using curl. Send and receive HTTP 
 * package, record traffic statices by the time. Easy to use for some common HTTP
 * request method, such as GET, POST, Upload etc.
 * ================================================================================
 */

namespace Corax\Common;

use Throwable;


final class CoraxHTTPClient
{
    public static $timeout = 30;
    public static $proxy = '';

    private static $async_count = 0;
    private static $key = 0;
    private static $ch = null;
    private static $ch_pool = [];
    private static $mch_pool = [];

    public $stabilizing;

    private $multi_handle;
    private $callback;
    private $ch_queue;
    private $ch_map;
    private $request_queue;
    private $storage;
    private $queue_count;
    private $async_counts;
    private $async_time;
    private $max_async_count;
    private $poss_min_count;
    private $poss_max_count;
    private $max_tolerance;
    private $min_tolerance;
    private $stabile_round;
    private $last_max_async_count;

    /**
     * Initialize a http client.
     * 
     * @param bool $async Enable async request. Defaults to false.
     * @param callable|null $callback The callback function for each finished request. Accept 3 arguments, the first 
     *   is key of the request, second is request ret which is the return value of "request", and the last is changeable
     *   count argument which is the stored array before request. Returns a bool value to show if this request is 
     *   successfully, returns false or other will show this request is failed. Given null will use default callback.
     *   Defaults to null.
     */
    public function __construct($async = false, $callback = null)
    {
        $this->multi_handle = $async ? curl_multi_init() : null;
        if ($this->multi_handle) self::$mch_pool[] = $this->multi_handle;
        $this->callback = $callback;
        $this->ch_queue = [];
        $this->ch_map = [];
        $this->request_queue = [];
        $this->storage = [];
        $this->queue_count = 0;
        $this->set_max_async_count(self::$async_count ?: 2, false);  // Defaults to 2.
        $this->stabilizing = false;
        $this->min_tolerance = 0;
        $this->max_tolerance = self::$timeout;
        $this->poss_min_count = 2;
        $this->poss_max_count = 4;
        $this->last_max_async_count = $this->max_async_count;
        $this->stabile_round = $this->async_counts = $this->async_time = 0;
        if (self::$ch === null) self::$ch = curl_init();
    }

    /**
     * Get curl request handle.
     * 
     * @param \CurlHandle $ch The curl handle.
     * @param string $method The request method. Upper letter case required.
     * @param string $url The url to request.
     * @param array $headers The headers with this request.
     * @param string|null $data The data will be sent in this request.
     * @param array|null $files The file to upload. It $files given and $data is array, the $data will 
     *   be parsed as post field data. If $data is string, it will be simply ignored. The $files formation is:
     *   {'file_name': {'filename' => '1.txt', 'content_type' => 'application/octet-stream', 'content' => '123'}}
     *   The "content_type" is optional, defaults content type is "application/octet-stream".
     * @param bool $redirect Enable follow request redirection such as 302.
     * @param int|null $timeout The timeout of this request, given null will use global request timeout.
     * @param string|null $proxy The proxy of this request, given null will use global request proxy. 
     * @param array &$resp_headers For saving the raw response headers.
     * @return \CurlHandle The set curl handle.
     */
    private static function set_handle(
        $ch,
        $method,
        $url,
        $headers,
        $data,
        $files,
        $redirect,
        $timeout,
        $proxy,
        &$resp_headers
    ) {
        CoraxStatistic::$sent_bytes += strlen($url) + 122;  // 122 for correction.

        if ($files !== null) {
            $boundary = '----CoraxBoundary' . uniqid();
            $sections_boundary = '--' . $boundary;
            $sections = [];

            if (is_array($data)) {
                foreach ($data as $key => $value) {
                    $sections[] = $sections_boundary;
                    $sections[] = "Content-Disposition: form-data; name=\"$key\"";
                    $sections[] = '';
                    $sections[] = $value;  // TODO: What if value is an array?
                }
            }

            foreach ($files as $name => $file) {
                $sections[] = $sections_boundary;
                $filename = $file['filename'];
                $sections[] = "Content-Disposition: form-data; name=\"$name\"; filename=\"$filename\"";
                $sections[] = 'Content-Type: ' . $file['type'] ?? 'application/octet-stream';
                $sections[] = '';
                $sections[] = $file['content'];
            }

            $sections[] = $sections_boundary . '--';
            $sections[] = '';
            $headers['Content-Type'] = "multipart/form-data; boundary=$boundary";
            $data = implode("\r\n", $sections);
        }

        $req_headers = ['Expect:'];  // Block 100-continue status for curl.
        if ($headers) foreach ($headers as $k => $v) {
            $h = (string) $k . ': ' . (string) $v;
            $req_headers[] = $h;
            CoraxStatistic::$sent_bytes += strlen($h) + 2;
        }

        $options = [
            CURLOPT_URL            => $url,
            CURLOPT_HEADER         => false,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_ENCODING       => '',
            CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_1_1,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_FOLLOWLOCATION => $redirect,
            CURLOPT_TIMEOUT        => $timeout === null ? self::$timeout : $timeout,
            CURLOPT_PROXY          => $proxy === null ? self::$proxy : $proxy,
            CURLOPT_SSL_VERIFYHOST => (strpos($url, 'https') !== false) ? 2 : 0,
            CURLOPT_HTTPHEADER     => $req_headers,
            CURLOPT_HEADERFUNCTION => function ($curl, $header) use (&$resp_headers) {
                $len = strlen($header);
                CoraxStatistic::$recv_bytes += $len + 2;
                $header = explode(':', $header, 2);
                if (count($header) < 2) return $len;
                $resp_headers[trim($header[0])] = trim($header[1]);
                return $len;
            }
        ];

        switch ($method) {
            case 'GET':
                break;
            case 'POST':
                $options[CURLOPT_POST] = 1;
                break;
            case 'HEAD':
                $options[CURLOPT_NOBODY] = true;
                break;
            default:
                $options[CURLOPT_CUSTOMREQUEST] = $method;
                break;
        }

        if ($data !== null) {
            if (is_array($data)) $data = http_build_query($data);
            CoraxStatistic::$sent_bytes += strlen($data);
            $options[CURLOPT_POSTFIELDS] = $data;
        }

        curl_reset($ch);
        @curl_setopt_array($ch, $options);
    }

    /**
     * Do request the given curl handle.
     * 
     * @param string $key The handle key in queue.
     * @param \CurlHandle $ch The handle to request.
     * @param float|null $timestamp The request start timestamp. Given null will use now as start time. 
     *   Defaults to null.
     * @param bool $async_request If this request is a async request. Defaults to false.
     * @return array|bool HTTP response or callback result. The http response including response status
     *   code "code", response headers "headers", response data "content", request error message if error
     *   happened "error", request spend time "time" and the raw http response "raw".
     */
    private function request_handle($key, $ch, $timestamp = null, $async_request = false)
    {
        if ($timestamp === null) $timestamp = microtime(true);
        $ret = (!$async_request || $this->multi_handle === null) ? curl_exec($ch) : curl_multi_getcontent($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($ret === false || $code === 0) {
            CoraxStatistic::$bad_req_count++;
            $ret = '';
            $resp_headers = [];
            $error = 'CURL(' . curl_errno($ch) . '): ' . curl_error($ch);
        } else {
            CoraxStatistic::$req_count++;
            CoraxStatistic::$recv_bytes += strlen($ret);
            $resp_headers = $this->request_queue[$key]['resp_headers'];
            $error = null;
        }

        if ($this->multi_handle) curl_multi_remove_handle($this->multi_handle, $ch);

        $callback = $this->request_queue[$key]['callback'];

        $response = [
            'code' => $code,
            'headers' => $resp_headers,
            'content' => $ret,
            'error' => $error,
            'time' => microtime(true) - $timestamp
        ];
        if ($callback) {
            try {
                $response = $callback($key, $response, ...$this->storage[$key]);
            } catch (Throwable $e) {
                if ($this->multi_handle) CoraxLogger::warn('Async request callback error: ' . (string) $e);
                else CoraxLogger::warn('Request callback error: ' . (string) $e);
                $response = false;
            }
            unset($this->storage[$key]);
        }

        $this->queue_count--;
        unset($this->request_queue[$key]);
        unset($this->ch_map[(string) $ch]);
        if ($async_request) $this->ch_queue[] = $ch;
        return $response;
    }

    /**
     * Initialize http client.
     * 
     * @param int|null $timeout Global request timeout. Defaults to null.
     * @param string|null $proxy Global request proxy. Defaults to null.
     * @param int $async_count Force assign a async count. Given 0 will enable auto-stabilize async 
     *   count. Defaults to 0;
     */
    public static function init($timeout = null, $proxy = null, $async_count = 0)
    {
        self::$key = 0;

        if ($timeout !== null) self::$timeout = $timeout;
        if ($proxy !== null) self::$proxy = $proxy;
        self::$async_count = ($async_count <= 0) ? max($async_count, 0) : $async_count;
    }

    /**
     * Parsed a full host with scheme, user, password, host and port from a url.
     * 
     * @param string $url The url to be parsed.
     * @return string Parsed host.
     */
    public static function parse_host($url)
    {
        $ret = parse_url($url);
        $host = $ret['scheme'] . '://';
        if (isset($ret['user'])) {
            $host .= $ret['user'];
            if (isset($ret['pass'])) $host .= ':' . $ret['pass'];
            $host .= '@';
        }
        $host .= $ret['host'];
        if (isset($ret['port'])) $host .= ':' . $ret['port'];
        return $host;
    }

    /**
     * Get count of total request handles.
     * 
     * @return int Count of total request handles.
     */
    public static function count_request_handles()
    {
        return count(self::$ch_pool) + count(self::$mch_pool);
    }

    /**
     * Shutdown all curl handles and release resources.
     */
    public static function shutdown()
    {
        @curl_close(self::$ch);
        foreach (self::$ch_pool as $ch) @curl_close($ch);
        foreach (self::$mch_pool as $mch) @curl_multi_close($mch);
    }

    /**
     * Reset request callback function.
     * 
     * @param callable $callback The callback function for each finished request. Accept 3 arguments, the first 
     *   is key of the request, second is request ret which is the return value of "request", and the last is changeable
     *   count argument which is the stored array before request. Returns a bool value to show if this request is 
     *   successfully, returns false or other will show this request is failed.
     */
    public function set_callback($callback)
    {
        $this->callback = $callback;
    }

    /**
     * Reset request max queue count. At least 2 and no more than 512.
     * 
     * @param bool $limit Limit the given count between 2 and 512. Defaults to true.
     * @param int $count The max request queue count.
     */
    public function set_max_async_count($count, $limit = true)
    {
        if ($limit) {
            if ($count <= 1) $count = 2;
            if ($count > 0x200) $count = 0x200;
        }
        $this->max_async_count = $count;
        $current_count = count($this->ch_queue) + count($this->ch_map);
        if ($count > $current_count)
            for ($i = $current_count; $i < $count; $i++) {
                $ch = curl_init();
                self::$ch_pool[] = $ch;
                $this->ch_queue[] = $ch;
            }
    }

    /**
     * Get current max queue count.
     */
    public function get_max_async_count()
    {
        return $this->max_async_count;
    }

    /**
     * Check if the http client request queue is empty.
     * 
     * @return bool The check result.
     */
    public function empty()
    {
        return empty($this->request_queue[0]);
    }

    /**
     * Get current http client request queue count.
     * 
     * @return int Current request queue count.
     */
    public function count()
    {
        return count($this->request_queue);
    }

    /**
     * Request a url with GET method.
     * 
     * @param string $url The url to request.
     * @param array $headers The headers with this request. Defaults to empty array.
     * @param bool $redirect Enable follow request redirection such as 302. Defaults to false.
     * @param int|null $timeout The timeout with this request, given null will use global request timeout. 
     *   Defaults to null.
     * @param string|null $proxy The proxy of this request, given null will use global request proxy. Defaults to null.
     * @param bool $async Enable async request. Enable this, the request will be added to queue and request on calling
     *   "request_all". Defaults to false.
     * @param callable|null $callback The callback function after the request finished. Accept 3 arguments, the first 
     *   is key of the request, second is request ret which is the return value of "request", and the last is changeable
     *   count argument which is the stored array before request. Returns a bool value to show if this request is 
     *   successfully, returns false or other will show this request is failed. Given null will use default callback.
     *   Available on async request. Defaults to null.
     * @param array $storage Store some data of this request, it will be transform to callback if enable async request.
     *   Defaults to an empty array.
     * @return array HTTP response.
     */
    public function get(
        $url,
        $headers = [],
        $redirect = false,
        $timeout = null,
        $proxy = null,
        $async = false,
        $callback = null,
        $storage = []
    ) {
        return $this->request(
            $url,
            'GET',
            $headers,
            null,
            null,
            $redirect,
            $timeout,
            $proxy,
            $async,
            $callback,
            $storage
        );
    }

    /**
     * Request a url with HEAD method.
     * 
     * @param string $url The url to request.
     * @param array $headers The headers with this request. Defaults to empty array.
     * @param bool $redirect Enable follow request redirection such as 302. Defaults to false.
     * @param int|null $timeout The timeout with this request, given null will use global request timeout. 
     *   Defaults to null.
     * @param string|null $proxy The proxy of this request, given null will use global request proxy. Defaults to null.
     * @param bool $async Enable async request. Enable this, the request will be added to queue and request on calling
     *   "request_all". Defaults to false.
     * @param callable|null $callback The callback function after the request finished. Accept 3 arguments, the first 
     *   is key of the request, second is request ret which is the return value of "request", and the last is changeable
     *   count argument which is the stored array before request. Returns a bool value to show if this request is 
     *   successfully, returns false or other will show this request is failed. Given null will use default callback.
     *   Available on async request. Defaults to null.
     * @param array $storage Store some data of this request, it will be transform to callback if enable async request.
     *   Defaults to an empty array.
     * @return array HTTP response.
     */
    public function head(
        $url,
        $headers = [],
        $redirect = false,
        $timeout = null,
        $proxy = null,
        $async = false,
        $callback = null,
        $storage = []
    ) {
        return $this->request(
            $url,
            'HEAD',
            $headers,
            null,
            null,
            $redirect,
            $timeout,
            $proxy,
            $async,
            $callback,
            $storage
        );
    }

    /**
     * Request a url with DELETE method.
     * 
     * @param string $url The url to request.
     * @param array $headers The headers with this request. Defaults to empty array.
     * @param bool $redirect Enable follow request redirection such as 302. Defaults to false.
     * @param int|null $timeout The timeout with this request, given null will use global request timeout. 
     *   Defaults to null.
     * @param string|null $proxy The proxy of this request, given null will use global request proxy. Defaults to null.
     * @param bool $async Enable async request. Enable this, the request will be added to queue and request on calling
     *   "request_all". Defaults to false.
     * @param callable|null $callback The callback function after the request finished. Accept 3 arguments, the first 
     *   is key of the request, second is request ret which is the return value of "request", and the last is changeable
     *   count argument which is the stored array before request. Returns a bool value to show if this request is 
     *   successfully, returns false or other will show this request is failed. Given null will use default callback.
     *   Available on async request. Defaults to null.
     * @param array $storage Store some data of this request, it will be transform to callback if enable async request.
     *   Defaults to an empty array.
     * @return array HTTP response.
     */
    public function delete(
        $url,
        $headers = [],
        $redirect = false,
        $timeout = null,
        $proxy = null,
        $async = false,
        $callback = null,
        $storage = []
    ) {
        return $this->request(
            $url,
            'DELETE',
            $headers,
            null,
            null,
            $redirect,
            $timeout,
            $proxy,
            $async,
            $callback,
            $storage
        );
    }

    /**
     * Request a url with OPTION method.
     * 
     * @param string $url The url to request.
     * @param array $headers The headers with this request. Defaults to empty array.
     * @param bool $redirect Enable follow request redirection such as 302. Defaults to false.
     * @param int|null $timeout The timeout with this request, given null will use global request timeout. 
     *   Defaults to null.
     * @param string|null $proxy The proxy of this request, given null will use global request proxy. Defaults to null.
     * @param bool $async Enable async request. Enable this, the request will be added to queue and request on calling
     *   "request_all". Defaults to false.
     * @param callable|null $callback The callback function after the request finished. Accept 3 arguments, the first 
     *   is key of the request, second is request ret which is the return value of "request", and the last is changeable
     *   count argument which is the stored array before request. Returns a bool value to show if this request is 
     *   successfully, returns false or other will show this request is failed. Given null will use default callback.
     *   Available on async request. Defaults to null.
     * @param array $storage Store some data of this request, it will be transform to callback if enable async request.
     *   Defaults to an empty array.
     * @return array HTTP response.
     */
    public function option(
        $url,
        $headers = [],
        $redirect = false,
        $timeout = null,
        $proxy = null,
        $async = false,
        $callback = null,
        $storage = []
    ) {
        return $this->request(
            $url,
            'OPTION',
            $headers,
            null,
            null,
            $redirect,
            $timeout,
            $proxy,
            $async,
            $callback,
            $storage
        );
    }

    /**
     * Request a url with POST method.
     * 
     * @param string $url The url to request.
     * @param string $data The data will be sent in this request.
     * @param array $headers The headers with this request. Defaults to empty array.
     * @param array|null $files The file to upload. If $files given and $data is array, the $data will be parsed as 
     *   post field data. If $data is string, it will be simply ignored. The $files formation is:
     *   {'file_name': {'filename' => '1.txt', 'content_type' => 'application/octet-stream', 'content' => '123'}}
     *   The "content_type" is optional, defaults content type is "application/octet-stream". Defaults to null.
     * @param bool $redirect Enable follow request redirection such as 302. Defaults to false.
     * @param int|null $timeout The timeout with this request, given null will use global request timeout. 
     *   Defaults to null.
     * @param string|null $proxy The proxy of this request, given null will use global request proxy. Defaults to null.
     * @param bool $async Enable async request. Enable this, the request will be added to queue and request on calling
     *   "request_all". Defaults to false.
     * @param callable|null $callback The callback function after the request finished. Accept 3 arguments, the first 
     *   is key of the request, second is request ret which is the return value of "request", and the last is changeable
     *   count argument which is the stored array before request. Returns a bool value to show if this request is 
     *   successfully, returns false or other will show this request is failed. Given null will use default callback.
     *   Available on async request. Defaults to null.
     * @param array $storage Store some data of this request, it will be transform to callback if enable async request.
     *   Defaults to an empty array.
     * @return array HTTP response.
     */
    public function post(
        $url,
        $data,
        $headers = [],
        $files = null,
        $redirect = false,
        $timeout = null,
        $proxy = null,
        $async = false,
        $callback = null,
        $storage = []
    ) {
        return $this->request(
            $url,
            'POST',
            $headers,
            $data,
            $files,
            $redirect,
            $timeout,
            $proxy,
            $async,
            $callback,
            $storage
        );
    }

    /**
     * Request a url with PUT method.
     * 
     * @param string $url The url to request.
     * @param string $data The data will be sent in this request.
     * @param array $headers The headers with this request. Defaults to empty array.
     * @param array|null $files The file to upload. If $files given and $data is array, the $data will be parsed as 
     *   post field data. If $data is string, it will be simply ignored. The $files formation is:
     *   {'file_name': {'filename' => '1.txt', 'content_type' => 'application/octet-stream', 'content' => '123'}}
     *   The "content_type" is optional, defaults content type is "application/octet-stream". Defaults to null.
     * @param bool $redirect Enable follow request redirection such as 302. Defaults to false.
     * @param int|null $timeout The timeout with this request, given null will use global request timeout. 
     *   Defaults to null.
     * @param string|null $proxy The proxy of this request, given null will use global request proxy. Defaults to null.
     * @param bool $async Enable async request. Enable this, the request will be added to queue and request on calling
     *   "request_all". Defaults to false.
     * @param callable|null $callback The callback function after the request finished. Accept 3 arguments, the first 
     *   is key of the request, second is request ret which is the return value of "request", and the last is changeable
     *   count argument which is the stored array before request. Returns a bool value to show if this request is 
     *   successfully, returns false or other will show this request is failed. Given null will use default callback.
     *   Available on async request. Defaults to null.
     * @param array $storage Store some data of this request, it will be transform to callback if enable async request.
     *   Defaults to an empty array.
     * @return array HTTP response.
     */
    public function put(
        $url,
        $data,
        $headers = [],
        $files = null,
        $redirect = false,
        $timeout = null,
        $proxy = null,
        $async = false,
        $callback = null,
        $storage = []
    ) {
        return $this->request(
            $url,
            'PUT',
            $headers,
            $data,
            $files,
            $redirect,
            $timeout,
            $proxy,
            $async,
            $callback,
            $storage
        );
    }

    /**
     * Upload files and data to url by using POST.
     * 
     * @param string $url The url to request.
     * @param array $files The file to upload. If $files given and $data is array, the $data will be parsed as 
     *   post field data. If $data is string, it will be simply ignored. The $files formation is:
     *   {'file_name': {'filename' => '1.txt', 'content_type' => 'application/octet-stream', 'content' => '123'}}
     *   The "content_type" is optional, defaults content type is "application/octet-stream".
     * @param array $headers The headers with this request. Defaults to empty array.
     * @param string $data The data will be sent in this request.
     * @param bool $redirect Enable follow request redirection such as 302. Defaults to false.
     * @param int|null $timeout The timeout with this request, given null will use global request timeout. 
     *   Defaults to null.
     * @param string|null $proxy The proxy of this request, given null will use global request proxy. Defaults to null.
     * @param bool $async Enable async request. Enable this, the request will be added to queue and request on calling
     *   "request_all". Defaults to false.
     * @param callable|null $callback The callback function after the request finished. Accept 3 arguments, the first 
     *   is key of the request, second is request ret which is the return value of "request", and the last is changeable
     *   count argument which is the stored array before request. Returns a bool value to show if this request is 
     *   successfully, returns false or other will show this request is failed. Given null will use default callback.
     *   Available on async request. Defaults to null.
     * @param array $storage Store some data of this request, it will be transform to callback if enable async request.
     *   Defaults to an empty array.
     * @return array HTTP response.
     */
    public function upload(
        $url,
        $files,
        $headers = [],
        $data = null,
        $redirect = false,
        $timeout = null,
        $proxy = null,
        $async = false,
        $callback = null,
        $storage = []
    ) {
        return $this->request(
            $url,
            'POST',
            $headers,
            $data,
            $files,
            $redirect,
            $timeout,
            $proxy,
            $async,
            $callback,
            $storage
        );
    }

    /**
     * Clean all request queue.
     */
    public function clean()
    {
        $this->queue_count -= count($this->ch_map);
        $this->ch_map = [];
        foreach (array_keys($this->request_queue) as $key)
            if ($ch = $this->request_queue[$key]['ch']) $this->ch_queue[] = $ch;
        $this->request_queue = [];
        $this->storage = [];
    }

    /**
     * Request a url. Supports async request, the async request will be putted to a queue until call "request_all"
     * to request them. If the async request queue count async more then the "max_request_queue_count", all request will
     * be called immediately.
     * 
     * @param string $url The url to request.
     * @param string $method The request method. Upper letter case required. Defaults to 'GET'.
     * @param array $headers The headers with this request. Defaults to empty array.
     * @param string|null $data The data will be sent in this request. Defaults to null.
     * @param array|null $files The file to upload. If $files given and $data is array, the $data will be parsed as 
     *   post field data. If $data is string, it will be simply ignored. The $files formation is:
     *   {'file_name': {'filename' => '1.txt', 'content_type' => 'application/octet-stream', 'content' => '123'}}
     *   The "content_type" is optional, defaults content type is "application/octet-stream". Defaults to null.
     * @param bool $redirect Enable follow request redirection such as 302. Defaults to false.
     * @param int|null $timeout The timeout of this request, given null will use global request timeout. 
     *   Defaults to null.
     * @param string|null $proxy The proxy of this request, given null will use global request proxy. 
     *   Defaults to null.
     * @param bool $async Enable async request. Enable this, the request will be added to queue and request on calling
     *   "request_all". Defaults to false.
     * @param callable|null $callback The callback function after the request finished. Accept 3 arguments, the first 
     *   is key of the request, second is request ret which is the return value of "request", and the last is changeable
     *   count argument which is the stored array before request. Returns a bool value to show if this request is 
     *   successfully, returns false or other will show this request is failed. Given null will use default callback.
     *   Available on async request. Defaults to null.
     * @param array $storage Store some data of this request, it will be transform to callback if enable async request.
     *   Defaults to an empty array.
     * @return array|int Returns the HTTP response array if not async, including response status code "code", 
     *   response headers "headers", response data "content", request error message if error happened "error" and
     *   request spend time "time". Returns the request key if request async.
     */
    public function request(
        $url,
        $method = 'GET',
        $headers = [],
        $data = null,
        $files = null,
        $redirect = false,
        $timeout = null,
        $proxy = null,
        $async = false,
        $callback = null,
        $storage = []
    ) {
        $key = self::$key++;
        $ch = $async ? array_pop($this->ch_queue) : self::$ch;
        $this->queue_count++;
        $this->request_queue[$key] = ['resp_headers' => [], 'ch' => null, 'callback' => null];
        $this->ch_map[(string) $ch] = $key;

        self::set_handle(
            $ch,
            $method,
            $url,
            $headers,
            $data,
            $files,
            $redirect,
            $timeout,
            $proxy,
            $this->request_queue[$key]['resp_headers']
        );

        if ($async) {
            $this->request_queue[$key]['ch'] = $ch;
            $this->request_queue[$key]['callback'] = $callback;
            $this->storage[$key] = $storage;
            if ($this->queue_count >= $this->max_async_count) $this->request_all();
            return $key;
        } else return $this->request_handle($key, $ch);
    }

    /**
     * Request all async requests in queue.
     * 
     * @return array The keys of failed requests.
     */
    public function request_all()
    {
        $failed_keys = [];
        if ($this->request_queue) {
            foreach (array_keys($this->request_queue) as $key) {
                $ch = $this->request_queue[$key]['ch'];
                if ($this->multi_handle) curl_multi_add_handle($this->multi_handle, $ch);
                else {
                    $response = $this->request_handle($key, $ch, null, true);
                    // No callback for the request, using default callback.
                    if (is_array($response)) {
                        if ($this->callback) {
                            try {
                                $response = ($this->callback)($key, $response, ...$this->storage[$key]);
                            } catch (Throwable $e) {
                                CoraxLogger::warn('Request callback error: ' . (string) $e);
                            }
                            if ($response !== true) $failed_keys[] = $key;
                        }
                        unset($this->storage[$key]);
                    } elseif ($response !== true) $failed_keys[] = $key;
                }
            }

            if ($this->multi_handle) {
                $active = null;
                $round_time = microtime(true);
                $count = 0;

                do {
                    // Execute all curl handle async.
                    while (($mrc = curl_multi_exec($this->multi_handle, $active)) === CURLM_CALL_MULTI_PERFORM);
                    if ($mrc !== CURLM_OK) {
                        CoraxLogger::warn('Async request failed! Please retry later to request all.');
                        $failed_keys = array_keys($this->request_queue);
                        break;
                    }

                    // Get the finished request and process it.
                    while ($finished = curl_multi_info_read($this->multi_handle)) {
                        $ch = $finished['handle'];
                        // Find key from ch.
                        $key = $this->ch_map[(string) $ch];
                        $response = $this->request_handle($key, $ch, $round_time, true);
                        $count++;

                        if (is_array($response)) {
                            // No callback for the request, using default callback.
                            if ($this->callback) {
                                try {
                                    $response = ($this->callback)($key, $response, ...$this->storage[$key]);
                                } catch (Throwable $e) {
                                    CoraxLogger::warn('Async request callback error: ' . (string) $e);
                                }
                                if ($response !== true) $failed_keys[] = $key;
                            }
                            unset($this->storage[$key]);
                        } else if ($response !== true) $failed_keys[] = $key;
                    }

                    if ($active > 0) curl_multi_select($this->multi_handle);
                } while ($active);

                if (self::$async_count === 0) {
                    // Avg time for each request.
                    $round_time = microtime(true) - $round_time;
                    $time = $round_time / $count;

                    // Stabilize async count by using binary search.
                    if ($this->stabilizing) {
                        if ($time >= $this->max_tolerance) $this->poss_max_count = $this->max_async_count;
                        elseif ($time <= $this->min_tolerance) $this->poss_min_count = $this->max_async_count;
                        else $this->stabilizing = false;

                        if ($this->stabilizing) {
                            if ($this->poss_min_count > $this->poss_max_count) {  // Not found.
                                $this->stabilizing = false;
                                $this->set_max_async_count($this->last_max_async_count);
                            } elseif ($this->max_async_count >= 511)  // Reach the max.
                                $this->stabilizing = false;
                            else {  // Keep seeking.
                                $async_count = max(($this->poss_min_count + $this->poss_max_count) >> 1, 2);
                                if ($async_count === $this->max_async_count) $this->stabilizing = false;
                                else $this->set_max_async_count($async_count);
                            }
                        }

                        // Reset avg time.
                        if (!$this->stabilizing) {
                            $this->async_time /= $this->async_counts;
                            $this->async_counts = 1;
                        }
                    } elseif ($this->async_counts !== 0) {
                        if ($time >= $this->max_tolerance || $this->max_async_count >= 511) {
                            $this->stabilizing = true;
                            $this->stabile_round = 0;
                            $this->last_max_async_count = $this->max_async_count;
                            // Fall back.
                            $this->poss_min_count = max($this->max_async_count >> 1, 2);
                            $this->poss_max_count = $this->max_async_count;
                            $this->set_max_async_count(($this->poss_min_count + $this->poss_max_count) >> 1);
                            // Make its easy to fall back.
                            $avg_time = $this->async_time / $this->async_counts;
                            $this->min_tolerance = $avg_time * 0.2;
                            $this->max_tolerance = $avg_time * 1.2;
                        } elseif (
                            ($time <= $this->min_tolerance ||
                                $this->max_async_count === 2 ||
                                $this->stabile_round == 10)
                        ) {
                            $this->stabilizing = true;
                            $this->stabile_round = 0;
                            $this->last_max_async_count = $this->max_async_count;
                            // Push forward.
                            $this->poss_min_count = $this->max_async_count;
                            $this->poss_max_count = min($this->max_async_count << 1, 512);
                            $this->set_max_async_count(($this->poss_min_count + $this->poss_max_count) >> 1);
                            // Make its easy to push forward.
                            $avg_time = $this->async_time / $this->async_counts;
                            $this->min_tolerance = $avg_time * 0.5;
                            $this->max_tolerance = $avg_time * 1.5;
                        } else $this->stabile_round++;
                    }

                    // Update tolerances.
                    if (!$this->stabilizing) {
                        $this->async_time += $round_time;
                        $this->async_counts += $count;
                        $avg_time = $this->async_time / $this->async_counts;
                        $this->min_tolerance = $avg_time * 0.5;
                        $this->max_tolerance = $avg_time * 1.5;
                    }
                }
            }
        }

        $this->clean();
        return $failed_keys;
    }
}
