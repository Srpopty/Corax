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
 * @Filename: CoraxParser.php
 * @Description: 
 *   Corax parser used in fuzzer. Parse a raw http input array to many inputs, 
 * supports dynamic register new parser. All parser function name should start with
 * "p_". Parser should parse the given raw http input array and for each parameter
 * in the raw http input, build a new CoraxInput and finally return an array 
 * contains all built inputs.
 * ================================================================================
 */

namespace Corax\Fuzz;

use Throwable;

use Corax\Common\CoraxLogger;
use Corax\Common\CoraxWorker;


final class CoraxParser extends CoraxWorker
{
    // Some of these headers are forbidden to modify.
    // Source: https://developer.mozilla.org/zh-CN/docs/Glossary/Forbidden_header_name
    protected static $useless_headers = [
        'Connection', 'Content-Length', 'Cookie', 'Date', 'DNT',
        'Expect', 'Host', 'Keep-Alive', 'Proxy-.*', 'Sec-.*',
        'Cache-Control', 'Upgrade-Insecure-Requests', 'Content-Type'
    ];

    protected static $useless_cookies = [
        'PHPSESSID', '.*sess.*'
    ];

    /**
     * Initialize a parser. It could load user custom parsers from plugin. The custom parser template is:
     * <?php
     * 
     * namespace Corax;
     * 
     * use Corax\Fuzz\CoraxInput;
     * 
     * 
     * class CoraxPlugin
     * {
     *     public function p_my_parser($input)
     *     {
     *         return new CoraxInput(
     *             'my_parser', $input,
     *             // Which value you parsed and want to be fuzzed from http input array.
     *             $input['data']['get']['my_value'][0],
     *             // The path to get value parsed from http input array.
     *             ['get', 'my_value', 0]
     *         );
     *     }
     * }
     * 
     * @param \Corax\CoraxPlugin|null $plugin User custom plugin including parsers. Defaults to null.
     * @param array $disable Manually disable parsers. Supports regex. Defaults to an empty array.
     */
    public function __construct($plugin = null, $disable = [])
    {
        parent::__construct('p_', $plugin, function ($func) {
            try {
                $ret = $func([
                    'data' => [
                        'get' => ['a' => 1, 'b' => ['c' => 2, 'd' => 3]],
                        'post' => ['a' => 1, 'b' => ['c' => 2, 'd' => 3]],
                        'path' => ['a', 'b', 'c'],  // /index.php/a/b/c
                        'raw_post' => 'test',
                        'files' => ['test' => ['filename' => 'test.txt', 'content' => 'test', 'type' => 'text/plain']],
                        'cookies' => ['test' => 'test'],
                        'headers' => ['test' => 'test']
                    ],
                    'info' => [
                        'php_self' => '/index.php',
                        'gateway_interface' => 'CGI/1.1',
                        'server_protocol' => 'HTTP/1.1',
                        'request_method' => 'POST',
                        'query_string' => '?a=1&b[c]=2&b[d]=3',
                        'script_filename' => '/var/www/html/index.php',
                        'script_name' => '/index.php',
                        'web_root' => '/var/www/html',
                        'site_root' => '/var/www/html/',
                        'request_uri' => '/index.php/a/b/c?a=1&b[c]=2&b[d]=3',
                        'get_keys' => [['a', 1], ['b', 'c', 2], ['b', 'd', 3]],
                        'post_keys' => [['a', 1], ['b', 'c', 2], ['b', 'd', 3]],
                        'feature' => 'a77777661d3e83b0f59c5424b5faa102',
                        'path_name' => 'p-4ba06a8d813a5534bef4338c8a995b62',
                        'hits' => ['89292ae8c3e8c2a66374509c952efd62' => 'h-098f6bcd4621d373cade4e832627b4f6'],
                        'mutated' => [
                            'http_request' => ['raw_http_input']
                        ],
                        'time' => 1696254948.012345,
                        'coverage_edges' => 1
                    ]
                ]);
            } catch (Throwable $e) {
                return 'Register user provided parser failed! Parser runtime error: ' . (string) $e;
            }

            if (!is_array($ret))
                return 'Register user provided parser failed! Parser should ' .
                    'return an array with "CoraxInput" objects or the ' .
                    '"CoraxInput" object, but returned: ' . print_r($ret, true);
        }, $disable);
    }

    /**
     * Parse a HTTP raw input to many input fields by using an enabled parser.
     * 
     * @param array $input The raw HTTP input array.
     * @param string|null $name Parser name. Given null will randomly choice an enabled parser. Defaults to null.
     * @param bool $force Force using the parser no matter if it is disabled. Defaults to false.
     * @return array|null Parsed Corax inputs. Null will be returned if parser not enabled or no parser to use.
     */
    public function parse($input, $name = null, $force = false)
    {
        $inputs = null;
        if ($parser = parent::get_worker($name, $force)) {
            try {
                $inputs = $parser($input);
            } catch (Throwable $e) {
                CoraxLogger::warn("Parser \"$name\" parses http input failed. Parser runtime error: " . (string) $e);
            }

            if (!is_array($inputs)) $inputs = [$inputs];
            for ($i = 0, $l = count($inputs); $i < $l; $i++) {
                if (!($inputs[$i] instanceof CoraxInput)) {
                    CoraxLogger::warn('Parser ' . print_r($parser, true) . ' returned array should include ' .
                        '"\Corax\Fuzz\CoraxInput", but returned: ' . print_r($inputs[$i], true));
                    unset($inputs[$i]);
                }
            }
        } else CoraxLogger::warn($name ? "Access denied for using disabled or unknown parser \"$name\"." :
            'No available parser!');
        return $inputs;
    }

    /**
     * Parse a HTTP raw input by using all enabled parsers.
     * 
     * @param mixed $input The raw HTTP input.
     * @param bool $random Parse input in random orders. Defaults to false.
     * @param bool $force Force using all parsers no matter if they are disabled. Defaults to false.
     * @yield string => array Parser name and parsed inputs.
     */
    public function parse_all($input, $random = false, $force = false)
    {
        foreach (parent::get_names(!$force, $random) as $name)
            if (($inputs = $this->parse($input, $name)) !== null) yield $name => $inputs;
    }

    /**
     * Parse get arguments from a http input.
     * 
     * @param array $input The raw HTTP input.
     * @return array Parsed inputs.
     */
    protected function p_get($input)
    {
        $inputs = [];
        if ($input['data']['get']) foreach ($input['info']['get_keys'] as $keys) {
            $value = array_pop($keys);
            array_unshift($keys, 'get');
            $inputs[] = new CoraxInput('get', $value, $keys);
        }
        return $inputs;
    }

    /**
     * Parse post arguments from a http input.
     * 
     * @param array $input The raw HTTP input.
     * @return array Parsed inputs.
     */
    protected function p_post($input)
    {
        $inputs = [];
        if ($input['data']['post']) foreach ($input['info']['post_keys'] as $keys) {
            $value = array_pop($keys);
            array_unshift($keys, 'post');
            $inputs[] = new CoraxInput('post', $value, $keys);
        }
        return $inputs;
    }

    /**
     * Parse request body from a http input.
     * 
     * @param array $input The raw HTTP input.
     * @return array Parsed inputs.
     */
    protected function p_raw_post($input)
    {
        return $input['data']['raw_post'] ?
            [new CoraxInput('raw_post', $input['data']['raw_post'], ['raw_post'])] : [];
    }

    /**
     * Parse path arguments from a http input.
     * 
     * @param array $input The raw HTTP input.
     * @return array Parsed inputs.
     */
    protected function p_path($input)
    {
        $inputs = [];
        if ($input['data']['path']) {
            foreach ($input['data']['path'] as $i => $p)
                if ($p) $inputs[] = new CoraxInput('path', $p, ['path', $i]);
        }
        return $inputs;
    }

    /**
     * Parse upload filenames from a http input.
     * 
     * @param array $input The raw HTTP input.
     * @return array Parsed inputs.
     */
    protected function p_filename($input)
    {
        $inputs = [];
        if ($input['data']['files']) {
            foreach ($input['data']['files'] as $name => $file)
                $inputs[] = new CoraxInput('filename', $file['filename'], ['files', $name, 'filename']);
        }
        return $inputs;
    }

    /**
     * Parse upload file type from a http input.
     * 
     * @param array $input The raw HTTP input.
     * @return array Parsed inputs.
     */
    protected function p_filetype($input)
    {
        $inputs = [];
        if ($input['data']['files']) {
            foreach ($input['data']['files'] as $name => $file)
                $inputs[] = new CoraxInput('filetype', $file['type'], ['files', $name, 'type']);
        }
        return $inputs;
    }

    /**
     * Parse upload file content from a http input.
     * 
     * @param array $input The raw HTTP input.
     * @return array Parsed inputs.
     */
    protected function p_files($input)
    {
        $inputs = [];
        if ($input['data']['files']) {
            foreach ($input['data']['files'] as $name => $file)
                $inputs[] = new CoraxInput('file_content', $file['content'], ['files', $name, 'content']);
        }
        return $inputs;
    }

    /**
     * Parse cookie arguments from a http input.
     * 
     * @param array $input The raw HTTP input.
     * @return array Parsed inputs.
     */
    protected function p_cookies($input)
    {
        $inputs = [];
        if ($input['data']['cookies']) {
            $cookies = $input['data']['cookies'];
            foreach (array_keys($cookies) as $cookie)
                foreach (self::$useless_cookies as $c) if (preg_match("/^$c$/i", $cookie)) unset($cookies[$cookie]);
            foreach ($cookies as $k => $v) $inputs[] = new CoraxInput('cookies', $v, ['cookies', $k]);
        }
        return $inputs;
    }

    /**
     * Parse header arguments from a http input.
     * 
     * @param array $input The raw HTTP input.
     * @return array Parsed inputs.
     */
    protected function p_headers($input)
    {
        $inputs = [];
        if ($input['data']['headers']) {
            // Skip cookies.
            unset($input['data']['headers']['Cookie']);
            $headers = $input['data']['headers'];
            foreach (array_keys($headers) as $header)
                foreach (self::$useless_headers as $h) if (preg_match("/^$h$/i", $header)) unset($headers[$header]);
            foreach ($headers as $k => $v) $inputs[] = new CoraxInput('headers', $v, ['headers', $k]);
        }
        return $inputs;
    }
}
