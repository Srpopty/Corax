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
 * @Filename: CoraxPath.php
 * @Description: 
 *   A path in Corax, saving input, value, and path information.
 * ================================================================================
 */

namespace Corax\Fuzz;

use Corax\Common\CoraxList;


final class CoraxPath
{
    private $name;
    private $raw_input;
    private $input;
    private $raw_path;
    private $response;
    private $feature;

    private $input_name = null;

    /**
     * Initialize a path.
     * 
     * @param string $name The path name.
     * @param array $raw_input The raw http input array for this path.
     * @param \Corax\Fuzz\CoraxInput $input The input which this path comes from.
     * @param array $raw_path The path to parse.
     * @param array $response The http response array of this path.
     */
    public function __construct($name, $raw_input, $input, $raw_path, $response)
    {
        $this->name = $name;
        $this->raw_input = $raw_input;
        $this->input = $input;
        $this->raw_path = $raw_path;
        $this->response = $response;
        $this->feature = md5(implode('.', $this->get_raw_path(true, true)));
    }

    /**
     * Get serialized content of this path.
     * 
     * @return string The serialized string. Serialized failed will return "<FAILED>".
     */
    public function __toString()
    {
        if ($result = CoraxList::json_encode([
            'name' => $this->name,
            'raw_input' => $this->raw_input,
            'input' => CoraxInput::serialize($this->input),
            'path' => $this->raw_path,
            'response' => $this->response
        ])) return $result;
        else return '<FAILED>';
    }

    /**
     * Get path count.
     * 
     * @return int The path count.
     */
    public function count()
    {
        return count($this->raw_path);
    }

    /**
     * Get name of this path.
     * 
     * @return string Path name.
     */
    public function get_name()
    {
        return $this->name;
    }

    /**
     * Get the raw http input array for this path.
     * 
     * @return array The raw http input array.
     */
    public function get_raw_input()
    {
        return $this->raw_input;
    }

    /**
     * Get name of the raw http input array.
     * 
     * @return mixed
     */
    public function get_input_name()
    {
        if ($this->input_name === null) $this->input_name = md5($this->name . $this->input->get_input_name($this->raw_input));
        return $this->input_name;
    }

    /**
     * Get the raw http input value.
     * 
     * @param string|null $key Get a specific value. Given null wil return the whole value array. Defaults to null.
     * @return string|array|null The value of key or the whole value array. Given a non-exist key will return null.
     */
    public function get_raw_input_value($key = null)
    {
        return $this->raw_input['data'][$key] ?? null;
    }

    /**
     * Get the raw http input info.
     * 
     * @param string|null $key Get a specific info. Given null wil return the whole info array. Defaults to null.
     * @return string|array|null The info of key or the whole info array. Given a non-exist key will return null.
     */
    public function get_raw_input_info($key = null)
    {
        return $this->raw_input['info'][$key] ?? null;
    }

    /**
     * Get the input which found this path.
     * 
     * @return \Corax\Fuzz\CoraxInput The corax input.
     */
    public function get_input()
    {
        return $this->input;
    }

    /**
     * Get the raw path array.
     * 
     * @param bool $sort Auto sort the path before getting. Defaults to true.
     * @param bool $compress Enable compressing the path count with path id. Defaults to false.
     * @return array Path array.
     */
    public function get_raw_path($sort = true, $compress = false)
    {
        $path = $this->raw_path;
        if ($sort) ksort($path);
        if ($compress) {
            $result = [];
            foreach ($path as $p => $c) {
                if ($c >= 0x04) {
                    if ($c < 0x08) $c = 0x07;
                    elseif ($c < 0x10) $c = 0x0f;
                    elseif ($c < 0x20) $c = 0x1f;
                    elseif ($c < 0x40) $c = 0x3f;
                    elseif ($c < 0x80) $c = 0x7f;
                    else $c = 0xff;
                }
                $result[] = $c << 0x38 | $p;
            }
            return $result;
        } else return $path;
    }

    /**
     * Get feature of this path.
     * 
     * @return string The path feature.
     */
    public function get_feature()
    {
        return $this->feature;
    }

    /**
     * Get response which found this path.
     * 
     * @param string|null $key The response key. Given null will return the whole response array. Defaults to null.
     * @return array|mixed|null The corax http client response. If the given key does not exists, null will be returned.
     */
    public function get_response($key = null)
    {
        return $key ? ($this->response[$key] ?? null) : $this->response;
    }

    /**
     * Get response headers which found this path.
     * 
     * @param string|null $key The response header key. Given null will return the whole response headers array. Defaults to null.
     * @return array|string|null The corax http client response headers. If the given key does not exists, null will be returned.
     */
    public function get_response_headers($key = null)
    {
        return $key ? ($this->response['headers'][$key] ?? null) : $this->response['headers'];
    }

    /**
     * Report a path info.
     * 
     * @param string $method Logger method. Defaults to "info".
     * @param int $level Logging ident level. Defaults to 0.
     */
    public function report($method = 'info', $level = 0)
    {
        $echo = ['\Corax\Common\CoraxLogger', $method];
        $echo('Path ' . $this->name . ' of feature ' . $this->feature .
            ' with ' . count($this->raw_path) . ' edges.', $level);
    }

    /**
     * Report response info of this path.
     * 
     * @param string $method Logger method. Defaults to "info".
     * @param int $level Logging ident level. Defaults to 0.
     */
    public function report_response($method = 'info', $level = 0)
    {
        CoraxInput::report_response($this->response, $method, $level);
    }

    /**
     * For data saving, serialize the path to a string.
     * 
     * @param \Corax\Fuzz\CoraxPath $path The path to be serialized.
     * @return string|false Serialized path. Serialize failed will return false.
     */
    public static function serialize($path)
    {
        $result = (string) $path;
        return $result === '<FAILED>' ? false : $result;
    }

    /**
     * Unserialize a string to a path. 
     * 
     * @param string $string The string to be unserialized.
     * @return \Corax\Fuzz\CoraxPath|false The unserialized path. Unserialize failed will return false.
     */
    public static function unserialize($string)
    {
        if ($content = CoraxList::json_decode($string)) {
            if ($input = CoraxInput::unserialize($content['input']))
                return new self(
                    $content['name'],
                    $content['raw_input'],
                    $input,
                    $content['path'],
                    $content['response']
                );
        }
        return false;
    }
}
