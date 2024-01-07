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
 * @Filename: CoraxInput.php
 * @Description: 
 *   The parsed corax input form the raw http input array. It is only used to focus
 * one http input value as a input field.
 * ================================================================================
 */

namespace Corax\Fuzz;

use Corax\Common\CoraxList;
use Corax\Common\CoraxLogger;


final class CoraxInput
{
    public static $_corax_encoder = null;

    private $type;
    private $value;
    private $value_path;

    private $encoding = '';
    private $encoder = '';
    private $decoder = '';

    private $expr;
    private $feature;
    private $mutated;

    /**
     * Initialize an input field which focus only one parameter value.
     * 
     * @param string $type The input type.
     * @param mixed $value The initial value of this input field. Default to an empty string.
     * @param array|null $value_path The path for a input field value such as ['get', 'a'] means 
     *   $input['get']['a']. Defaults to null.
     * @param bool $detect_encoding Enable auto detect value encoding. Defaults to true.
     */
    public function __construct($type, $value = '', $value_path = null, $detect_encoding = true)
    {
        $this->type = $type;
        $this->value = $value;
        $this->value_path = $value_path;

        if ($value_path) {
            $this->expr = '[\'data\']';
            foreach ($value_path as $path) {
                if (is_string($path)) $this->expr .= '[\'' . addcslashes($path, '\\\'') . '\']';
                elseif (is_int($path)) $this->expr .= "[$path]";
            }
        } else $this->expr = '';

        $this->feature = md5($this->expr);
        $this->mutated = [];
        if ($detect_encoding && is_string($value)) $this->detect_encoding();
    }

    /**
     * Get serialized content of this input.
     * 
     * @return string The serialized string. Serialized failed will return "<FAILED>".
     */
    public function __toString()
    {
        if ($result = json_encode([
            'type' => $this->type,
            'value' => base64_encode($this->value),
            'value_path' => $this->value_path,
            'encoding' => $this->encoding,
            'encoder' => $this->encoder,
            'decoder' => $this->decoder
        ])) return $result;
        else return '<FAILED>';
    }

    /**
     * Get input name.
     * 
     * @param array $input The raw http input.
     * @return string The input name.
     */
    public static function get_input_name($input)
    {
        return md5(CoraxList::json_encode($input['data']));
    }

    /**
     * Get type of this input field.
     * 
     * @return string The input type.
     */
    public function get_type()
    {
        return $this->type;
    }

    /**
     * Get the original value of this input field.
     * 
     * @return string The original value.
     */
    public function get_original_value()
    {
        return $this->value;
    }

    /**
     * Get value path of this input field.
     * 
     * @return array The input value path.
     */
    public function get_value_path()
    {
        return $this->value_path;
    }

    /**
     * Get value path eval expr of this input field.
     * 
     * @return string|null The input eval expr. Null will be returned if this input has no value path.
     */
    public function get_expr()
    {
        return $this->expr;
    }

    /**
     * Get value feature of this input field.
     * 
     * @return string The input feature.
     */
    public function get_feature()
    {
        return $this->feature;
    }

    /**
     * Get value encoding of this input field.
     * 
     * @return string|null The value encoding.
     */
    public function get_encoding()
    {
        return $this->encoding;
    }

    /**
     * Get value encoder name of this input field.
     * 
     * @return string|null The value encoder name.
     */
    public function get_encoder()
    {
        return $this->encoder;
    }

    /**
     * Get value decoder name of this input field.
     * 
     * @return string|null The value decoder name.
     */
    public function get_decoder()
    {
        return $this->decoder;
    }

    /**
     * Get value mutation history of this input field.
     * 
     * @return array Including mutators for this input field value.
     */
    public function get_mutate_history()
    {
        return $this->mutated;
    }

    /**
     * Record input mutate history and time.
     * 
     * @param array &$raw_input The raw http input array.
     * @param string $mutator The mutator to record.
     */
    public function mutated_by(&$raw_input, $mutator)
    {
        $raw_input['info']['mutated'][$mutator] = $this->value_path;
        $raw_input['info']['time'] = microtime(true);
        $this->mutated[] = $mutator;
    }

    /**
     * Detect and set value encoding of this input field.
     */
    public function detect_encoding()
    {
        // Detect value encoding.
        $len = strlen($this->value);
        if (
            $len > 8 && $len % 4 === 0 &&
            preg_match(
                '/^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})$/',
                $this->value
            )
        ) $this->set_encoding('base64', 'base64_encode', 'base64_decode');
        elseif (preg_match('/%[A-Fa-z0-9]{2}/', $this->value))
            $this->set_encoding('urlencode', 'url_encode', 'url_decode');
        elseif ($len && ($this->value[0] === '{' || $this->value[0] === '[') && json_decode($this->value, true) !== null)
            $this->set_encoding('json', 'json_encode', 'json_decode');
    }

    /**
     * Set value encoding and encoder/decoder of this input field.
     * 
     * @param string $encoding The value encoding name.
     * @param string $encoder The Corax encoder name for value encoding.
     * @param string $decoder The Corax decoder name for value decoding.
     * @return bool If set the encoding successfully. False will be returned if the encoder/decode could not encode/decode
     *   the original value.
     */
    public function set_encoding($encoding, $encoder, $decoder)
    {
        if ($encoding) {
            if (self::$_corax_encoder->encode($this->value, $encoder) === null) {
                CoraxLogger::warn("Set encoding \"$encoding\" for input field value failed. " .
                    "Invalid encoder \"$encoder\"!");
                return false;
            }
            if (self::$_corax_encoder->encode($this->value, $decoder) === null) {
                CoraxLogger::warn("Set encoding \"$encoding\" for input field value failed. " .
                    "Invalid decoder \"$encoder\"!");
                return false;
            }
            $this->encoding = $encoding;
            $this->encoder = $encoder;
            $this->decoder = $decoder;
        }
        return true;
    }

    /**
     * Get an encoded value.
     * 
     * @param mixed $value The value to encode.
     * @return string|null Encoded value. Encode failed will return null.
     */
    public function encode_value($value)
    {
        return $this->encoder ? self::$_corax_encoder->encode($value, $this->encoder) : $value;
    }

    /**
     * Get a decoded value.
     * 
     * @param string $value The value to decode.
     * @return mixed|null Decoded value. Decode failed will return null.
     */
    public function decode_value($value)
    {
        return $this->decoder ? self::$_corax_encoder->encode($value, $this->decoder) : $value;
    }

    /**
     * Get the raw http input value of this input field, and decode value by the way.
     * 
     * @param array &$input The raw http input array.
     * @param bool $decode Enable auto decode value after getting. Defaults to true.
     * @return mixed The may be decoded value. Null will be returned if this input has no value path.
     */
    public function get_value(&$input, $decode = true)
    {
        if ($this->expr) {
            $value = eval("return \$input$this->expr;");
            if ($decode && $this->decoder) {
                if (($v = $this->decode_value($value)) === null)
                    CoraxLogger::warn(
                        "Decode value by using decoder \"$this->decoder\" failed, value will not be decoded."
                    );
                else $value = $v;
            }
            return $value;
        }
        return null;
    }

    /**
     * Set a new value of this input field to a raw http input array, and encode value by the way.
     * 
     * @param array &$input The raw http input array to set value.
     * @param mixed $value The new value. If non-string given, it will be transform to string type.
     *   Given null will use the original value of this input. Defaults to null.
     * @param bool $encode Enable auto encode value before setting. Defaults to true.
     */
    public function set_value(&$input, $value = null, $encode = true)
    {
        if ($this->expr) {
            if ($value === null) {
                $value = $this->value;
                $encode = true;
            }
            if ($encode && $this->encoder) {
                if (($v = $this->encode_value($value)) === null)
                    CoraxLogger::warn("Encode value by using encoder \"$this->encoder\" failed, " .
                        'value will not be encoded.');
                else $value = $v;
            }
            if (!is_string($value)) $value = (string) $value;
            $value = str_replace("\r\n", '%0a%0d', $value);
            eval("\$input$this->expr = " . '\'' . addcslashes($value, '\\\'') . '\';');
        }
    }

    /**
     * Report the raw http input array info.
     * 
     * @param array &$input The raw http input array to report.
     * @param string $method Logger method. Defaults to "info".
     * @param int $level Logging ident level. Defaults to 0.
     */
    public static function report_input(&$input, $method = 'info', $level = 0)
    {
        $echo = ['\Corax\Common\CoraxLogger', $method];
        $data = $input['data'];
        $info = $input['info'];
        $echo('Request: ' . $info['request_method'] . ' ' . $info['server_protocol'] .
            ' ' . $info['request_uri'], $level);
        $echo('PHP File: ' . $info['php_self'], $level);
        $echo('Script File: ' . $info['script_name'], $level);
        $echo('Local File: ' . $info['script_filename'], $level);
        $echo('Web Root: ' . $info['web_root'], $level);
        $echo('Gateway Interface: ' . $info['gateway_interface'], $level);
        $echo('Query String: ' . $info['query_string'], $level);
        $echo('Raw Input Feature: ' . $info['feature'], $level);
        $echo('Path: ' . $info['path_name'], $level);
        $count = 0;
        foreach ($info['hits'] as $hit) $count += count($hit);
        $echo('Hits: ' . $count, $level);

        $echo('GET(' . count($info['get_keys']) . ' values): ', $level);
        foreach ($info['get_keys'] as $keys) {
            $value = array_pop($keys);
            $echo(implode('.', $keys) . ": " . strlen($value) . ' bytes', $level + 1);
        }
        $echo('POST(' . count($info['post_keys']) . ' values): ', $level);
        foreach ($info['post_keys'] as $keys) {
            $value = array_pop($keys);
            $echo(implode('.', $keys) . ": " . strlen($value) . ' bytes', $level + 1);
        }
        $echo('PATH(' . count($data['path']) . ' values): ' .
            implode('/', $data['path']), $level);
        $echo('RAW-POST: ' . strlen($data['raw_post']) . ' bytes', $level);
        $echo('UPLOADS(' . count($data['files']) . ' files): ', $level);
        foreach ($data['files'] as $name => $file)
            $echo($name . '(' . $file['type'] . '): ' . $file['filename'] .
                '(' . strlen($file['content']) . 'bytes)', $level + 1);
        $echo('HEADERS(' . count($data['headers']) . ' values): ', $level);
        foreach ($data['headers'] as $key => $value) $echo($key . ': ' . strlen($value) . ' bytes', $level + 1);
        $echo('COOKIES(' . count($data['cookies']) . ' values): ', $level);
        foreach ($data['cookies'] as $key => $value) $echo($key . ': ' . strlen($value) . ' bytes', $level + 1);
    }

    /**
     * Report a request array info.
     * 
     * @param array $request The request to report.
     * @param string $method Logger method. Defaults to "info".
     * @param int $level Logging ident level. Defaults to 0.
     */
    public static function report_request(&$request, $method = 'info', $level = 0)
    {
        $echo = ['\Corax\Common\CoraxLogger', $method];
        $data = $request['data'];
        $echo(sprintf(
            'Request %s to %s with %d headers, %d data, %d files.',
            $request['method'],
            $request['uri'],
            count($request['headers']),
            $data ? (is_array($data) ? count($data) : strlen($data)) : 0,
            count($request['files'])
        ), $level);
    }

    /**
     * Report a response array info.
     * 
     * @param array $response The response to report.
     * @param string $method Logger method. Defaults to "info".
     * @param int $level Logging ident level. Defaults to 0.
     */
    public static function report_response(&$response, $method = 'info', $level = 0)
    {
        $echo = ['\Corax\Common\CoraxLogger', $method];
        $echo(sprintf(
            'Response[%d] with %d bytes and %d headers in %.3f s%s:',
            $response['code'],
            strlen($response['content']),
            count($response['headers']),
            $response['time'],
            $response['error'] ? ('. Error: ' . $response['error']) : ' without any error'
        ), $level);
    }

    /**
     * Report this input info.
     * 
     * @param string $method Logger method. Defaults to "info".
     * @param int $level Logging ident level. Defaults to 0.
     */
    public function report($method = 'info', $level = 0)
    {
        $echo = ['\Corax\Common\CoraxLogger', $method];
        $echo(sprintf(
            'Input %s (%s, %d bytes%s): %s',
            $this->type,
            $this->feature,
            strlen($this->value),
            $this->encoding ? ", $this->encoding encoded, $this->encoder/$this->decoder" : '',
            implode('->', $this->value_path)
        ), $level);
    }

    /**
     * Serialize an input to a string.
     * 
     * @param \Corax\Fuzz\CoraxInput $input The input to be serialized.
     * @return string|null Serialized input. Serialize failed will return null.
     */
    public static function serialize($input)
    {
        $result = (string) $input;
        return $result === '<FAILED>' ? false : $result;
    }

    /**
     * Unserialize a string to an input.
     * 
     * @param string $string The string to be unserialized.
     * @return \Corax\Fuzz\CoraxInput|false The unserialized input. Unserialize failed will return null.
     */
    public static function unserialize($string)
    {
        if ($content = json_decode($string, true)) {
            $input = new self(
                $content['type'],
                base64_decode($content['value']),
                $content['value_path'],
                false
            );
            $input->set_encoding($content['encoding'], $content['encoder'], $content['decoder']);
            return $input;
        }
        return false;
    }
}
