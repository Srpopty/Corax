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
 * @Filename: CoraxEncoder.php
 * @Description: 
 *   Corax encoder used in fuzzer. Encode and decode value.
 * ================================================================================
 */

namespace Corax\Fuzz;

use Throwable;

use Corax\Common\CoraxLogger;
use Corax\Common\CoraxWorker;


final class CoraxEncoder extends CoraxWorker
{
    /**
     * Initialize an encoder. It could load user custom encoders and decoders from plugin. The custom encoder template is:
     * <?php
     * namespace Corax;
     *  
     * 
     * class CoraxPlugin
     * {
     *     public function e_my_encoder($value)
     *     {
     *          // Encode or decode value amd return result.
     *          ...
     *          return $value;
     *     }
     * }
     * 
     * @param \Corax\CoraxPlugin|null $plugin User custom plugin including encoders and decoders. Defaults to null.
     * @param array $disable Manually disable some encoders and decoders. Supports regex. Defaults to an empty array.
     */
    public function __construct($plugin = null, $disable = [])
    {
        parent::__construct('e_', $plugin, function ($func) {
            try {
                $func('abc');
            } catch (Throwable $e) {
                return 'Register user provided encoder/decoder from plugin failed. ' .
                    'Encoder/decoder runtime error: ' .  $e;
            }
        }, $disable);
    }

    /**
     * Encode the given string by using an enabled encoder.
     * 
     * @param string $str The string to encode.
     * @param string $name The encoder name.
     * @param bool $force Force using the encoder no matter if it is enabled. Defaults to false.
     * @return mixed|null The encoded string. If encode failed or encoder does not enabled, null will be returned.
     */
    public function encode($str, $name, $force = false)
    {
        $result = null;
        if ($encoder = parent::get_worker($name, $force)) {
            try {
                $result = $encoder($str);
            } catch (Throwable $e) {
                CoraxLogger::warn("Encoder \"$name\" encode/decode string failed. Encoder runtime error: " . (string) $e);
            }
        } else CoraxLogger::warn(
            $name ?
                "Access denied for using disabled or unknown encoder/decoder \"$name\"." :
                'No available encoder!'
        );
        return $result;
    }

    /**
     * Encode string to base64.
     * 
     * @param string $str The string to encode.
     * @return string The encoded string.
     */
    protected function e_base64_encode($str)
    {
        return base64_encode($str);
    }

    /**
     * Decode string from base64.
     * 
     * @param string $str The string to decode.
     * @return string|null The decoded string. Decode failed will return null.
     */
    protected function e_base64_decode($str)
    {
        if ($result = base64_decode($str))
            return $result;
        else return null;
    }

    /**
     * Encode string to urlencode.
     * 
     * @param string $str The string to encode.
     * @return string The encoded string.
     */
    protected function e_url_encode($str)
    {
        return urlencode($str);
    }

    /**
     * Decode string from urlencode.
     * 
     * @param string $str The string to decode.
     * @return string The decoded string.
     */
    protected function e_url_decode($str)
    {
        return urldecode($str);
    }

    /**
     * Encode value to json.
     * 
     * @param mixed $value The value to encode.
     * @return string|null The encoded string. Encode failed will return null.
     */
    protected function e_json_encode($value)
    {
        if ($result = json_encode($value)) return $result;
        else return null;
    }

    /**
     * Decode string from json.
     * 
     * @param string $str The string to decode.
     * @return mixed|null The decoded value. Decode failed will return null,
     */
    protected function e_json_decode($str)
    {
        if ($result = json_decode($str)) return $result;
        else return null;
    }
}
