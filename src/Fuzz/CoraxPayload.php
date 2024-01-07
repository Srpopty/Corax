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
 * @Filename: CoraxPayload.php
 * @Description: 
 *   Payload for tainting, saving payload information and checking hit.
 * ================================================================================
 */

namespace Corax\Fuzz;

use Corax\Common\CoraxList;
use Corax\Common\CoraxLogger;
use Corax\Common\CoraxRandom;
use Throwable;


final class CoraxPayload
{
    public $hunter;
    public $type;
    public $payload;
    public $is_vulnerable;

    private $mix;
    private $expect_arg_pos;
    private $checker;

    /**
     * Create a new payload for tainting.
     * 
     * @param string $hunter The hunter who creates this payload.
     * @param string $type Payload type.
     * @param string $payload The payload.
     * @param bool $is_vuln If this payload can trigger a vulnerability. Defaults to true.
     * @param bool $mix If this payload needs to be mixed with the input field value. Defaults to true. 
     * @param int $arg_pos Payload expecting argument position. Given -1 means does not expect any position.
     *   Defaults to -1.
     * @param callable|null $checker Argument position checking callback function. The function signature is 
     *   ($payload, $raw_hit, $pos), $payload is the payload for checking, $raw_hit is the checking hit, and
     *   $pos is the payload appeared position in checking hit argument. Defaults to null.
     */
    public function __construct($hunter, $type, $payload, $is_vuln = true, $mix = true, $arg_pos = -1, $checker = null)
    {
        $this->hunter = $hunter;
        $this->type = $type;
        $this->payload = $payload;
        $this->is_vulnerable = $is_vuln;
        $this->mix = $mix;
        $this->expect_arg_pos = $arg_pos;
        $this->checker = $checker;
    }

    /**
     * Get formatted string type of this payload.
     * 
     * @return string The formatted string of this payload..
     */
    public function __toString()
    {
        return $this->type . '[' . $this->hunter . ']: ' . $this->payload;
    }

    /**
     * Mix payload to the given value, including insert or replace to value.
     * 
     * @param string $value The original value to mix with.
     * @param string $payload The payload to mix in.
     * @param int|null $pos Mix with the value position. Given null will choose randomly. Defaults to null.
     * @return string The mixed value.
     */
    public static function mix_payload($value, $payload, $pos = null)
    {
        if ($value) {
            if (CoraxRandom::random_bool()) {  // Insert to value.
                if ($pos === null) {
                    $pos = CoraxRandom::random_pos($value);
                    if (CoraxRandom::random_bool()) $pos++;
                }
                return substr($value, 0, $pos) . $payload . substr($value, $pos);
            } else {  // Replace in value.
                if (CoraxRandom::random_bool()) return $payload;
                if ($pos === null) $pos = CoraxRandom::random_pos($value);
                $len = strlen($payload);
                return ($pos + $len >= strlen($value))
                    ? (substr($value, 0, $pos) . $payload)
                    : (substr($value, 0, $pos) . $payload . substr($value, $pos + $len));
            }
        } else return $payload;
    }

    /**
     * Get mixed value with payload.
     * 
     * @param string $value The original value to mix with.
     * @return string The mixed value.
     */
    public function get_value($value)
    {
        return $this->mix ? self::mix_payload($value, $this->payload) : $this->payload;
    }

    /**
     * Get payload expected argument positions which payload appeared.
     * 
     * @return int Payload expected argument position.
     */
    public function get_expect_arg_pos()
    {
        return $this->expect_arg_pos;
    }

    /**
     * Get payload callback function for checking.
     * 
     * @return callable|null The checker of this payload.
     */
    public function get_checker()
    {
        return $this->checker;
    }

    /**
     * Check if this payload needs to mix with input field value.
     * 
     * @return bool The check result.
     */
    public function is_mix()
    {
        return $this->mix;
    }

    /**
     * Check if payload exists in the given hit argument.
     * 
     * @param array $raw_hit The hit for checking.
     * @param bool $simple Only do the simplest checking, not using the payload given checker. Defaults to false.
     * @return array The check result, which if the payload appeared argument positions. -1 will be returned if
     *   checker failed or payload did not exist in the hit argument.
     */
    public function check(&$raw_hit, $simple = false)
    {
        $pos = [];
        $payload = $this->payload;
        $args = CoraxList::decode_array($raw_hit[0]['args']);
        for ($i = 0, $l = count($args); $i < $l; $i++) {
            if ($this->expect_arg_pos !== -1 && $this->expect_arg_pos !== $i) continue;
            if (strpos($args[$i], $payload) !== false) $pos[] = $i;
        }

        if ($this->checker !== null && !$simple) {
            if (is_callable($this->checker)) {
                try {
                    $pos = ($this->checker)($payload, $raw_hit, $pos);
                } catch (Throwable $e) {
                    CoraxLogger::warn('Runtime error for checking "' . $this->hunter .
                        '" payload "' . $this->type . ': ' . (string) $e);
                }
            } else CoraxLogger::warn('Invalid checker of "' . $this->hunter . ' payload "' .
                $this->type . '": "' . print_r($this->checker, true));
        }

        return $pos;
    }
}
