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
 * @Filename: CoraxVuln.php
 * @Description: 
 *   Saving information of a vulnerability in Corax.
 * ================================================================================
 */

namespace Corax\Fuzz;


class CoraxVuln
{
    private $name;
    private $type;
    private $payload;
    private $pos;
    private $value;
    private $hunter;
    private $hit;

    /**
     * Initialize a vulnerability.
     * 
     * @param string $name Vulnerability name.
     * @param string $type Vulnerability type.
     * @param string $payload The payload of this vulnerability.
     * @param array $pos Vulnerable function argument position.
     * @param string $value The value triggered the payload in function argument.
     * @param string $hunter Hunter name who found this vulnerability.
     * @param \Corax\Fuzz\CoraxHit $hit The hit of this vulnerability.
     */
    public function __construct($name, $hunter, $type, $payload, $pos, $value, $hit)
    {
        $this->name = $name;
        $this->hunter = $hunter;
        $this->type = $type;
        $this->payload = $payload;
        $this->pos = $pos;
        $this->value = $value;
        $this->hit = $hit;
    }

    /**
     * Get name of this vulnerability.
     * 
     * @return string The vulnerability name.
     */
    public function get_name()
    {
        return $this->name;
    }

    /**
     * Get hunter name who found this vulnerability.
     * 
     * @return string The hunter name.
     */
    public function get_hunter()
    {
        return $this->hunter;
    }

    /**
     * Get type of this vulnerability.
     * 
     * @return string The vulnerability type.
     */
    public function get_type()
    {
        return $this->type;
    }

    /**
     * Get payload of this vulnerability.
     * 
     * @return string The vulnerability payload.
     */
    public function get_payload()
    {
        return $this->payload;
    }

    /**
     * Get argument position of this vulnerability.
     * 
     * @return array The vulnerability argument position.
     */
    public function get_arg_pos()
    {
        return $this->pos;
    }

    /**
     * Get value of this vulnerability which mixed with the payload.
     * 
     * @return string The vulnerability value.
     */
    public function get_value()
    {
        return $this->value;
    }

    /**
     * Get hit of this vulnerability.
     * 
     * @return \Corax\Fuzz\CoraxHit The vulnerability hit.
     */
    public function get_hit()
    {
        return $this->hit;
    }

    /**
     * Get serialized content of this vuln.
     * 
     * @return string The serialized string. Serialized failed will return "<FAILED>".
     */
    public function __toString()
    {
        if ($result = json_encode([
            'name' => $this->name,
            'hunter' => $this->hunter,
            'type' => $this->type,
            'payload' => base64_encode($this->payload),
            'pos' => $this->pos,
            'value' => base64_encode($this->value),
            'hit' => CoraxHit::serialize($this->hit),
        ])) return $result;
        else return '<FAILED>';
    }

    /**
     * For data saving, serialize the vuln to a string.
     * 
     * @param \Corax\Fuzz\CoraxVuln $vuln The vuln to be serialized.
     * @return string|false Serialized vuln. Serialize failed will return false.
     */
    public static function serialize($vuln)
    {
        $result = (string) $vuln;
        return $result === '<FAILED>' ? false : $result;
    }

    /**
     * Unserialize a content to a vuln. 
     * 
     * @param string $string The string to be unserialized.
     * @return \Corax\Fuzz\CoraxVuln|false The unserialized vuln. Unserialize failed will return false.
     */
    public static function unserialize($string)
    {
        if ($content = json_decode($string, true)) {
            if ($hit = CoraxHit::unserialize($content['hit'])) {
                return new self(
                    $content['name'],
                    $content['hunter'],
                    $content['type'],
                    base64_decode($content['payload']),
                    $content['pos'],
                    base64_decode($content['value']),
                    $hit
                );
            }
        }
        return false;
    }
}
