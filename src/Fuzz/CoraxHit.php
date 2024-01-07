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
 * @Filename: CoraxHit.php
 * @Description: 
 *   A hit in Corax, saving input, value, hit function call stack and other
 * information.
 * ================================================================================
 */

namespace Corax\Fuzz;

use Corax\Common\CoraxList;


final class CoraxHit
{
    private $name;
    private $path;
    private $raw_hit;
    private $func_info;
    private $call_stack;

    private $func_name;
    private $func_args;
    private $func_args_count;

    private $vulns;
    private $tmp_vulns;
    private $filtered;

    /**
     * Initialize a hit.
     * 
     * @param string $name The hit name.
     * @param array $raw_input The raw http input array for this hit.
     * @param \Corax\Fuzz\CoraxInput $input The input which this hit comes from.
     * @param array $raw_hit The raw hit array.
     * @param array $response The http response array of this hit.
     * @param array $vulns The initialized vulnerabilities of this hit. Defaults to an empty array.
     * @param array $filtered The initialized filtered vulnerabilities of this hit. Defaults to an empty array.
     */
    public function __construct($name, $raw_input, $input, $raw_hit, $response, $vulns = [], $filtered = [])
    {
        $this->name = $name;
        $this->raw_hit = $raw_hit;

        $this->func_info = array_shift($raw_hit);
        $this->path = new CoraxPath(
            $this->func_info['path_name'],
            $raw_input,
            $input,
            $this->func_info['path'],
            $response
        );
        $this->call_stack = $raw_hit;
        $this->func_name = $this->func_info['func'];
        $this->func_args = CoraxList::decode_array($this->func_info['args']);;
        $this->func_args_count = count($this->func_args);

        $this->vulns = $vulns;
        $this->tmp_vulns = [];
        $this->filtered = $filtered;
    }

    /**
     * Get serialized content of this hit.
     * 
     * @return string The serialized string. Serialized failed will return "<FAILED>".
     */
    public function __toString()
    {
        if ($result = CoraxList::json_encode([
            'name' => $this->name,
            'raw_input' => $this->path->get_raw_input(),
            'input' => CoraxInput::serialize($this->path->get_input()),
            'hit' => $this->raw_hit,
            'response' => $this->path->get_response(),
            'vulns' => $this->vulns,
            'filtered' => $this->filtered
        ])) return $result;
        else return '<FAILED>';
    }

    /**
     * Get name of this hit.
     * 
     * @return string Hit name.
     */
    public function get_name()
    {
        return $this->name;
    }

    /**
     * Get the raw path array.
     * 
     * @return \Corax\Fuzz\CoraxPath Path array.
     */
    public function get_path()
    {
        return $this->path;
    }

    /**
     * Get the raw hit array.
     * 
     * @return array Hit array.
     */
    public function get_raw_hit()
    {
        return $this->raw_hit;
    }

    /**
     * Get hit function info array or value.
     * 
     * @param string|null $key The info key. Given null will return the whole info array. Defaults to null.
     * @return array|string|null The hit function information including function name "func", function arguments
     *   "args", function filename "file", function start position in file "start_pos", function end 
     *   position in file "end_pos", function start line no in file "start_line", function end line 
     *   no in file "end_line" and function return value "ret". The key is null will return the whole info array.
     *   If the key does not exist, null will be returned.
     */
    public function get_func_info($key = null)
    {
        return $key ? ($this->func_info[$key] ?? null) : $this->func_info;
    }

    /**
     * Get hit feature.
     * 
     * @return string The hit feature.
     */
    public function get_feature()
    {
        return $this->func_info['feature'];
    }

    /**
     * Check if this hit contains new path.
     * 
     * @return bool Returns true if this hit contains new path, or false.
     */
    public function is_new_path()
    {
        return $this->func_info['new_path'];
    }

    /**
     * Get prev block index before reach this hit.
     * 
     * @return int The prev block index.
     */
    public function get_prev_block()
    {
        return $this->func_info['prev_block'];
    }

    /**
     * Get hit function call stack.
     * 
     * @return array The hit function call stack. Each element is an array including function name "func",
     *   function filename "file" and function start line no in file "line".
     */
    public function get_callstack()
    {
        return $this->call_stack;
    }

    /**
     * Get hit function name.
     * 
     * @return string The function name.
     */
    public function get_func_name()
    {
        return $this->func_name;
    }

    /**
     * Get hit function arguments.
     * 
     * @return array The function arguments.
     */
    public function get_args()
    {
        return $this->func_args;
    }

    /**
     * Get count of function arguments.
     * 
     * @return int Count of arguments.
     */
    public function get_args_count()
    {
        return $this->func_args_count;
    }

    /**
     * Get hit function filename.
     * 
     * @return string The function filename.
     */
    public function get_file()
    {
        return $this->func_info['file'];
    }

    /**
     * Get hit function start position in file.
     * 
     * @return string The function start file position.
     */
    public function get_start_pos()
    {
        return $this->func_info['start_pos'];
    }

    /**
     * Get hit function end position in file.
     * 
     * @return string The function end file position.
     */
    public function get_end_pos()
    {
        return $this->func_info['end_pos'];
    }

    /**
     * Get hit function start line no in file.
     * 
     * @return string The function start line no.
     */
    public function get_start_line()
    {
        return $this->func_info['start_line'];
    }

    /**
     * Get hit function end line no in file.
     * 
     * @return string The function end file no.
     */
    public function get_end_line()
    {
        return $this->func_info['end_line'];
    }

    /**
     * Get hit function return value in string.
     * 
     * @return string The function return value.
     */
    public function get_ret()
    {
        return $this->func_info['ret'];
    }

    /**
     * Get all filtered payloads of this hit.
     * 
     * @return array All added filtered payloads.
     */
    public function get_filtered()
    {
        return array_keys($this->filtered);
    }

    /**
     * Get all vulnerabilities or a specific hunter vulnerability of this hit.
     * 
     * @param string|null $hunter Specific a hunter. Given null will return all vulnerabilities. Defaults to null.
     * @return array All added vulnerabilities or a specific hunter vulnerability. If get all vulnerabilities, key is hunter,
     *   value is an array contains all vulns, including affected argument position, vulnerability hunter and value 
     *   and vulnerability type. Empty array will be returned if hunter does not exists.
     */
    public function get_vulns($hunter = null)
    {
        if ($hunter) {
            if (isset($this->vulns[$hunter])) return $this->vulns[$hunter];
            else return [];
        } else return $this->vulns;
    }

    /**
     * Count all vulnerabilities of this hit.
     * 
     * @return int The count of al vulnerabilities of this hit.
     */
    public function count_vulns()
    {
        $result = 0;
        foreach ($this->vulns as $_ => $vulns) $result += count($vulns);
        return $result;
    }

    /**
     * Check if this hit is vulnerable.
     * 
     * @return bool Check result.
     */
    public function is_vulnerable()
    {
        return $this->vulns || $this->tmp_vulns;
    }

    /**
     * Add a valid vulnerability from a hunter.
     * 
     * @param string $hunter The hunter who found this vulnerability.
     * @param string $type Vulnerability type.
     * @param \corax\Fuzz\CoraxVuln $vuln The vulnerability to add.
     */
    public function add_vuln($hunter, $type, $vuln)
    {
        if (isset($this->tmp_vulns[$hunter][$type])) return;
        if (isset($this->tmp_vulns[$hunter])) $this->tmp_vulns[$hunter][$type] = $vuln;
        else $this->tmp_vulns[$hunter] = [$type => $vuln];
    }

    /**
     * Remove an added vulnerability.
     * 
     * @param string $hunter Hunter who found this vulnerability.
     * @param string $type Vulnerability type.
     */
    public function remove_vuln($hunter, $type)
    {
        unset($this->tmp_vulns[$hunter][$type]);
        unset($this->vulns[$hunter][$type]);
    }

    /**
     * Save all vulnerabilities that just added to this hit and get these new vulnerabilities.
     * 
     * @return array All just added vulnerabilities, key is the hunter name, value is an array contains all vulnerabilities,
     *   including affected argument position, vulnerability found hunter and value and vulnerability type.
     */
    public function save_vulns()
    {
        $new_vulns = $this->tmp_vulns;
        $this->tmp_vulns = [];

        foreach ($new_vulns as $hunter => $vulns) {
            if (!isset($this->vulns[$hunter])) $this->vulns[$hunter] = [];
            // Overwrite existed vulnerabilities.
            foreach ($vulns as $type => $vuln) $this->vulns[$hunter][$type] = $vuln->get_name();
        }
        return $new_vulns;
    }

    /**
     * Check if a type of vulnerability has existed. Only hunter can call this method.
     * 
     * @param string $hunter The hunter to check.
     * @param string $type The vulnerability type to check.
     * @return bool|null The check result. If not a hunter access this method, null will be returned.
     */
    public function vuln_exists($hunter, $type)
    {
        return isset($this->tmp_vulns[$hunter][$type]) || isset($this->vulns[$hunter][$type]);
    }

    /**
     * Add a filtered payload.
     * 
     * @param string $payload The filtered payload.
     */
    public function add_filtered($payload)
    {
        $this->filtered[$payload] = true;
    }

    /**
     * Check if a payload has been filtered in this hit.
     * 
     * @param string|array $payload The payload or payloads to check.
     * @return bool The check result.
     */
    public function is_filtered($payload)
    {
        if (is_string($payload)) return isset($this->filtered[$payload]);
        elseif (is_array($payload)) {
            foreach ($payload as $p) if (!isset($this->filtered[$p])) return false;
            return true;
        } else return false;
    }

    /**
     * Remove one or more filtered payloads.
     * 
     * @param string|array $payload The payload or payloads to remove.
     */
    public function remove_filtered($payload)
    {
        if (is_string($payload)) unset($this->filtered[$payload]);
        elseif (is_array($payload)) foreach ($payload as $p) unset($this->filtered[$p]);
    }

    /**
     * Report a hit info.
     * 
     * @param string $method Logger method. Defaults to "info".
     * @param int $level Logging ident level. Defaults to 0.
     */
    public function report($method = 'info', $level = 0)
    {
        $echo = ['\Corax\Common\CoraxLogger', $method];
        $echo(sprintf(
            'Function "%s" (%d args, req[%d]) from hit %s of feature %s.',
            $this->func_info['func'],
            count($this->func_info['args']),
            $this->path->get_response('code'),
            $this->name,
            $this->func_info['feature']
        ), $level);

        $echo(sprintf(
            'File: %s, pos %d-%d, line %d-%d',
            $this->func_info['file'],
            $this->func_info['start_pos'],
            $this->func_info['end_pos'],
            $this->func_info['start_line'],
            $this->func_info['end_line']
        ), $level);

        $args = $this->get_args();
        $echo('Arguments(' . count($args) . '): ' . implode(' bytes, ', array_map(function ($x) {
            return strlen($x);
        }, $args)) . ' bytes', $level);

        $echo('Returned: ' . strlen($this->func_info['ret']) . ' bytes', $level);
        $echo('Path:', $level);
        $this->path->report($method, $level + 1);
        $echo('Input:', $level);
        $this->path->get_input()->report($method, $level + 1);
        $echo('Call Stacks(' . count($this->call_stack) . '):', $level);
        foreach ($this->call_stack as $call) {
            $echo(sprintf(
                'Called => %s in file %s:%d',
                $call['func'],
                $call['file'],
                $call['line']
            ), $level + 1);
        }
    }

    /**
     * For data saving, serialize the hit to a string.
     * 
     * @param \Corax\Fuzz\CoraxHit $hit The hit to be serialized.
     * @return string|false Serialized hit. Serialize failed will return false.
     */
    public static function serialize($hit)
    {
        $result = (string) $hit;
        return $result === '<FAILED>' ? false : $result;
    }

    /**
     * Unserialize a content to a hit. 
     * 
     * @param string $string The string to be unserialized.
     * @return \Corax\Fuzz\CoraxHit|false The unserialized hit. Unserialize failed will return false.
     */
    public static function unserialize($string)
    {
        if ($content = CoraxList::json_decode($string)) {
            if ($input = CoraxInput::unserialize($content['input'])) return new self(
                $content['name'],
                $content['raw_input'],
                $input,
                $content['hit'],
                $content['response'],
                $content['vulns'],
                $content['filtered']
            );
        }
        return false;
    }
}
