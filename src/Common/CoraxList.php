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
 * @Filename: CoraxList.php
 * @Description: 
 *   An list data structure used in Corax, store array data with base64-json 
 * encoded in file and holding index by a data filename for saving memory, for some
 * UTF-8 characters, supports using base64 to encode/decode data array.
 * ================================================================================
 */

namespace Corax\Common;


class CoraxList
{
    private $dir;
    private $encoder;
    private $decoder;
    private $list;

    /**
     * Initialize and load data filename from directory.
     * 
     * @param string $dir Data saving directory. If it does not exist, new one will be created.
     * @param callable|null $encoder Encode object to string. Defaults to null.
     * @param callable|null $encoder Decode string to object. Defaults to null.
     */
    public function __construct($dir, $encoder = null, $decoder = null)
    {
        $this->dir = $dir;
        $this->encoder = $encoder;
        $this->decoder = $decoder;

        if (!file_exists($dir) || (!is_dir($dir) && CoraxUtils::delete_path($dir))) {
            if (!CoraxUtils::mkdir($dir)) CoraxLogger::error("Create Corax local data directory \"$dir\" failed!");
        }

        for ($i = 0; $i <= 0xff; $i++) {
            $d = $dir . str_pad(dechex($i), 2, '0', STR_PAD_LEFT) . DIRECTORY_SEPARATOR;
            if (!file_exists($d) || (!is_dir($dir) && CoraxUtils::delete_path($dir)))
                if (!CoraxUtils::mkdir($d)) CoraxLogger::error("Create Corax local data prefix directory \"$d\" failed!");
        }

        $this->list = [];
        $this->scan();
    }

    /**
     * Encode all array values using base64.
     * 
     * @param array $arr The array to be encoded.
     * @return array Encoded array.
     */
    public static function encode_array($arr)
    {
        $result = [];
        foreach ($arr as $key => $value) {
            if (is_array($value)) $value = self::encode_array($value);
            elseif (is_string($value)) $value = base64_encode($value);
            $result[$key] = $value;
        }
        return $result;
    }

    /**
     * Decode all array values using base64.
     * 
     * @param array $arr The array to be decoded.
     * @return array Decoded array.
     */
    public static function decode_array($arr)
    {
        $result = [];
        foreach ($arr as $key => $value) {
            if (is_array($value)) $value = self::decode_array($value);
            elseif (is_string($value)) $value = base64_decode($value);
            $result[$key] = $value;
        }
        return $result;
    }

    /**
     * Encode array values using base64 and encode whole array using json.
     * 
     * @param array $arr The array to be encoded.
     * @return string|false Encoded array. Encode failed will return false.
     */
    public static function json_encode($arr)
    {
        if (($string = json_encode(self::encode_array($arr))) !== false) return $string;
        else return false;
    }

    /**
     * Decode string to an array using json and decode array values using base64,
     * 
     * @param string $string The string to be decoded.
     * @return array|false Decoded array. Decode failed will return false.
     */
    public static function json_decode($string)
    {
        if (($array = json_decode($string, true)) !== null) return self::decode_array($array);
        else return false;
    }

    /**
     * Scan list directory and load names.
     */
    public function scan()
    {
        if (!(file_exists($this->dir) && is_dir($this->dir))) return;
        $this->list = [];

        $l = strlen($this->dir);
        foreach (CoraxUtils::scandir($this->dir, true) as $f) {
            // Remove ".json".
            $f = substr($f, $l, -5);
            $pos = strrpos($f, DIRECTORY_SEPARATOR);
            if ($pos === false) $this->list[$f] = '';
            else {
                $name = substr($f, $pos + 1);
                $this->list[$name] = substr($f, 0, $pos);
            }
        }
    }

    /**
     * Get list saving directory.
     * 
     * @return string The list saving directory.
     */
    public function get_dir()
    {
        return $this->dir;
    }

    /**
     * Check if the list is empty.
     * 
     * @return bool The check result.
     */
    public function empty()
    {
        return empty($this->list);
    }

    /**
     * Count list elements.
     * 
     * @param string|null $prefix Only counting the names of given prefix. Defaults to null.
     * @return int Count result.
     */
    public function count($prefix = null)
    {
        if ($prefix === null) return count($this->list);
        else {
            $count = 0;
            foreach ($this->list as $p) if ($p === $prefix) $count++;
            return $count;
        }
    }

    /**
     * Check if the name in this list.
     * 
     * @param string $name The name to be checked.
     * @return bool The check result.
     */
    public function exists($name)
    {
        return isset($this->list[$name]);
    }

    /**
     * Get all names of this list.
     * 
     * @param string $with_prefix Get names with path prefix. Defaults to false.
     * @return array Contains all names, with or without prefix.
     */
    public function list($with_prefix = false)
    {
        if ($with_prefix) {
            $names = [];
            foreach ($this->list as $name => $prefix) $names[] = $prefix . DIRECTORY_SEPARATOR . $name;
            return $names;
        } else return array_keys($this->list);
    }

    /**
     * Get path prefix of the given name.
     * 
     * @param string $name The name in this list.
     * @return string|false Prefix of the given name. Null will be returned if the given name not in the list.
     */
    public function get_prefix($name)
    {
        return $this->list[$name] ?? false;
    }

    /**
     * Get names in this list by the given path prefix.
     * 
     * @param string $prefix The path prefix.
     * @return array Contains all names of the given prefix.
     */
    public function get_names($prefix)
    {
        $names = [];
        foreach ($this->list as $name => $p) if ($p === $prefix) $names[] = $name;
        return $names;
    }

    /**
     * Put data to the list. After the data putted to this list, a new file will be created, 
     * and the filename will be the given name with ".json" ext. If a non-string data given
     * and this list has an encoder, it will use encoder to encode the data before putting.
     * 
     * @param string $name The name of data.
     * @param mixed $data Data content.
     * @param string|null $prefix The path prefix of this name. Given null will use the 
     *   first 2 chars from hash of the data. Defaults to null.
     * @param bool $overwrite Force put data to file no matter if it exists. Defaults to false.
     * @return bool If put the data successfully.
     */
    public function put($name, $data, $prefix = null, $overwrite = false)
    {
        if (!isset($this->list[$name]) || $overwrite) {
            if (!is_string($data)) {
                if ($this->encoder) {
                    $data = ($this->encoder)($data);
                    if (!is_string($data)) return false;
                } else $data = (string) $data;
            }

            if ($prefix === null) $prefix = substr(md5($data), 0, 2);

            $d = $this->dir . $prefix . DIRECTORY_SEPARATOR;
            if (!file_exists($d) || !is_dir($d)) if (!CoraxUtils::mkdir($d)) return false;

            if (file_put_contents($d . $name . '.json', $data) !== false) {
                $this->list[$name] = $prefix;
                return true;
            }
        }
        return false;
    }

    /**
     * Load data from a file of this list. If this list has a decoder, it will use decoder to 
     * decode data after loading.
     * 
     * @param string $name The data name.
     * @return mixed|false|null The loaded data. If given a name not in the list, or decode
     *   error happened, null will be returned.
     */
    public function load($name)
    {
        if (isset($this->list[$name])) {
            if ($data = file_get_contents($this->dir . $this->list[$name] . DIRECTORY_SEPARATOR . $name . '.json')) {
                if ($this->decoder) if (($data = ($this->decoder)($data)) === false) return null;
                return $data;
            }
        }
        return null;
    }

    /**
     * Load all data one by one.
     * 
     * @yield string => array The data name and an array with data content and extra data.
     */
    public function load_all()
    {
        foreach ($this->list as $name => $_)
            if (isset($this->list[$name])) yield $name => $this->load($name);
    }

    /**
     * Remove data of this list.
     * 
     * @param string $name The data name.
     * @param bool $del Delete the file in local filesystem. Defaults to false.
     * @return bool If remove successfully.
     */
    public function remove($name, $del = false)
    {
        $result = false;
        if (isset($this->list[$name])) {
            if ($del) $result = unlink($this->dir . $this->list[$name] . DIRECTORY_SEPARATOR . $name . '.json');
            else $result = true;
            if ($result) unset($this->list[$name]);
        }
        return $result;
    }
}
