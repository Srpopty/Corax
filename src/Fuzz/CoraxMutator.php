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
 * @Filename: CoraxMutator.php
 * @Description: 
 *   Corax mutator used in fuzzer. Mutate a value to a new value, supports 
 * dynamic register new mutator. All mutator function name should start with "m_".
 * ================================================================================
 */

namespace Corax\Fuzz;

use Throwable;

use Corax\Common\CoraxDictionary;
use Corax\Common\CoraxLogger;
use Corax\Common\CoraxRandom;
use Corax\Common\CoraxWorker;


final class CoraxMutator extends CoraxWorker
{
    /**
     * Initialize a mutator. It could load user custom mutators from plugin. The custom mutator template is:
     * <?php
     * namespace Corax;
     *  
     * 
     * class CoraxPlugin
     * {
     *     public function m_my_mutator($str, $type)
     *     {
     *         // Do something for $str.
     *         // ...
     *         return $str;
     *     }
     * }
     * 
     * @param \Corax\CoraxPlugin|null $plugin User custom plugin including mutators. Defaults to null.
     * @param array $disable Manually disable some mutators. Supports regex. Defaults to an empty array.
     */
    public function __construct($plugin = null, $disable = [])
    {
        parent::__construct('m_', $plugin, function ($func) {
            try {
                $ret = $func('test', 'test');
            } catch (Throwable $e) {
                return 'Register user provided mutator from plugin failed! Mutator runtime error: ' . (string) $e;
            }
            if (!(is_string($ret) || $ret === null))
                return 'Register user provided mutator from plugin failed! Mutator should return a string or null!';
        }, $disable);
    }

    /**
     * Mutate a value by using an enabled mutator.
     * 
     * @param mixed $value The value to be mutated.
     * @param string $type The value type.
     * @param string|null $name Specific a mutator to mutate. Given null will randomly choice an enabled mutator. 
     *     Defaults to null.
     * @param bool $force Force using the mutator no matter if it is disabled. Defaults to false.
     * @return string|null The mutated string. Null will be returned of mutator not enabled or no mutator to use.
     */
    public function mutate($value, $type, $name = null, $force = false)
    {
        $result = null;
        if ($mutator = parent::get_worker($name, $force)) {
            try {
                $result = $mutator($value, $type);
            } catch (Throwable $e) {
                CoraxLogger::warn(
                    "Mutator \"$name\" mutate \"$type\" value failed. Mutator runtime error: " . (string) $e
                );
            }
        } else CoraxLogger::warn($name ? "Access denied for using disabled or unknown mutator \"$name\"." :
            'No available mutator!');
        return $result;
    }

    /**
     * Mutate a value by using all enabled mutators.
     * 
     * @param mixed $value The value to be mutated.
     * @param string $type The value type.
     * @param bool $random Mutate string in random orders. Defaults to false.
     * @param bool $force Force using all mutators no matter if they are disabled. Defaults to false.
     * @yield string => string Mutator name and mutated string.
     */
    public function mutate_all($value, $type, $random = false, $force = false)
    {
        foreach (parent::get_names(!$force, $random) as $name)
            if (($result = $this->mutate($value, $type, $name)) !== null) yield $name => $result;
    }

    /**
     * Randomly use a basic mutators for a string value. Including remove, insert and change string.
     * 
     * @param string $str The string to mutate.
     * @return string|null The mutated string. If non-string or empty value given, null will be returned.
     */
    public function basic_mutate($str)
    {
        switch (CoraxRandom::random_int(0, 5)) {
            case 0:
                return $this->m_remove_byte($str, '');
            case 1:
                return $this->m_remove_bytes($str, '');
            case 2:
                return $this->m_insert_byte($str, '');
            case 3:
                return $this->m_insert_bytes($str, '');
            case 4:
                return $this->m_change_byte($str, '');
            case 5:
                return $this->m_change_bytes($str, '');
        }
    }

    /**
     * Mutate string by randomly removing one byte.
     * 
     * @param string $str The string to mutate.
     * @param string $type The value type.
     * @return string|null The removed string. If non-string or empty string given, null will be returned.
     */
    protected function m_remove_byte($str, $type)
    {
        if (!is_string($str)) return null;
        $len = strlen($str);
        if ($len === 0) return null;
        if ($len === 1) return '';

        $pos = CoraxRandom::random_pos($str);
        return substr($str, 0, $pos) . substr($str, $pos + 1);
    }

    /**
     * Mutate string by randomly removing some bytes.
     * 
     * @param string $str The string to mutate.
     * @param string $type The value type.
     * @return string|null The removed string. If non-string or empty string given, null will be returned.
     */
    protected function m_remove_bytes($str, $type)
    {
        if (!is_string($str)) return null;
        $len = strlen($str);
        if ($len === 0) return null;
        if ($len < 3) return '';

        // From 2 to 20% string length.
        $max = CoraxRandom::random_int(2, max(ceil(strlen($str) * 0.2), 2));
        for ($i = 0; $i < $max; $i++) $str = $this->m_remove_byte($str, $type);

        return $str;
    }

    /**
     * Mutate string by randomly inserting one byte.
     * 
     * @param string $str The string to mutate.
     * @param string $type The value type.
     * @return string|null The inserted string. If non-string given, null will be returned.
     */
    protected function m_insert_byte($str, $type)
    {
        if (!is_string($str)) return null;
        if (strlen($str) === 0) return CoraxRandom::random_char();

        CoraxRandom::insert_string($str);

        return $str;
    }

    /**
     * Mutate string by randomly inserting some bytes.
     * 
     * @param string $str The string to mutate.
     * @param string $type The value type.
     * @return string|null The inserted string. If non-string given, null will be returned.
     */
    protected function m_insert_bytes($str, $type)
    {
        if (!is_string($str)) return null;
        // From 2 to 20% string length.
        $max = CoraxRandom::random_int(2, max(ceil(strlen($str) * 0.2), 2));
        for ($i = 0; $i < $max; $i++) $str = $this->m_insert_byte($str, $type);

        return $str;
    }

    /**
     * Mutate string by randomly changing one byte.
     * 
     * @param string $str The string to mutate.
     * @param string $type The value type.
     * @return string|null The changed string. If non-string or empty string given, null will be returned.
     */
    protected function m_change_byte($str, $type)
    {
        if (!is_string($str)) return null;
        $len = strlen($str);
        if ($len === 0) return null;
        if ($len === 1) return CoraxRandom::random_char();
        CoraxRandom::change_string($str);

        return $str;
    }

    /**
     * Mutate string by randomly changing some bytes.
     * 
     * @param string $str The string to mutate.
     * @param string $type The value type.
     * @return string|null The changed string. If non-string or empty string given, null will be returned.
     */
    protected function m_change_bytes($str, $type)
    {
        if (!is_string($str)) return null;
        $len = strlen($str);
        if ($len === 0) return null;
        if ($len === 1) return CoraxRandom::random_char();

        $max = CoraxRandom::random_int(2, $len);
        for ($i = 0; $i < $max; $i++) $str = $this->m_change_byte($str, $type);

        return $str;
    }

    /**
     * Mutate file type.
     * 
     * @param string $str The string to mutate.
     * @param string $type The value type.
     * @return string|null The changed string. If string type is not "filetype", null will be returned.
     */
    protected function m_change_filetype($str, $type)
    {
        if ($type !== 'filetype' || !is_string($str)) return null;
        return CoraxRandom::random_choice(CoraxDictionary::$context_types);
    }

    /**
     * Mutate upload filename.
     * 
     * @author DiliLearngent <dililearngent@gmail.com>
     * @param string $str The string to mutate.
     * @param string $type The value type.
     * @return string|null The changed string. If string type is not "filename", null will be returned.
     */
    protected function m_change_filename($str, $type)
    {
        if ($type !== 'filename' || !is_string($str)) return null;

        $idx = strrpos($str, '.') ?: strlen($str);

        $filename = substr($str, 0, $idx);
        if (CoraxRandom::random_bool(0.5)) $filename = $this->basic_mutate($filename);
        if (CoraxRandom::random_bool(0.3)) $filename = str_repeat('../', CoraxRandom::random_int(1, 4)) . $filename;

        $ext = substr($str, $idx + 1) ?: '';
        if (CoraxRandom::random_bool(0.1)) {
            $filename .= '.' . $ext;
            $ext = '';
        }

        return $filename . '.' .
            ((!isset($ext[0]) || CoraxRandom::random_bool(0.6))
                ? CoraxRandom::random_choice(CoraxDictionary::$file_exts)
                : (CoraxRandom::random_bool(0.5) ? $this->basic_mutate($ext) : $ext));
    }

    /**
     * Mutate upload file content.
     * 
     * @author DiliLearngent <dililearngent@gmail.com>
     * @param string $str The string to mutate.
     * @param string $type The value type.
     * @return string|null The changed string. If string type is not "file_content", null will be returned.
     */
    protected function m_change_filecontent($str, $type)
    {
        if ($type !== 'file_content' || !is_string($str)) return  null;
        return CoraxRandom::random_choice(CoraxDictionary::$hex_file_headers) . $str;
    }

    /**
     * Mutate string by change or insert one byte to a special char.
     * 
     * @param string $str The string to mutate.
     * @param string $type The value type.
     * @return string|null The mutated string. If non-string given, null will be returned.
     */
    protected function m_special_char($str, $type)
    {
        if (!is_string($str)) return null;
        $char = CoraxRandom::random_choice(CoraxDictionary::$special_chars);
        if (isset($str[0]) && CoraxRandom::random_bool()) CoraxRandom::change_string($str, $char);
        else CoraxRandom::insert_string($str, $char);
        return $str;
    }

    /**
     * Mutate string by change or insert one byte to a space char.
     * 
     * @param string $str The string to mutate.
     * @param string $type The value type.
     * @return string|null The mutated string. If non-string given, null will be returned.
     */
    protected function m_space_char($str, $type)
    {
        if (!is_string($str)) return null;
        $char = CoraxRandom::random_choice(CoraxDictionary::$space_chars);
        if (isset($str[0]) && CoraxRandom::random_bool()) CoraxRandom::change_string($str, $char);
        else CoraxRandom::insert_string($str, $char);
        return $str;
    }

    /**
     * Mutate int by random choice.
     * 
     * @Author: DiliLearngent
     * @Email: dililearngent@gmail.com
     * @param string $str The number to mutate.
     * @param string $type The value type.
     * @return string|null The changed number. If the given string is not a number, null will be returned.
     */
    protected function m_change_number($str, $type)
    {
        if (!is_numeric($str)) return (string) CoraxRandom::random_int(-1024, 1024);
        if (CoraxRandom::random_bool(0.4))
            return (string)@eval('return ' . $str . (CoraxRandom::random_bool() ? '+' : '-') .
                CoraxRandom::random_int(0, 1024) . ';');
        else return (string)(CoraxRandom::random_choice(CoraxDictionary::$special_numbers));
    }

    /**
     * Cross mutate by some basic mutator.
     * 
     * @param string $str The number to mutate.
     * @param string $type The value type.
     * @return string|null The mutated string. If non-string given, null will be returned.
     */
    protected function m_cross($str, $type)
    {
        if (!is_string($str)) return null;
        for ($i = CoraxRandom::random_int(2, 10); $i; $i--) $str = $this->basic_mutate($str);
        return $str;
    }
}
