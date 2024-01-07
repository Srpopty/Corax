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
 * @Filename: CoraxRandom.php
 * @Description: 
 *   Randomize function used in Corax, supports most array and string.
 * ================================================================================
 */

namespace Corax\Common;


class CoraxRandom
{
    protected static $rand_max = null;

    /**
     * Generate a random id by using [A-Za-z0-9].
     * 
     * @param int $length The id length. Defaults to 8.
     * @return string Generated id.
     */
    public static function random_id($length = 8)
    {
        $dict = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        $result = '';
        $r = ceil($length / 8.0);
        for ($i = 0; $i < $r; $i++) {
            $dict = str_shuffle($dict);
            $result .= substr($dict, 0, $length);
            $length -= 8;
        }
        return $result;
    }

    /**
     * Generate a random int value from [$min, $max].
     * 
     * @param int $min Min value range.
     * @param int $max Max value range.
     * @return int Generated int.
     */
    public static function random_int($min, $max)
    {
        return mt_rand($min, $max);
    }

    /**
     * Randomly choice an element from a sequence.
     * 
     * @param array|string &$seq The sequence to choice.
     * @return string|mixed|null The choose element. Empty sequence will return null.
     */
    public static function random_choice(&$seq)
    {
        $len = is_array($seq) ? count($seq) : strlen($seq);
        if ($len === 0) return null;
        return is_array($seq) ? $seq[array_rand($seq)] : $seq[mt_rand(0, $len - 1)];
    }

    /**
     * Randomly choice true or false.
     * 
     * @param float $p The probability to return true. Defaults to 0.5.
     * @return bool Random bool value.
     */
    public static function random_bool($p = 0.5)
    {
        if ($p === 0.5) return (bool) mt_rand(0, 1);
        else {
            if (self::$rand_max === null) self::$rand_max = mt_getrandmax();
            return (mt_rand() / self::$rand_max) <= $p;
        }
    }

    /**
     * Generated a random ASCII char from [\x00-\xff].
     * 
     * @return string Generated random char.
     */
    public static function random_char()
    {
        return chr(mt_rand(0x00, 0xff));
    }

    /**
     * Generated a random string.
     * 
     * @param int $len String length.
     * @param string|null $charset Generate the random string by using chars from the charset. Given null or empty string
     *   will use random char. Defaults to null.
     * @return string Generated random string.
     */
    public static function random_string($len, $charset = null)
    {
        $result = '';
        $len = $charset ? strlen($charset) : 0;
        for ($i = 0; $i < $len; $i++) $result .= ($charset ? $charset[mt_rand(0, $len - 1)] : chr(mt_rand(0x00, 0xff)));
        return $result;
    }

    /**
     * Randomly choice a position from a sequence.
     * 
     * @param array|string &$seq The sequence to choice.
     * @return int|null The choose position. Empty sequence will return null.
     */
    public static function random_pos(&$seq)
    {
        $len = is_array($seq) ? count($seq) : strlen($seq);
        if ($len === 0) return null;
        return is_array($seq) ? array_rand($seq) : mt_rand(0, $len - 1);
    }

    /**
     * Shuffle an array or string.
     * 
     * @param array|string &$seq The sequence to shuffle.
     * @return null Empty sequence will return null.
     */
    public static function shuffle(&$seq)
    {
        $len = is_array($seq) ? count($seq) : strlen($seq);
        if ($len === 0) return null;
        is_array($seq) ? shuffle($seq) : ($seq = str_shuffle($seq));
    }

    /**
     * Choice some samples from a sequence randomly.
     * 
     * @param array|string &$seq The sequence to choice.
     * @param int $count The count to choice. Defaults to 1.
     * @param bool $unique Unique samples. Defaults to false.
     * @return array The randomly chaoses samples. Key it sample pos in the original sequence and 
     *   value is the choices sample.
     */
    public static function sample(&$seq, $count = 1, $unique = false)
    {
        $len = is_array($seq) ? count($seq) : strlen($seq);

        $samples = [];
        if ($len) {
            $keys = is_array($seq) ? array_rand($seq, $count) :
                array_rand(range(0, $len - 1), $count);
            if ($count === 1) $samples[$keys] = $seq[$keys];
            else foreach ($keys as $k) {
                if ($unique) {
                    if (!in_array($seq[$k], $samples)) $samples[] = $seq[$k];
                } else $samples[$k] = $seq[$k];
            }
        }

        return $samples;
    }

    /**
     * Randomly change a string with a char.
     * 
     * @param string &$str The string to change.
     * @param string|null $value All changed char will be replaced to value. 
     *   Given null or empty string will use a random char to change. Given a string 
     *   more than one chars, the first char will be used. Defaults to null.
     * @param int $times The times to change. Defaults to 1.
     */
    public static function change_string(&$str, $value = null, $times = 1)
    {
        $len = strlen($str) - 1;
        if ($len === -1) return;

        if ($value === null) $value = chr(mt_rand(0x00, 0xff));
        elseif (strlen($value) > 1) $value = $value[0];
        while ($times--) $str[mt_rand(0, $len)] = $value;
    }

    /**
     * Randomly insert a new string to a string.
     * 
     * @param string &$str The string to insert.
     * @param string|null $value The value will be insert to string. 
     *   Given null or empty string will use a random char to insert. Defaults to null.
     * @param int $times The times to insert. Defaults to 1.
     */
    public static function insert_string(&$str, $value = null, $times = 1)
    {
        if ($value === null) $value = chr(mt_rand(0x00, 0xff));

        if (strlen($str) == 0) $str = $value;

        while ($times--) {
            $pos = mt_rand(0, strlen($str) - 1);
            if (mt_rand(0, 1)) $pos++;
            $str = substr($str, 0, $pos) . $value . substr($str, $pos);
        }
    }
}
