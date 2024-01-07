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
 * @Filename: CoraxHound.php
 * @Description: 
 *   Corax hound is used to bypass payload filter for hunter.
 * ================================================================================
 */

namespace Corax\Fuzz;

use Corax\Common\CoraxRandom;
use Corax\Common\CoraxDictionary;


final class CoraxHound
{
    /**
     * Randomly shuffle payload letters case.
     * 
     * @param string $payload The payload to shuffle.
     * @return string Shuffled payload.
     */
    public static function shuffle_letter_case($payload)
    {
        for ($i = 0, $l = strlen($payload); $i < $l; $i++) {
            $c = $payload[$i];
            if (ctype_alpha($c)) {
                if (CoraxRandom::random_bool()) $payload[$i] = strtoupper($c);
                else $payload[$i] = strtolower($c);
            }
        }

        return $payload;
    }

    /**
     * Replace payload keywords to double keywords, double formation is randomly.
     * 
     * @param string $payload The payload to replace.
     * @param array $keywords Keywords to replace.
     * @return string The replaced payload.
     */
    public static function replace_double_keywords($payload, $keywords)
    {
        $double_keywords = [];
        foreach ($keywords as $keyword) {
            $pos = CoraxRandom::random_int(1, strlen($keyword) - 1);
            $double_keywords[] = substr($keyword, 0, $pos) . $keyword . substr($keyword, $pos);
        }

        return str_replace($keywords, $double_keywords, $payload);
    }

    /**
     * Randomly replace space \x20 to other equal char from spaces array.
     * 
     * @param string $payload The payload to replace.
     * @param array $spaces Equal space char to replace.
     * @return string The replaced payload.
     */
    public static function replace_space($payload, $spaces)
    {
        $result = '';
        for ($pos = 0, $l = strlen($payload); $pos < $l; $pos++)
            $result .= ($payload[$pos] === ' ') ? CoraxRandom::random_choice($spaces) : $payload[$pos];
        return $result;
    }

    /**
     * Generate random assign statements.
     * E.g. src, src=, src="123", src='123', src=123.
     * 
     * @param int $count The count to generate.
     * @return array Generated random assign statements.
     */
    public static function fake_assign($count)
    {
        $attrs = [];
        while ($count--) {
            $attr = CoraxRandom::random_id(CoraxRandom::random_int(1, 4));
            if (CoraxRandom::random_bool()) {
                // Need quotes maybe.
                $quote = CoraxRandom::random_choice(CoraxDictionary::$quotes);
                $attr .= '=' . $quote . CoraxRandom::random_id(CoraxRandom::random_int(1, 4)) . $quote;
            }
            $attrs[] = $attr;
        }

        return $attrs;
    }

    /**
     * Generate random system command with some bypass technologies.
     * E.g. cat, cat -a, cat --aa, cat -a=1, cat --a=1, cat "a=1", cat 'a=1'.
     * 
     * @param int $count The count of command arguments.
     * @return string Generated system command.
     */
    public static function fake_command($count)
    {
        $command_name = CoraxRandom::random_choice(CoraxDictionary::$command_names);

        // Keyword filter bypass.
        if (CoraxRandom::random_bool(0.3)) {
            $c = CoraxRandom::random_choice($command_name);
            switch (CoraxRandom::random_int(0, 7)) {
                case 0:
                    $d = "[$c]";  // cm[d]
                    break;
                case 1:
                    $d = "'$c'";  // cm'd'
                    break;
                case 2:
                    $d = "\\$c";  // cm"d"
                    break;
                case 3:
                    $d = "\$@$c";  // cm$@d
                    break;
                case 4:
                    $d = "\${x}$c";  // cm${x}d
                    break;
                case 5:
                    $d = "\$(x)$c";  // cm$(x)d
                    break;
                case 6:
                    $d = "`x`$c";  // cm`x`d
                    break;
                default:
                    $d = "\"$c\""; // cm\d
                    break;
            }
            $command_name = str_replace($c, $d, $command_name);
        } elseif (CoraxRandom::random_bool(0.3))
            CoraxRandom::insert_string($command_name, CoraxRandom::random_bool() ? '\'\'' : '""');  // cm''d

        $args = self::fake_assign($count);
        foreach ($args as $k => $v) {
            if (CoraxRandom::random_bool(0.3)) {  // Need quotes.
                $quote = CoraxRandom::random_choice(CoraxDictionary::$quotes);
                $v = $quote . addcslashes($v, $quote . '\\') . $quote;
            } else {
                if (CoraxRandom::random_bool(0.3)) $v = '-' . $v;  // Short args.
                if (CoraxRandom::random_bool(0.3)) $v = '-' . $v;  // Long args.
            }
            $args[$k] = $v;
        }

        // Space bypass.
        $sep = CoraxRandom::random_choice(CoraxDictionary::$command_spaces);
        if (!isset($sep[0])) {  // Split bypass.
            $sep = CoraxRandom::random_char();
            $command_name = "IFS=$sep $command_name";
        }
        if (CoraxRandom::random_bool(0.3))
            CoraxRandom::insert_string($command_name, CoraxRandom::random_choice(CoraxDictionary::$command_splits));

        $command = $command_name . $sep . implode($sep, $args);

        return ($sep === ',') ? "{$command}" : $command;
    }

    /**
     * Generate a random function call code string.
     * 
     * @return string The random function call code string.
     */
    public static function fake_func_call($funcs = [])
    {
        $charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_';
        $funcs[] = $charset[mt_rand(0, 52)] . CoraxRandom::random_string(
            mt_rand(0, 5),
            $charset . '0123456789'
        );
        $func_name = $funcs[array_rand($funcs)];
        $arg_count = mt_rand(0, 5);
        $args = [];
        while ($arg_count--) {
            switch (mt_rand(0, 5)) {
                case 0:  // int
                    $args[] = (string) mt_rand();
                    break;
                case 1:  // string
                    $args[] = '"' . addcslashes(CoraxRandom::random_string(mt_rand(0, 8)), '\\"') . '"';
                    break;
                case 2:  // bool
                    $args[] = mt_rand(0, 1) ? 'true' : 'false';
                    break;
                case 3:  // float
                    $args[] = (string) mt_rand() . '.' . mt_rand();
                    break;
                case 4:  // null
                    $args[] = 'null';
                    break;
                case 5:  // func
                    $args[] = self::fake_func_call($funcs);
                    break;
                default:
                    break;
            }
        }

        return $func_name . '(' . implode(', ', $args) . ')';
    }

    /**
     * Generate random url. 
     * TODO: Finish this method.
     * 
     * @return string The random url.
     */
    public static function fake_url()
    {
    }

    /**
     * Randomly encode some chars in payload by using use specified encoder.
     * Builtin encoding:
     *      CoraxHound::encode_hex_escape - escaped hex encoding for a char
     *      CoraxHound::encode_url - url encoding for a char
     *      CoraxHound::encode_html_entity - html entity encoding for a char
     *      CoraxHound::encode_unicode - unicode encoding for a char
     * 
     * @param string $payload The payload to encode.
     * @param callable $encoder The callable function to replace a char from payload. The callback signature is ($c), which is 
     *   single char from payload and it should return a string which is encoded char.
     * @return string The encoded payload.
     */
    public static function encode($payload, $encoder)
    {
        $p = CoraxRandom::random_int(1, 100) / 100;
        $result = '';
        for ($pos = 0, $l = strlen($payload); $pos < $l; $pos++)
            $result .= CoraxRandom::random_bool($p) ? $encoder($payload[$pos]) : $payload[$pos];
        return $result;
    }

    /**
     * Escaped hex encoding for the hound encode.
     * 
     * @param string $c The char to encode.
     * @return string Encoded char.
     */
    public static function encode_hex_escape($c)
    {
        return '\x' . dechex(ord($c));
    }

    /**
     * URLencoding for the hound encode.
     * 
     * @param string $c The char to encode.
     * @return string Encoded char.
     */
    public static function encode_url($c)
    {
        return '%' . dechex(ord($c));
    }

    /**
     * HTML entity encoding for the hound encode.
     * 
     * @param string $c The char to encode.
     * @return string Encoded char.
     */
    public static function encode_html_entity($c)
    {
        return '&#' . dechex(ord($c)) . ';';
    }

    /**
     * Unicode encoding for the hound encode.
     * 
     * @param string $c The char to encode.
     * @return string Encoded char.
     */
    public static function encode_unicode($c)
    {
        return '\u00' . dechex(ord($c));
    }
}
