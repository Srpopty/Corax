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
 * @Filename: CoraxLogger.php
 * @Description: 
 *   A dummy logger in Corax, supports log debug mode. All messages including debug
 * messages will be store in a file with time. For each different log messages 
 * type, will show different prefix to highlight it. Also supports log level to 
 * ident message to make a beautiful logging output.
 * ================================================================================
 */

namespace Corax\Common;


final class CoraxLogger
{
    public static $debug = false;
    public static $log_debug = false;
    public static $colorful = true;
    public static $log_file = './corax.log';

    private static $logging_level_ident = [
        '',
        '  ',
        '    ',
        '      ',
        '        ',
        '          ',
        '            ',
        '              ',
        '                ',
    ];

    // Logging file handle.
    private static $fp = null;
    private static $running = false;

    /**
     * Initialize logger. This should be called manually to set up logger parameters 
     * and start to log messages to file.
     * 
     * @param bool $debug Enable logging debug messages. Defaults to false.
     * @param bool $log_debug Enable logging debug message to log file. Defaults to false.
     * @param bool $colorful Enable colorful output. Defaults to true.
     * @param string $log_file The file to record logging messages. Defaults to "./corax.log".
     * @return bool If initialize logging file successfully.
     */
    public static function init(
        $debug = false,
        $log_debug = false,
        $colorful = true,
        $log_file = './corax.log'
    ) {
        self::$running = true;
        self::$debug = $debug;
        self::$log_debug = $log_debug;
        self::$colorful = $colorful;
        if ($fp = fopen($log_file, 'a')) {
            self::$log_file = $log_file;
            self::$fp = $fp;
            return true;
        } else echo "Failed Initialize Corax logging file \"$log_file\". Access log file denied!\n";
        return false;
    }

    /**
     * Start logging on terminal.
     */
    public static function start()
    {
        self::$running = true;
    }

    /**
     * Stop logging on terminal.
     */
    public static function stop()
    {
        self::$running = false;
    }

    /**
     * Check if logger is running.
     * 
     * @return mixed
     */
    public static function is_running()
    {
        return self::$running;
    }

    /**
     * Shutdown logger manually. This will be called before php shutting down.
     */
    public static function shutdown()
    {
        self::stop();
        if (self::$fp) {
            fclose(self::$fp);
            self::$fp = null;
        }
    }

    /**
     * Move terminal cursor to the head of a line.
     */
    public static function clear_line()
    {
        echo "\x1b[0F";
    }

    /**
     * Clean terminal screen.
     */
    public static function clear_screen()
    {
        echo "\x1b[H\x1b[2J";
    }

    /**
     * Print a message and logging to a log file.
     * 
     * @param string $msg The message to print.
     * @param string $end Message end. Defaults to the endline char.
     * @param bool $debug If this message is a debug message. Logger debug controlled by 
     *   this parameter and class debug parameter. Some messages will not be printed at 
     *   non-debug mode. Defaults to false.
     * @param string|null $color Print a colorful message. Accept "red", "blue", "green", 
     *   "yellow". Defaults to null.
     * @param bool $to_file Enable logging message to log file. Defaults to true.
     */
    public static function print($msg, $end = PHP_EOL, $debug = false, $color = null, $to_file = true)
    {
        // if (self::$running && (!$debug || self::$debug)) {
        if (!$debug || self::$debug) {
            if (self::$colorful && $color) echo "\x1b[{$color}m$msg\x1b[0m$end";
            else echo $msg, $end;
        }

        if ($to_file && (!$debug || self::$log_debug) && self::$fp)
            fwrite(self::$fp, '[' . date('m/d/Y H:i:s', time()) . ']' . $msg . $end);
    }

    /**
     * Print a debugging message.
     * 
     * @param string $msg The message to print.
     * @param int $level Message ident level. Defaults to 0.
     * @param bool $to_file Enable logging message to log file. Defaults to true.
     */
    public static function debug($msg,  $level = 0, $to_file = true)
    {
        if (self::$running) self::print(
            '[$] ' . self::$logging_level_ident[$level] . $msg,
            PHP_EOL,
            true,
            '38;5;226',
            $to_file
        );  // Yellow
    }

    /**
     * Print an information message.
     * 
     * @param string $msg The message to print.
     * @param int $level Message ident level. Defaults to 0.
     * @param bool $to_file Enable logging message to log file. Defaults to true.
     */
    public static function info($msg, $level = 0, $to_file = true)
    {
        if (self::$running) self::print(
            '[*] ' . self::$logging_level_ident[$level] . $msg,
            PHP_EOL,
            false,
            '38;5;87',
            $to_file
        );  // Blue
    }

    /**
     * Print a successful message.
     * 
     * @param string $msg The message to print.
     * @param int $level Message ident level. Defaults to 0.
     * @param bool $to_file Enable logging message to log file. Defaults to true.
     */
    public static function success($msg, $level = 0, $to_file = true)
    {
        if (self::$running) self::print(
            '[+] ' . self::$logging_level_ident[$level] . $msg,
            PHP_EOL,
            false,
            '38;5;46',
            $to_file
        );  // Green
    }

    /**
     * Print a failed message.
     * 
     * @param string $msg The message to print.
     * @param int $level Message ident level. Defaults to 0.
     * @param bool $to_file Enable logging message to log file. Defaults to true.
     */
    public static function failed($msg, $level = 0, $to_file = true)
    {
        if (self::$running) self::print(
            '[-] ' . self::$logging_level_ident[$level] . $msg,
            PHP_EOL,
            false,
            '38;5;196',
            $to_file
        );  // Red
    }

    /**
     * Print a warning message.
     * 
     * @param string $msg The message to print.
     * @param int $level Message ident level. Defaults to 0.
     * @param bool $to_file Enable logging message to log file. Defaults to true.
     */
    public static function warn($msg, $level = 0, $to_file = true)
    {
        self::print(
            '[!] Corax: ' . self::$logging_level_ident[$level] . $msg,
            PHP_EOL,
            false,
            '38;5;202',
            $to_file
        );  // Orange
    }

    /**
     * Print an error message and quit Corax. The exit code is 1.
     * 
     * @param string $msg The message to print.
     * @param int $level Message ident level. Defaults to 0.
     * @param bool $to_file Enable logging message to log file. Defaults to true.
     */
    public static function error($msg, $level = 0, $to_file = true)
    {
        self::print(
            '[x] Corax: ' . self::$logging_level_ident[$level] . $msg,
            PHP_EOL,
            false,
            '38;5;196',
            $to_file
        );  // Red
        self::info('Corax is shutting down...');
        exit(1);
    }
}
