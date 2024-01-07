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
 * @Filename: CoraxInstrumenter.php
 * @Description: 
 *   Corax main instrumenter. By using PhpParser, instrument php code with spacial 
 * code snippets. Parse the raw php code to AST, and use PhpParser to travel the
 * AST by using Visitor to analyze AST node, find basic block and target functions
 * to instrument. All instrumented code will relatively require a root php file in
 * the instrumented directory, this php file supports a fuzzing server.
 * 
 *   The fuzzing server (which is the required php file) will automatically 
 * capture user input and record to file, dynamically identify fuzzer mutated 
 * inputs to record fuzzing path and hits by the instrumented code.
 * ================================================================================
 */

namespace Corax\Instrument;

use Throwable;

use PhpParser\Lexer;
use PhpParser\NodeTraverser;
use PhpParser\ParserFactory;
use PhpParser\NodeVisitor;

use Corax\Common\CoraxUtils;
use Corax\Common\CoraxLogger;
use Corax\Common\CoraxRandom;
use Corax\Common\CoraxStatistic;
use Corax\CoraxMain;


final class CoraxInstrumenter
{
    public static $nest = '__corax__';

    private static $corax = <<< 'CODE'
<?php

\ini_set('display_errors', '1');
\error_reporting(\E_ALL);

// Make sure it will be included only once.
if (defined('\CORAX_##key##')) return;
define('CORAX_##key##', true);


final class Corax_##key##
{
    public static $prev = 0;
    public static $edges = [];

    private static $timer = 0;
    private static $cpu_time = 0;
    private static $new_coverage = 0;
    private static $raw_input = null;
    private static $headers = [];
    private static $fuzzing_mode = 0;
    private static $input_feature = '-';
    private static $raw_input_feature = '';
    private static $target_hit = null;
    private static $get_path = true;
    private static $get_hits = true;
    private static $hits = [];
    private static $web_root = '';
    private static $site_root = '';
    private static $site_root_length = 0;
    
    // Share memory.
    private static $sem_lock_fp = null;
    private static $sem_acquire = 'sem_acquire';
    private static $sem_release = 'sem_release';
    private static $sem_remove = 'sem_remove';
    private static $shmop_key = -1;
    private static $shmop_lock = false;
    private static $sp = null;
    private static $shmop_file = __DIR__ . \DIRECTORY_SEPARATOR . 'shmop.mem';
    private static $shmop_lock_file = __DIR__ . \DIRECTORY_SEPARATOR . '.shmop.mem.lock';
    private static $need_shutdown = false;

    private static $input_path = __DIR__ . \DIRECTORY_SEPARATOR . 'inputs' . \DIRECTORY_SEPARATOR;
    private static $output_path = __DIR__ . \DIRECTORY_SEPARATOR . 'outputs' . \DIRECTORY_SEPARATOR;
    private static $corpus_path = __DIR__ . \DIRECTORY_SEPARATOR . 'corpus' . \DIRECTORY_SEPARATOR;
    private static $cache_path = __DIR__ . \DIRECTORY_SEPARATOR . 'caches' . \DIRECTORY_SEPARATOR;

    /**
     * Get request headers from $_SERVER.
     *
     * @return array Request headers.
     */
    private static function get_all_headers()
    {
        $headers = [];
        foreach ($_SERVER as $name => $value) {
            if (\substr($name, 0, 5) === 'HTTP_')
                $headers[\str_replace(
                    ' ',
                    '-',
                    \ucwords(\strtolower(\str_replace('_', ' ', \substr($name, 5))))
                )] = $value;
        }
        return $headers;
    }

    /**
     * Convert a pathname and a project identifier to a System V IPC key.
     * Same as php-linux "ftok", but for windows. Stolen from glibc-2.3.2.
     * 
     * @param string $filename Path to an accessible file.
     * @param string $project_id Project identifier. This must be a one character string.
     * @return int On success the return value will be the created key value, otherwise -1 is returned.
     */
    private static function ftok($filename, $project_id)
    {
        if ($st = @\stat($filename)) 
            return \sprintf("%u", (($st['ino'] & 0xffff) | (($st['dev'] & 0xff) << 16) | (($project_id & 0xff) << 24)));
        else return -1;
    }

    /**
     * Get a semaphore id. Returns an id that can be used to access the System V semaphore with the given key.
     * A second call to sem_get() for the same key will return a different semaphore identifier, but both identifiers
     * access the same underlying semaphore. If key is 0, a new private semaphore is created for each call to "sem_get".
     * Same as php-linux "sem_get", but for windows. This "sem_get" was implemented by using file lock.
     * 
     * @param int $key Key of the semaphore. 
     * @param int $max_acquire The number of processes that can acquire the semaphore simultaneously is set to max_acquire. 
     *   Useless currently, only for argument compatibility. Defaults to 1.
     * @param int $permissions The semaphore file access permissions. Defaults to 0666.
     * @param bool $auto_release Specifies if the semaphore should be automatically released on request shutdown. 
     *   Defaults to true.
     * @return resource|false Returns the opened lock file resource on success, or false on error.
     */
    private static function sem_get($key, $max_acquire=1, $permissions=0666, $auto_release=true)
    {
        $filename = __DIR__ . '.sem.lock-' . $key;
        if($fp = @\fopen($filename, 'w+')){
            @\chmod($filename, $permissions);
            if ($auto_release) self::$sem_lock_fp = $fp;
            return $fp;
        }
        return false;
    }

    /**
     * Remove a semaphore, removes the given semaphore. After removing the semaphore, it is no longer accessible.
     * 
     * @param resource $semaphore A semaphore as returned by "sem_get".
     * @return bool Returns true on success, or false on failure.
     */
    private static function sem_remove($semaphore)
    {
        @\flock($semaphore, LOCK_UN);
        return @\fclose($semaphore); // && @\unlink(__DIR__ . '.sem.lock-' . $key);
    }

    /**
     * Acquire a semaphore, by default blocks (if necessary) until the semaphore can be acquired. 
     * A process attempting to acquire a semaphore which it has already acquired will block forever if acquiring the 
     * semaphore would cause its maximum number of semaphore to be exceeded. After processing a request, any semaphores 
     * acquired by the process but not explicitly released will be released automatically and a warning will be generated.
     * Same as php-linux "sem_acquire", but for windows. This "sem_acquire" was implemented by using file lock.
     * 
     * @param resource $semaphore A semaphore obtained from "sem_get".
     * @param bool $non_blocking Specifies if the process shouldn't wait for the semaphore to be acquired. If set to true,
     *   the call will return false immediately if a semaphore cannot be immediately acquired. Defaults to false.
     * @return bool Returns true on success, or false on failure.
     */
    private static function sem_acquire($semaphore, $non_blocking=false)
    {
        return @\flock($semaphore, $non_blocking ? (\LOCK_EX|\LOCK_NB) : \LOCK_EX);
    }

    /**
     * Release a semaphore, releases the semaphore if it is currently acquired by the calling process, otherwise a 
     * warning is generated. After releasing the semaphore, "sem_acquire" may be called to re-acquire it.
     * Same as php-linux "sem_acquire", but for windows. This "sem_acquire" was implemented by using file lock.
     * 
     * @param resource $semaphore A semaphore obtained from "sem_get".
     * @return bool Returns true on success, or false on failure.
     */
    private static function sem_release($semaphore)
    {
        return @\flock($semaphore, \LOCK_UN);
    }

    /**
     * Warp the feed with "register_shutdown_function" one more time to make sure the feed will be called
     * at the end of shutdown function queue.
     */
    public static function __feed_shutdown_warp()
    {
        \register_shutdown_function(["Corax_##key##", "feed"]);
    }

    /**
     * Parse tree-like array key path and value, such as GET or POST array.
     * 
     * For example:
     *     $array = [
     *         'a' => [
     *             'b' => 1
     *         ],
     *         'c' => 2
     *     ]
     * And it will get:
     *     [['a', 'b', 1], ['c', 2]]
     * 
     * @param array $array The array to parse.
     * @return array Parsed array keys and value.
     */
    private static function parse_array($array)
    {
        $result = [];

        if ($array) {
            $stack = [[[], $array]];

            while ($stack) {
                list($keys, $value) = \array_pop($stack);

                if (\is_array($value)) {
                    foreach ($value as $k => $v) {
                        $tmp = $keys;
                        $tmp[] = $k;
                        $stack[] = [$tmp, $v];
                    }
                } else {
                    $keys[] = $value;
                    $result[] = $keys;
                }
            }
        }

        return $result;
    }

    /**
     * Encode entire array values by using base64 recurrently.
     *
     * @param array $arr The array to be encoded.
     * @return array Encoded array.
     */
    private static function encode_array($arr)
    {
        $result = [];
        foreach ($arr as $key => $value) {
            if (\is_array($value)) $value = self::encode_array($value);
            elseif (\is_string($value)) $value = \base64_encode($value);
            $result[$key] = $value;
        }
        return $result;
    }

    /**
     * Save input value as corpus to local file, filename is corpus hash.
     *
     * @param array|string $input The input value to record. If array given, it will recurrently call until get a string.
     */
    private static function feed_corpus($input)
    {
        if (\is_array($input)) foreach ($input as $v) self::feed_corpus($v);
        else {
            if (!\is_string($input)) $input = (string) $input;
            // No need empty or big string.
            if (!isset($input[0]) || isset($input[1024])) return;
            $filename = \md5($input) . '.json';
            $filename = self::$corpus_path . \substr($filename, 0, 2) . \DIRECTORY_SEPARATOR . $filename;
            if (!\file_exists($filename)) \file_put_contents($filename, $input);
        }
    }

    /**
     * Get current runtime edges feature and check if current edges contain new edge.
     * 
     * @param &$new_path The result of new edge contained.
     * @param $record Enable record new edge to shared memory. Defaults to false.
     * @return string|null The edges feature if enable record, else null will be returned.
     */
    private static function get_path_feature(&$new_path, $record=false)
    {
        $result = '';
        $edges = self::$edges;
        // Make sure the runtime edges is in order.
        \ksort($edges);
        $sp = self::$sp;
        $new_edge_count = 0;
        
        if ((self::$sem_acquire)(self::$shmop_lock)) {
            foreach ($edges as $edge => $count) {
                // Path count normalization.
                if ($count >= 0x04) {
                    if ($count < 0x08) $count = 0x07;
                    elseif ($count < 0x10) $count = 0x0f;
                    elseif ($count < 0x20) $count = 0x1f;
                    elseif ($count < 0x40) $count = 0x3f;
                    elseif ($count < 0x80) $count = 0x7f;
                    else $count = 0xff;
                }

                // Edge to ID with 29 bits.
                $id = ($edge >> 29) ^ ($edge & 0xfffffff) ^ $count;

                // Shaded shmop memory access to check if the edge is exists globally.
                $val = \ord(\shmop_read($sp, $id >> 3, 1));
                if (($val & (1 << ($id & 7))) === 0){
                    // We found a new edge, which mean the runtime edges is a new path.
                    $new_path = true;
                    // And save to shomp memory.
                    if ($record) {
                        $new_edge_count++;
                        \shmop_write(
                            $sp,
                            \chr($val | (1 << ($id & 7))),
                            $id >> 3
                        );
                    }
                }
                // For getting the path feature from each edge id.
                $result .= '.' . $id;
            }
            if ($new_edge_count) self::$new_coverage += $new_edge_count;
            // Do not forget release the shmop lock.
            (self::$sem_release)(self::$shmop_lock);
        }

        // Path feature.
        return \md5($result);
    }

    /**
     * Dump the given variable detail information as a string.
     * Stolen from: https://www.php.net/manual/en/function.var-dump.php#51119
     * 
     * @param mixed $var The variable to dump.
     * @return string The variable detail information.
     */
    private static function var_dump($var)
    {
        \ob_start();
        \var_dump($var);
        $content = \ob_get_contents();
        \ob_end_clean();
        return $content;
    }

    /**
     * Transform a variable to a human readable readable string. 
     * The array and object can not be transform due to the low efficiency.
     * 
     * TODO: Array to string instead of "{Array}"
     * TODO: Object to string instead of "{Object_name}"
     * 
     * @param mixed $var The variable to transform.
     * @return string Human readable string of the given variable.
     */
    private static function to_string($var)
    {
        if ($var === null) return 'null';
        elseif ($var === false) return 'false';
        elseif ($var === true) return 'true';
        elseif (\is_string($var)) return '"' . \addcslashes($var, '"\\') . '"';
        elseif (\is_int($var) || \is_float($var)) return \print_r($var, true);
        elseif (\is_resource($var)) return '{Resource}' . self::var_dump($var);
        elseif ($var instanceof \Generator) return '{Generator}' . \print_r($var, true);
        elseif ($var instanceof \Closure) return '{Closure}';  // No print_r for closure!
        elseif (\is_array($var)) {
            $result = '{Array}';
            return $result;

            foreach ($var as $k => $v) $result .= '{Key}' . self::to_string($k) . '{Value}' . self::to_string($v);
            return $result;
        } elseif (\is_object($var)) {
            $class_name = get_class($var);
            $result = "{Object_$class_name}";
            return $result;
            
            $len = strlen($class_name) + 2;
            foreach (((array) $var) as $key => $value) {
                $result .= (
                    (strlen($key) > 2 && $key[0] === "\0") ?
                    ($key[1] === "*" ? ('{Protected_' . substr($key, 3) . '}') : ('{Private_' . substr($key, $len) . '}')) :
                    "{Public_$key}"
                ) . self::to_string($value);
            }
            return $result;
        } else return '{Unknown}' . \print_r($var);
    }

    /**
     * Trace a block which the block in a condition such as "if" or "while".
     *
     * @param int $idx Block index.
     * @param mixed $v The condition expression value.
     * @return mixed The condition expression value.
     */
    public static function trace($idx, $v)
    {
        $key = self::$prev << 28 | $idx;
        self::$edges[$key] = (self::$edges[$key] ?? 0) + 1;
        self::$prev = $idx;
        return $v;
    }

    /**
     * Capture target watching function information and record to a file.
     *
     * @param string $func The target function name.
     * @param string $file The file which target function located.
     * @param int $start_pos Target function start position in file.
     * @param int $end_pos Target function end position in file.
     * @param int $start_line Target function start line.
     * @param int $end_line Target function end line.
     * @param int $unpack Arguments count of what needs to be unpacked at the end of $args.
     * @param string $feature Target function feature.
     * @param array|null $watching_args Watching function runtime arguments position array. Given null will watch all arguments.
     * @param array $args Target function runtime arguments.
     * @return array|null Target function call trace back stack.
     */
    public static function watch(
        $func, 
        $file, 
        $start_pos, 
        $end_pos, 
        $start_line, 
        $end_line, 
        $unpack, 
        $feature, 
        $watching_args, 
        $args) {
        if (self::$get_hits) {
            if (self::$target_hit && self::$target_hit !== $feature) return;

            if ($unpack) {
                for ($c = \count($args), $i = $c - $unpack; $i < $c; $i++) {
                    foreach ($args[$i] as $arg) $args[] = $arg;
                    unset($args[$i]);
                }
                // Reset array index.
                $args = \array_values($args);
            }

            // Filter by watching args positions.
            if (is_array($watching_args)) {
                for ($i=0, $j=0, $l = count($args); $i<$l; $i++) {
                    if ($i !== $watching_args[$j]) {
                        unset($args[$i]);
                        $j++;
                    }
                }
            }

            // TODO: This is one of the big choke point of efficiency.
            // Make sure the args value is a safe string.
            $args = self::encode_array(\array_map(function ($arg) {
                return self::to_string($arg);
            }, $args));
            $args_json = \json_encode($args);

            // Check if argument has been changed, for raw_input->hit->argument.
            $hit_name = 'h-' . \md5(
                self::$raw_input_feature .  // Current whole input.
                    $feature .  // Current function.
                    $args_json  // Current arguments.
            );

            // Capture mode, save to cache.
            $save_path = self::$cache_path . \substr($hit_name, 2, 2) . \DIRECTORY_SEPARATOR;            
            $new_path = false;

            // Fuzzing & Tainting mode.
            if (self::$fuzzing_mode > 0) {
                // Not a changeable hit.
                if (\file_exists($save_path . $hit_name . '.json')) return null;

                // TODO: This is one of the big choke point of efficiency.
                // Get path feature and check if it is a new path by the way.
                $path_feature = self::get_path_feature($new_path);
                $hit_name = 'h-' . \md5(
                    self::$input_feature .  // Current fuzzing input, avoid repeating fuzz.
                        $feature .  // Current function.
                        ((self::$fuzzing_mode === 1) ? $path_feature  // Current path.
                            : $args_json) // Current arguments in tainting mode.
                );
                $save_path = self::$output_path . \substr($hit_name, 2, 2) . \DIRECTORY_SEPARATOR;
            } else $path_feature = self::get_path_feature($new_path);

            $save_path .= $hit_name . '.json';
            // Not a new hit.
            if (\file_exists($save_path)) return null;

            if ($fp = @\fopen($save_path, 'cb')) {
                if (\flock($fp, LOCK_EX | LOCK_NB)) {
                    \ftruncate($fp, 0);
                    if (self::$fuzzing_mode === 0) {
                        if (isset(self::$hits[$feature])) self::$hits[$feature][] = $hit_name;
                        else self::$hits[$feature] = [$hit_name];
                        \flock($fp, LOCK_UN);
                        @\fclose($fp);
                        return null;
                    }
                    $tb = [[
                        'func' => $func, 'args' => $args, 'file' => $file, 'start_pos' => $start_pos, 'end_pos' => $end_pos,
                        'start_line' => $start_line, 'end_line' => $end_line, 'ret' => null,
                        'path' => self::$edges, 'path_name' => "p-$path_feature", 'new_path' => $new_path, 'feature' => $feature,
                        'prev_block' => self::$prev
                    ]];

                    $t = \debug_backtrace(\DEBUG_BACKTRACE_IGNORE_ARGS);
                    // Remove "watch".
                    unset($t[0]);

                    foreach ($t as $frame) {
                        $func = $frame['function'];
                        if (isset($frame['class'])) $func = $frame['class'] . $frame['type'] . $func;

                        $tb[] = [
                            'func' => $func,
                            'file' => isset($frame['file']) ? \substr($frame['file'], self::$site_root_length) : '<unknown>',
                            'line' => $frame['line'] ?? 0
                        ];
                    }

                    // Record first time before call the target function.
                    // Now we do not know the ret, but what if something error happened while calling
                    // the target function, we will never get the ret, at least we still have the first
                    // record to save arguments.
                    if (@\fwrite($fp, \json_encode($tb) . "\n")){
                        if (isset(self::$hits[$feature])) self::$hits[$feature][] = $hit_name;
                        else self::$hits[$feature] = [$hit_name];
                        return $fp;
                    } else \flock($fp, LOCK_UN);
                }
                @\fclose($fp);
            }
        }

        return null;
    }

    /**
     * A dummy function only used for watching a target function and record trace back stack.
     * It will hold a argument for "watch" to record target function arguments.
     * Before call the target function, we can get the trace back stack, and after the target function
     * called, we will still record the trace back and call result to file one more time to update
     * the call result.
     *
     * @param \Resource|null $fp The hit file fp.
     * @param mixed $ret The target function return value.
     * @return mixed The target function return value.
     */
    public static function watching($fp, $ret)
    {
        if ($fp) {
            // Save function return value.
            @\fwrite($fp, self::to_string($ret));
            \flock($fp, LOCK_UN);
            @\fclose($fp);
        }

        return $ret;
    }

    /**
     * Reset Corax server status, delete all inputs, path, caches and outputs,
     * and re-init local shared memory file.
     * 
     * TODO: Does the input and caches is necessary?
     * 
     * @return bool If reset Corax server successfully.
     */
    public static function reset_server()
    {
        $result = false;
        // Let's start from reset shared memory local file.
        if (!\file_exists(self::$shmop_lock_file)) {
            if ($fp = @\fopen(self::$shmop_file, 'wb')) {
                if (@\flock($fp, LOCK_EX | LOCK_NB)) {  // Lock local shared memory file.
                    // 32 KB each time to write.
                    $chunk = \str_repeat("\0", 0x8000);
                    $result = true;
                    // Erase file to zero.
                    for ($i = 0; $i < 0x400; $i++) $result = $result && (@\fwrite($fp, $chunk) === 0x8000);

                    // Now let's reset files.
                    if ($result) {
                        $base = __DIR__ . \DIRECTORY_SEPARATOR;
                        foreach ([/*'caches', 'inputs',*/ 'outputs'] as $dir) {
                            $dirs = [$base . $dir . \DIRECTORY_SEPARATOR];
                            while ($dirs) {
                                $d = \array_shift($dirs);
                                if ($dd = scandir($d)) {
                                    foreach($dd as $filename) {
                                        if ($filename[0] === '.' || \strrchr($filename, '.') === '.php') continue;
                                        $filename = $d . $filename;
                                        if (is_dir($filename)) $dirs[] = $filename . \DIRECTORY_SEPARATOR;
                                        else $result = @\unlink($filename) && $result;
                                    }
                                } else $result = false;
                            }
                            if ($result === false) break;
                        }
                    }
                    @\flock($fp, LOCK_UN);
                } else $result = true;
                @\fclose($fp);
            }
        }
        return $result;
    }

    /**
     * Start Corax server, open and prepare shared memory.
     * 
     * @return bool If start Corax server successfully.
     */
    public static function run_server()
    {
        $result = false;
        if ($fp = @\fopen(self::$shmop_file, 'rb')) {
            if (@\flock($fp, LOCK_EX)) {  // Lock local shared memory file.
                if (@(self::$sem_acquire)(self::$shmop_lock)) {  // Lock shared memory.
                    // Server running status check.
                    if (\file_exists(self::$shmop_lock_file)) {  // Server already running.
                        // For multiple Corax clients and single Corax server running at same time.
                        if ($sp = @\shmop_open(self::$shmop_key, 'w', 0666, 0x2000001)) {
                            // Count as one fuzzer. Max fuzzer count is 255.
                            $count = \min(\ord(@\shmop_read($sp, 0x2000000, 1)) + 1, 0xff);
                            // Save back to shared memory.
                            @\shmop_write($sp, \chr($count), 0x2000000);
                            @\shmop_close($sp);
                            $result = true;
                        }
                    } else {
                        // Corax server not running, start now. Delete existed shared memory.
                        if ($sp = @\shmop_open(self::$shmop_key, 'a', 0666, 0x2000001)) {
                            @\shmop_delete($sp);
                            @\shmop_close($sp);
                        }

                        // Create our new shared memory and read from local shared memory file.
                        if ($sp = @\shmop_open(self::$shmop_key, 'n', 0666, 0x2000001)) {
                            // 32 KB each time to write.
                            for ($i = 0; $i < 0x400; $i++) @\shmop_write($sp, @\fread($fp, 0x8000), $i << 0xa);
                            // Default as one client count.
                            @\shmop_write($sp, "\1", 0x2000000);
                            @\shmop_close($sp);
                            // Lock server running file.
                            @\touch(self::$shmop_lock_file);
                            $result = true;
                        }
                    }
                    (self::$sem_release)(self::$shmop_lock);
                }
                @\flock($fp, LOCK_UN);
            }
            @\fclose($fp);
        }
        return $result;
    }

    /**
     * Shutdown Corax server, close shared memory and save it to local.
     * 
     * @return bool If shutdown Corax server successfully.
     */
    public static function shutdown_server()
    {
        $result = false;
        // Server is running.
        if (\file_exists(self::$shmop_lock_file)) {
            if ($fp = @\fopen(self::$shmop_file, 'wb')) {
                if (@\flock($fp, LOCK_EX)) {  // Lock local shared memory file.
                    if (@(self::$sem_acquire)(self::$shmop_lock)) {  // Lock shared memory.
                        if ($sp = shmop_open(self::$shmop_key, 'w', 0666, 0x2000001)) {
                            // One fuzzer stopped, min is zero.
                            $count = \max(\ord(@\shmop_read($sp, 0x2000000, 1)) - 1, 0);
                            // Save back to shared memory.
                            shmop_write($sp, \chr($count), 0x2000000);
                            // No Corax client required this Corax server, shutdown server now.
                            if ($count === 0) {
                                // 32 KB each time to write.
                                for ($i = 0; $i < 0x400; $i++) @\fwrite($fp, @\shmop_read($sp, $i << 0xa, 0x8000));
                                @\shmop_delete($sp);
                                // Unlock server running file.
                                @\unlink(self::$shmop_lock_file);
                            }
                            @\shmop_close($sp);
                            $result = true;
                        }
                        // Server has been totally shuted down, remove lock.
                        // if (isset($count) && $count === 0) (self::$sem_remove)(self::$shmop_lock);
                        // else 
                            (self::$sem_release)(self::$shmop_lock);
                    }
                    @\flock($fp, LOCK_UN);
                } 
                @\fclose($fp);
            }
        } else $result = true;
        return $result;
    }

    /**
     * Capture all user input to local file on each user request, filename is input hash.
     */
    public static function hunt()
    {
        // Server statistics.
        self::$timer = \microtime(true);
        $ru = \getrusage();
        self::$cpu_time = $ru['ru_utime.tv_sec'] + $ru['ru_utime.tv_usec'] / 1e6 +
            $ru['ru_stime.tv_sec'] + $ru['ru_stime.tv_usec'] / 1e6;

        // Prepare shared memory.
        if (\function_exists('ftok') && \function_exists('sem_get')) {
            self::$shmop_key = \ftok(__FILE__, 'h');
            self::$shmop_lock = \sem_get(self::$shmop_key);
        } else {  // Not support sem_*, using Corax builtin.
            self::$shmop_key = self::ftok(__FILE__, 'h');
            self::$shmop_lock = self::sem_get(self::$shmop_key);
            self::$sem_acquire = [__CLASS__, 'sem_acquire'];
            self::$sem_release = [__CLASS__, 'sem_release'];
            self::$sem_remove = [__CLASS__, 'sem_remove'];
        }

        // Register Corax shutdown feed warper for safely quit server.
        \register_shutdown_function(["Corax_##key##", "__feed_shutdown_warp"]);

        // Switch server mode.
        if (isset($_REQUEST['##key##'])) {
            $msg = 'failed';
            switch ($_REQUEST['##key##']) {
                case 'run':
                    $msg = self::run_server() ? 'ok' : 'Start Corax server failed!';
                    break;
                case 'shutdown':
                    $msg = self::shutdown_server() ? 'ok' : 'Shutdown Corax server failed!';
                    break;
                case 'reset':
                    $msg = self::reset_server() ? 'ok' : 'Reset Corax server failed!';
                    break;
                default:
                    $msg = 'Unknown command "' . $_REQUEST['##key##'] . '".';
                    break;
            }
            die($msg);
        }

        // Server in running.
        if (\file_exists(self::$shmop_lock_file)) {  // Corax server is running, use shmop.
            $count = 10;
            while ($count) {
                // 32 MB shared memory.
                if (self::$sp = @\shmop_open(self::$shmop_key, 'w', 0666, 0x2000001)) break;
                $count--;
                usleep(5000);
            }
            if ($count == 0) {
                \http_response_code(500);
                die('Open corax shared memory failed! Please remove "' . __DIR__ . '/.shmop.mem.lock" manually!');
            }
        } elseif (self::$fuzzing_mode) {  // Corax in fuzzing, should start server earlier.
            \http_response_code(500);
            die('Corax server is not running!');
        } elseif (self::run_server()) {  // Capture user input, start server now.
            // Open shared memory. It has to exist.
            $count = 10;
            while ($count) {
                if (self::$sp = @\shmop_open(self::$shmop_key, 'w', 0666, 0x2000001)) break;
                $count--;
                usleep(5000);
            }
            if ($count === 0) {
                \http_response_code(500);
                die('Open corax shared memory failed!');
            }
            self::$need_shutdown = true;
        } else {
            \http_response_code(500);
            die('Start Corax server failed!');
        }

        // Reset server status.
        self::$prev = 0;
        self::$edges = [];
        self::$hits = [];
        self::$raw_input = null;
        self::$headers = self::get_all_headers();
        self::$web_root = $_SERVER['DOCUMENT_ROOT'];
        self::$site_root = \realpath(__DIR__ . \DIRECTORY_SEPARATOR . '..') . \DIRECTORY_SEPARATOR;
        self::$site_root_length = strlen(self::$site_root);

        // Setup Corax server from request header commands.
        if (isset(self::$headers['##ucl_key##-Fuzzing']))  // Fuzzing mode.
            self::$fuzzing_mode = (int) self::$headers['##ucl_key##-Fuzzing'];
        if (isset(self::$headers['##ucl_key##-Input-Feature'])) {  // Current fuzzing input mark.
            self::$input_feature = self::$headers['##ucl_key##-Input-Feature'];
            self::$raw_input_feature = \explode('-', self::$input_feature)[0];
        }
        if (isset(self::$headers['##ucl_key##-Target-Hit']))  // Target hit mark.
            self::$target_hit = self::$headers['##ucl_key##-Target-Hit'];
        if (isset(self::$headers['##ucl_key##-No-Path']))  // Path gather mode.
            self::$get_path = !((bool) self::$headers['##ucl_key##-No-Path']);
        if (isset(self::$headers['##ucl_key##-No-Hits']))   // Hit gather mode.
            self::$get_hits = !((bool) self::$headers['##ucl_key##-No-Hits']);

        // Fuzzing mode quit now, or we need to capture user input.
        if (self::$fuzzing_mode || !isset($_SERVER['REQUEST_URI'])) return;

        // Extract user uploaded files.
        $files = [];
        foreach ($_FILES as $k => $v) {
            if (is_string($v['name'])) {
                $content = @\file_get_contents($v['tmp_name']);
                if ($content === false || $content === null) $content = '';
                $files[$k] = ['filename' => $v['name'], 'type' => $v['type'], 'content' => $content];
            } elseif (is_array($v['name'])) {
                $names = self::parse_array($v['name']);
                $types = self::parse_array($v['type']);
                $tnames = self::parse_array($v['tmp_name']);

                for ($i=0,$l=count($names); $i<$l; $i++) {
                    $name = $names[$i];
                    $filename = \array_pop($name);
                    foreach ($name as $n) $k .= "[$n]";
                    $content = $tnames[$i];
                    $content = @\file_get_contents(\end($content));
                    if ($content === false || $content === null) $content = '';
                    $type = $types[$i];
                    $files[$k] = ['filename' => $filename, 'type' => \end($type), 'content' => $content];
                }
            }
        }

        // Get http post data.
        if ($_POST) $raw_post = '';
        elseif (($raw_post = @\file_get_contents('php://input')) === false) $raw_post = '';

        $headers = self::$headers;
        if (isset($_SERVER['CONTENT_TYPE'])) $headers['Content-Type'] = $_SERVER['CONTENT_TYPE'];
        $input = [
            'data' => [
                'get' => $_GET,
                'post' => $_POST,
                'path' => isset($_SERVER['PATH_INFO']) ? \explode('/', $_SERVER['PATH_INFO']) : [],
                'raw_post' => $raw_post ?? '',
                'files' => $files,
                'cookies' => $_COOKIE,
                'headers' => $headers
            ],
            'info' => [
                'php_self' => $_SERVER['PHP_SELF'],
                'gateway_interface' => $_SERVER['GATEWAY_INTERFACE'] ?? '',
                'server_protocol' => $_SERVER['SERVER_PROTOCOL'] ?? '',
                'request_method' => $_SERVER['REQUEST_METHOD'] ?? '',
                'query_string' => $_SERVER['QUERY_STRING'] ?? '',
                'script_filename' => $_SERVER['SCRIPT_FILENAME'] ?? '',
                'script_name' => $_SERVER['SCRIPT_NAME'] ?? '',
                'web_root' => self::$web_root,
                'site_root' => self::$site_root,
                'request_uri' => $_SERVER['REQUEST_URI'],
                // Keys of get.
                'get_keys' => self::parse_array($_GET),
                // Keys of post.
                'post_keys' => self::parse_array($_POST),
                // Input feature.
                'feature' => '',
                // Initial input path name.
                'path_name' => '',
                // Initial input hit names.
                'hits' => [],
                // Input mutate history, for fuzzing client.
                'mutated' => ['http_request' => ['raw_http_input']],
                'time' => microtime(true)
            ]
        ];

        // Get the whole input feature.
        $get_keys = [];
        foreach ($input['info']['get_keys'] as $keys) {
            \array_pop($keys);
            $get_keys[] = \implode('.', $keys);
        }
        \sort($get_keys);
        $post_keys = [];
        foreach ($input['info']['post_keys'] as $keys) {
            \array_pop($keys);
            $post_keys[] = \implode('.', $keys);
        }
        \sort($post_keys);
        $file_keys = \array_keys($input['data']['files']);
        \sort($file_keys);
        $cookie_keys = \array_keys($input['data']['cookies']);
        \sort($cookie_keys);
        $header_keys = \array_keys($input['data']['headers']);
        \sort($header_keys);

        $feature = md5(sprintf(
            'GET[%s].POST[%s].PATH[%d].RAW_POST[%d].FILES[%s].COOKIES[%s].HEADERS[%s]',
            \implode('.', $get_keys),
            \implode('.', $post_keys),
            \count($input['data']['path']),
            (int)(\strlen($input['data']['raw_post']) > 0),
            \implode('.', $file_keys),
            \implode('.', $cookie_keys),
            \implode('.', $header_keys)
        ));
        $input['info']['feature'] = self::$raw_input_feature = $feature;
        self::$raw_input = $input;
    }

    /**
     * Save input, hits and path which this request input passed at the end of request.
     */
    public static function feed()
    {
        if (!isset($_SERVER['REQUEST_URI'])) return;

        // Check new path.
        $new_path = false;
        if (self::$sp){
            $path_name = 'p-' . self::get_path_feature($new_path, self::$get_path);
            if ((self::$sem_acquire)(self::$shmop_lock)) {
                \shmop_close(self::$sp);
                (self::$sem_release)(self::$shmop_lock);
            }
        } else $path_name = 'none';

        if (self::$fuzzing_mode) {
            $server_time = \round(\microtime(true) - self::$timer, 3);
            $ru = \getrusage();
            // Generate path and hits index.
            echo '<!-- Corax{' . \base64_encode(\json_encode([
                'path_name' => $path_name,
                'path' => (self::$get_path && $new_path) ? self::$edges : null,
                'hits' => self::$hits,
                'new_coverage' => self::$new_coverage,
                'server_time' => $server_time,
                'server_cpu' => $server_time ? (100 * round(($ru['ru_utime.tv_sec'] + $ru['ru_utime.tv_usec'] / 1e6 +
                    $ru['ru_stime.tv_sec'] + $ru['ru_stime.tv_usec'] / 1e6 - self::$cpu_time) / $server_time, 3)) : 0
            ])) . '} -->';
        } elseif (self::$raw_input) {
            if ($new_path){
                // Record input info.
                self::$raw_input['info']['path_name'] = $path_name;
                self::$raw_input['info']['coverage_edges'] = self::$new_coverage;
                self::$raw_input['info']['hits'] = self::$hits;
                // Save new captured input.
                $input_path = \md5($path_name . \md5(\json_encode(self::encode_array(self::$raw_input['data'])))) . '.json';
                $input_path = self::$input_path . \substr($input_path, 0, 2) . \DIRECTORY_SEPARATOR . $input_path;
                if (!\file_exists($input_path)) {
                    if (\file_put_contents($input_path, \json_encode(self::encode_array(self::$raw_input))) !== false) {
                        $path_path = self::$cache_path . \substr($path_name, 2, 2) . \DIRECTORY_SEPARATOR . $path_name . '.json';
                        if (!\file_exists($path_path)) \file_put_contents($path_path, json_encode(self::$edges));
                        self::feed_corpus(self::$raw_input['data']);
                    }
                }
            } else {
                // Not capture input, remove all cached hits.
                foreach (self::$hits as $hits) {
                    foreach ($hits as $hit_name) 
                        @\unlink(self::$cache_path . \substr($hit_name, 2, 2) . \DIRECTORY_SEPARATOR . $hit_name);
                }
            }

            if (self::$need_shutdown) {
                if (!self::shutdown_server()) {
                    \http_response_code(500);
                    echo 'Shutdown Corax server failed!';
                }
            }
        }

        // TODO: If this release if required?
        // Auto release the fp of sem lock.
        // if (self::$sem_lock_fp) (self::sem_remove)(self::$sem_lock_fp);
        // End the shutdown function queue.
        exit();
    }
}

\Corax_##key##::hunt();

CODE;

    // Corax nest directory htaccess for safely fuzzing and high efficiency.
    private static $corax_htaccess = <<< 'CODE'
# Access granted for Corax from all.
<FilesMatch ".">
    Require all granted
    Order allow,deny
    Allow from all
</FilesMatch>

# Hide directory listing.
Options -Indexes

# Set default handler
DirectoryIndex index.php

# PHP 7, Apache 1 and 2.
<IfModule mod_php7.c>
    # Session expired after 72 hours.
    php_value session.cookie_lifetime 259200
    php_value session.gc_maxlifetime 259200
</IfModule>

# PHP 8, Apache 1 and 2.
<IfModule mod_php.c>
    # Session expired after 72 hours.
    php_value session.cookie_lifetime 259200
    php_value session.gc_maxlifetime 259200
</IfModule>

# Bypass rewrite rules for Corax.
<IfModule mod_rewrite.c>
    RewriteEngine on
    RewriteRule "^.+/__corax__/.*($|/)" - [L]
</IfModule>

CODE;

    // Corax nest index.php content.
    private static $corax_index = <<< 'CODE'
<?php

die('Corax ##version##');

CODE;

    // Corax nest directories index.php content, manipulate files in the directory.
    private static $dir_index = <<< 'CODE'
<?php

error_reporting(E_ALL);
ini_set('display_errors','On');

if (isset($_REQUEST['f'])) {  // Fetch files.
    $filenames = explode(',', $_REQUEST['f']);
    for ($i = 0, $count = count($filenames); $i < $count; $i++) {
        $filename = $filenames[$i];
        // Skip hidden files and php scripts.
        if ($filename[0] === '.' || strrchr($filename, '.') === '.php') {
            http_response_code(403);
            break;
        }

        // Filter for "/".
        $filename = __DIR__ . DIRECTORY_SEPARATOR . str_replace('/', '', str_replace('\\', '/', $filename));
        if (file_exists($filename)) {
            if (isset($_REQUEST['e'])) {
                echo (isset($_REQUEST['h']) ? @hash_file('md5', $filename) : @file_get_contents($filename));
                if ($i + 1 !== $count) echo "\n------------CoraxSplitLine------------\n";
            }
            if (isset($_REQUEST['d'])) @unlink($filename);
        } else {
            http_response_code(404);
            break;
        }
    }
} else {  // List directory or delete files.
    $root = __DIR__;
    $length = strlen($root);
    $dirs = [$root];
    $files = [];
    while ($dirs) {  // Get all files.
        $dir = array_shift($dirs);
        if ($d = scandir($dir)) {
            foreach ($d as $filename) {
                // Skip hidden files and php scripts.
                if ($filename[0] === '.' || strrchr($filename, '.') === '.php') continue;
                $path = $dir . DIRECTORY_SEPARATOR . $filename;
                // Traveling directory.
                if (is_dir($path)) $dirs[] = $path;
                else $files[] = substr($path, $length);
            }
        }
    }

    if (isset($_REQUEST['x'])) {  // Delete files.
        $result = true;
        foreach ($d as $f) $result = $result && @unlink($f);
        echo $result ? 'ok' : 'failed';
    } else {  // List files.
        sort($files);
        $files = implode("\n", $files);
        echo $files ? (isset($_REQUEST['h']) ? md5($files) : $files) : '0';
    }
}

CODE;

    public $src;

    private $parser;
    private $traverser;

    private $visitor = null;

    // Statistics data.
    private $start_time = 0;
    private $total_corpus = 0;
    private $total_watch = 0;
    private $failed_modify = [];
    private $failed_write = [];
    private $failed_source = [];
    private $failed_instrumented = [];
    private $fileinfo = [];
    private $watchinfo = [];

    /**
     * Initialize a instrumenter.
     * 
     * @param string $src Instrument source directory.
     * @param int $php_version The source php major version. Defaults to 7.
     */
    public function __construct($src, $php_version = 7)
    {
        // Source directory check.
        if (!file_exists($src)) CoraxLogger::error("Source directory \"$src\" does not exist.");
        if (!is_dir($src)) CoraxLogger::error("Source directory \"$src\" is not a directory.");
        $src = realpath($src) . DIRECTORY_SEPARATOR;
        $this->src = $src;

        switch ($php_version) {
            case 5:
                $this->parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP5, new Lexer\Emulative([
                    'usedAttributes' => [
                        'comments', 'startLine', 'endLine',
                        'startFilePos', 'endFilePos',
                    ]
                ]));
                break;
            case 7:
            default:
                $this->parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP7, new Lexer\Emulative([
                    'usedAttributes' => [
                        'comments', 'startLine', 'endLine',
                        'startFilePos', 'endFilePos',
                    ]
                ]));
        }

        $this->traverser = new NodeTraverser();
        $this->traverser->addVisitor(new NodeVisitor\NameResolver(null, [
            'preserveOriginalNames' => false,
            'replaceNodes' => true,
        ]));
    }

    /**
     * Reset instrument data and visitor.
     * 
     * @param string $key The Corax fuzzing key.
     * @param bool $lazy If enable lazy instrument mode.
     * @param string|null $watching Watch function. Supports regex.
     */
    private function reset($key, $lazy, $watching)
    {
        if ($this->visitor) $this->traverser->removeVisitor($this->visitor);
        $this->visitor = new CoraxVisitor($key, $lazy, $watching);
        $this->traverser->addVisitor($this->visitor);

        $this->total_corpus = $this->total_watch = 0;
        $this->failed_modify = $this->failed_write = $this->failed_source =
            $this->failed_instrumented = $this->fileinfo = $this->watchinfo = [];
        $this->start_time = microtime(true);
    }

    /**
     * Instrument a file.
     * 
     * @param string $src File source path.
     * @param string $dst File destination path.
     * @param string $filename File relative path of source path.
     * @param string $context Corax relative context path of destination path.
     * @param string $nest Corpus nest in destination directory.
     * @param bool $want_watch Enable watching target functions while instrumenting the file.
     */
    private function instrument_file($src, $dst, $filename, $context, $nest, $want_watch)
    {
        $time = microtime(true);
        CoraxLogger::info("Instrumenting \"$filename\"...", 1);
        if (!$want_watch) CoraxLogger::info("File \"$filename\" will not be watched.", 2);

        $code = file_get_contents($src);
        $this->visitor->init($filename, $code, $context, $want_watch);
        $start_index = $this->visitor->current_index();

        try {
            // Pase source code to AST tree nodes.
            $nodes = $this->parser->parse($code);
            // Traverse node tree and instrument.
            $this->traverser->traverse($nodes);
        } catch (Throwable $e) {
            CoraxLogger::failed("Failed! Broken source code from $src, this file will not be instrumented.", 2);
            // Simply copied.
            if (!CoraxUtils::file_put_contents($dst, $code)) {
                CoraxLogger::failed("Write source code to \"$dst\" failed!", 3);
                $this->failed_write[] = $dst;
            }
            $this->failed_source[$src] = $e->getMessage();
            return;
        }

        // The instrumented source code.
        $instrumented_code = $this->visitor->get_code();
        $end_index = $this->visitor->current_index() - 1;
        // Some conflict may be happened while instrumenting.
        if ($conflict = $this->visitor->get_conflict()) $this->failed_modify[$filename] = $conflict;
        CoraxLogger::debug(
            "Instrument finished, index range: [$start_index, $end_index]. Extracting corpus...",
            2
        );

        // Saving collected corpus which from source code.
        $corpus = $this->visitor->get_corpus();
        $corpus_count = 0;
        foreach ($corpus as $name => $value) {
            if (file_put_contents($nest . 'corpus' . DIRECTORY_SEPARATOR . substr($name, 0, 2) . DIRECTORY_SEPARATOR .
                $name . '.json', $value) !== false) $corpus_count++;
            else CoraxLogger::warn("Save corpus \"$name\" failed!");
        }
        $this->total_corpus += $corpus_count;
        CoraxLogger::debug("Extracted $corpus_count corpus. Checking instrumented code...", 2);

        try {
            // Check if instrumented code is grammatically correct. This may take a while...
            $this->parser->parse($instrumented_code);
        } catch (Throwable $e) {
            if (CoraxLogger::$debug) {
                CoraxLogger::failed("Failed! Broken instrumented code from $src.", 2);
                CoraxLogger::debug("Notice: The broken code will be written to \"$dst\" for debugging.", 2);
                if (!CoraxUtils::file_put_contents($dst, $instrumented_code)) {
                    CoraxLogger::failed("Write instrumented code to \"$dst\" failed!", 3);
                    $this->failed_write[] = $dst;
                }
            } else {
                CoraxLogger::failed("Failed! Broken instrumented code from $src, this file will not be instrumented.", 2);
                if (!CoraxUtils::file_put_contents($dst, $code)) {
                    CoraxLogger::failed("Write source code to \"$dst\" failed!", 3);
                    $this->failed_write[] = $dst;
                }
            }
            $this->failed_instrumented[$src] = $e->getMessage();
            return;
        }

        // Check passed and save instrumented source code.
        if (CoraxUtils::file_put_contents($dst, $instrumented_code)) {
            $fileinfo = $this->visitor->get_fileinfo();
            if ($fileinfo) {
                $this->fileinfo[$filename] = $fileinfo;
                $msg = 'OK, instrumented ' . count($fileinfo) . ' block(s)';

                $watchinfo = $this->visitor->get_watchinfo();
                if ($watchinfo) {
                    $count = count($watchinfo);
                    $this->total_watch += $count;
                    $msg .= " and $count watch point(s)";
                    $this->watchinfo[$filename] = $watchinfo;
                }

                CoraxLogger::success($msg . ' in ' . round(microtime(true) - $time, 3) . ' s.', 2);
            } else CoraxLogger::info('No block instrumented.', 2);
        } else {
            CoraxLogger::failed("Write instrumented code to \"$dst\" failed!", 2);
            $this->failed_write[] = $dst;
        }
    }

    /**
     * Instrument to destination directory.
     * 
     * @param string $dst The destination directory.
     * @param string $nest Corax next path in destination directory.
     * @param string $context Corax context path.
     * @param string $file_ext Filter file ext regex.
     * @param string $exclude Filter excluded file regex.
     * @param string|null $watch_only Filter watching file regex. Given null will watch all files. Defaults to null.
     */
    private function instrument_dir($dst, $nest, $context, $file_ext, $exclude, $watch_only = null)
    {
        CoraxLogger::info("Start instrumenting from \"$this->src\"...");
        $src_length = strlen($this->src);
        foreach (CoraxUtils::scandir($this->src) as $s) {
            pcntl_signal_dispatch();
            $filename = substr($s, $src_length);
            $d = $dst . $filename;

            if (is_dir($s)) {
                if (file_exists($d) || CoraxUtils::mkdir($d)) CoraxLogger::debug("Empty directory \"$filename\" created.", 1);
                else {
                    CoraxLogger::failed("Create empty directory \"$d\" failed!", 1);
                    $this->failed_write[] = $d;
                }
                continue;
            }

            if ($file_ext && preg_match($file_ext, $filename)) {  // Filtered by file extension.
                if (!($exclude && preg_match($exclude, $filename))) {  // Filtered by exclude rules.
                    // Instrument the file.
                    $this->instrument_file($s, $d, $filename, '\' . __DIR__ . \'' . DIRECTORY_SEPARATOR .
                        CoraxUtils::a2r($d, $context), $nest, ($watch_only === null) || preg_match($watch_only, $filename));
                    continue;
                } elseif (strpos($filename, self::$nest) === false) {
                    CoraxLogger::info("File \"$filename\" will not be instrumented because the exclude dir or file rule.", 1);
                }
            }

            if (file_exists($d) || (CoraxUtils::mkdir(dirname($d)) && @copy($s, $d) && chmod($d, 0777)))
                CoraxLogger::debug("Simply copied \"$filename\".", 1);
            else {
                CoraxLogger::failed("Copy file \"$s\" to \"$d\" failed!", 1);
                $this->failed_write[] = $d;
            }
        }
    }

    /**
     * Show instrument report.
     * 
     * @param string $dst The instrument destination directory.
     */
    private function instrument_report($dst)
    {
        $count = count($this->fileinfo);
        if ($count) {
            CoraxLogger::success(
                "Totally $count files of \"$this->src\" instrumented to \"$dst\" with " .
                    ($this->visitor->current_index() - 1) .
                    " block(s), $this->total_watch watch point(s) and $this->total_corpus corpus " .
                    'in ' . round(microtime(true) - $this->start_time, 3) . ' s. (' .
                    (count($this->failed_source) + count($this->failed_instrumented)) . ' file(s) instrumented failed)'
            );
        } else CoraxLogger::warn('No file instrumented!');

        // Error report.
        if ($this->failed_modify) {
            CoraxLogger::warn('These files have conflict instrumentations (conflict instrumentations will be abort):');
            foreach ($this->failed_modify as $filename => $node_info) {
                CoraxLogger::warn($filename . ' - ' . count($node_info) . ' conflation(s)', 1);
                if (CoraxLogger::$debug) {
                    foreach ($node_info as $id => $infos) {
                        CoraxLogger::warn("Conflicted node id: " . $id, 2);
                        CoraxLogger::warn("Aborted instrumentation(s): ", 2);
                        $i = 0;
                        foreach ($infos as $info) {
                            CoraxLogger::warn("Instrumentation #$i:", 3);
                            CoraxLogger::warn('Source code: ' . $info[6], 4);
                            CoraxLogger::warn("Modification position: " . $info[4], 4);
                            CoraxLogger::warn("Modification length: " . $info[5], 4);
                            CoraxLogger::warn('Modification source code: ' . $info[7], 4);
                            CoraxLogger::warn("Modification string: " . $info[8], 4);
                            $i++;
                        }
                    }
                }
            }
        }

        if ($this->failed_write) {
            CoraxLogger::warn("These files could not be wrote to destination path \"$dst\":");
            foreach ($this->failed_write as $filename) CoraxLogger::warn($filename, 1);
        }

        if ($this->failed_source) {
            CoraxLogger::warn("These files are instrumented failed because of broken source code from \"$this->src\":");
            foreach ($this->failed_source as $filename => $msg) {
                CoraxLogger::warn($filename, 1);
                CoraxLogger::warn('Parse error: ' . $msg, 2);
            }
        }

        if ($this->failed_instrumented) {
            CoraxLogger::warn('These files are instrumented failed because of broken instrumented code:');
            foreach ($this->failed_instrumented as $filename => $msg) {
                CoraxLogger::warn($filename, 1);
                CoraxLogger::warn('Parse error: ' . $msg, 2);
            }
            if (CoraxLogger::$debug) CoraxLogger::warn(
                'Notice: In debug mode, the broken code will be write to target file for debugging.'
            );
        }
    }

    /**
     * Ready to instrument.
     * 
     * @param string $dst The destination path.
     * @param mixed $nest Corax nest directory.
     * @param mixed $key Corax fuzzing key.
     * @param bool $lazy If enable lazy instrument mode.
     * @param array $watching Watch functions. Empty string is not allowed. Supports regex.
     * @param array $file_ext Instrument file ext. Empty string is not allowed. Supports regex.
     * @param array $exclude Exclude files and directories while instrumenting. Empty string is not allowed. 
     *   Supports regex.
     * @param array $watch_only Only watch the given files and directories while instrumenting. Empty string
     *   is not allowed. Supports regex.
     * @return string Corax fuzzing key.
     */
    private function ready($dst, $nest, $key, $lazy, $watching, $file_ext, $exclude, $watch_only)
    {
        // Corax nest initialize.
        CoraxLogger::info('Initializing nest...');
        $context = $nest . "$key.php";
        if (!CoraxUtils::file_put_contents($context, str_replace(
            ['##key##', '##ucl_key##'],
            [$key, 'Corax-' . ucwords(strtolower($key))],
            self::$corax
        ), 0754)) CoraxLogger::error("Create corax \"$context\" failed!");
        CoraxLogger::info("Corax \"$context\" initialized.", 1);

        CoraxUtils::file_put_contents("{$nest}.htaccess", self::$corax_htaccess, 0644);
        CoraxLogger::info("Corax nest access control \"{$nest}.htaccess\" initialized.", 1);

        CoraxUtils::file_put_contents(
            "{$nest}index.php",
            str_replace('##version##', CoraxMain::$version, self::$corax_index),
            0754
        );
        CoraxLogger::info("Corax nest index \"{$nest}index.php\" initialized.", 1);

        // Initialize Corax nest directories.
        foreach (['corpus', 'inputs', 'outputs', 'caches'] as $name) {
            $dir = $nest . $name . DIRECTORY_SEPARATOR;
            CoraxUtils::file_put_contents($dir . 'index.php', self::$dir_index, 0754);
            for ($i = 0; $i <= 0xff; $i++) {
                CoraxUtils::file_put_contents($dir . str_pad(dechex($i), 2, '0', STR_PAD_LEFT) . DIRECTORY_SEPARATOR .
                    'index.php', self::$dir_index, 0754);
            }
            CoraxLogger::info("Corax nest $name \"$dir\" initialized.", 1);
        }

        CoraxUtils::file_put_contents("{$nest}key.txt", $key, 0444);
        CoraxLogger::info("Corax key file \"{$nest}key.txt\" initialized.", 1);
        CoraxUtils::file_put_contents("{$nest}test_$key.php", "<?php echo '$key';", 0754);
        CoraxLogger::info("Corax test key file \"{$nest}test_$key.php\" initialized.", 1);

        CoraxLogger::info("Ready to instrument to \"$dst\".");
        CoraxLogger::info("Corax nest: $nest", 1);
        CoraxLogger::info("Fuzzing key: $key", 1);
        if ($watching) CoraxLogger::info('Watching functions: ' . implode(', ', $watching), 1);
        if ($file_ext) CoraxLogger::info('Target file ext: ' . implode(', ', $file_ext), 1);
        if ($exclude) CoraxLogger::info('Excluded files and directories: ' . implode(', ', $exclude), 1);
        if ($watch_only) CoraxLogger::info('Watching files and directories: ' . implode(', ', $watch_only), 1);

        if ($watching) {
            $watching = '/^(' . implode('|', array_filter($watching))  . ')$/um';
            CoraxLogger::debug('Watching function regex: ' . $watching, 1);
        } else $watching = null;

        if ($file_ext) {
            $file_ext = '/\.(' . implode('|', array_filter($file_ext))  . ')$/um';
            CoraxLogger::debug('File ext regex: ' . $file_ext, 1);
        } else $file_ext = null;

        if ($exclude) {
            $exclude = '/' . implode('|', array_filter($exclude)) . '/um';
            CoraxLogger::debug('Exclude files or directories regex: ' . $exclude, 1);
        } else $exclude = null;

        if ($watch_only) {
            $watch_only = '/' . implode('|', array_filter($watch_only)) . '/um';
            CoraxLogger::debug('Watching files or directories regex: ' . $watch_only, 1);
        } else $watch_only = null;

        // Ready to roll.
        for ($i = 3; $i; $i--) {
            CoraxLogger::info("Corax will start instrument in $i s...");
            CoraxLogger::clear_line();
            sleep(1);
        }

        // TODO: Build report UI for instrument mode.
        // if (CoraxStatistic::$enable_ui) {
        //     CoraxLogger::clear_screen();
        //     CoraxLogger::stop();
        // }

        $this->reset($key, $lazy, $watching);
        $this->instrument_dir($dst, $nest, $context, $file_ext, $exclude, $watch_only);
        $this->instrument_report($dst);

        // Initialize shmop.
        CoraxLogger::info('Generating shared memory file...');
        $fname = "{$nest}shmop.mem";
        if ($fp = fopen($fname, 'w')) {
            $chunk = str_repeat("\0", 0x8000);
            // Totally 0x2000000 (32 MB) zero bytes filled.
            for ($i = 0; $i < 0x400; $i++) fwrite($fp, $chunk);
            fclose($fp);
            chmod($fname, 0666);
        }
        CoraxLogger::debug("Corax shared memory file \"$fname\" initialized.");

        CoraxUtils::file_put_contents("{$nest}fileinfo.json", json_encode($this->fileinfo), 0444);
        CoraxLogger::debug("Corax file position info file \"{$nest}fileinfo.json\" initialized.");
        CoraxUtils::file_put_contents("{$nest}watchinfo.json", json_encode($this->watchinfo), 0444);
        CoraxLogger::debug("Corax watching info file \"{$nest}watchinfo.json\" initialized.");

        CoraxLogger::info("Instrument done. Corax-$key is ready to roll.");

        return $key;
    }

    /**
     * Get instrumented file info.
     * 
     * @return array The file info.
     */
    public function get_fileinfo()
    {
        return $this->fileinfo;
    }

    /**
     * Get instrumented watching info.
     * 
     * @return array The watching info.
     */
    public function get_watchinfo()
    {
        return $this->watchinfo;
    }

    /**
     * Check if a path has been instrumented.
     * 
     * @param string $path The path to check.
     * @return bool Check result.
     */
    public static function is_instrumented($path)
    {
        CoraxLogger::info('Instrument checking...');
        $path = $path . DIRECTORY_SEPARATOR . self::$nest . DIRECTORY_SEPARATOR;

        CoraxLogger::debug("Target path: $path", 1);
        $checklist = [
            '$path . \'key.txt\'',
            '$path . \'test_\' . file_get_contents($path . \'key.txt\') . \'.php\'',
            '$path . \'fileinfo.json\'',
            '$path . \'watchinfo.json\'',
            '$path . \'inputs\' . DIRECTORY_SEPARATOR . \'index.php\'',
            '$path . \'outputs\' . DIRECTORY_SEPARATOR . \'index.php\'',
            '$path . \'corpus\' . DIRECTORY_SEPARATOR . \'index.php\'',
            '$path . \'caches\' . DIRECTORY_SEPARATOR . \'index.php\''
        ];

        $result = true;
        foreach ($checklist as $f) {
            $f = eval("return $f;");
            CoraxLogger::debug("Checking \"$f\"...", 1);
            $result = file_exists($f) && $result;
            if ($result) CoraxLogger::debug('OK, file exists.', 2);
            else {
                CoraxLogger::debug("File \"$f\" missing.", 2);
                break;
            }
        }

        CoraxLogger::success('Check OK.', 1);
        return $result;
    }

    /**
     * The main entry function for Corax Instrumenter, instrument code from here.
     * 
     * @param string|null $dst The destination path. Given null will instrument to $src. Defaults to null.
     * @param bool $overwrite Overwrite destination path if it has been instrumented. Defaults to false.
     * @param bool $lazy Enable lazy instrument mode, it will not check if the watching function has empty arguments 
     *   or all arguments are const value, simply instrument all watching functions. Defaults to false.
     * @param array $watching Watch functions. Empty string is not allowed. Supports regex. Defaults to an empty array.
     * @param array $file_ext Instrument file ext. Empty string is not allowed. Supports regex. Defaults to ['php'].
     * @param array $exclude Exclude files and directories while instrumenting. Empty string is not allowed. 
     *   Supports regex. Defaults to an empty array.
     * @param array $watch_only Only watch the given files and directories while instrumenting. Empty string is not
     *   allowed. Supports regex. Defaults to an empty array.
     * @return string The Corax fuzzing key.
     */
    public function instrument(
        $dst = null,
        $overwrite = false,
        $lazy = false,
        $watching = [],
        $file_ext = ['php'],
        $exclude = [],
        $watch_only = []
    ) {
        $_dst = $dst;
        if ($dst === null) {
            $dst = substr($this->src, 0, -1);
            $overwrite = false;
            $exclude[] = self::$nest;
            CoraxLogger::warn('Instrument to source code directory!');
        }

        // Destination directory check.
        // Just make sure $dst has to exist and is an empty directory.
        if (file_exists($dst)) {
            if ($overwrite) {
                if (!CoraxUtils::delete_path($dst))
                    CoraxLogger::error("Delete existed destination directory \"$dst\" failed. Permission denied.");
                if (!CoraxUtils::mkdir($dst))
                    CoraxLogger::error("Create destination directory \"$dst\" failed. Permission denied.");
            } else {
                if (is_dir($dst)) {
                    // Instrumented check.
                    if (self::is_instrumented($dst)) {
                        CoraxLogger::warn("Destination directory \"$dst\" has been instrumented.");
                        $nest = $dst . DIRECTORY_SEPARATOR . self::$nest . DIRECTORY_SEPARATOR;
                        return [
                            file_get_contents($nest . 'key.txt'),
                            json_decode(file_get_contents($nest . 'fileinfo.json'), true),
                            json_decode(file_get_contents($nest . 'watchinfo.json'), true),
                        ];
                    }

                    // Empty check.
                    if ($_dst !== null) {
                        $res = scandir($dst);
                        if ($res === false) CoraxLogger::error("Invalid destination directory \"$dst\". Permission denied.");
                        if (count($res) > 2 && !$overwrite)
                            CoraxLogger::error(
                                "Destination directory \"$dst\" is not empty. Remove it or enable \"overwrite\" to rewrite it."
                            );
                    }
                } else CoraxLogger::error(
                    "Destination directory \"$dst\" is not a directory. Remove it or enable \"overwrite\" to rewrite it."
                );
            }
        } elseif (!CoraxUtils::mkdir($dst)) CoraxLogger::error("Create destination directory \"$dst\" failed. Permission denied.");

        if ($overwrite) CoraxLogger::warn('Instrument overwrite enabled!');
        if ($watching && $lazy) CoraxLogger::warn('Enable lazy instrument mode, it may instruments many redundant functions!');

        $dst = realpath($dst) . DIRECTORY_SEPARATOR;
        $key = CoraxRandom::random_id();
        $this->ready($dst, $dst . self::$nest . DIRECTORY_SEPARATOR, $key, $lazy, $watching, $file_ext, $exclude, $watch_only);
        return $key;
    }
}
