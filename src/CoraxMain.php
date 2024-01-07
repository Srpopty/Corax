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
 * @Filename: CoraxMain.php
 * @Description: 
 *   Corax main luncher. Start corax from command line, parse command line options
 * and check if available. Prepare instrumenter, fuzzer and tainter and make sure
 * it is ready to run. Some components such as mutator, parser and hunter will be 
 * prepared too for fuzzer and tainter.
 * ================================================================================
 */

namespace Corax;

use Throwable;

use Corax\Common\CoraxLogger;
use Corax\Common\CoraxDictionary;
use Corax\Common\CoraxHTTPClient;
use Corax\Common\CoraxStatistic;
use Corax\Instrument\CoraxInstrumenter;

use Corax\Fuzz\CoraxFuzzer;
use Corax\Fuzz\CoraxMutator;
use Corax\Fuzz\CoraxParser;
use Corax\Fuzz\CoraxEncoder;
use Corax\Fuzz\CoraxHunter;


final class CoraxMain
{
    public static $version = '0.0.1';

    # Builtin corax target for hunting. 
    private static $targets = [
        'xss' => [
            'debug_zval_dump', 'echo', 'exit', 'die', 'print', 'printf', 'var_dump',
            'image2wbmp', 'imageavif', 'imagebmp', 'imagegd', 'imagegd2', 'imagegif', 'imagejpeg',
            'imagepng', 'imagewbmp', 'imagewebp', 'imagexbm',
            'var_export', 'vprintf',
            'Exception', 'Error'
        ],
        'command_execution' => [
            'system', 'shell_exec', 'exec', 'expect_popen', 'proc_open', 'ssh2_exec',
            'Swoole\\\\Process::exec', 'passthru', 'pcntl_exec', 'popen', 'except_popen',
        ],
        // 'environ_rewrite' => [
        //     'putenv'
        // ],
        // 'var_rewrite' => ['extract', 'import_request_variables', 'parse_str'],
        // 'unserialize' => ['unserialize'],
        // 'ssti' => ['.*->render', 'Smarty_Internal_Write_File::writeFile'],
        // 'rce' => [
        //     'eval', 'assert'
        // ],
        // 'ssrf' => [
        //     'curl_multi_setopt', 'curl_setopt', 'curl_setopt_array',
        //     'hash_file', 'hash_hmac_file', 'md5_file',
        //     'include', 'include_once', 'require', 'require_once',
        //     'get_headers', 'SoapClient', 'gzopen',
        //     'copy', 'highlight_file', 'show_source', 'parse_ini_file', 'fopen', 'SplFileObject', 'file_get_contents',
        //     'file', 'readfile', 'gzfile', 'readgzfile', 'getimagesize', 'imagecreatefromgif', 'imagecreatefromjpeg',
        //     'imagecreatefrompng', 'imagecreatefromwbmp',  'imagecreatefromxbm', 'imagecreatefromxpm', 'exif_read_data',
        //     'read_exif_data', 'exif_thumbnail', 'exif_imagetype', 'php_strip_whitespace', 'get_meta_tags',
        //     'mime_content_type', 'imageloadfont'
        // ],
        // 'sqli' => [
        //     '.*->query', '.*->multi_query', '.*->real_query', '.*->exec', '.*->execute', 'pg_query',
        //     'mysql_query', 'mysql_unbuffered_query', 'mysql_db_query', 'mysqli_query', 'mysqli_real_query',
        //     'mysqli_master_query', 'mysqli_multi_query', 'mysqli_stmt_execute', 'mysqli_execute',
        //     'db2_exec', 'pg_send_query'
        // ],
        // 'xxe' => ['.*->loadXML', '.*->loadHTML', 'simplexml_load_string', 'SimpleXMLElement'],

        // 'file_upload' => ['move_uploaded_file'],
        // 'file_include' => ['include', 'include_once', 'require', 'require_once'],
        // 'file_read' => [],
        // 'file_write' => [],
        // 'file_access' => [],
        // 'file_access' => [
        //     'bzopen', 'chdir', 'chroot', 'copy', 'dir', 
        //     'touch', 'alter_ini', 'highlight_file', 'show_source', 'ini_alter', 'fgetcsv',
        //     'ini_get_all', 'openlog', 'syslog', 'rename', 'parse_ini_file', 'fopen', 'tmpfile',
        //     'gzopen', 'SplFileObject', 'chgrp', 'chmod', 'chown', 'file_put_contents', 'lchgrp',
        //     'lchown', 'link', 'mkdir', 'move_uploaded_file', 'rmdir', 'symlink', 'tempnam', 'unlink',
        //     'image2wbmp', 'imageavif', 'imagebmp', 'imagegd', 'imagegd2', 'imagegif', 'imagejpeg',
        //     'imagepng', 'imagewbmp', 'imagewebp', 'imagexbm', 'iptcembed', 'ftp_get', 'ftp_nb_get',
        //     'file_exists', 'file_get_contents', 'file', 'fileatime', 'filectime', 'filegroup',
        //     'fileinode', 'filemtime', 'fileowner', 'fileperms', 'filesize', 'filetype', 'glob',
        //     'is_dir', 'is_executable', 'is_file', 'is_link', 'is_readable', 'is_uploaded_file',
        //     'is_writable', 'is_writeable', 'linkinfo', 'lstat', 'pathinfo', 'readfile', 'readlink',
        //     'realpath', 'stat', 'gzfile', 'readgzfile', 'getimagesize', 'imagecreatefromgif',
        //     'imagecreatefromjpeg', 'imagecreatefrompng', 'imagecreatefromwbmp', 'imagecreatefromxbm',
        //     'imagecreatefromxpm', 'ftp_put', 'ftp_nb_put', 'exif_read_data', 'read_exif_data',
        //     'exif_thumbnail', 'exif_imagetype', 'hash_file', 'hash_hmac_file', 'hash_update_file',
        //     'md5_file', 'md5_file', 'php_strip_whitespace', 'get_meta_tags', 'mime_content_type',
        //     'imageloadfont', 'include', 'include_once', 'require', 'require_once'
        // ],
    ];

    // Builtin information flow filter.
    private static $filters = [
        'base64_encode', 'str_replace', 'str_rot13', 'strtok', 'strtolower',
        'strtoupper', 'strtr', 'substr', 'substr_replace', 'trim', 'ucfirst', 'ucwords',
        'mcrypt_encrypt', 'openssl_encrypt', 'trip_tags', 'mysql_escape_string', 'mysql_real_escape_string',
        'mysqli_escape_string', 'mysqli_real_escape_string', 'mysqli_stmt_bind_param', '.*->real_escape_string',
        '.*->escape_string', '.*->bind_param', 'db2_escape_string', 'pg_escape_string', 'pg_escape_bytea',
        'san_mix', 'san_osci', 'htmlentities', 'htmlspecialchars', 'urlencode', 'escapeshellarg', 'escapeshellcmd'
    ];

    // Runtime Corax options.
    public static $config = [
        // Instrument config.
        'instrument' => false, 'instrument-check' => false,
        'src' => null, 'dst' => null,
        'overwrite' => false, 'ext' => ['php'],
        'exclude' => ['\/caches?\/', '[a-f0-9]{16}\\.php$'], 'watch_only' => [],
        'php' => 7, 'watch' => [],
        // Fuzzing and tainting config.
        'fuzz' => false, 'fuzz-check' => false,
        'url' => 'http://127.0.0.1/',
        'corpus' => null,
        'disable-parsers' => [], 'disable-mutators' => [], 'disable-encoders' => [],
        'taint' => false, 'disable-hunters' => [], 'hunt' => [], 'plugin' => null,
        // Other config.
        'targets' => null,
        'work-dir' => '.', 'lazy' => false, 'dry-run' => false,
        'debug' => false, 'log-debug' => false, 'no-color' => false, 'async-count' => 0,
        'timeout' => 30, 'shutdown' => null, 'proxy' => null, 'reset' => false, 'no-ui' => false,
        'dump-statistics' => -1
    ];

    // Corax command line options formation.
    private static $options = [
        // Instrument options.
        'i|instrument||' => 'Only enable instrument mode and disable fuzzing and taint mode. Default disabled.',
        '|instrument-check||' => 'Check if the "dst" directory has been instrumented.',
        's|src|:dir|' => 'Instrument source directory. Required on instrument mode. In fuzzing or tainting mode, ' .
            'fuzzer can render source code in fuzzing reports if given this.',
        'd|dst|:dir|' => 'Instrument destination directory. Defaults to source directory.',
        'O|overwrite||' => 'Enable automatic removing instrument destination directory if exists. ' .
            'Available on instrument mode. Default disabled.',
        'E|ext|:exts|php' => 'Only instrument files with specific extension. Separated by ",". Supports regex. ' .
            'Available on instrument mode. Defaults to "php".',
        'X|exclude|:files|\\/caches?\\/,[a-f0-9]{16}\\.php$' => 'Exclude files or directories while instrumenting. ' .
            'Separated by ",". Supports regex. Available on instrument mode. ' .
            'Defaults to exclude some php cache directories or files.',
        'W|watch-only|:files|' => 'Only watch the specific files or directories while instrumenting. Separated by ",". ' .
            'Supports regex. Available on instrument mode.',
        'p|php|:version|7' => 'Specify PHP version for instrumenting. Available on instrument mode. Defaults to 7.',
        'w|watch|:fn1,fn2...|...' => [
            'Corax watching functions, formatted by "func1,func2,func3", e.g. "--watch exec,system".',
            'Separated by ",". Supports regex. Available on instrument mode. ',
            'Default watching functions please see README.' . "\n",
        ],

        // Fuzz options.
        'f|fuzz||' => 'Only enable fuzzing mode and disable instrument and taint mode. Default disabled.',
        '|fuzz-check||' => 'Check the target url if has been instrumented and is fuzzable.',
        'u|url|:url|http://127.0.0.1/' => 'Target fuzzing url. Available on fuzzing mode. Defaults to "http://127.0.0.1/".',
        '|corpus|:dir|' => 'The corpus directory. Each file in this directory is a corpus and will be saved ' .
            'to fuzzing working directory. Available on fuzzing mode.',
        'P|plugin|:file|' => 'Specify custom plugin file. Available on fuzzing or tainting mode.',
        '|disable-mutators|:mutators|' => 'Disable fuzzing mutators manually by mutator name. Separated by ",". ' .
            'Supports regex. Available on fuzzing mode.',
        '|disable-parsers|:parsers|' => 'Disable fuzzing parsers manually by parser name. Separated by ",". ' .
            'Supports regex. Available on fuzzing mode.',
        '|disable-encoders|:encoders|' => 'Disable fuzzing encoders manually by encoder name. Separated by ",". ' .
            'Supports regex. Available on fuzzing mode.' . "\n",

        // Taint options.
        't|taint||' => 'Only enable taint mode and disable instrument and fuzz mode. Default disabled.',
        '|disable-hunters|:hunters|' => 'Disable tainting hunters manually by hunter name. Separated by ",". ' .
            'Supports regex. Available on tainting mode.',
        '|hunt|:hunter:fn1,fn2;...|...' => [
            'Specify taint hunting targets with hunter.',
            'Formatted by "hunter1:functions;hunter2:functions;...", e.g. "--hunt xss:echo,print;rce:system,exec", ',
            'targets are separated by ";", and functions in a target separated by ",". ',
            'Supports regex. Available on tainting mode. Default hunting targets please see README.' . "\n"
        ],

        // Common options.
        '|targets|:file|' => [
            'Corax targets json file. The default Corax builtin targets will be overwrote if given this. ' .
                'The json content should be a key-value array. ',
            'Key is hunter name and value is hunter target functions, such as {"hunter": ["func1", "func2"]}.',
            'This option is equal with the combine of --watch and --hunt, ' .
                'all functions will be watched and registered for hunting.',
            'Available on instrument, fuzzing and tainting mode.'
        ],
        'T|timeout|:seconds|30' => 'Corax global timeout seconds. Minimum second is 0s. Defaults to 30s.',
        'j|async-count|:count|0' => 'Corax global default async count for each http client. Corax will adjust this by itself ' .
            'if 0 is given. Defaults to 0.',
        '|shutdown|:seconds|' => 'Enable auto shutdown mode. Corax will be stopped running after the given seconds. ' .
            'Minimum second is 10s if enable this.',
        '|proxy|:url|' => 'Corax global http request proxy, such as "http://127.0.0.1:8080".',
        'o|work-dir|:dir|.' => 'Fuzz or taint working directory. Available on fuzzing and tainting mode. ' .
            'Defaults to current working directory.',
        '|lazy||' => 'Enable lazy mode. Available on instrument, fuzzing and tainting mode. ' .
            'Enable this will skip checking some functions that with empty or const arguments ' .
            'in instrument mode or skip hit checking in fuzzing mode.',
        '|dry-run||' => 'Enable dry run mode only. Available on fuzzing and tainting mode. Default disabled.' . "\n",

        // Other options.
        'h|help||' => 'Show help messages.',
        'v|version||' => 'Show Corax version.',
        '|log-debug||' => 'Enable logging debug message to log file.',
        'D|debug||' => 'Enable Corax debug mode. Default disabled.',
        'R|reset||' => 'Reset fuzzer before fuzzing or tainting, including local cached data and server outputs. ' .
            'Available on fuzzing and tainting mode.',
        'c|config|:file|' => 'Reading all Corax command line options from a json file.',
        '|dump-statistics|:seconds|' => 'Enable Dumping Corax running statistics to file "./corax_statistics.json" with' .
            ' the given seconds. Minimum second is 1s if enable this.',
        '|no-ui||' => 'Disable terminal UI.',
        '|no-color||' => 'Disable colorful output.',
        '|show-watching||' => 'Show current instrument watching functions.',
        '|show-targets||' => 'Show current hunter targets.',
        '|show-examples||' => 'Show some Corax examples.',
        '|show-templates||' => 'Show custom fuzzing mutator, parser and tainting hunter templates.'
    ];

    // Corax command line examples.
    private static $examples = [
        // TODO: Add more Corax examples.
        'corax -d /var/www/html/a --instrument-check' => 'Check if the directory "/var/www/html/a" is instrumentable.',
    ];

    // Corax plugin templates.
    private static $templates = [
        '
    /**
     * Mutate value from parser parsed input fields.
     * 
     * @param mixed $str The value to mutate.
     * @param string $type The parser assigned type.
     * @return mixed|null The mutated value.
     */
    public function m_my_mutator($str, $type)
    {
        // Do something for $str...
        return $str;
    }', '
    /**
     * Parse HTTP request array to Corax input fields.
     * 
     * @param array $input The raw HTTP input array.
     * @return array|\Corax\Fuzz\CoraxInput The parsed input fields.
     */
    public function p_my_parser($input)
    {
        return new CoraxInput(
            \'my_parser\', $input, 
            $input[\'get\'][\'my_value\'][0],  // Which value you parsed from http input.
            [\'get\', \'my_value\', 0]  // The path to get value parsed from http input.
        );
    }', '
    /**
     * Encode or decode value which from input fields.
     * 
     * @param mixed $value The value to encode or decode.
     * @return mixed The encoded or decoded value.
     */
    public function e_my_encoder($value)
    {
        // Encode or decode value and return result.
        ...
        return $value;
    }
    ', '
    /**
     * Detect a vulnerability.
     * 
     * @param \Corax\Fuzz\CoraxHit $hit The hit to hunt.
     * @param string $value The value which triggered this hit. This value is a un-decoded string.
     * @param bool $lazy If enable lazy tainting. In lazy mode, hunter could yield some simple payloads only for a quick taint.
     * @yield array|false|null If an array yield, each array value should be a CoraxPayload object. The false value could be yielded 
     *   if hunter want to stop hunting and no more value will be yielded. If yield a null value, corax will automatically create 
     *   a probe payload with the type "Probe" to check which runtime argument of the target function can be controlled. The return
     *   value of yield is an array, key is yielded payload type and value is an array with target function argument positions which
     *   contain the yield payload completely, but if the payload could not control any argument, the payload type will not be in the
     *   array.
     */
    public function h_my_hunter($hit, $value, $lazy)
    {
        $pos = yield null;  // Which argument positions is controllable?
        
        if (
            // If no argument is controllable
            empty($pos) or 
            // or the controllable argument position is unexpected, stop the hunter.
            ($hit->get_func_name() === \'my_func\' and isset($pos[\'Probe\']) and !in_array($pos[\'Probe\'], 1))
        ) yield false;

        $payloads = [];  // Payloads array to be yield.
        if (!$his->vuln_exists(\'my_hunter\', \'my_vuln\')) {  // Skip the detected vulnerability.
            // Create a new test payload with type "my_vuln".
            $payloads[] = new CoraxPayload(\'my_hunter\', \'my_vuln\', \'my_payload\');
        }

        // More different payload can be test at the same time.
        if (!$his->vuln_exists(\'my_hunter\', \'my_other_vuln\')) {
            // The false means it is not a vulnerable payload.
            $payloads[] = new CoraxPayload(\'my_hunter\', \'my_other_vuln\', \'my_other_payload\', false);
        }
        
        // Yield payloads and get taint results.
        $pos = yield $payloads;

        // A vulnerable payload, vuln_exists can check if the payload test successfully.
        if (!$his->vuln_exists(\'my_hunter\', \'my_vuln\')) {
            // Payload is filtered of can not arrive the target argument, try more payloads.
            // ...
        }

        // Not a vulnerable payload, check position from the result directly.
        if (isset($pos[\'my_other_vuln\']) and !in_array($pos[\'my_other_vuln\'], 1)) {
            // Could not get an expected position? Try more payloads.
            // ...
        }

        // Check more payloads...
        $pos = yield $payloads;

        // ...

        if (!$lazy) {
            $payloads = [];
            // More complex payloads should be test on non-lazy mode.
            // ...
            yield $payloads;
        }
    }
    '
    ];

    /**
     * Print Corax version and exit.
     */
    private static function show_version()
    {
        fwrite(STDOUT, self::$version . "\n");
        exit(0);
    }

    /**
     * Print error message and exit with code 1.
     * 
     * @param string $msg Message to print.
     * @param bool $exit Enable exiting after message printed. Defaults to true.
     */
    private static function show_error($msg, $exit = true)
    {
        fwrite(STDERR, "Corax: $msg\n\n");
        if ($exit) exit(1);
    }

    /**
     * Print help menu or some other helpful messages and exit Corax. If error message is not empty, exit code 
     * will be 1, otherwise will be 0.
     * 
     * @param string $error Error message to print before show any helpful message.
     * @param bool $show_example Showing Corax example usage only. Defaults to false.
     * @param bool $show_template Showing Corax custom mutator, parser and hunter templates. Defaults to false.
     * @param bool $show_watching Showing Corax watching functions. Defaults to false.
     * @param bool $show_targets Showing Corax hunting targets. Defaults to false.
     */
    private static function show_help(
        $error = '',
        $show_example = false,
        $show_template = false,
        $show_watching = false,
        $show_targets = false
    ) {
        // Show error message first.
        if ($error) self::show_error($error, false);

        $max_len = 0;
        if ($show_example) {
            // Find max length of first column.
            foreach (self::$examples as $example => $_) $max_len = max($max_len, strlen($example));

            $examples = [];
            $fmt_str = "%-{$max_len}s  %s";
            foreach (self::$examples as $example => $desc) $examples[] = sprintf($fmt_str, $example, $desc);
            $output = "Examples:\n    " . implode("\n    ", $examples);
        } elseif ($show_template) {
            $output = "------------------------------=<[ Custom Plugin Templates ]>=------------------------------\n\n" .
                "<?php\n\nnamespace Corax;\n\n" .
                "use Corax\Fuzz\CoraxAgent;\nuse Corax\Taint\CoraxTrace;\n\n" .
                "final class CoraxPlugin\n{" .
                implode("\n\n", self::$templates) . "\n}\n";
        } elseif ($show_watching) {
            $output = "Corax Watching Functions:";
            $watching = [];
            foreach (self::$targets as $functions) {
                foreach ($functions as $function)
                    if (!in_array($function, $watching)) $watching[] = $function;
            }

            $count = 0;
            foreach ($watching as $function) {
                $count++;
                if ($count % 5 === 1) $output .= "\n    ";
                else $output .= ", ";
                $output .= $function;
            }
        } elseif ($show_targets) {
            $output = "Corax Hunting Targets:\n    ";
            foreach (self::$targets as $name => $functions) {
                $output .= "Hunting for $name: ";
                $count = 0;
                foreach ($functions as $function) {
                    $count++;
                    if ($count % 5 === 1) $output .= "\n        ";
                    else $output .= ", ";
                    $output .= $function;
                }
                $output .= "\n\n    ";
            }
        } else {
            $tmp = [];
            // Build a pretty help menu only once.
            foreach (self::$options as $key => $desc) {
                list($short_opt, $long_opt, $value, $default) = explode('|', $key);

                $option = '';
                // Short option format.
                if ($short_opt) $option .= "-$short_opt";
                // Long option format.
                if ($long_opt) {
                    if ($short_opt) $option .= ', ';
                    $option .= "--$long_opt";
                }

                // Option required value.
                if ($value) $option .= ' <' . substr($value, 1) . '>';
                // Option default value.
                if ($default) $option .= " [=$default]";

                // Find max length of first column.
                $max_len = max($max_len, strlen($option));
                $tmp[$option] = $desc;
            }

            $options = [];
            $fmt_str = "%-{$max_len}s  %s";
            foreach ($tmp as $option => $desc) {
                if (is_array($desc)) {
                    $f = true;
                    foreach ($desc as $d) {
                        // Only the first is available.
                        if ($f) {
                            $options[] = sprintf($fmt_str, $option, $d);
                            $f = false;
                        } else $options[] = sprintf($fmt_str, '', $d);
                    }
                } else $options[] = sprintf($fmt_str, $option, $desc);
            }
            $output = "Usage:\n    corax [options]\n\nOptions:\n    " . implode("\n    ", $options);
        }

        fwrite(
            $error ? STDERR : STDOUT,
            "Corax -- A PHP application vulnerability fuzzing framework. Made by Srpopty.\n\n$output\n\n"
        );
        exit($error ? 1 : 0);
    }

    /**
     * Show Corax banner with version info.
     */
    private static function banner()
    {
        $version = self::$version;
        echo <<<EOF

                    _____                      
                   /  __ \                     
                   | /  \/ ___  _ __ __ ___  __
                   | |    / _ \| '__/ _` \ \/ /
                   | \__/\ (_) | | | (_| |>  < 
                    \____/\___/|_|  \__,_/_/\_\
                          -=[ $version ]=-
                          
   A PHP application vulnerability fuzzing framework. Made by Srpopty.


EOF;
    }

    /**
     * Parse received command line options and build an option array.
     * 
     * @return array Parsed command line options.
     */
    private static function get_options()
    {
        $short_options = '';
        $long_options = [];
        foreach (array_keys(self::$options) as $key) {
            list($short_option, $long_option, $value, $_) = explode('|', $key);
            if ($short_option) {
                if ($value) $short_option .= $value[0];
                $short_options .= $short_option;
            }
            if ($long_option) {
                if ($value) $long_option .= $value[0];
                $long_options[] = $long_option;
            }
        }

        $index = null;
        $options = getopt($short_options, $long_options, $index);

        global $argv;
        $rest = array_slice($argv, $index);
        // The rest will be only value. Unknown options such as  "-x" or "-xxx" will be simply ignored.
        if ($rest) self::show_help("Unknown option value \"$rest[0]\".");

        return $options;
    }

    /**
     * Parse command line options and do some simple option check.
     * 
     * @param array $options Command line option array.
     */
    private static function parse_options($options)
    {
        $show_watching = false;
        $show_targets = false;
        // Noticed that the $value may be an array if more than one values of a option are received.
        foreach ($options as $key => $value) {
            switch ($key) {
                    // Instrument options.
                case 'i':
                case 'instrument':
                    self::$config['instrument'] = true;
                    break;
                case 'instrument-check':
                    self::$config['instrument-check'] = true;
                    break;
                case 's':
                case 'src':
                    self::$config['src'] = is_array($value) ? $value[0] : $value;
                    break;
                case 'd':
                case 'dst':
                    self::$config['dst'] = is_array($value) ? $value[0] : $value;
                    break;
                case 'O':
                case 'overwrite':
                    self::$config['overwrite'] = true;
                    break;
                case 'E':
                case 'ext':
                    if (is_array($value)) {
                        $ext = [];
                        foreach ($value as $v) foreach (explode(',', $v) as $vv) $ext[] = $vv;
                        foreach ($ext as $f) self::$config['ext'][] = addcslashes($f, '/');
                    } else foreach (explode(',', $value) as $f)
                        self::$config['ext'][] = addcslashes($f, '/');
                    break;
                case 'X':
                case 'exclude':
                    if (is_array($value)) {
                        $files = [];
                        foreach ($value as $v) foreach (explode(',', $v) as $vv) $files[] = $vv;
                        foreach ($files as $f) self::$config['exclude'][] = addcslashes($f, '/');
                    } else foreach (explode(',', $value) as $f)
                        self::$config['exclude'][] = addcslashes($f, '/');
                    break;
                case 'W':
                case 'watch-only':
                    if (is_array($value)) {
                        $files = [];
                        foreach ($value as $v) foreach (explode(',', $v) as $vv) $files[] = $vv;
                        foreach ($files as $f) self::$config['watch_only'][] = addcslashes($f, '/');
                    } else foreach (explode(',', $value) as $f)
                        self::$config['watch_only'][] = addcslashes($f, '/');
                    break;
                case 'p':
                case 'php':
                    self::$config['php'] = is_array($value) ? $value[0] : $value;
                    break;
                case 'w':
                case 'watch':
                    if (is_array($value)) {
                        $watch = [];
                        foreach ($value as $v) foreach (explode(',', $v) as $vv) $watch[] = $vv;
                        foreach ($watch as $f) self::$config['watch'][] = addcslashes($f, '/');
                    } else foreach (explode(',', $value) as $f)
                        self::$config['watch'][] = addcslashes($f, '/');
                    break;
                    // Fuzz options.
                case 'f':
                case 'fuzz':
                    self::$config['fuzz'] = true;
                    break;
                case 'fuzz-check':
                    self::$config['fuzz-check'] = true;
                    break;
                case 'u':
                case 'url':
                    self::$config['url'] = is_array($value) ? $value[0] : $value;
                    break;
                case 'corpus':
                    self::$config['corpus'] = is_array($value) ? $value[0] : $value;
                    break;
                case 'P':
                case 'plugin':
                    self::$config['plugin'] = is_array($value) ? $value[0] : $value;
                    break;
                case 'disable-mutators':
                    if (is_array($value)) {
                        $mutators = [];
                        foreach ($value as $v) foreach (explode(',', $v) as $vv) $mutators[] = $vv;
                        foreach ($mutators as $f) self::$config['disable-mutators'][] = addcslashes($f, '/');
                    } else foreach (explode(',', $value) as $f)
                        self::$config['disable-mutators'][] = addcslashes($f, '/');
                    break;
                case 'disable-parsers':
                    if (is_array($value)) {
                        $parsers = [];
                        foreach ($value as $v) foreach (explode(',', $v) as $vv) $parsers[] = $vv;
                        foreach ($parsers as $f) self::$config['disable-parsers'][] = addcslashes($f, '/');
                    } else foreach (explode(',', $value) as $f)
                        self::$config['disable-parsers'][] = addcslashes($f, '/');
                    break;
                case 'disable-encoders':
                    if (is_array($value)) {
                        $encoders = [];
                        foreach ($value as $v) foreach (explode(',', $v) as $vv) $encoders[] = $vv;
                        foreach ($encoders as $f) self::$config['disable-encoders'][] = addcslashes($f, '/');
                    } else foreach (explode(',', $value) as $f)
                        self::$config['disable-encoders'][] = addcslashes($f, '/');
                    break;
                    // Taint options.
                case 't':
                case 'taint':
                    self::$config['taint'] = true;
                    break;
                case 'disable-hunters':
                    if (is_array($value)) {
                        $hunters = [];
                        foreach ($value as $v) foreach (explode(',', $v) as $vv) $hunters[] = $vv;
                        foreach ($hunters as $f) self::$config['disable-hunters'][] = addcslashes($f, '/');
                    } else foreach (explode(',', $value) as $f)
                        self::$config['disable-hunters'][] = addcslashes($f, '/');
                    break;
                case 'hunt':
                    if (!is_array($value)) $value = [$value];
                    foreach ($value as $v) {
                        foreach (explode(';', $v) as $target) {
                            list($hunter, $funcs) = explode(':', $target);
                            if (isset(self::$config['hunt'][$hunter])) {
                                self::$config['hunt'][$hunter] = array_merge(
                                    self::$config['hunt'][$hunter],
                                    explode(',', $funcs)
                                );
                            } else self::$config['hunt'][$hunter] = explode(',', $funcs);
                        }
                    }
                    break;
                    // Common options.
                case 'targets':
                    self::$config['targets'] = is_array($value) ? $value[0] : $value;
                    break;
                case 'T':
                case 'timeout':
                    self::$config['timeout'] = max(intval(is_array($value) ? $value[0] : $value), 0);
                    break;
                case 'j':
                case 'async-count':
                    self::$config['async-count'] = max(intval(is_array($value) ? $value[0] : $value), 0);
                    break;
                case 'shutdown':
                    self::$config['shutdown'] = max(intval(is_array($value) ? $value[0] : $value), 10);
                    break;
                case 'proxy':
                    self::$config['proxy'] = is_array($value) ? $value[0] : $value;
                    break;
                case 'o':
                case 'work-dir':
                    self::$config['work-dir'] = is_array($value) ? $value[0] : $value;
                    break;
                case 'lazy':
                    self::$config['lazy'] = true;
                    break;
                case 'dry-run':
                    self::$config['dry-run'] = true;
                    break;
                    // Other options.
                case 'h':
                case 'help':
                    self::show_help();
                    break;
                case 'v':
                case 'version':
                    self::show_version();
                    break;
                case 'log-debug':
                    self::$config['log-debug'] = true;
                    break;
                case 'D':
                case 'debug':
                    self::$config['debug'] = true;
                    break;
                case 'R':
                case 'reset':
                    self::$config['reset'] = true;
                    break;
                case 'c':
                case 'config':
                    $config_file = is_array($value) ? $value[0] : $value;
                    if (file_exists($config_file)) {
                        $config = file_get_contents($config_file);
                        if ($config) {
                            $config = json_decode($config, true);
                            if ($config) {
                                unset($config['config']);
                                self::parse_options($config);
                            } else self::show_error("Invalid json format from config file \"$config_file\".");
                        } else self::show_error("Could not read config from file \"$config_file\".");
                    } else self::show_error("Config file \"$config_file\" does not exist.");
                    break;
                case 'dump-statistics':
                    self::$config['dump-statistics'] = max(intval(is_array($value) ? $value[0] : $value), 1);
                    break;
                case 'no-ui':
                    self::$config['no-ui'] = true;
                    break;
                case 'no-color':
                    self::$config['no-color'] = true;
                    break;
                case 'show-examples':
                    self::show_help('', true);
                    break;
                case 'show-templates':
                    self::show_help('', false, true);
                    break;
                case 'show-watching':
                    $show_watching = true;
                    break;
                case 'show-targets':
                    $show_targets = true;
                    break;
                default:
                    self::show_help("Invalid option \"$key\".");
                    break;
            }
        }

        // After all arguments parsed to show these.
        if ($show_watching) self::show_help('', false, false, true);
        elseif ($show_targets) self::show_help('', false, false, false, true);

        // Nether enable instrument, fuzz or taint, seen as all be enabled.
        if (!(self::$config['instrument'] || self::$config['fuzz'] || self::$config['taint']))
            self::$config['instrument'] = self::$config['fuzz'] = self::$config['taint'] = true;

        // Option requirement checking.
        if (self::$config['instrument'] && self::$config['src'] === null)
            self::show_help('The option "src" is required on instrument mode.');


        if (self::$config['instrument-check'] && self::$config['dst'] === null)
            self::show_help('The option "dst" is required if enable instrument check.');
    }

    /**
     * For quit Corax client safely.
     * 
     * @param int $signo Signal number.
     */
    public static function signal_handler($signo)
    {
        CoraxLogger::debug('Captured signal of: ' . CoraxDictionary::$signals[$signo] . "($signo)");
        CoraxLogger::warn('Corax will be shutting down soon...');
        exit(0);
    }

    /**
     * Corax error handler for PHP runtime error.
     * 
     * @param int $errno Error level.
     * @param string $errstr Error message.
     * @param string $errfile Error occurred file.
     * @param int $errline The line in error occurred file.
     * @return bool If is a Corax wanted error.
     */
    public static function error_handler($errno, $errstr, $errfile, $errline)
    {
        if (error_reporting() & $errno) {
            if (!isset(CoraxDictionary::$errors[$errno]))  return false;
            CoraxLogger::warn('PHP Runtime Error (' . CoraxDictionary::$errors[$errno] .
                "): $errstr\n    in file $errfile:$errline\n    on PHP " . PHP_VERSION . '(' . PHP_OS . ')');
            if ($errno === E_ERROR || $errno === E_USER_ERROR || $errno === E_RECOVERABLE_ERROR)
                CoraxLogger::error('Fatal error occurred, aborting...');
            return true;
        } else return false;
    }

    /**
     * Run corax with parsed options from here.
     */
    private static function run()
    {
        error_reporting(E_ALL);
        if (self::$config['debug']) {
            // Auto enable dump statistics in debug mode.
            self::$config['dump-statistics'] = 10;
        }

        ini_set('display_errors', '1');
        ini_set('log_errors', '1');
        ini_set('error_log', CoraxLogger::$log_file);
        // Register signal handlers.
        foreach (CoraxDictionary::$signals as $signal => $_) pcntl_signal($signal, [__CLASS__, 'signal_handler']);

        // Common components config.
        CoraxStatistic::init(self::$config['no-ui'] === false, self::$config['dump-statistics'], self::$config['shutdown']);
        CoraxHTTPClient::init(self::$config['timeout'], self::$config['proxy'], self::$config['async-count']);
        if (CoraxLogger::init(self::$config['debug'], self::$config['log-debug'], !self::$config['no-color']))
            set_error_handler([__CLASS__, 'error_handler']);
        else self::show_error('Start Corax logger failed!');

        // Logger output from here.
        CoraxLogger::info('Starting Corax...');
        if (self::$config['shutdown']) {
            CoraxLogger::info('Corax will be shutdown automatically at: ' .
                date('m/d/Y H:i:s', microtime(true) + CoraxStatistic::$shutdown_time));
        }

        // Debug banner.
        $log_banner = '------------------------------=[Corax ' . self::$version .
            ' Debugging]=------------------------------';
        CoraxLogger::debug(str_repeat('-', strlen($log_banner)));
        CoraxLogger::debug($log_banner);
        CoraxLogger::debug(str_repeat('-', strlen($log_banner)));

        // Debug warning.
        if (self::$config['debug']) {
            CoraxLogger::info('Enable Corax debug mode.');
            CoraxLogger::info('This may case a lot of redundant outputs and slow down Corax!', 1);
            CoraxLogger::info('The flag "dump-statistics" will be enabled automatically in debug mode.', 1);
        }

        if ($targets = self::$config['targets']) {
            if ($targets = json_decode(file_get_contents($targets), true)) self::$targets = $targets;
            else CoraxLogger::warn(
                'Failed read targets from file "' . self::$config['targets'] .
                    '", file missing or invalid json content. Corax will use default targets.'
            );
        }

        $dst = self::$config['dst'];
        if (self::$config['instrument-check']) {
            if (CoraxInstrumenter::is_instrumented($dst)) {
                CoraxLogger::failed("Path \"$dst\" has been instrumented!");
                return;
            } else CoraxLogger::success("Path \"$dst\" is not instrumented.");
        }

        $url = self::$config['url'];
        if (self::$config['fuzz-check']) {
            if (CoraxFuzzer::is_fuzzable($url))
                CoraxLogger::success("URL \"$url\" is fuzzable.");
            else {
                CoraxLogger::failed("URL \"$url\" is unfuzzable!");
                return;
            }
        }

        $key = $plugin = null;
        $fileinfo = $watchinfo = null;
        // Signal process.
        pcntl_signal_dispatch();
        try {
            // Load plugin.
            if ($plugin) {
                if (file_exists($plugin) && (include($plugin)) === true) {
                    try {
                        $plugin = new Corax\CoraxPlugin();
                    } catch (Throwable $e) {
                        CoraxLogger::warn('Could not find plugin class ' .
                            "\"Corax\CoraxPlugin\" in file \"$plugin\" or load plugin failed. " .
                            (string) $e);
                    }
                }
            }

            // Prepare instrumenter.
            if (self::$config['instrument']) {
                $watching = self::$config['watch'];
                // Marge watching functions.
                foreach (self::$targets as $functions) {
                    foreach ($functions as $function)
                        if (!in_array($function, $watching)) $watching[] = $function;
                }
                $instrumenter = new CoraxInstrumenter(self::$config['src'], self::$config['php']);
                $key = $instrumenter->instrument(
                    $dst,
                    self::$config['overwrite'],
                    self::$config['lazy'],
                    $watching,
                    self::$config['ext'],
                    self::$config['exclude'],
                    self::$config['watch_only']
                );
                $fileinfo = $instrumenter->get_fileinfo();
                $watchinfo = $instrumenter->get_watchinfo();
            }

            // Prepare fuzzer.
            if (self::$config['fuzz'] || self::$config['taint']) {
                if (self::$config['taint']) {
                    $targets = self::$targets;
                    // Marge hunting targets.
                    foreach (self::$config['hunt'] as $name => $functions) {
                        if (isset($targets[$name])) $targets[$name] = array_merge($targets[$name], $functions);
                        else $targets[$name] = $functions;
                    }
                    $hunter = new CoraxHunter($plugin, self::$config['disable-hunters'], $targets);
                } else $hunter = null;

                $fuzzer = new CoraxFuzzer(
                    new CoraxMutator($plugin, self::$config['disable-mutators']),
                    new CoraxParser($plugin, self::$config['disable-hunters']),
                    new CoraxEncoder($plugin, self::$config['disable-encoders']),
                    $hunter
                );

                $fuzzer->init(
                    $url,
                    $key,
                    self::$config['work-dir'],
                    self::$config['src'],
                    $fileinfo,
                    self::$config['reset']
                );

                if (self::$config['fuzz'])
                    $fuzzer->fuzz(
                        self::$config['dry-run'],
                        self::$config['corpus']
                    );
                else $fuzzer->taint(self::$config['dry-run']);
            }
        } catch (Throwable $e) {
            CoraxLogger::error('Corax runtime error! ' . $e);
        }
    }

    /**
     * Corax main entry function. Parsed command line options, show banner and start logging.
     */
    public static function main()
    {
        // Corax runtime environment checking.
        $sapi_name = php_sapi_name();
        if (isset($sapi_name) && substr($sapi_name, 0, 3) !== 'cli')
            self::show_error("Corax should running at command line interface instead of \"$sapi_name\".");
        elseif (!extension_loaded('curl'))
            self::show_error('The extension "php-curl" is required for Corax but did not enabled or installed.');

        self::parse_options(self::get_options());
        self::banner();

        // Corax starts here.
        self::run();
    }
}
