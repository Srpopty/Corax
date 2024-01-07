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
 * @Filename: CoraxHunter.php
 * @Description: 
 *   Corax hunter used in tainter. Generate probes and payload in a trace for a 
 * hit, based on input, path and hit. Supports dynamic register new hunter. All 
 * hunter function name should start with "h_".
 * ================================================================================
 */

namespace Corax\Fuzz;

use Throwable;
use Generator;

use Corax\Common\CoraxDictionary;
use Corax\Common\CoraxList;
use Corax\Common\CoraxLogger;
use Corax\Common\CoraxRandom;
use Corax\Common\CoraxWorker;


final class UNS_OBJ
{
}

final class UNS_OBJ_PUB
{
    public $a;

    public function __construct($a)
    {
        $this->a = $a;
    }
}

final class UNS_OBJ_POT
{
    protected $a;

    public function __construct($a)
    {
        $this->a = $a;
    }
}

final class UNS_OBJ_PYT
{
    private $a;

    public function __construct($a)
    {
        $this->a = $a;
    }
}

final class UNS_OBJ_REF
{
    public $a;
    private $b;

    public function __construct($a)
    {
        $this->a = $a;
        $this->b = &$this->a;
    }
}


final class CoraxHunter extends CoraxWorker
{
    protected $func_targets;

    /**
     * Initialize a hunter. It could load user custom workers from plugin. The custom hunter template is:
     * <?php
     * namespace Corax;
     * 
     * use Corax\Fuzz\CoraxPayload;
     * 
     * 
     * class CoraxPlugin
     * {
     *     public function h_my_hunter($hit, $value, $lazy)
     *     {
     *         $pos = yield null;  // Which argument positions is controllable?
     *          
     *          if (
     *              // If no argument is controllable
     *              empty($pos) or 
     *              // or the controllable argument position is unexpected, stop the hunter.
     *              ($hit->get_func_name() === 'my_func' and isset($pos['Probe']) and !in_array($pos['Probe'], 1))
     *          ) yield false;
     *
     *          $payloads = [];  // Payloads array to be yield.
     *          if (!$his->vuln_exists('my_hunter', 'my_vuln')) {  // Skip the detected vulnerability.
     *              // Create a new test payload with type "my_vuln".
     *              $payloads[] = new CoraxPayload('my_hunter', 'my_vuln', 'my_payload');
     *          }
     *
     *          // More different payload can be test at the same time.
     *          if (!$his->vuln_exists('my_hunter', 'my_other_vuln')) {
     *              // The false means it is not a vulnerable payload.
     *              $payloads[] = new CoraxPayload('my_hunter', 'my_other_vuln', 'my_other_payload', false);
     *          }
     *          
     *          // Yield payloads and get taint results.
     *          $pos = yield $payloads;
     *
     *          // A vulnerable payload, vuln_exists can check if the payload test successfully.
     *          if (!$his->vuln_exists('my_hunter', 'my_vuln')) {
     *              // Payload is filtered of can not arrive the target argument, try more payloads.
     *              // ...
     *          }
     *
     *          // Not a vulnerable payload, check position from the result directly.
     *          if (isset($pos['my_other_vuln']) and !in_array($pos['my_other_vuln'], 1)) {
     *              // Could not get an expected position? Try more payloads.
     *              // ...
     *          }
     *
     *          // Check more payloads...
     *          $pos = yield $payloads;
     *
     *          // ...
     *
     *          if (!$lazy) {
     *              $payloads = [];
     *              // More complex payloads should be test on non-lazy mode.
     *              // ...
     *              yield $payloads;
     *          }
     *     }
     * }
     * 
     * @param \Corax\CoraxPlugin|null $plugin User custom plugin including workers. Defaults to null.
     * @param array $disable Manually disable workers. Supports regex. Defaults to an empty array.
     * @param array $targets Register hunter targets. Key is hunter name and value is array of targets 
     *   which Supports regex. Defaults to an empty array.
     */
    public function __construct($plugin = null, $disable = [], $targets = [])
    {
        parent::__construct('h_', $plugin, function ($func) {
            $value = 'test';
            try {
                $ret = $func(new CoraxHit(
                    'h-098f6bcd4621d373cade4e832627b4f6',
                    [
                        'data' => [
                            'get' => [],
                            'post' => [],
                            'path' => [],
                            'raw_post' => '',
                            'files' => [],
                            'cookies' => ['test' => 'test'],
                            'headers' => ['test' => 'test']
                        ],
                        'info' => [
                            'php_self' => '/index.php',
                            'gateway_interface' => 'CGI/1.1',
                            'server_protocol' => 'HTTP/1.1',
                            'request_method' => 'GET',
                            'query_string' => '',
                            'script_filename' => '/var/www/html/index.php',
                            'script_name' => '/index.php',
                            'web_root' => '/var/www/html',
                            'site_root' => '/var/www/html/',
                            'request_uri' => '/index.php',
                            'get_keys' => [],
                            'post_keys' => [],
                            'feature' => 'a77777661d3e83b0f59c5424b5faa102',
                            'path_name' => 'p-4ba06a8d813a5534bef4338c8a995b62',
                            'hits' => ['89292ae8c3e8c2a66374509c952efd62' => 'h-098f6bcd4621d373cade4e832627b4f6'],
                            'mutated' => [
                                'http_request' => ['raw_http_input'],
                                'remove_bytes' => ['cookies', 'test']
                            ],
                            'time' => 1696254948.012345,
                            'coverage_edges' => 1
                        ]
                    ],
                    new CoraxInput('cookies', 'test', ['cookies', 'test']),
                    [
                        [
                            'func' => 'test',
                            'args' => ['test'],
                            'file' => '/var/www/html/index.php',
                            'start_pos' => 1,
                            'end_pos' => 10,
                            'start_line' => 1,
                            'end_line' => 1,
                            'ret' => 'test',
                            'path' => ['1' => 1],
                            'path_name' => 'p-4ba06a8d813a5534bef4338c8a995b62',
                            'new_path' => true,
                            'feature' => '89292ae8c3e8c2a66374509c952efd62',
                            'pre_block' => 1
                        ]
                    ],
                    [
                        'code' => 200,
                        'headers' => ['test' => 'test'],
                        'content' => 'test',
                        'error' => null,
                        'time' => 0.008127927780151367
                    ]
                ), $value, true);
            } catch (Throwable $e) {
                return 'Register user provided hunter from plugin failed! Hunter runtime error: ' . (string) $e;
            }

            if (!($ret instanceof Generator))
                return 'Register user provided hunter from plugin failed! hunter should ' .
                    'return a "Generator" object, but returns: ' . print_r($ret, true);
        }, $disable);

        foreach (array_keys($this->workers) as $name)
            $this->workers[$name]['targets'] = [];

        // Register targets.
        $this->func_targets = [];
        foreach ($targets as $name => $funcs) {
            if (!isset($this->workers[$name])) {
                CoraxLogger::warn("Unknown hunter \"$name\".");
                continue;
            }

            foreach ($funcs as $func) {
                if (isset($this->func_targets[$func])) $this->func_targets[$func][] = $name;
                else $this->func_targets[$func] = [$name];
                $this->workers[$name]['targets'][] = $func;
            }

            $this->workers[$name]['targets'] = array_flip(array_flip($this->workers[$name]['targets']));
        }
    }

    /**
     * Register a new hunter. Same hunter will be overwrote.
     * 
     * @param string $name New hunter name.
     * @param callable $hunter The callable hunter method.
     * @param array|null $target The hunter target functions names. Defaults to an empty array.
     * @return bool If register successfully.
     */
    public function register($name, $hunter, $targets = [])
    {
        if ($result = parent::register($name, $hunter)) $this->workers[$name]['targets'] = $targets;
        return $result;
    }

    /**
     * Get one or all hunter targets.
     * 
     * @param string|null $name Hunter name. Given null will return all hunter targets. Defaults to null.
     * @return array Hunter targets. Key is hunter name and value is array with target function names.
     */
    public function get_targets($name = null)
    {
        $targets = [];
        if ($name) {
            if (isset($this->workers[$name])) return [$name => $this->workers[$name]['targets']];
        } else foreach ($this->workers as $name => $hunter) $targets[$name] = $hunter['targets'];
        return $targets;
    }

    /**
     * Register a new hunter target.
     * 
     * @param string|array $target Target function name or names. Supports regex.
     * @param string|null $name Hunter name. Given null will register the target to all hunter. Defaults to null.
     * @return bool If register successfully. False will be returned if hunter does not exist.
     */
    public function register_target($target, $name = null)
    {
        if ($name) {
            if (isset($this->workers[$name])) {
                if (is_array($target)) {
                    foreach ($target as $t) {
                        if (!in_array($t, $this->workers[$name]['targets']))
                            $this->workers[$name]['targets'][] = $t;
                    }
                } elseif (!in_array($target, $this->workers[$name]['targets']))
                    $this->workers[$name]['targets'][] = $target;
            } else return false;
        } else {
            foreach (array_keys($this->workers) as $name) {
                if (!in_array($target, $this->workers[$name]['targets']))
                    $this->workers[$name]['targets'][] = $target;
            }
        }
        return true;
    }

    /**
     * Remove a target from a hunter.
     * 
     * @param string $target Target function name.
     * @param string|null $name Hunter name. Given null will remove the target from all workers. Defaults to null.
     * @return bool If register successfully. False will be returned if hunter does not exist.
     */
    public function remove_target($target, $name = null)
    {
        if ($name) {
            if (isset($this->workers[$name])) {
                if (($key = array_search($target, $this->workers[$name]['targets'])) !== false)
                    unset($this->workers[$name]['targets'][$key]);
            } else return false;
        } else {
            foreach ($this->workers as $name => $_) {
                if (($key = array_search($target, $this->workers[$name]['targets'])) !== false)
                    unset($this->workers[$name]['targets'][$key]);
            }
        }
        return true;
    }

    /**
     * Hunt a hit by tainting.
     * 
     * @param \Corax\Fuzz\CoraxHit $hit The hit to taint.
     * @param string &$value The value which triggered this hit. This value is un-decoded.
     * @param bool $lazy Enable or disable lazy hunting.
     * @param string|null $name Specific a hunter to taint the hit. Given null will use all registered hunters. Defaults to null.
     * @param bool $force Force using the parser no matter if it is enabled. Defaults to false.
     * @return array Key is hunter name and value is the hunter generator.
     */
    public function hunt($hit, &$value, $lazy, $name = null, $force = false)
    {
        $hunters = [];
        if ($name) {
            if ($hunter = parent::get_worker($name, $force)) $hunters[$name] = $hunter($hit, $value, $lazy);
            else CoraxLogger::warn($name ? "Access denied for using disabled or unknown hunter \"$name\"." :
                'No available hunter!');
        } else {
            $target = $hit->get_func_name();
            foreach ($this->func_targets as $func => $names) {
                if (preg_match("/^$func$/um", $target)) {
                    CoraxLogger::debug(sprintf(
                        'Target matched /^%s$/ with %d hunters: ',
                        $func,
                        count($names)
                    ) . implode(', ', $names), 1);
                    foreach ($names as $name) {
                        if ($hunter = parent::get_worker($name, $force)) {
                            CoraxLogger::debug("Hit function matched \"$func\" for hunter \"$name\".", 1);
                            $hunters[$name] = $hunter($hit, $value, $lazy);
                        } else CoraxLogger::debug("Hunter \"$name\" disabled.");
                    }
                }
            }
        }

        return $hunters;
    }

    /**
     * Hunter for xss (cross site scripting).
     * 
     * https://www.cnblogs.com/wjrblogs/p/12341190.html#%E5%9B%9Bjs%E4%B8%AD%E4%B8%80%E4%BA%9B%E5%A5%87%E6%80%AA%E7%9A%84%E5%87%BD%E6%95%B0%E7%89%B9%E6%80%A7
     * https://saucer-man.com/information_security/103.html
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
    protected function h_xss($hit, &$value, $lazy)
    {
        // Payload types.
        if (!defined('XSS_HUNTER_NAME')) {
            define('XSS_HUNTER_NAME', 'xss');
            // " src=x
            define('XSS_UNESC_DB_QT', 'Unescaped Double Quote');
            // <abc>
            define('XSS_UNESC_TG_MK', 'Unescaped Tag Mark');
            // <img onerror=alert(1);/>
            // <a href=javascript:alert(1)>test</a>
            define('XSS_HTML_TG_ATTR_EVT_JS', 'HTML Tag Attribute/Event for JS');
            // <script>alert(1);</script>
            define('XSS_HTML_STG_JS', 'HTML Script Tag for JS');
            // <img src=x />
            define('XSS_SG_TG_IJC', 'HTML Single Tag Injection');
            // <a href=x>test</a>
            define('XSS_DB_TG_IJC', 'HTML Double Tag Injection');
        }

        $arg_pos = -1;
        // The content-type of response has to be html.
        $content_type = $hit->get_path()->get_response_headers('Content-Type');
        if (!($content_type && (strpos($content_type, 'text/html') !== false))) yield false;

        $func = $hit->get_func_name();
        if ($func === 'var_export') {
            // No HTML outputs if the 2nd arguments of `var_export` is true.
            $args = $hit->get_args();
            if (isset($args[1]) && $args[1] === 'true') yield false;
        } elseif ($func === 'vprintf') {
            // Only consider the 1st parameter of `vprintf`.
            $arg_pos = 1;
        }

        if (!$hit->vuln_exists(XSS_HUNTER_NAME, XSS_UNESC_DB_QT))
            $payloads[] = new CoraxPayload(XSS_HUNTER_NAME, XSS_UNESC_DB_QT, 'xxx"xxx', true, true, $arg_pos, null);
        if (!$hit->vuln_exists(XSS_HUNTER_NAME, XSS_UNESC_TG_MK))
            $payloads[] = new CoraxPayload(XSS_HUNTER_NAME, XSS_UNESC_TG_MK, '<x>', true, true, $arg_pos, null);

        yield $payloads;

        if ($hit->vuln_exists(XSS_HUNTER_NAME, XSS_UNESC_TG_MK)) {
            $payloads = [];
            if (!$hit->vuln_exists(XSS_HUNTER_NAME, XSS_HTML_TG_ATTR_EVT_JS))
                $payloads[] = new CoraxPayload(XSS_HUNTER_NAME, XSS_HTML_TG_ATTR_EVT_JS, '<img src=1 onerror=alert(1)>', true, true, $arg_pos, null);
            if (!$hit->vuln_exists(XSS_HUNTER_NAME, XSS_HTML_STG_JS))
                $payloads[] = new CoraxPayload(XSS_HUNTER_NAME, XSS_HTML_STG_JS, '<script>alert(1)</script>', true, true, $arg_pos, null);
            if (!$hit->vuln_exists(XSS_HUNTER_NAME, XSS_SG_TG_IJC))
                $payloads[] = new CoraxPayload(XSS_HUNTER_NAME, XSS_SG_TG_IJC, '<frame src=x/>', true, true, $arg_pos, null);
            if (!$hit->vuln_exists(XSS_HUNTER_NAME, XSS_DB_TG_IJC))
                $payloads[] = new CoraxPayload(XSS_HUNTER_NAME, XSS_DB_TG_IJC, '<form action=x></form>', true, true, $arg_pos, null);
            yield $payloads;
        }

        if (!$lazy || CoraxRandom::random_bool(0.3)) {
            $spaces = ["\x09", "\x0c", "\r", ' ', '/', "\t", "\n"];
            $payloads = [];

            if (!$hit->vuln_exists(XSS_HUNTER_NAME, XSS_HTML_TG_ATTR_EVT_JS)) {
                $is_single = CoraxRandom::random_bool();
                $tag = $is_single ? CoraxDictionary::$html_single_tags : CoraxDictionary::$html_paired_tags;
                $tag = CoraxRandom::random_choice($tag);
                // Letter case bypass.
                if (CoraxRandom::random_bool()) $tag = CoraxHound::shuffle_letter_case($tag);

                // Choice a HTML attribute or javascript event.
                $is_event = CoraxRandom::random_bool();
                $attr = $is_event ? CoraxDictionary::$js_events : CoraxDictionary::$html_attrs;
                $attr = CoraxRandom::random_choice($attr);
                // Letter case bypass.
                if (CoraxRandom::random_bool()) $attr = CoraxHound::shuffle_letter_case($attr);

                // Need quotes maybe.
                $quote = CoraxRandom::random_choice(CoraxDictionary::$quotes);
                // The HTML attribute has to use the javascript pseudo, but javascript event not.
                $pseudo = (!$is_event || CoraxRandom::random_bool()) ? 'javascript:' : '';

                if ($pseudo && CoraxRandom::random_bool()) {
                    // Letter case bypass.
                    $pseudo = CoraxHound::shuffle_letter_case($pseudo);
                    if ($quote) {
                        // Space in quote bypass.
                        CoraxRandom::insert_string($pseudo, ' ', CoraxRandom::random_int(1, 8));
                        // Space replace bypass.
                        if (CoraxRandom::random_bool())
                            $pseudo = CoraxHound::replace_space($pseudo, $is_event ? ["\t"] : ["\r", "\n"]);
                    }
                }

                // Space bypass.
                $sep = CoraxRandom::random_choice($spaces);
                $payloads[] = new CoraxPayload(
                    XSS_HUNTER_NAME,
                    XSS_HTML_TG_ATTR_EVT_JS,
                    '<' . $tag . $sep .
                        // Fake attrs.
                        implode($sep, CoraxHound::fake_assign(CoraxRandom::random_int(0, 4))) . $sep .
                        $attr . '=' . $quote . $pseudo .
                        // Fake code.
                        CoraxHound::fake_func_call(['alert', 'confirm', 'xss', 'String.fromCharCode']) . $quote .
                        // Close tag.
                        (($is_single) ? (CoraxRandom::random_bool() ? '/' : '') . '>' :
                            '>' . CoraxRandom::random_id(CoraxRandom::random_int(0, 5)) . "</$tag>"),
                    true,
                    true,
                    $arg_pos,
                    null
                );
            }

            if (!$hit->vuln_exists(XSS_HUNTER_NAME, XSS_HTML_STG_JS)) {
                $tag = 'script';
                // Letter case bypass.
                if (CoraxRandom::random_bool()) $tag = CoraxHound::shuffle_letter_case($tag);

                // Space bypass.
                $sep = CoraxRandom::random_choice($spaces);
                $payloads[] = new CoraxPayload(
                    XSS_HUNTER_NAME,
                    XSS_HTML_STG_JS,
                    '<' . $tag . $sep .
                        // Fake attrs.
                        implode($sep, CoraxHound::fake_assign(CoraxRandom::random_int(0, 4))) . '>' .
                        // Fake code.
                        CoraxHound::fake_func_call(['alert', 'confirm', 'xss', 'String.fromCharCode']) . "</$tag>",
                    true,
                    true,
                    $arg_pos,
                    null
                );
            }

            if (!$hit->vuln_exists(XSS_HUNTER_NAME, XSS_SG_TG_IJC)) {
                $tag = CoraxRandom::random_choice(CoraxDictionary::$html_single_tags);
                // Letter case bypass.
                if (CoraxRandom::random_bool()) $tag = CoraxHound::shuffle_letter_case($tag);

                // Space bypass.
                $sep = CoraxRandom::random_choice($spaces);
                $payloads[] = new CoraxPayload(
                    XSS_HUNTER_NAME,
                    XSS_SG_TG_IJC,
                    '<' . $tag . $sep .
                        // Fake attrs.
                        implode($sep, CoraxHound::fake_assign(CoraxRandom::random_int(0, 4))) .
                        (CoraxRandom::random_bool() ? '/' : '') . '>',
                    true,
                    true,
                    $arg_pos,
                    null
                );
            }

            if (!$hit->vuln_exists(XSS_HUNTER_NAME, XSS_DB_TG_IJC)) {
                $tag = CoraxRandom::random_choice(CoraxDictionary::$html_paired_tags);
                // Letter case bypass.
                if (CoraxRandom::random_bool()) $tag = CoraxHound::shuffle_letter_case($tag);

                // Space bypass.
                $sep = CoraxRandom::random_choice($spaces);
                $payloads[] = new CoraxPayload(
                    XSS_HUNTER_NAME,
                    XSS_DB_TG_IJC,
                    '<' . $tag . $sep .
                        // Fake attrs.
                        implode($sep, CoraxHound::fake_assign(CoraxRandom::random_int(0, 4))) . '>' .
                        CoraxRandom::random_id(CoraxRandom::random_int(0, 5)) . "</$tag>",
                    true,
                    true,
                    $arg_pos,
                    null
                );
            }

            yield $payloads;
        }
    }

    /**
     * Hunter for command execution.
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
    protected function h_command_execution($hit, &$value, $lazy)
    {
        // Payload types.
        if (!defined('CE_HUNTER_NAME')) {
            define('CE_HUNTER_NAME', 'command_execution');
            // comm*
            define('CE_UNSEC_WDCD_ALL', 'Unescaped Shell Wildcard ALL');
            // comm?nd
            define('CE_UNSEC_WDCD_ONE', 'Unescaped Shell Wildcard ONE');
            // command > file
            define('CE_UNSEC_RD_OUT', 'Unescaped Shell Redirection Output');
            // command < file
            define('CE_UNSEC_RD_IN', 'Unescaped Shell Redirection Input');
            // commmand$a
            define('CE_UNSEC_DL', 'Unescaped Shell Dollar');
            // " command
            define('CE_UNESC_DB_QT', 'Unescaped Double Quote');
            // ;command
            define('CE_TCT_INJ', 'Command Truncated Injection');
            // `command`
            define('CE_BKQT_INJ', 'Command Back Quote Injection');
            // $(command)
            define('CE_BKT_INJ', 'Command Brackets Injected');
            // $PATH
            define('CE_SV_INJ', 'Command Shell Variables Injected');
        }

        $payloads = [];

        // Special chars injection.
        if (!$hit->vuln_exists(CE_HUNTER_NAME, CE_UNSEC_WDCD_ALL))
            $payloads[] = new CoraxPayload(CE_HUNTER_NAME, CE_UNSEC_WDCD_ALL, 'xxx*xxx');
        if (!$hit->vuln_exists(CE_HUNTER_NAME, CE_UNSEC_WDCD_ONE))
            $payloads[] = new CoraxPayload(CE_HUNTER_NAME, CE_UNSEC_WDCD_ONE, 'xxx?xxx');
        if (!$hit->vuln_exists(CE_HUNTER_NAME, CE_UNSEC_RD_OUT))
            $payloads[] = new CoraxPayload(CE_HUNTER_NAME, CE_UNSEC_RD_OUT, 'xxx>xxx');
        if (!$hit->vuln_exists(CE_HUNTER_NAME, CE_UNSEC_RD_IN))
            $payloads[] = new CoraxPayload(CE_HUNTER_NAME, CE_UNSEC_RD_IN, 'xxx<xxx');
        if (!$hit->vuln_exists(CE_HUNTER_NAME, CE_UNSEC_DL))
            $payloads[] = new CoraxPayload(CE_HUNTER_NAME, CE_UNSEC_DL, 'xxx$xxx');
        // Command injection.
        if (!$hit->vuln_exists(CE_HUNTER_NAME, CE_UNESC_DB_QT))
            $payloads[] = new CoraxPayload(CE_HUNTER_NAME, CE_UNESC_DB_QT, 'xxx"xxx');
        if (!$hit->vuln_exists(CE_HUNTER_NAME, CE_TCT_INJ))
            $payloads[] = new CoraxPayload(
                CE_HUNTER_NAME,
                CE_TCT_INJ,
                CoraxRandom::random_choice(CoraxDictionary::$command_truncates) . 'uid'
            );
        if (!$hit->vuln_exists(CE_HUNTER_NAME, CE_BKQT_INJ))
            $payloads[] = new CoraxPayload(CE_HUNTER_NAME, CE_BKQT_INJ, '`uid`');
        if (!$hit->vuln_exists(CE_HUNTER_NAME, CE_BKT_INJ))
            $payloads[] = new CoraxPayload(CE_HUNTER_NAME, CE_BKT_INJ, '$(uid)');
        if (!$hit->vuln_exists(CE_HUNTER_NAME, CE_SV_INJ))
            $payloads[] = new CoraxPayload(CE_HUNTER_NAME, CE_SV_INJ, '$PATH');

        yield $payloads;

        if (!$lazy || CoraxRandom::random_bool(0.3)) {
            $payloads = [];

            // ;cmd
            if (!$hit->vuln_exists(CE_HUNTER_NAME, CE_TCT_INJ)) $payloads[] = new CoraxPayload(
                CE_HUNTER_NAME,
                CE_TCT_INJ,
                CoraxRandom::random_choice(CoraxDictionary::$command_truncates) .
                    CoraxHound::fake_command(CoraxRandom::random_int(0, 4))
            );

            // `cmd`
            if (!$hit->vuln_exists(CE_HUNTER_NAME, CE_BKQT_INJ)) $payloads[] = new CoraxPayload(
                CE_HUNTER_NAME,
                CE_BKQT_INJ,
                '`' . CoraxHound::fake_command(CoraxRandom::random_int(0, 4)) . '`'
            );

            // $(cmd)
            if (!$hit->vuln_exists(CE_HUNTER_NAME, CE_BKT_INJ)) $payloads[] = new CoraxPayload(
                CE_HUNTER_NAME,
                CE_BKT_INJ,
                '$(' . CoraxHound::fake_command(CoraxRandom::random_int(0, 4)) . ')'
            );

            // $NAME or ${NAME}
            if (!$hit->vuln_exists(CE_HUNTER_NAME, CE_SV_INJ)) {
                $name = CoraxRandom::random_id(CoraxRandom::random_int(1, 4));
                if (CoraxRandom::random_bool()) $name = "{$name}";
                $payloads[] = new CoraxPayload(CE_HUNTER_NAME, CE_SV_INJ, '$' . $name);
            }

            yield $payloads;
        }
    }

    /**
     * Hunter for environment variables rewrite.
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
    protected function h_environ_rewrite($hit, &$value, $lazy)
    {
        // Payload types.
        if (!defined('EVR_HUNTER_NAME')) {
            define('EVR_HUNTER_NAME', 'environ_rewrite');
            // PATH
            define('EVR_VAR_DEL', 'Environ Variable Delete');
            // PATH=123
            define('EVR_VAR_SET', 'Environ Variable Put');
        }

        $payloads = [];

        if (!$hit->vuln_exists(EVR_HUNTER_NAME, EVR_VAR_DEL))
            $payloads[] = new CoraxPayload(EVR_HUNTER_NAME, EVR_VAR_DEL, 'LD_LIBRARY_PATH');
        if (!$hit->vuln_exists(EVR_HUNTER_NAME, EVR_VAR_SET))
            $payloads[] = new CoraxPayload(EVR_HUNTER_NAME, EVR_VAR_SET, 'LD_LIBRARY_PATH=x');

        yield $payloads;

        if (!$lazy || CoraxRandom::random_bool(0.3)) {
            if (!$hit->vuln_exists(EVR_HUNTER_NAME, EVR_VAR_DEL)) $payloads[] = new CoraxPayload(
                EVR_HUNTER_NAME,
                EVR_VAR_DEL,
                CoraxRandom::random_id(CoraxRandom::random_int(1, 4))
            );
            if (!$hit->vuln_exists(EVR_HUNTER_NAME, EVR_VAR_SET)) $payloads[] = new CoraxPayload(
                EVR_HUNTER_NAME,
                EVR_VAR_SET,
                CoraxRandom::random_id(CoraxRandom::random_int(1, 4)) . '=' .
                    CoraxRandom::random_id(CoraxRandom::random_int(1, 4))
            );
        }
        yield $payloads;
    }

    /**
     * Hunter for variable rewrite.
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
    protected function h_var_rewrite($hit, &$value, $lazy)
    {
        // Payload types.
        if (!defined('VR_HUNTER_NAME')) {
            define('VR_HUNTER_NAME', 'var_rewrite');
            // GET/POST/COOKIE
            define('VR_HTTP_VAR_REG', 'HTTP GET/POST/COOKIE Variable Register');
            // ?a=1&b=2
            define('VR_STR_REG', 'Parsed String Variable Register');
            // ['a' => 1, 'b' => 2]
            define('VR_ARR_REG', 'Extract Array Variable Register');
        }

        $func = $hit->get_func_name();
        if ($func === 'parse_str' && $hit->get_args_count() === 2) yield false;  // No vulnerability.
        elseif (
            $func === 'import_request_variables' &&
            !$hit->vuln_exists(VR_HUNTER_NAME, VR_HTTP_VAR_REG)
        ) {  // Global variable register.
            $hit->add_vuln(
                VR_HUNTER_NAME,
                VR_HTTP_VAR_REG,
                new CoraxVuln(
                    md5($hit->get_name() . VR_HUNTER_NAME . VR_HTTP_VAR_REG),
                    VR_HUNTER_NAME,
                    VR_HTTP_VAR_REG,
                    'GLOBAL_VAR1=a&GLOBAL_VAR2=b',
                    [0],
                    '',
                    $hit
                )
            );
        } elseif ($func === 'extract') {
            // TODO: How to detect extract var rewrite?
        } else yield false;

        $payloads = [];

        if (!$hit->vuln_exists(VR_HUNTER_NAME, VR_STR_REG))
            $payloads[] = new CoraxPayload(VR_HUNTER_NAME, VR_STR_REG, 'a=b');
        if (!$hit->vuln_exists(VR_HUNTER_NAME, VR_ARR_REG))
            $payloads[] = new CoraxPayload(VR_HUNTER_NAME, VR_ARR_REG, 'aaa');

        yield $payloads;

        if (!$lazy || CoraxRandom::random_bool(0.3)) {
        }
    }

    /**
     * Hunter for unserialize.
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
    protected function h_unserialize($hit, &$value, $lazy)
    {
        // Payload types.
        if (!defined('UNS_HUNTER_NAME')) {
            define('UNS_HUNTER_NAME', 'unserialize');
            define('UNS_NUL', 'Unserialized NULL');
            define('UNS_BOL', 'Unserialized Boolean');
            define('UNS_NUM', 'Unserialize Number');
            define('UNS_STR', 'Unserialize String');
            define('UNS_ARR', 'Unserialized Array');
            define('UNS_OBJ', 'Unserialized Object');
            define('UNS_OBJ_PUB', 'Unserialized Object Public Variable');
            define('UNS_OBJ_POT', 'Unserialized Object Protected Variable');
            define('UNS_OBJ_PYT', 'Unserialized Object Private Variable');
            define('UNS_OBJ_REF', 'Unserialized Object Reference Variable');
        }

        $payloads = [];

        if (!$hit->vuln_exists(UNS_HUNTER_NAME, UNS_NUL))
            $payloads[] = new CoraxPayload(UNS_HUNTER_NAME, UNS_NUL, 'N;');  // Null
        if (!$hit->vuln_exists(UNS_HUNTER_NAME, UNS_BOL))
            $payloads[] = new CoraxPayload(UNS_HUNTER_NAME, UNS_BOL, serialize(CoraxRandom::random_bool()));  // Boolean
        if (!$hit->vuln_exists(UNS_HUNTER_NAME, UNS_NUM)) {  // Numbers
            if (CoraxRandom::random_bool()) $pld = 'i:' . CoraxRandom::random_int(-255, 255);
            else $pld = 'd:' . CoraxRandom::random_int(-255, 255) .
                ('.' ? CoraxRandom::random_bool() : '') . CoraxRandom::random_int(0, 255);
            $payloads[] = new CoraxPayload(UNS_HUNTER_NAME, UNS_NUM, $pld . ';');
        }
        if (!$hit->vuln_exists(UNS_HUNTER_NAME, UNS_STR))  // String
            $payloads[] = new CoraxPayload(
                UNS_HUNTER_NAME,
                UNS_STR,
                serialize(CoraxRandom::random_string(CoraxRandom::random_int(1, 8)))
            );
        if (!$hit->vuln_exists(UNS_HUNTER_NAME, UNS_ARR))  // Array
            $payloads[] = new CoraxPayload(UNS_HUNTER_NAME, UNS_ARR, 'a:0:{}');
        if (!$hit->vuln_exists(UNS_HUNTER_NAME, UNS_OBJ))  // Object
            $payloads[] = new CoraxPayload(UNS_HUNTER_NAME, UNS_OBJ, 'O:7:"UNS_OBJ":0:{}');

        yield $payloads;

        if ($hit->vuln_exists(UNS_HUNTER_NAME, UNS_OBJ)) {
            $payloads = [];
            if (!$hit->vuln_exists(UNS_HUNTER_NAME, UNS_OBJ_PUB))  // Public var in object
                $payloads[] = new CoraxPayload(
                    UNS_HUNTER_NAME,
                    UNS_OBJ_PUB,
                    'O:11:"UNS_OBJ_PUB":1:{s:1:"a";i:1;}'
                );
            if (!$hit->vuln_exists(UNS_HUNTER_NAME, UNS_OBJ_POT))  // Protected var in object
                $payloads[] = new CoraxPayload(
                    UNS_HUNTER_NAME,
                    UNS_OBJ_POT,
                    "O:11:\"UNS_OBJ_POT\":1:{s:4:\"\x00*\x00a\";i:1;}"
                );
            if (!$hit->vuln_exists(UNS_HUNTER_NAME, UNS_OBJ_PYT))  // Private var in object
                $payloads[] = new CoraxPayload(
                    UNS_HUNTER_NAME,
                    UNS_OBJ_PYT,
                    "O:11:\"UNS_OBJ_PYT\":1:{s:14:\"\x00UNS_OBJ_PYT\x00a\";i:1;}"
                );
            if (!$hit->vuln_exists(UNS_HUNTER_NAME, UNS_OBJ_REF))  // Reference var in object
                $payloads[] = new CoraxPayload(
                    UNS_HUNTER_NAME,
                    UNS_OBJ_REF,
                    "O:11:\"UNS_OBJ_REF\":2:{s:1:\"a\";i:1;s:14:\"\x00UNS_OBJ_REF\x00b\";R:2;}"
                );
            yield $payloads;
        }

        if (!$lazy || CoraxRandom::random_bool(0.3)) {
            $payloads = [];

            $arr = [null];
            $i = CoraxRandom::random_int(1, 20);
            while ($i--) {
                switch (CoraxRandom::random_int(0, 7)) {
                    case 0:
                        $arr[] = null;
                        break;
                    case 1:
                        $arr[] = CoraxRandom::random_bool();
                        break;
                    case 2:
                        $arr[] = CoraxRandom::random_int(-255, 255);
                        break;
                    case 3:
                        $arr[] = new UNS_OBJ(CoraxRandom::random_choice($arr));
                        break;
                    case 4:
                        $arr[] = new UNS_OBJ_PUB(CoraxRandom::random_choice($arr));
                        break;
                    case 5:
                        $arr[] = new UNS_OBJ_POT(CoraxRandom::random_choice($arr));
                        break;
                    case 6:
                        $arr[] = new UNS_OBJ_PYT(CoraxRandom::random_choice($arr));
                        break;
                    case 7:
                        $arr[] = new UNS_OBJ_REF(CoraxRandom::random_choice($arr));
                    default:
                        break;
                }
            }

            $payloads[] = new CoraxPayload(UNS_HUNTER_NAME, UNS_ARR, serialize($arr));
            $payloads[] = new CoraxPayload(UNS_HUNTER_NAME, UNS_OBJ, new UNS_OBJ(CoraxRandom::random_choice($arr)));
            $payloads[] = new CoraxPayload(UNS_HUNTER_NAME, UNS_OBJ_PUB, new UNS_OBJ_PUB(CoraxRandom::random_choice($arr)));
            $payloads[] = new CoraxPayload(UNS_HUNTER_NAME, UNS_OBJ_POT, new UNS_OBJ_POT(CoraxRandom::random_choice($arr)));
            $payloads[] = new CoraxPayload(UNS_HUNTER_NAME, UNS_OBJ_PYT, new UNS_OBJ_PYT(CoraxRandom::random_choice($arr)));
            $payloads[] = new CoraxPayload(UNS_HUNTER_NAME, UNS_OBJ_REF, new UNS_OBJ_REF(CoraxRandom::random_choice($arr)));
            yield $payloads;
        }
    }

    /**
     * Hunter for ssti (server side template injection).
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
    protected function h_ssti($hit, &$value, $lazy)
    {
        // Payload types.
        if (!defined('SSTI_HUNTER_NAME')) {
            define('SSTI_HUNTER_NAME', 'ssti');
            // {7*7}
            define('SSTI_SMT', 'SSTI in Smarty');
            // {{7*7}}
            define('SSTI_TWG', 'SSTI in Twig');
        }

        $payloads = [];

        if (!$hit->vuln_exists(SSTI_HUNTER_NAME, SSTI_SMT))
            $payloads[] = new CoraxPayload(SSTI_HUNTER_NAME, SSTI_SMT, '{phpinfo()}');
        if (!$hit->vuln_exists(SSTI_HUNTER_NAME, SSTI_TWG))
            $payloads[] = new CoraxPayload(SSTI_HUNTER_NAME, SSTI_TWG, '{{7*7}}');

        yield $payloads;

        if (!$lazy || CoraxRandom::random_bool(0.3)) {
        }
    }

    /**
     * Hunter for rce (remote code execution).
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
    protected function h_rce($hit, &$value, $lazy)
    {
        // Payload types.
        if (!defined('RCE_HUNTER_NAME')) {
            define('RCE_HUNTER_NAME', 'rce');
            // ".xxx."
            define('RCE_UNSEC_DB_QT', 'Unescaped Double Quote');
            // '.xxx.'
            define('RCE_UNSEC_SG_QT', 'Unescaped Single Quote');
            // ;phpinfo();
            define('RCE_TCT_INJ', 'Code Truncated Injection');
            // ? >aaa
            define('RCE_TAG_INJ', 'PHP Tag Injection');
            // // /*
            define('RCE_CMT_INJ', 'Comment Injection');
            // $_GET
            define('RCE_VAR_INJ', 'Code Variable Injection');
            // `ls`
            define('RCE_BKQT_INJ', 'Command for Back Quote Injection');
        }

        $payloads = [];

        if (!$hit->vuln_exists(RCE_HUNTER_NAME, RCE_UNSEC_DB_QT))
            $payloads[] = new CoraxPayload(RCE_HUNTER_NAME, RCE_UNSEC_DB_QT, '"."');
        if (!$hit->vuln_exists(RCE_HUNTER_NAME, RCE_UNSEC_SG_QT))
            $payloads[] = new CoraxPayload(RCE_HUNTER_NAME, RCE_UNSEC_SG_QT, '\'.\'');
        if (!$hit->vuln_exists(RCE_HUNTER_NAME, RCE_TCT_INJ))
            $payloads[] = new CoraxPayload(RCE_HUNTER_NAME, RCE_TCT_INJ, ';test();');
        if (!$hit->vuln_exists(RCE_HUNTER_NAME, RCE_TAG_INJ))
            $payloads[] = new CoraxPayload(RCE_HUNTER_NAME, RCE_TAG_INJ, '?>xxx');
        if (!$hit->vuln_exists(RCE_HUNTER_NAME, RCE_CMT_INJ)) {
            $comments = ['//', '/*', '#'];
            $payloads[] = new CoraxPayload(RCE_HUNTER_NAME, RCE_CMT_INJ, CoraxRandom::random_choice($comments));
        }
        if (!$hit->vuln_exists(RCE_HUNTER_NAME, RCE_VAR_INJ))
            $payloads[] = new CoraxPayload(RCE_HUNTER_NAME, RCE_VAR_INJ, '{$_GET}');
        if (!$hit->vuln_exists(RCE_HUNTER_NAME, RCE_BKQT_INJ))
            $payloads[] = new CoraxPayload(RCE_HUNTER_NAME, RCE_BKQT_INJ, '`ls`');

        yield $payloads;

        if (!$lazy || CoraxRandom::random_bool(0.3)) {
        }
    }

    /**
     * Hunter for ssrf (server side request forgery)
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
    protected function h_ssrf($hit, &$value, $lazy)
    {
        // Payload types.
        if (!defined('SSRF_HUNTER_NAME')) {
            define('SSRF_HUNTER_NAME', 'ssrf');
            // file:///xxx
            define('SSRF_FILE_INJ', 'File Protocol Injection');
            // http://0.0.0.0
            define('SSRF_HTTP_INJ', 'HTTP Protocol Injection');
            // https://0.0.0.0
            define('SSRF_HTTPS_INJ', 'HTTPS Protocol Injection');
            // ftp://0.0.0.0/a
            define('SSRF_FTP_INJ', 'FTP Protocol Injection');
            // gopher://0.0.0.0:xx/_a
            define('SSRF_GOPHER_INJ', 'Gopher Protocol Injection');
            // dict://0.0.0.0:xx/a
            define('SSRF_DICT_INJ', 'Dict Protocol Injection');
            // ldap://0.0.0.0
            define('SSRF_LDAP_INJ', 'Ldap Protocol Injection');
        }

        $payloads = [];
        if (!$hit->vuln_exists(SSRF_HUNTER_NAME, SSRF_FILE_INJ))
            $payloads[] = new CoraxPayload(
                SSRF_HUNTER_NAME,
                SSRF_FILE_INJ,
                CoraxPayload::mix_payload($value, 'file:///a', 0),
                true,
                false
            );
        if (!$hit->vuln_exists(SSRF_HUNTER_NAME, SSRF_HTTP_INJ))
            $payloads[] = new CoraxPayload(
                SSRF_HUNTER_NAME,
                SSRF_HTTP_INJ,
                CoraxPayload::mix_payload($value, 'http://0.0.0.0', 0),
                true,
                false
            );
        if (!$hit->vuln_exists(SSRF_HUNTER_NAME, SSRF_HTTPS_INJ))
            $payloads[] = new CoraxPayload(
                SSRF_HUNTER_NAME,
                SSRF_HTTPS_INJ,
                CoraxPayload::mix_payload($value, 'https://0.0.0.0', 0),
                true,
                false
            );
        if (!$hit->vuln_exists(SSRF_HUNTER_NAME, SSRF_FTP_INJ))
            $payloads[] = new CoraxPayload(
                SSRF_HUNTER_NAME,
                SSRF_FTP_INJ,
                CoraxPayload::mix_payload($value, 'ftp://0.0.0.0/a', 0),
                true,
                false
            );
        if (!$hit->vuln_exists(SSRF_HUNTER_NAME, SSRF_GOPHER_INJ))
            $payloads[] = new CoraxPayload(
                SSRF_HUNTER_NAME,
                SSRF_GOPHER_INJ,
                CoraxPayload::mix_payload($value, 'gopher://0.0.0.0:0/_a', 0),
                true,
                false
            );
        if (!$hit->vuln_exists(SSRF_HUNTER_NAME, SSRF_DICT_INJ))
            $payloads[] = new CoraxPayload(
                SSRF_HUNTER_NAME,
                SSRF_DICT_INJ,
                CoraxPayload::mix_payload($value, 'dict://0.0.0.0:0/a', 0),
                true,
                false
            );
        if (!$hit->vuln_exists(SSRF_HUNTER_NAME, SSRF_LDAP_INJ))
            $payloads[] = new CoraxPayload(
                SSRF_HUNTER_NAME,
                SSRF_LDAP_INJ,
                CoraxPayload::mix_payload($value, 'ldap://0.0.0.0:0', 0),
                true,
                false
            );

        yield [] => $payloads;

        if (!$lazy || CoraxRandom::random_bool(0.3)) {
        }
    }

    /**
     * Hunter for sqli (sql injection).
     * 
     * @author YingNing <1361024472@qq.com>
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
    protected function h_sqli($hit, &$value, $lazy)
    {
        // Payload types.
        if (!defined('SQLI_HUNTER_NAME')) {
            define('SQLI_HUNTER_NAME', 'sqli');
            define('SQLI_HUNTER_PROB', 'SQL Injection Probe');
            //Unescaped Single Quote
            define('SQLI_HUNTER_SG_QT', 'Unescaped Single Quote Injection');
            //Unescaped Double Quote "="1
            define('SQLI_HUNTER_DB_QT', 'Unescaped Double Quote Injection');
            //' union select 1(Union Injection)
            define('SQLI_HUNTER_UN_ST', 'Unescaped Union Select Injection');
            //' and if(1=1,1,0)（Boolean Blinds）
            define('SQLI_HUNTER_AD_IF', 'Boolean Blinds And If');
            //' and sleep(10)(Time Injection)
            define('SQLI_HUNTER_AD_SP', 'Time Injection And Sleep');
            //' and updatexml(1,'~',1) (Error Injection)
            define('SQLI_HUNTER_UP_CT', 'Error Injection Updatexml Concat');
            //'; (Stack Injection)
            define('SQLI_HUNTER_SN', 'Stack Injection Semicolon');
        }

        $payloads = [];
        // Quote detection.
        $prob = 'Corax' . CoraxRandom::random_id(3);
        $quote = '';
        $payloads[] = new CoraxPayload(SQLI_HUNTER_NAME, SQLI_HUNTER_PROB, $prob, false, false, -1, function (&$payload, &$raw_hit, &$pos) use (&$quote) {
            if ($pos !== -1) {
                $args = explode($payload, CoraxList::decode_array($raw_hit[0]['args'])[$pos]);
            }
            return -1;
        });


        $tag_filtered_SG_QT = !$hit->vuln_exists(SQLI_HUNTER_NAME, SQLI_HUNTER_SG_QT);
        $tag_filtered_DB_QT = !$hit->vuln_exists(SQLI_HUNTER_NAME, SQLI_HUNTER_DB_QT);
        if (!$hit->vuln_exists(SQLI_HUNTER_NAME, SQLI_HUNTER_SG_QT))
            $payloads[] = new CoraxPayload(SQLI_HUNTER_NAME, SQLI_HUNTER_SG_QT, "'='1");
        if (!$hit->vuln_exists(SQLI_HUNTER_NAME, SQLI_HUNTER_DB_QT))
            $payloads[] = new CoraxPayload(SQLI_HUNTER_NAME, SQLI_HUNTER_DB_QT, '"="1');

        $result = yield $payloads;

        $payloads = [];

        $quote = "";
        if (!($tag_filtered_SG_QT) || $result[SQLI_HUNTER_SG_QT]) $quote = '\'';
        elseif (!($tag_filtered_DB_QT) || $result[SQLI_HUNTER_DB_QT]) $quote = '"';
        else yield false;

        if (!$hit->vuln_exists(SQLI_HUNTER_NAME, SQLI_HUNTER_UN_ST))
            $payloads[] = new CoraxPayload(SQLI_HUNTER_NAME, SQLI_HUNTER_UN_ST, $quote . ' union select 1 -- ');
        if (!$hit->vuln_exists(SQLI_HUNTER_NAME, SQLI_HUNTER_AD_IF))
            $payloads[] = new CoraxPayload(SQLI_HUNTER_NAME, SQLI_HUNTER_AD_IF, $quote . ' and if(1,1,0) -- ');
        if (!$hit->vuln_exists(SQLI_HUNTER_NAME, SQLI_HUNTER_AD_SP))
            $payloads[] = new CoraxPayload(SQLI_HUNTER_NAME, SQLI_HUNTER_AD_SP, $quote . ' and sleep(5) -- ');
        if (!$hit->vuln_exists(SQLI_HUNTER_NAME, SQLI_HUNTER_UP_CT))
            $payloads[] = new CoraxPayload(SQLI_HUNTER_NAME, SQLI_HUNTER_UP_CT, $quote . ' and updatexml(1,\'~\',1) -- ');
        if (!$hit->vuln_exists(SQLI_HUNTER_NAME, SQLI_HUNTER_SN))
            $payloadS[] = new CoraxPayload(SQLI_HUNTER_NAME, SQLI_HUNTER_SN, $quote . '; -- ');

        yield $payloads;

        if (!$lazy || CoraxRandom::random_bool(0.3)) {
        }
    }

    /**
     * Hunter for file upload.
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
    protected function h_file_upload($hit, &$value, $lazy)
    {
        // Payload types.
        if (!defined('FU_HUNTER_NAME')) {
            define('FU_HUNTER_NAME', 'file_upload');
            define('FU_MOV_CTR', 'File Upload Destination Controllable');
        }

        $payloads = [];

        yield $payloads;

        if (!$lazy || CoraxRandom::random_bool(0.3)) {
        }
    }

    /**
     * Hunter for file include.
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
    protected function h_file_include($hit, &$value, $lazy)
    {
        // Payload types.
        if (!defined('FI_HUNTER_NAME')) {
            define('FI_HUNTER_NAME', 'file_include');
        }

        $payloads = [];

        yield $payloads;

        if (!$lazy || CoraxRandom::random_bool(0.3)) {
        }
    }

    /**
     * Hunter for file access.
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
    protected function h_file_access($hit, &$value, $lazy)
    {
        // Payload types.
        if (!defined('FA_HUNTER_NAME')) {
            define('FA_HUNTER_NAME', 'file_access');
        }

        $payloads = [];

        yield $payloads;

        if (!$lazy || CoraxRandom::random_bool(0.3)) {
        }
    }

    /**
     * Hunter for xxe (xml external entity).
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
    protected function h_xxe($hit, &$value, $lazy)
    {
        // Payload types.
        if (!defined('XXE_HUNTER_NAME')) {
            define('XXE_HUNTER_NAME', 'xxe');
            // Tag injected
            define('XXE_HUNTER_TAG_IJ', "Unescape XML Tag Injection");
            // XML injected.
            define('XXE_HUNTER_XML_IJ', "Unescape Basic XML Injection");
            // Internal entity injection.
            define('XXE_HUNTER_IN_ETY', 'Internal Entity Injection');
            // External entity injection.
            define('XXE_HUNTER_EX_ETY', 'External Entity Injection');
            // Parameter entity injection.
            define('XXE_HUNTER_PA_ETY', 'Parameter Entity Injection');
            // External entity to file read.
            define('XXE_HUNTER_EX_ETY_FILE', 'External Entity File Read');
            // External entity to SSRF.
            define('XXE_HUNTER_EX_ETY_SSRF', 'External Entity SSRF');
        }

        $payloads = [];
        $tag_filtered = !$hit->vuln_exists(XXE_HUNTER_NAME, XXE_HUNTER_TAG_IJ);
        if (!$hit->vuln_exists(XXE_HUNTER_NAME, XXE_HUNTER_TAG_IJ))
            $payloads[] = new CoraxPayload(XXE_HUNTER_NAME, XXE_HUNTER_TAG_IJ,  '<a>b</a>');
        $results = yield $payloads;

        if (!$tag_filtered || $results[XXE_HUNTER_TAG_IJ]) {
            $payloads = [];
            if (!$hit->vuln_exists(XXE_HUNTER_NAME, XXE_HUNTER_XML_IJ))
                $payloads[] = new CoraxPayload(XXE_HUNTER_NAME, XXE_HUNTER_XML_IJ,  '<?xml version="1.0"?><a>b</a>');
            if (!$hit->vuln_exists(XXE_HUNTER_NAME, XXE_HUNTER_IN_ETY))
                $payloads[] = new CoraxPayload(
                    XXE_HUNTER_NAME,
                    XXE_HUNTER_IN_ETY,
                    '<?xml version="1.0"?><!DOCTYPE A[<!ENTITY a "a">]><b>&a;</b>'
                );
            if (!$hit->vuln_exists(XXE_HUNTER_NAME, XXE_HUNTER_EX_ETY))
                $payloads[] = new CoraxPayload(
                    XXE_HUNTER_NAME,
                    XXE_HUNTER_EX_ETY,
                    '<?xml version="1.0" ?><!DOCTYPE A[<!ENTITY a SYSTEM "a">]><b>&a;</b>'
                );
            if (!$hit->vuln_exists(XXE_HUNTER_NAME, XXE_HUNTER_PA_ETY))
                $payloads[] = new CoraxPayload(
                    XXE_HUNTER_NAME,
                    XXE_HUNTER_PA_ETY,
                    '<?xml version="1.0" ?><!DOCTYPE A[<!ENTITY % a SYSTEM "a">%a;]>'
                );

            yield $payloads;

            if (!$hit->vuln_exists(XXE_HUNTER_NAME, XXE_HUNTER_EX_ETY)) {
                if (!$hit->vuln_exists(XXE_HUNTER_NAME, XXE_HUNTER_EX_ETY_FILE))
                    $payloads[] = new CoraxPayload(
                        XXE_HUNTER_NAME,
                        XXE_HUNTER_EX_ETY_FILE,
                        '<?xml version="1.0" ?><!DOCTYPE A[<!ENTITY a SYSTEM "/a/b">]><b>&a;</b>'
                    );

                if (!$hit->vuln_exists(XXE_HUNTER_NAME, XXE_HUNTER_EX_ETY_SSRF))
                    $payloads[] = new CoraxPayload(
                        XXE_HUNTER_NAME,
                        XXE_HUNTER_EX_ETY_SSRF,
                        '<?xml version="1.0" ?><!DOCTYPE A[<!ENTITY a SYSTEM "http://0.0.0.0/a">]><b>&a;</b>'
                    );
            }
        }

        if (!$lazy || CoraxRandom::random_bool(0.3)) {
        }
    }
}
