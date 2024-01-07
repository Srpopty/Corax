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
 * @Filename: CoraxFuzzer.php
 * @Description: 
 *   Corax main fuzzer. Synchronous raw http inputs from fuzzing server, parse 
 * and mutate these local inputs, reassemble inputs and send to server, retrieve 
 * path and hits of sent input from fuzzing server to check. After finding a hit 
 * and send it tainter for tracing.
 * ================================================================================
 */

namespace Corax\Fuzz;

use Corax\Instrument\CoraxInstrumenter;

use Corax\Common\CoraxLogger;
use Corax\Common\CoraxHTTPClient;
use Corax\Common\CoraxList;
use Corax\Common\CoraxRandom;
use Corax\Common\CoraxStatistic;
use Corax\Common\CoraxUtils;
use Corax\CoraxMain;
use Throwable;


final class CoraxFuzzer
{
    // Fuzzing parameters.
    private $url = 'http://127.0.0.1/';
    private $host = 'http://127.0.0.1/';
    private $key = '';
    private $nest = '';
    private $header_key = '';
    private $work_dir = './';
    private $reports_dir = './';
    private $statistic_dir = './';
    private $src_dir = '';
    private $fileinfo = [];
    private $fileinfo_cache = [];  // For quick seek fileinfo.
    private $first_fileinfo_filename = null;  // Always the first filename in fileinfo.
    private $server_running = false;

    // Containers.
    public $inputs = null;
    public $path = null;
    public $hits = null;
    public $corpus = null;
    public $vulns = null;
    public $vuln_hits = null;

    // Components.
    public $mutator = null;
    public $parser = null;
    public $encoder = null;
    public $hunter = null;
    public $common_http_client = null;
    public $sync_input_http_client = null;
    public $sync_corpus_http_client = null;
    public $fuzz_http_client = null;
    public $taint_http_client = null;

    private static $extract_ptn = "/<!-- Corax\{(.*)?\} -->/";

    /**
     * Initialize fuzzer with components.
     * 
     * @param \Corax\Fuzz\CoraxMutator|null $mutator Mutator used for fuzzer. Given null will create a new mutator. 
     *   Defaults to null.
     * @param \Corax\Fuzz\CoraxParser|null $parser Parser used for fuzzer. Given null will create a new parser. 
     *   Defaults to null.
     *   Defaults to null.
     * @param \Corax\Fuzz\CoraxEncoder|null $encoder Encoder used for fuzzer. Given null will create a new encoder. 
     *   Defaults to null.
     * @param \Corax\Fuzz\CoraxHunter|null $hunter Hunter used for fuzzer. Given null will create a new hunter. 
     *   Defaults to null.
     */
    public function __construct($mutator = null, $parser = null, $encoder = null, $hunter = null)
    {
        if ($mutator === null) {
            CoraxLogger::warn('No Corax mutator assigned, using default mutator.');
            $mutator = new CoraxMutator();
        }

        // Create corps cross mutation dynamically.
        if (!$mutator->exists('cross_corpus')) $mutator->register('cross_corpus', function ($str, $type) {
            if (!is_string($str)) return null;

            $corpus = CoraxRandom::random_choice(CoraxStatistic::$corpus_name);
            if (!isset($corpus[0])) return null;

            $corpus = $this->corpus->load($corpus);
            if ($corpus === null) return null;

            if (CoraxRandom::random_bool(0.1)) {
                $corpus = $this->mutator->basic_mutate($corpus);
                if (!isset($corpus[0])) return null;
            }

            // Totally replace.
            if (CoraxRandom::random_bool(0.5) || !isset($str[0])) return $corpus;

            // Insert to value.
            if (CoraxRandom::random_bool(0.5)) {
                CoraxRandom::insert_string($str, $corpus);
                return $str;
            }

            $str_len = strlen($str);
            $corpus_len = strlen($corpus);

            // Replace block to value.
            if (CoraxRandom::random_bool(0.1)) {
                $replace_len = ($str_len >= $corpus_len) ?
                    CoraxRandom::random_int(1, $corpus_len) :
                    CoraxRandom::random_int(1, $str_len);

                // Replace $str start with $str_no
                $pos = CoraxRandom::random_int(0, $str_len - $replace_len);
                // Get corpus block start with $corpus_no
                return substr($str, 0, $pos) .
                    substr($corpus, CoraxRandom::random_int(0, $corpus_len - $replace_len), $replace_len) .
                    substr($str, $pos + $replace_len);
            }

            // Replace to value.
            $pos = CoraxRandom::random_pos($str);
            return ($pos + $corpus_len >= $str_len || CoraxRandom::random_bool(0.3))
                ? (substr($str, 0, $pos) . $corpus)
                : (substr($str, 0, $pos) . $corpus . substr($str, $pos + $corpus_len));
        });

        if ($parser === null) {
            CoraxLogger::warn('No Corax parser assigned, using default parser.');
            $parser = new CoraxMutator();
        }

        if ($encoder === null) {
            CoraxLogger::warn('No Corax encoder assigned, using default encoder.');
            $encoder = new CoraxMutator();
        }

        $this->mutator = $mutator;
        $this->parser = $parser;
        $this->encoder = $encoder;
        $this->hunter = $hunter;

        // Bind encoder for input.
        CoraxInput::$_corax_encoder = $encoder;

        // Async http clients initialize.
        $this->common_http_client = new CoraxHTTPClient();
        $this->sync_input_http_client = new CoraxHTTPClient(true, [$this, '_sync_input_callback']);
        $this->sync_corpus_http_client = new CoraxHTTPClient(true, [$this, '_sync_corpus_callback']);
        $this->fuzz_http_client = new CoraxHTTPClient(true, [$this, '_fuzz_input_callback']);
        $this->taint_http_client = new CoraxHTTPClient(true, [$this, '_taint_hit_callback']);

        register_shutdown_function([$this, 'shutdown']);
    }

    /**
     * Callback of async request for syncing an input from fuzzing server.
     * 
     * @param string $key Request key.
     * @param array &$response Request response. Including response status code "code", response headers "headers",
     *   response data "content", request error message if error happened "error", request spend time "time"
     *   and the raw http response "raw".
     * @param string $input_name Name of synced input.
     * @param string $prefix Path prefix of the input name.
     * @param bool $dry_run Enable dry run after request.
     * @return bool If synced the input successfully.
     */
    public function _sync_input_callback($key, &$response, $input_name, $prefix, $dry_run)
    {
        if ($this->inputs->put($input_name, $response['content'], $prefix)) {
            CoraxLogger::info("Retrieved new input \"$prefix-$input_name\".", 1);
            CoraxStatistic::corax_fuzz_report($this);

            // Dry run synced input by the way.
            if ($dry_run && !$this->dry_run_input($input_name, CoraxList::json_decode($response['content']))) {
                CoraxLogger::warn("Dry run input \"$input_name\" failed!");
                return false;
            }

            CoraxStatistic::$last_sync_input_count++;
            return true;
        } else CoraxLogger::warn("Retrieve input \"$prefix-$input_name\" to local failed.");
        return false;
    }

    /**
     * Callback of async request for syncing a corpus from fuzzing server.
     * 
     * @param string $key Request key.
     * @param array &$response Request response. Including response status code "code", response headers "headers",
     *   response data "content", request error message if error happened "error", request spend time "time"
     *   and the raw http response "raw".
     * @param string $corpus_name Name of synced corpus.
     * @param string $prefix Path prefix of the corpus name.
     * @return bool If synced the corpus successfully.
     */
    public function _sync_corpus_callback($key, &$response, $corpus_name, $prefix)
    {
        $content = $response['content'];
        if ($this->corpus->put($corpus_name, $content, $prefix)) {
            CoraxStatistic::corax_fuzz_report($this);
            CoraxLogger::debug("Retrieved new corpus \"$prefix-$corpus_name\" with length: " . strlen($content), 1);
            CoraxStatistic::$corpus_name[] = $corpus_name;
            CoraxStatistic::$last_sync_corpus_count++;
            return true;
        } else CoraxLogger::warn("Retrieve corpus \"$prefix-$corpus_name\" to local failed.");
        return false;
    }

    /**
     * Callback of async request for processing fuzzed input response.
     * 
     * @param string $key Request key.
     * @param array &$response The response array of input request.
     * @param array $mutated_input The mutated raw http input array.
     * @param \Corax\Fuzz\CoraxInput $input The parsed input of raw input array for fuzzing.
     * @param string $mutator The mutator name.
     * @return bool If server returns an expected response for fuzzing.
     */
    public function _fuzz_input_callback($key, &$response, &$mutated_input, $input, $mutator)
    {
        CoraxStatistic::$processed_count++;
        CoraxStatistic::$total_input_fuzzed++;

        $parser = $input->get_type();
        $target = implode(' -> ', $input->get_value_path());
        $value_len = strlen($input->get_value($mutated_input, false));

        // Statistics for fuzzing report.
        CoraxStatistic::$current_fuzzing_parser = $parser;
        CoraxStatistic::$current_fuzzing_mutator = $mutator;
        CoraxStatistic::$current_fuzzing_target = $target;
        CoraxStatistic::$current_fuzzing_value_len = $value_len;
        CoraxStatistic::$current_fuzzing_input_file = substr(
            $mutated_input['info']['script_filename'],
            strlen($mutated_input['info']['site_root'])
        );

        $encoding = $input->get_encoding();
        CoraxLogger::debug(sprintf(
            'Fuzzing %s: %s. Mutated by %s (%d bytes).%s',
            $parser,
            $target,
            $mutator,
            $value_len,
            $encoding ? " $encoding encoded." : ''
        ), 1);

        CoraxStatistic::corax_fuzz_report($this);

        // Bad request.
        if ($response['code'] === 400 || $response['code'] === 0) {
            CoraxStatistic::$bad_trans_count++;
            CoraxLogger::debug("Bad request! " . $response['error'], 2);
            return false;
        }

        $ret = $this->extract_response($mutated_input, $response);
        $path_name = $ret['path_name'];
        if ($path_name === null) {
            CoraxLogger::debug('Missing path of last mutated request, ' .
                'Corax did not response this request! (Invalid request or server error?)', 2);
            return true;
        }

        CoraxLogger::debug('Request path: ' . $path_name, 2);
        $path = $ret['path'];
        $hits = $ret['hits'];

        // Record mutate history.
        $input->mutated_by($mutated_input, $mutator);

        // New path found and save it.
        if ($path) {
            if ($this->path->exists($path_name)) $this->path->remove($path_name);

            $path = new CoraxPath($path_name, $mutated_input, $input, $path, $response);
            if ($this->path->put($path_name, $path, substr($path_name, 2, 2))) {
                CoraxStatistic::$last_path_time = microtime(true);
                $input_name = $path->get_input_name();
                if (!$this->inputs->exists($input_name)) {
                    if ($this->inputs->put($input_name, $mutated_input, substr($input_name, 0, 2)))
                        CoraxLogger::debug("Found new path! input $input_name added to queue.", 2);
                    else {
                        CoraxLogger::warn("Found new path but save input $input_name locally failed!");
                        // Remove the file by the way.
                        $this->path->remove($path_name, true);
                        return true;
                    }
                }
            } else {
                CoraxLogger::warn("Found new path $path_name but save it locally failed!");
                return true;
            }
        }

        // Found hits.
        $all_hits = [];
        if ($hits) {
            CoraxLogger::debug('Found ' . count($hits) . ' different type hits!', 2);
            foreach ($hits as $hit => $names) {
                CoraxLogger::debug('Found ' . count($names) . " hits of $hit.", 3);
                foreach ($names as $name) {
                    if ($this->hits->exists($name)) continue;
                    if ($hit = $this->fetch_hit($name)) {
                        $hit = new CoraxHit($name, $mutated_input, $input, $hit, $response);
                        if ($this->hits->put($name, $hit, substr($name, 2, 2))) {
                            $all_hits[$name] = $hit;
                            CoraxStatistic::$last_hit_time = microtime(true);
                        } else CoraxLogger::warn("Found new hit $name but save it locally failed!");
                    }
                }
            }
        }

        // Report path results.
        if ($path) {
            CoraxLogger::success('Found new path!', 1);
            $path->report('success', 2);
            $path->report_response('debug', 2);
        }

        // Report hit results.
        if ($all_hits) {
            CoraxLogger::success('Found ' . count($all_hits) . ' different type hits!', 1);
            foreach ($all_hits as $name => $hit) {
                if ($this->hunter) {
                    CoraxLogger::info("--=[Sending hit $name to hunter for tainting]=-");
                    CoraxLogger::info('Tainting "' . $hit->get_func_name() . "\" from hit $name...");
                    $this->taint_hit($hit, true);
                } else {
                    CoraxLogger::success("Hit $name report:", 2);
                    $hit->report('success', 3);
                }
            }
        }

        return true;
    }

    /**
     * 
     * @param string $key Request key.
     * @param array &$response The  response array of input request.
     * @param array &$raw_input Thr raw http input array for request.
     * @param \Corax\Fuzz\CoraxInput $input The parsed input of raw input array which trigger the hit.
     * @param string $value The input value for tainting.
     * @param \Corax\Fuzz\CoraxHit $hit The hit for tainting.
     * @param \Corax\Fuzz\CoraxPayload $payload The payload of the tainting hit.
     * @param array &$result Array for saving tainting result.
     * @return bool If server returns an expected response for tainting.
     */
    public function _taint_hit_callback(
        $key,
        &$response,
        &$raw_input,
        $input,
        $value,
        $hit,
        $payload,
        &$results
    ) {
        $hit_feature = $hit->get_feature();
        $hunter = $payload->hunter;
        $type = $payload->type;

        // Statistics for tainting report.
        CoraxStatistic::$processed_count++;
        CoraxStatistic::$processed_payload_count++;
        CoraxStatistic::$current_tainting_hunter = $hunter;
        CoraxStatistic::$current_tainting_vuln = $type;
        CoraxStatistic::$current_tainting_value_len = strlen($value);
        CoraxStatistic::corax_fuzz_report($this);

        CoraxLogger::debug("Tainting hit $hit_feature for \"$type\" by $hunter: " . $payload->payload, 3);

        // Bad request.
        if ($response['code'] === 400 || $response['code'] === 0) {
            CoraxStatistic::$bad_trans_count++;
            CoraxLogger::debug("Bad request! " . $response['error'], 4);
            return false;
        }

        $ret = $this->extract_response($raw_input, $response);

        if (!isset($ret['hits'][$hit_feature])) {
            CoraxLogger::debug('No target hits found in this payload.', 4);
            return true;
        }

        $hits = $ret['hits'][$hit_feature];
        CoraxLogger::debug('Got ' . count($hits) . ' hit(s) to check.', 4);

        foreach ($hits as $hit_name) {
            if ($raw_hit = $this->fetch_hit($hit_name, true)) {
                CoraxLogger::debug("Checking payload result from hit $hit_name...", 4);
                $pos = $payload->check($raw_hit);
                // Argument position of this hit reached.
                if ($pos) {
                    if ($payload->is_vulnerable) $hit->add_vuln($hunter, $type, new CoraxVuln(
                        md5($hit->get_name() . $hunter . $type),
                        $hunter,
                        $type,
                        $payload->payload,
                        $pos,
                        $value,
                        new CoraxHit(
                            $hit_name,
                            $raw_input,
                            $input,
                            $raw_hit,
                            $response
                        )
                    ));

                    $results[$hunter][$type] = $pos;
                    CoraxLogger::debug('Payload not filtered and directly passed in argument: ' . implode(', ', $pos), 5);
                } else CoraxLogger::debug('Payload was filtered or desensitized.', 5);
            } else CoraxLogger::warn("Get hit $hit_name failed for checking payload.");
        }

        return true;
    }

    /**
     * Build request info of an input.
     * 
     * @param array &$raw_input The raw http input array.
     * @param \Corax\Fuzz\CoraxInput $input The parsed input of raw input array.
     * @param bool $del_path Automatically delete path after the request. Defaults to false.
     * @param bool $del_hits Automatically delete hits after the request. Defaults to false.
     * @param string|null $target_hit Specific a hit feature to get this hit result only. Defaults to null.
     * @return array The request info array.
     */
    private function build_request(&$raw_input, $input, $del_path = false, $del_hits = false, $target_hit = null)
    {
        $headers = $raw_input['data']['headers'];
        $headers[$this->header_key . '-Fuzzing'] = $target_hit ? '2' : '1';
        $headers[$this->header_key . '-Input-Feature'] = $raw_input['info']['feature'] . '-' .  $input->get_feature();
        if ($del_path) $headers[$this->header_key . '-No-Path'] = '1';
        if ($del_hits) $headers[$this->header_key . '-No-Hits'] = '1';
        if ($target_hit) $headers[$this->header_key . '-Target-Hit'] = $target_hit;

        if ($raw_input['data']['cookies']) {
            $cookies = [];
            foreach ($raw_input['data']['cookies'] as $key => $value) $cookies[] = "$key=$value";
            $headers['Cookie'] = implode(';', $cookies);
        }

        $url = $this->host . $raw_input['info']['script_name'];
        if ($raw_input['data']['path']) $url .= implode('/', $raw_input['data']['path']);
        if ($raw_input['data']['get']) $url .= '?' . http_build_query($raw_input['data']['get']);
        if ($raw_input['data']['files']) $files = $raw_input['data']['files'];
        if ($raw_input['data']['post']) $data = $raw_input['data']['post'];
        elseif ($raw_input['data']['raw_post']) $data = $raw_input['data']['raw_post'];

        return [
            'url' => $url, 'method' => $raw_input['info']['request_method'],
            'headers' => $headers, 'data' => $data ?? null, 'files' => $files ?? null
        ];
    }

    /**
     * Process the response of sent input and extract fuzzing or tainting information.
     * 
     * @param array|null &$raw_input The raw http input array.
     * @param array &$response The raw response array.
     * @return array The fuzzing request returned information including path and hit.
     */
    private function extract_response(&$raw_input, &$response)
    {
        $path_name = $path = $hits = null;
        if ($response['code'] && $response['code'] !== 400) {
            // Get index.
            $index = null;
            // Try to get index from HTTP response.
            if ($response['content'] && preg_match(self::$extract_ptn, $response['content'], $matches) === 1) {
                $index = json_decode(base64_decode($matches[1]), true);
                // Replace the index content.
                $response['content'] = preg_replace(self::$extract_ptn, '', $response['content'], 1);
            }

            if ($index) {
                $path_name = $index['path_name'];
                $path = $index['path'];
                $hits = $index['hits'];
                $server_time = $index['server_time'];
                $server_cpu = $index['server_cpu'];
                $new_coverage = $index['new_coverage'];

                // Statistics for fuzzing report.
                CoraxStatistic::$trans_time += $server_time;
                CoraxStatistic::$trans_count++;
                CoraxStatistic::$server_running_cpu += $server_cpu;
                CoraxStatistic::$coverage_edges += $new_coverage;

                // Block coverages.
                if ($path) foreach ($path as $edge => $_) {
                    $from = $edge >> 28;
                    $to = $edge & 0xfffffff;
                    if (!isset(CoraxStatistic::$visited_blocks[$from])) {
                        CoraxStatistic::$visited_blocks[$from] = 1;
                        CoraxStatistic::$coverage_blocks++;
                    }
                    if (!isset(CoraxStatistic::$visited_blocks[$to])) {
                        CoraxStatistic::$visited_blocks[$to] = 1;
                        CoraxStatistic::$coverage_blocks++;
                    }
                }

                CoraxLogger::debug(sprintf(
                    'Request[%d] transformed %s bytes in %.3f s ' .
                        '(request time: %.3f s, response time: %.3f s, cpu: %.3f%%, %d new coverage edges).',
                    $response['code'],
                    strlen($response['content']),
                    $response['time'],
                    $server_time,
                    $response['time'],
                    $server_cpu,
                    $new_coverage
                ), 2);

                $raw_input['info']['path_name'] = $path_name;
                $raw_input['info']['hits'] = $hits;
            } else {
                CoraxLogger::warn(
                    'Missing request path and hits index, invalid request or server error! ' .
                        'Request status code: ' . $response['code']
                );
                CoraxStatistic::$bad_trans_count++;
            }
        } else CoraxStatistic::$bad_trans_count++;

        return [
            'path_name' => $path_name,
            'path' => $path,
            'hits' => $hits
        ];
    }

    /**
     * Fetch hit from fuzzing server.
     * 
     * @param string $hit_name The hit name to fetch.
     * @param bool $del Enable delate to hit after fetching it. Defaults to false.
     * @return array|null The fetched raw hit array. Null will be returned if fetch failed.
     */
    private function fetch_hit($hit_name, $del = false)
    {
        $hit_response = $del ?
            $this->common_http_client->get($this->nest . 'outputs/' .
                substr($hit_name, 2, 2) . '/?f=' . $hit_name . '.json&e&d') :
            $this->common_http_client->get($this->nest . 'outputs/' .
                substr($hit_name, 2, 2) . '/' . $hit_name . '.json');

        if ($hit_response['code'] === 200) {
            $hit_response = explode("\n", $hit_response['content']);
            if (($hit = json_decode($hit_response[0], true)) !== null) {
                $hit[0]['ret'] = $hit_response[1] ?? '<NO RETURN>';
                return $hit;
            }
        } else {
            CoraxLogger::warn("Retrieve hit $hit_name failed. Server status code: " .
                $hit_response['code']);
            if ($hit_response['error']) CoraxLogger::warn("Request error:" . $hit_response['error']);
            return null;
        }
    }

    /**
     * Show corax fuzzing or tainting parameters.
     */
    private function ready()
    {
        CoraxLogger::info("Target url: \"$this->url\".");
        CoraxLogger::info("Target Host: $this->host", 1);
        CoraxLogger::info("Corax nest: $this->nest", 1);
        CoraxLogger::info("Verified Corax fuzzing key: $this->key", 1);
        CoraxLogger::info("Header key: $this->header_key", 1);
        CoraxLogger::info("Source code directory: $this->src_dir", 1);
        CoraxLogger::info("Working directory: $this->work_dir", 1);
        CoraxLogger::info("Request timeout: " . CoraxHTTPClient::$timeout, 1);
        if (CoraxHTTPClient::$proxy) CoraxLogger::info("Request proxy: " . CoraxHTTPClient::$proxy, 1);

        $names = $this->mutator->get_names(true);
        if ($names) CoraxLogger::info('Available fuzzing mutator(s): ' . implode(', ', $names), 1);
        else CoraxLogger::warn('No available fuzzing mutator!');

        $names = $this->parser->get_names(true);
        if ($names) CoraxLogger::info('Available fuzzing parser(s): ' . implode(', ', $names), 1);
        else CoraxLogger::warn('No available fuzzing parser!');

        $names = $this->encoder->get_names(true);
        if ($names) CoraxLogger::info('Available fuzzing encoder(s): ' .
            implode(', ', $this->encoder->get_names(true)), 1);
        else CoraxLogger::warn('No available fuzzing encoder!');

        if ($this->hunter) {
            $names = $this->hunter->get_names(true);
            if ($names) {
                CoraxLogger::info('Available hunter(s): ' . implode(', ', $names), 1);
                $tmp = [];
                foreach ($this->hunter->get_targets() as $n => $f) $tmp[] = $n . '{' . implode(',', $f) . '}';
                CoraxLogger::info('Hunter target(s): ' . implode(', ', $tmp), 1);
            } else CoraxLogger::warn('No available hunter!');
        }
    }

    /**
     * Dry run all local hits before tainting.
     */
    private function dry_run_hits()
    {
        CoraxLogger::info('Dry running ' . $this->hits->count() . ' hit(s) before tainting...');

        $time = microtime(true);
        foreach ($this->hits->load_all() as $name => $hit) {
            // Signal process.
            pcntl_signal_dispatch();
            if ($hit === null) {
                // Dry run failed will be auto removed.
                $this->hits->remove($name);
                CoraxLogger::warn("Could not dry run \"$name\", broken hit.");
            } elseif (!$this->dry_run_hit($name, $hit)) CoraxLogger::warn("Dry run hit \"$name\" failed!");
        }

        CoraxLogger::info('Dry run finished in ' . round(microtime(true) - $time, 3) . ' s.', 1);
    }


    /**
     * Dry run a single hit to check if this hit has reproducible path.
     * 
     * @param string $name Hit name.
     * @param \Corax\Fuzz\CoraxHit $hit The hit to dry run.
     * @return bool Dry run result.
     */
    private function dry_run_hit($name, $hit)
    {
        CoraxLogger::debug("Dry running hit \"$name\"...", 1);

        $path = $hit->get_path();
        $input = $path->get_input();
        $raw_input = $path->get_raw_input();

        CoraxLogger::debug('Requesting to ' . $raw_input['info']['request_uri'] . '...', 2);
        $request = $this->build_request($raw_input, $input, false, true);
        $response = $this->common_http_client->request(
            $request['url'],
            $request['method'],
            $request['headers'],
            $request['data'],
            $request['files']
        );
        $ret = $this->extract_response($raw_input, $response);
        CoraxStatistic::corax_fuzz_report($this);

        if ($response['code'] && $response['code'] !== 400) {
            if ($path_name = $ret['path_name']) {
                CoraxLogger::debug("Found path $path_name while dry running hit.", 2);
                // Check if it is the same path.
                if ($path_name === $path->get_name()) $result = true;
                else CoraxLogger::failed('Path changed while dry running this hit, ' .
                    'this hit may not be accessible anymore! (Website session expired?)', 1);
            } else CoraxLogger::failed('Missing path of last mutated request, ' .
                'Corax did not response this request! (Invalid request or server error?)', 1);
        } else CoraxLogger::failed('Server returns bad status code[' . $response['code'] .
            ']. Server dead or request timeout.', 1);

        if ($result) CoraxLogger::debug("OK, validated hit.", 2);
        else {
            CoraxLogger::failed("Dry run failed for hit \"$name\" and it will be removed! " .
                '(Local file will not be removed)', 2);
            // Dry run failed will be auto removed.
            $this->hits->remove($name);
        }

        return $result;
    }

    /**
     * Dry run all local inputs before fuzzing.
     */
    private function dry_run_inputs()
    {
        $this->sync(false);
        CoraxLogger::info('Dry running ' . $this->inputs->count() . ' input(s) before fuzzing...');

        $time = microtime(true);
        foreach ($this->inputs->load_all() as $name => $raw_input) {
            // Signal process.
            pcntl_signal_dispatch();
            if ($raw_input === null) {
                // Dry run failed will be auto removed.
                $this->inputs->remove($name);
                CoraxLogger::warn("Could not dry run \"$name\", broken input.");
            } elseif (!$this->dry_run_input($name, $raw_input)) CoraxLogger::warn("Dry run input \"$name\" failed!");
        }

        CoraxLogger::info('Dry run finished in ' . round(microtime(true) - $time, 3) . ' s.', 1);
    }

    /**
     * Dry run a single input to check if the input can trigger a path. If dry run failed, the input will be removed.
     * 
     * @param string $name The input name.
     * @param array $raw_input The raw http input to dry run.
     * @return bool Dry run result.
     */
    private function dry_run_input($name, $raw_input)
    {
        CoraxLogger::debug("Dry running input \"$name\"...", 1);

        $result = false;
        $input = new CoraxInput('dry_run');
        $raw_path_name = $raw_input['info']['path_name'];
        CoraxLogger::debug('Requesting to ' . $raw_input['info']['request_uri'] . '...', 2);
        $request = $this->build_request($raw_input, $input, false, true);
        $response = $this->common_http_client->request(
            $request['url'],
            $request['method'],
            $request['headers'],
            $request['data'],
            $request['files']
        );
        $ret = $this->extract_response($raw_input, $response);
        CoraxStatistic::corax_fuzz_report($this);

        if ($response['code'] && $response['code'] !== 400) {
            if ($path_name = $ret['path_name']) {
                $result = true;
                CoraxLogger::debug("Found path $path_name while dry running input.", 2);
                // New path should be recorded even it find at dry run mode.
                if ($ret['path']) {
                    if (
                        !$this->path->exists($path_name) &&
                        !$this->path->put(
                            $path_name,
                            new CoraxPath($path_name, $raw_input, $input, $ret['path'], $response),
                            substr($path_name, 2, 2)
                        )
                    ) {
                        CoraxLogger::warn("Find new path $path_name while dry running input" .
                            ' but save it locally failed!');
                        $result = false;
                    }
                }

                // Sync raw input path to local.
                $path_name = $raw_path_name;
                if (!$this->path->exists($path_name)) {
                    $prefix = substr($path_name, 2, 2);
                    $path_response = $this->common_http_client->get($this->nest . "caches/$prefix/$path_name.json");
                    if ($path_response['code'] === 200) {
                        $path =  json_decode($path_response['content'], true);
                        if ($this->path->put(
                            $path_name,
                            new CoraxPath($path_name, $raw_input, $input, $path, $response),
                            $prefix
                        )) {
                            CoraxStatistic::$coverage_edges += $raw_input['info']['coverage_edges'];
                            // Record blocks by the way.
                            foreach ($path as $edge => $_) {
                                $from = $edge >> 28;
                                $to = $edge & 0xfffffff;
                                if (!isset(CoraxStatistic::$visited_blocks[$from])) {
                                    CoraxStatistic::$visited_blocks[$from] = 1;
                                    CoraxStatistic::$coverage_blocks++;
                                }
                                if (!isset(CoraxStatistic::$visited_blocks[$to])) {
                                    CoraxStatistic::$visited_blocks[$to] = 1;
                                    CoraxStatistic::$coverage_blocks++;
                                }
                            }
                        } else {
                            CoraxLogger::warn("Saving retrieved path $path_name to local failed while dry running input!");
                            $result = false;
                        }
                    } else {
                        CoraxLogger::warn("Retrieve path $path_name failed while dry running input. Server status code: " .
                            $path_response['code']);
                        if ($path_response['error']) CoraxLogger::warn("Request error:" . $path_response['error']);
                        $result = false;
                    }
                }
            } else CoraxLogger::failed('Missing path of last mutated request, ' .
                'Corax did not response this request! (Invalid request or server error?)', 1);
        } else CoraxLogger::failed('Server returns bad status code[' . $response['code'] .
            ']. Server dead or request timeout.', 1);

        if ($result) CoraxLogger::debug("OK, validated input.", 2);
        else {
            CoraxLogger::failed("Dry run failed for input \"$name\" and it will be removed! " .
                '(The local file will not be remove)', 1);
            // Dry run failed will be auto removed.
            $this->inputs->remove($name);
        }

        return $result;
    }

    /**
     * Sync inputs and corpus from fuzzing server.
     * 
     * @param bool $dry_run Dry run each synced inputs automatically. Defaults to true.
     */
    private function sync($dry_run = true)
    {
        $url = $this->nest . 'inputs/';
        CoraxLogger::info('Synchronizing inputs...');

        $ret = $this->sync_input_http_client->get($url . 'index.php?h');
        if ($ret['code'] !== 200) {
            CoraxLogger::warn("Retrieve inputs from \"$url\" failed. Server returns " . $ret['code']);
            if ($ret['error']) CoraxLogger::warn($ret['error']);
            return;
        }

        $hash = $ret['content'];
        if ($hash !== CoraxStatistic::$last_sync_input_hash && $hash !== '0') {
            CoraxStatistic::$last_sync_input_hash = $hash;

            $new = [];
            // Only sync input name catalogue in this step.
            foreach (explode("\n", $this->sync_input_http_client->get($url . 'index.php')['content']) as $f) {
                $dir_sep = $f[0];
                $f = substr($f, 1, -5);
                $pos = strrpos($f, $dir_sep);

                if ($pos === false) {
                    $name = $f;
                    if ($this->inputs->exists($name)) continue;
                    $new[$name] = '';
                } else {
                    $name = substr($f, $pos + 1);
                    if ($this->inputs->exists($name)) continue;
                    $new[$name] = str_replace(['\\', '/'], DIRECTORY_SEPARATOR, substr($f, 0, $pos));
                }
            }

            // Now lets sync the diffed new inputs.
            $total_count = count($new);
            CoraxStatistic::$last_sync_input_count = 0;
            $time = microtime(true);
            if ($total_count) {
                CoraxLogger::info("Total $total_count inputs is ready to be synced.", 1);
                foreach ($new as $input_name => $prefix) {
                    $this->sync_input_http_client->get(
                        $url . str_replace('\\', '/', $prefix) . "/$input_name.json",
                        [],
                        false,
                        null,
                        null,
                        true,
                        null,
                        [$input_name, $prefix, $dry_run]
                    );
                    // Signal process.
                    pcntl_signal_dispatch();
                }
                $this->sync_input_http_client->request_all();

                if (CoraxStatistic::$last_sync_input_count)
                    CoraxLogger::info('Retrieved ' . CoraxStatistic::$last_sync_input_count .
                        ' new input(s) in ' . round(microtime(true) - $time, 3) . ' s.', 1);
            } else CoraxLogger::info('No inputs to sync.', 1);
        }

        // Sync input corpus.
        $url = $this->nest . 'corpus/';
        CoraxLogger::info('Synchronizing corpus...');
        $ret = $this->sync_corpus_http_client->get($url . 'index.php?h');
        if ($ret['code'] !== 200) {
            CoraxLogger::warn("Retrieve corpus from \"$url\" failed. Server returns " . $ret['code']);
            if ($ret['error']) CoraxLogger::warn($ret['error']);
            return;
        }

        $hash = $ret['content'];
        if ($hash === CoraxStatistic::$last_sync_corpus_hash || $hash === '0') return;
        CoraxStatistic::$last_sync_corpus_hash = $hash;

        $new = [];
        // Only sync corpus name catalogue in this step.
        foreach (explode("\n", $this->sync_corpus_http_client->get($url . 'index.php')['content']) as $f) {
            $dir_sep = $f[0];
            $f = substr($f, 1, -5);
            $pos = strrpos($f, $dir_sep);

            if ($pos === false) {
                $name = $f;
                if ($this->corpus->exists($name)) continue;
                $new[$name] = '';
            } else {
                $name = substr($f, $pos + 1);
                if ($this->corpus->exists($name)) continue;
                $new[$name] = str_replace(['\\', '/'], DIRECTORY_SEPARATOR, substr($f, 0, $pos));
            }
        }

        // Now lets sync the diffed new corpus.
        $total_count = count($new);
        CoraxStatistic::$last_sync_corpus_count = 0;
        $time = microtime(true);
        if ($total_count) {
            CoraxLogger::info("Total $total_count corpus is ready to be synced.", 1);
            foreach ($new as $corpus_name => $prefix) {
                $this->sync_corpus_http_client->get(
                    $url . str_replace('\\', '/', $prefix) . "/$corpus_name.json",
                    [],
                    false,
                    null,
                    null,
                    true,
                    null,
                    [$corpus_name, $prefix]
                );
                // Signal process.
                pcntl_signal_dispatch();
            }
            $this->sync_corpus_http_client->request_all();

            if (CoraxStatistic::$last_sync_corpus_count)
                CoraxLogger::info('Retrieved ' . CoraxStatistic::$last_sync_corpus_count .
                    ' new corpus in ' . round(microtime(true) - $time, 3) . ' s.', 1);
        } else CoraxLogger::info('No corpus to sync.', 1);
    }

    /**
     * Report a found vulnerability from hit.
     * 
     * @param \Corax\Fuzz\CoraxHit $hit The hit to report.
     */
    private function vulnerability_report($hit)
    {
        $hit_name = $hit->get_name();
        // Save the vulnerability hit to vuln_hits.
        CoraxLogger::debug("Saving vulnerability hit $hit_name...", 2);
        if ($this->hits->exists($hit_name)) {
            if (!$this->hits->remove($hit_name, true)) {
                CoraxLogger::warn("Save vulnerability hit $hit_name failed: could not remove original hit file!");
                return;
            }
        }

        if (!$this->vuln_hits->put($hit_name, $hit, substr($hit_name, 2, 2), true)) {
            CoraxLogger::warn("Save vulnerability hit $hit_name failed: could not save vuln hit to local file!");
            return;
        }

        // Generate markdown file report.
        $report_name = 'r-' . substr($hit_name, 2);
        $time = microtime(true);
        CoraxLogger::info("Generating Corax report to \"$report_name\"...", 2);
        CoraxStatistic::corax_markdown_report($report_name, $hit, $this);
        CoraxLogger::success('Corax report generated in ' . round(microtime(true) - $time, 3) . ' s', 2);
    }

    /**
     * The main fuzzing loop.
     */
    private function fuzz_loop()
    {
        CoraxLogger::info("Start fuzzing \"$this->url\"...");

        // Ready to roll.
        for ($i = 3; $i; $i--) {
            CoraxLogger::info("Corax will start fuzzing in $i s...");
            CoraxLogger::clear_line();
            // Signal process.
            pcntl_signal_dispatch();
            sleep(1);
        }

        if (CoraxStatistic::$enable_ui) {
            CoraxLogger::clear_screen();
            CoraxLogger::stop();
        }
        CoraxStatistic::start();

        while (true) {
            // Sync inputs and coups first on the first of each fuzzing round.
            $this->sync();

            if ($this->inputs->empty()) {
                if (CoraxStatistic::$enable_ui) CoraxLogger::start();
                CoraxLogger::warn('Empty input queue.');
                // Signal process.
                pcntl_signal_dispatch();
                sleep(3);
                if (CoraxStatistic::$enable_ui) {
                    CoraxLogger::clear_screen();
                    CoraxLogger::stop();
                }
                continue;
            }

            // New cycle round.
            CoraxLogger::info('***********************************=<[ Fuzzing Cycle ' .
                ++CoraxStatistic::$cycles . ' ]>=***********************************');
            CoraxStatistic::$cycle_time = microtime(true);
            CoraxStatistic::$cycle_total = $this->inputs->count();
            CoraxStatistic::$cycle_count = 0;

            // Fuzzing each input one by one.
            foreach ($this->inputs->load_all() as $name => $raw_input) {
                // Signal process.
                pcntl_signal_dispatch();
                CoraxStatistic::$cycle_count++;
                if ($raw_input === null) {
                    CoraxLogger::failed("Broken input \"$name\"!");
                    $this->inputs->remove($name);
                    continue;
                }

                // One input could be parsed to many agents.
                foreach ($this->parser->parse_all($raw_input, true) as $parser => $inputs) {
                    foreach ($inputs as $input) {
                        // Signal process.
                        pcntl_signal_dispatch();
                        $mutated_input = $raw_input;
                        foreach ($this->mutator->mutate_all(
                            $input->get_value($raw_input),
                            $input->get_type(),
                            true
                        ) as $mutator => $value) {
                            $input->set_value($mutated_input, $value);
                            $request = $this->build_request($mutated_input, $input);
                            $this->fuzz_http_client->request(
                                $request['url'],
                                $request['method'],
                                $request['headers'],
                                $request['data'],
                                $request['files'],
                                false,
                                null,
                                null,
                                true,
                                null,
                                [$mutated_input, $input, $mutator]
                            );
                        }  // End foreach mutator.
                    }  // End foreach input.
                }  // End foreach input parser.
            }  // End foreach raw inputs.
            $this->fuzz_http_client->request_all();
        }  // End while true.
    }

    /**
     * Taint a singly hit.
     * 
     * @param \Corax\Fuzz\CoraxHit $hit The hit to taint.
     * @param bool $lazy If enable lazy mode. Defaults to false.
     * @return bool If any payloads found by hunter.
     */
    private function taint_hit($hit, $lazy = false)
    {
        $path = $hit->get_path();
        $input = $path->get_input();
        $raw_input = $path->get_raw_input();
        // The value should be string.
        $value = $input->get_value($raw_input, false);
        $target = $hit->get_func_name();

        $hunters = $this->hunter->hunt($hit, $value, $lazy);

        if (empty($hunters)) {
            CoraxLogger::failed("No available hunter for \"$target\".", 1);
            return false;
        }

        CoraxStatistic::$total_hit_tainted++;
        CoraxStatistic::$current_tainting_hit_target = $target;
        CoraxStatistic::$current_tainting_hit_file = $hit->get_file();

        CoraxLogger::info(sprintf(
            'Tainting target "%s" (%d bytes) with %d hunter(s): %s',
            $target,
            strlen($value),
            count($hunters),
            implode(', ', array_keys($hunters))
        ), 1);

        $hit_feature = $hit->get_feature();
        $round = 0;
        while (true) {
            $round++;
            $hunter_payloads = [];
            // Collect hunter payload for this round.
            foreach ($hunters as $name => $hunter) {
                if ($hunter && $hunter->valid()) {
                    try {
                        $payloads = $hunter->current();
                    } catch (Throwable $e) {
                        CoraxLogger::warn("Hunter \"$name\" getting payload runtime error: " .  (string) $e);
                        $hunters[$name] = null;
                        continue;
                    }

                    // Check payload type.
                    if ($payloads === false) {  // Stop hunting.
                        CoraxLogger::info("Hunter \"$name\" stopped hunting...", 1);
                        $hunters[$name] = null;
                        continue;
                    } elseif ($payloads === null) {  // Probe testing.
                        CoraxLogger::info("Hunter \"$name\" probe testing...", 1);
                        $payloads = [new CoraxPayload(
                            $name,
                            'Probe',
                            CoraxRandom::random_id(CoraxRandom::random_int(3, 6)),
                            false
                        )];
                    } elseif (!is_array($payloads)) {  // Unknown type.
                        CoraxLogger::warn(
                            "Hunter \"$name\" should yield an array, null or false, but yields: " .
                                print_r($payloads, true)
                        );
                        $hunters[$name] = null;
                        continue;
                    }

                    $hunter_payloads[$name] = $payloads;
                }
            }

            if ($hunter_payloads) {
                CoraxLogger::debug("Round $round with " . count($hunter_payloads) . ' hunters are tainting: ' .
                    implode(', ', array_keys($hunter_payloads)), 2);
                $results = [];
                foreach ($hunter_payloads as $payloads) {
                    $results[$name] = [];
                    foreach ($payloads as $payload) {
                        $results[$name][$payload->type] = false;
                        $mixed_value = $payload->get_value($value);
                        $input->set_value($raw_input, $mixed_value, false);
                        $request = $this->build_request($raw_input, $input, true, false, $hit_feature);
                        $this->taint_http_client->request(
                            $request['url'],
                            $request['method'],
                            $request['headers'],
                            $request['data'],
                            $request['files'],
                            false,
                            null,
                            null,
                            true,
                            null,
                            [$raw_input, $input, $mixed_value, $hit, $payload, &$results]
                        );
                    }
                }
                $this->taint_http_client->request_all();

                // Send feed backs for hunter.
                foreach ($results as $name => $result) {
                    try {
                        $hunters[$name]->send($result);
                    } catch (Throwable $e) {
                        CoraxLogger::warn("Hunter \"$name\" sending payload testing result runtime error: " . (string) $e);
                    }
                }
            } else break;
        }  // End while.

        // New vulnerabilities found.
        if ($vulns = $hit->save_vulns()) {
            CoraxLogger::success('Found ' . count($vulns) . ' vulnerabilities of this hit!', 2);
            foreach ($vulns as $hunter => $payloads) {
                CoraxLogger::success("Hunter $hunter found " . count($payloads) . ' different type of payloads:', 3);
                foreach ($payloads as $type => $vuln) {
                    $vuln_name = $vuln->get_name();
                    CoraxLogger::success(sprintf(
                        'Found payload of "%s" in argument %d: %s',
                        $vuln->get_type(),
                        $vuln->get_arg_pos(),
                        $vuln->get_payload()
                    ), 4);

                    // Save the vulnerability.
                    if (!$this->vulns->exists($vuln->get_name())) {
                        if ($this->vulns->put($vuln_name, $vuln, substr($vuln_name, 2, 2))) {
                            CoraxStatistic::$last_vuln_time = microtime(true);
                        } else {
                            CoraxLogger::failed("Saving vulnerability with payload to local file $vuln_name.json failed!", 5);
                            $hit->remove_vuln($hunter, $type);
                        }
                    }
                }
            }

            // Save the his and generate report on fonding new vulnerabilities.
            $this->vulnerability_report($hit);
            return true;
        } else CoraxLogger::info('No vulnerability found of this hit, it may not be vulnerable.', 2);
        return false;
    }

    /**
     * The main tainting loop.
     */
    private function taint_loop()
    {
        CoraxLogger::info("Start tainting \"$this->url\"...");
        // Ready to roll.
        for ($i = 3; $i; $i--) {
            CoraxLogger::info("Corax will start tainting in $i s...");
            CoraxLogger::clear_line();
            // Signal process.
            pcntl_signal_dispatch();
            sleep(1);
        }

        if (CoraxStatistic::$enable_ui) {
            CoraxLogger::clear_screen();
            CoraxLogger::stop();
        }
        CoraxStatistic::start();

        $hits_list = [$this->hits, $this->vuln_hits];
        while (true) {
            // Signal process.
            pcntl_signal_dispatch();
            CoraxLogger::info('***********************************=<[ Tainting Cycle ' .
                ++CoraxStatistic::$cycles . ' ]>=***********************************');
            CoraxStatistic::$cycle_time = microtime(true);
            CoraxStatistic::$cycle_total = $this->hits->count() + $this->vuln_hits->count();
            CoraxStatistic::$cycle_count = 0;

            foreach ($hits_list as $hits) {
                foreach ($hits->load_all() as $name => $hit) {
                    CoraxStatistic::$cycle_count++;
                    if ($hit === null) {
                        CoraxLogger::failed("Broken hit \"$name\"!");
                        $this->hits->remove($name);
                        continue;
                    }

                    CoraxLogger::info('Tainting "' . $hit->get_func_name() . "\" from hit $name...");
                    CoraxLogger::debug("Hit $name report:", 1);
                    $hit->report('debug', 2);
                    $this->taint_hit($hit);
                }
            }
        }
    }

    /**
     * Get corax fuzzing url.
     * 
     * @return string The fuzzing url.
     */
    public function get_url()
    {
        return $this->url;
    }

    /**
     * Get Corax fuzzing host.
     * 
     * @return string The fuzzing host.
     */
    public function get_host()
    {
        return $this->host;
    }

    /**
     * Get Corax fuzzing key.
     * 
     * @return string The fuzzing key.
     */
    public function get_key()
    {
        return $this->key;
    }

    /**
     * Get local fuzzing working directory.
     * 
     * @return string The local fuzzing working directory.
     */
    public function get_work_dir()
    {
        return $this->work_dir;
    }

    /**
     * Get report directory.
     * 
     * @return string The reports directory.
     */
    public function get_reports_dir()
    {
        return $this->reports_dir;
    }

    /**
     * Get source code directory.
     * 
     * @return string The source code directory.
     */
    public function get_src_dir()
    {
        return $this->src_dir;
    }

    /**
     * Find filename by block index.
     * 
     * @param int $index The block index.
     * @return string The filename of this block. If given 0 index, "<main>" will be returned.
     */
    private function find_index_file($index)
    {
        if ($index === 0) return '<main>';
        $filename = $this->first_fileinfo_filename;
        foreach ($this->fileinfo_cache as $start_index => $index_filename) {
            if ($index < $start_index) break;
            $filename = $index_filename;
        }
        return $filename;
    }

    /**
     * Find block file information by the given index, including filename, position and line.
     * 
     * @param int $index Block index.
     * @return array Including filename, position and line.
     */
    public function find_fileinfo($index)
    {
        $filename = $this->find_index_file($index);
        $file_pos = $this->fileinfo[$filename][$index] ?? 0;
        return [$filename, ($file_pos & 0xffffffff00000000) >> 32, $file_pos & 0xffffffff];
    }

    /**
     * Extract edges from the given path and to blocks, including block information.
     * 
     * @param array $path The path array contains edges to extract.
     * @param bool $detail Enable extract detail block information, including block file, position 
     *   and line. Defaults to false.
     * @param bool $follow Enable follow the path flow, if not enable this, it will only yield each
     *   edge in path array, enable this, it will follow the jump flow in this path. Defaults to false.
     * @yield array Contains the edge index, from block index, end block index and edges count. If enable detail,
     *   the array contains the edge index, from block index, filename, file position, line, the to block index,
     *   filename, file position, line and edges count.
     */
    public function extract_path($path, $detail = false, $follow = false)
    {
        $roads = [];
        foreach ($path as $edge => $count) {
            $from = $edge >> 28;
            $to = $edge & 0xfffffff;
            if ($follow) {
                if (!isset($roads[$from])) $roads[$from] = [];
                // Single loop, put it ahead.
                if ($from === $to) $roads[$from] = [$to => $count] + $roads[$from];
                else $roads[$from][$to] = $count;
                continue;
            }
            if ($detail) {
                $from_file = $this->find_index_file($from);
                $from_file_pos = $this->fileinfo[$from_file][$from] ?? 0;
                $to_file = $this->find_index_file($to);
                $to_file_pos = $this->fileinfo[$to_file][$to];
                yield [
                    $edge, $from, $from_file, $from_file_pos >> 32, $from_file_pos & 0xffffffff,
                    $to, $to_file, $to_file_pos >> 32, $to_file_pos & 0xffffffff, $count
                ];
            } else yield [$edge, $from, $to, $count];
        }

        if ($roads) {
            $from = key($roads);
            $to = key($roads[$from]);
            while ($roads) {
                if ($detail) {
                    $from_file = $this->find_index_file($from);
                    $from_file_pos = $this->fileinfo[$from_file][$from] ?? 0;
                    $to_file = $this->find_index_file($to);
                    $to_file_pos = $this->fileinfo[$to_file][$to] ?? 0;
                    yield [
                        $from, $from_file, $from_file_pos >> 32, $from_file_pos & 0xffffffff,
                        $to, $to_file, $to_file_pos >> 32, $to_file_pos & 0xffffffff
                    ];
                } else yield [$from, $to];

                if ($roads[$from][$to] === 1) {
                    unset($roads[$from][$to]);
                    if (empty($roads[$from])) unset($roads[$from]);
                } else $roads[$from][$to] -= 1;

                $from = $to;
                if (isset($roads[$from])) $to = key($roads[$from]);
                else break;
            }
        }
    }

    /**
     * Get instrument file information, including block index and block position.
     * 
     * @param string|null $path Specific the path for fileinfo. Given null will return all fileinfo.
     *   Defaults to null.
     * @return array The fileinfo, if given path, key is block index and value is block position, else
     *   the key is path and value is an array which key is block index and value is block position.
     *   If given path does not exist in fileinfo, an empty array will be returned.
     */
    public function get_fileinfo($path = null)
    {
        return $path ? ($this->fileinfo[$path] ?? []) : $this->fileinfo;
    }

    /**
     * Check if the target fuzzing url is fuzzable.
     * 
     * @param string $url The url to check.
     * @return bool Check result.
     */
    public static function is_fuzzable($url)
    {
        CoraxLogger::info('Fuzzable checking...');
        if ($url[strlen($url) - 1] !== '/') $url .= '/';
        $nest = $url . CoraxInstrumenter::$nest . '/';
        $http_client = new CoraxHTTPClient();

        $checklist = [
            '\'index.php\'',
            '\'key.txt\'',
            '\'test_\' . $http_client->get($nest . \'key.txt\')[\'content\'] . \'.php\'',
            '\'fileinfo.json\'',
            '\'watchinfo.json\'',
            '\'inputs/index.php\'',
            '\'outputs/index.php\'',
            '\'corpus/index.php\'',
            '\'caches/index.php\''
        ];
        CoraxLogger::debug("Corax nest url: $nest", 1);

        $result = true;
        foreach ($checklist as $u) {
            $u = eval("return \$nest . $u;");
            CoraxLogger::debug("Checking \"$u\"...", 1);
            $ret = $http_client->head($u);
            $result = ($ret['code'] === 200) && $result;
            if ($result) CoraxLogger::debug('OK, status code 200.', 2);
            else {
                CoraxLogger::failed("Checking \"$u\" with status code " . $ret['code'] . ' not 200!', 1);
                if ($ret['error']) CoraxLogger::warn($ret['error']);
                return false;
            }
        }

        $ret = $http_client->get($nest);
        if ($ret['content']) {
            $version = explode(' ', $ret['content']);
            if (substr($ret['content'], 0, 6) === 'Corax ' && count($version) === 2) {
                $version = $version[1];
                if ($version !== CoraxMain::$version) {
                    CoraxLogger::failed("Corax server version \"$version\" did not compatible with client version \"" .
                        CoraxMain::$version . "\"!", 1);
                    return false;
                }
            } else {
                CoraxLogger::failed('Unknown Corax server version string: ' . $ret['content'], 1);
                return false;
            }
        } else {
            CoraxLogger::failed('Could not get Corax server version!', 1);
            return false;
        }

        CoraxLogger::success('Check OK.', 1);
        return true;
    }

    /**
     * Initialize fuzzer parameters.
     * 
     * @param string $url Fuzzing server url. Defaults to "http://127.0.0.1".
     * @param string|null $key Fuzzing key. Given null will try to retrieve to fuzzing server. Defaults to null.
     * @param string $work_dir Fuzzer working directory. Defaults to current working directory.
     * @param string $src_dir Source code directory. Given this, fuzzer could render source code 
     *   for fuzz report. Defaults to null.
     * @param array|null $fileinfo Source code instrument file information, including block index and block position.
     *   Given null will try to retrieve to fuzzing server. Defaults to null.
     * @param bool $reset Reset Corax local data and server outputs before fuzzing. Defaults to false.
     */
    public function init(
        $url = 'http://127.0.0.1/',
        $key = null,
        $work_dir = '.',
        $src_dir = null,
        $fileinfo = null,
        $reset = false
    ) {
        if (filter_var($url, FILTER_VALIDATE_URL) === false) CoraxLogger::error("Invalid url \"$url\"!");
        if ($url[strlen($url) - 1] !== '/') $url .= '/';

        if (!self::is_fuzzable($url)) CoraxLogger::error("Target url \"$url\" is not instrumented and unfuzzable!");

        $this->url = $url;
        $this->nest = $url . CoraxInstrumenter::$nest . '/';
        $this->host = CoraxHTTPClient::parse_host($url);

        if (!file_exists($work_dir)) {
            if (!CoraxUtils::mkdir($work_dir)) CoraxLogger::error("Create Corax working directory root \"$work_dir\" failed!");
        } elseif (!is_dir($work_dir)) CoraxLogger::error("Corax working directory root \"$work_dir\" is not a directory!");

        // Get source directory.
        if ($src_dir) {
            if (!file_exists($src_dir)) CoraxLogger::error("Source directory \"$src_dir\" does not exist.");
            if (!is_dir($src_dir)) CoraxLogger::error("Source directory \"$src_dir\" is not a directory.");
            $this->src_dir = realpath($src_dir) . DIRECTORY_SEPARATOR;
        } else {
            CoraxLogger::warn('Not given source code directory. Given this the fuzzer could render source code to fuzz report!');
            $this->src_dir = '';
        }

        // Initialize key.
        if ($key === null)  $key = $this->common_http_client->get($this->nest . 'key.txt')['content'];
        $this->key = $key;
        $this->header_key = 'Corax-' . ucwords(strtolower($key));
        if ($this->common_http_client->get($this->nest . "test_$key.php")['content'] !== $key)
            CoraxLogger::error("Invalid fuzzing key \"$key\".");

        // Initialize fileinfo.
        if ($fileinfo === null) {
            $fileinfo = json_decode($this->common_http_client->get($this->nest . 'fileinfo.json')['content'], true);
            if (!is_array($fileinfo) || empty($fileinfo)) CoraxLogger::error('Invalid fileinfo: ' . print_r($fileinfo));
        }
        $this->fileinfo = $fileinfo;
        $this->fileinfo_cache = [];
        foreach ($fileinfo as $filename => $block_pos)
            $this->fileinfo_cache[key($block_pos)] = $filename;
        $this->first_fileinfo_filename = array_slice($this->fileinfo_cache, 0, 1);

        // Initialize working directory.
        $work_dir = realpath($work_dir) . DIRECTORY_SEPARATOR . 'Corax_' . $key . DIRECTORY_SEPARATOR;
        if (!file_exists($work_dir)) {
            if (!CoraxUtils::mkdir($work_dir))
                CoraxLogger::error("Initialize Corax working directory \"$work_dir\" failed!");
        } elseif (!is_dir($work_dir)) CoraxLogger::error("Corax working directory \"$work_dir\" is not a directory!");
        $this->work_dir = realpath($work_dir) . DIRECTORY_SEPARATOR;

        // Initialize reports and statistic directory.
        $this->reports_dir = $this->work_dir . 'reports' . DIRECTORY_SEPARATOR;
        $this->statistic_dir = $this->work_dir . 'statistic' . DIRECTORY_SEPARATOR;
        foreach ([$this->reports_dir, $this->statistic_dir] as $dir) {
            if (!file_exists($dir) || (!is_dir($dir) && CoraxUtils::delete_path($dir))) {
                if (!CoraxUtils::mkdir($dir)) CoraxLogger::error("Create Corax local working directory \"$dir\" failed!");
            }
        }

        $tmp = $fileinfo;
        $tmp = end($tmp);
        end($tmp);
        CoraxStatistic::$total_blocks = key($tmp);

        // Initialize corax status to file.
        if ($fp = fopen($this->statistic_dir . 'corax-' . date('ymdHis', CoraxStatistic::$start_time) . '.json', 'w')) {
            fwrite($fp, json_encode([
                'key' => $key,
                'version' => CoraxMain::$version,
                'url' => $this->url,
                'host' => $this->host,
                'proxy' => CoraxHTTPClient::$proxy,
                'working_directory' => $this->work_dir,
                'source_directory' => $this->src_dir,
                'start_time' => CoraxStatistic::$start_time,
                'shutdown_time' => CoraxStatistic::$shutdown_time,
                'instrument_fileinfo' => $fileinfo,
                'total_blocks' => CoraxStatistic::$total_blocks
            ]) . PHP_EOL);
            CoraxStatistic::$dump_statistics_file = $fp;
        } else {
            CoraxLogger::warn('Create Corax status file failed!');
            if (CoraxStatistic::$enable_dump_statistics) {
                CoraxLogger::warn('Dump statistics disabled.');
                CoraxStatistic::$enable_dump_statistics = false;
            }
        }

        // Reset fuzzing server status.
        if ($reset) {
            $result = false;
            CoraxLogger::info("Resetting Corax $key...");

            CoraxLogger::info('Resetting Corax server...', 1);
            $ret = $this->common_http_client->post($this->nest . "$key.php", [$key => 'reset']);
            if ($ret['code'] === 200) {
                if ($ret['content'] === 'ok') $result = true;
                else {
                    CoraxLogger::failed(
                        'Reset Corax server outputs failed! Corax server may still running,' .
                            ' please stop it first! Server returned: ' . $ret['content'],
                        1
                    );
                }
            } else {
                CoraxLogger::failed(
                    'Reset Corax server failed! Server returned status code ' . $ret['code'] . ' not 200.',
                    1
                );
            }

            if ($result) {
                CoraxLogger::info('Resetting Corax client...', 1);
                foreach (['inputs', 'path', 'hits', 'corpus'] as $dir) {
                    $d = $work_dir . $dir;
                    if (file_exists($d) && is_dir($d)) {
                        foreach (CoraxUtils::scandir($d) as $filename) {
                            if (is_dir($filename)) continue;
                            if (!CoraxUtils::delete_path($filename)) {
                                CoraxLogger::failed("Reset Corax client directory \"$dir\" failed!", 1);
                                $result = false;
                                break;
                            }
                        }
                    }
                }
            }

            if ($result) CoraxLogger::success('Corax has been reset!');
            else CoraxLogger::error('Corax reset failed!');
        }

        CoraxLogger::info('Initializing working directories...');
        // Initialize container.
        $this->inputs = new CoraxList(
            $work_dir . 'inputs' . DIRECTORY_SEPARATOR,
            ['\Corax\Common\CoraxList', 'json_encode'],
            ['\Corax\Common\CoraxList', 'json_decode']
        );
        CoraxLogger::info('Inputs directory initialized with ' . $this->inputs->count() . ' inputs.', 1);
        $this->path = new CoraxList(
            $work_dir . 'path' . DIRECTORY_SEPARATOR,
            ['\Corax\Fuzz\CoraxPath', 'serialize'],
            ['\Corax\Fuzz\CoraxPath', 'unserialize']
        );
        CoraxLogger::info('Paths directory initialized with ' . $this->path->count() . ' paths.', 1);
        $this->hits = new CoraxList(
            $work_dir . 'hits' . DIRECTORY_SEPARATOR,
            ['\Corax\Fuzz\CoraxHit', 'serialize'],
            ['\Corax\Fuzz\CoraxHit', 'unserialize']
        );
        CoraxLogger::info('Hits directory initialized with ' . $this->hits->count() . ' hits.', 1);
        $this->vuln_hits = new CoraxList(
            $work_dir . 'vuln_hits' . DIRECTORY_SEPARATOR,
            ['\Corax\Fuzz\CoraxHit', 'serialize'],
            ['\Corax\Fuzz\CoraxHit', 'unserialize']
        );
        CoraxLogger::info('Vulnerability hits directory initialized with ' . $this->vuln_hits->count() . ' hits.', 1);
        $this->vulns = new CoraxList(
            $work_dir . 'vulns' . DIRECTORY_SEPARATOR,
            ['\Corax\Fuzz\CoraxVuln', 'serialize'],
            ['\Corax\Fuzz\CoraxVuln', 'unserialize']

        );
        CoraxLogger::info('Vulnerabilities directory initialized with ' . $this->vulns->count() . ' vulnerabilities.', 1);
        $this->corpus = new CoraxList($work_dir . 'corpus' . DIRECTORY_SEPARATOR);
        CoraxLogger::info('Corpora directory initialized with ' . $this->corpus->count() . ' corpora.', 1);

        // Start Corax server.
        CoraxLogger::info('Starting Corax server...');
        $count = 10;
        while (--$count) {
            $ret = $this->common_http_client->post($this->nest . "$key.php", [$key => 'run']);
            if ($ret['code'] === 200) {
                if ($ret['content'] === 'ok') break;
                else CoraxLogger::warn('Start Corax server failed! Server returned "' .
                    $ret['content'] . "\". Retrying($count)...");
            } else CoraxLogger::warn('Start Corax server failed! Server returned status code ' .
                $ret['code'] . " not 200. Retrying($count)...");
            sleep(1);
        }

        if ($count) {
            $this->server_running = true;
            CoraxLogger::success("Corax server $key has been started.", 1);
        } else CoraxLogger::error('Start Corax server failed! All retries failed!');
    }

    /**
     * The main fuzzing entrypoint.
     * 
     * @param bool $dry_run Enable only dry run local inputs but not fuzz. Defaults to false.
     * @param string|null $corpus_path The directory contains corpus file path. Defaults to null.
     */
    public function fuzz($dry_run = false, $corpus_path = null)
    {
        // Load user provided corpus.
        if ($corpus_path) {
            if (
                file_exists($corpus_path) && is_dir($corpus_path) &&
                $corpus = CoraxUtils::scandir($corpus_path, true)
            ) {
                CoraxLogger::info("Loading user provided corpus from \"$corpus\"...");
                foreach ($corpus as $f) {
                    if ($content = file_get_contents($f) !== false) {
                        if ($content) {
                            $filename = md5($content);
                            $this->corpus->put($filename, $content, substr($filename, 0, 2));
                            CoraxLogger::debug(
                                "Corpus \"$filename\" with length " . strlen($content) . " loaded from file \"$f\".",
                                1
                            );
                        } else CoraxLogger::debug("Empty corpus from file \"$f\", simply dropped.", 1);
                    } else CoraxLogger::warn("Could not load corpus from file \"$f\".");
                }
            } else CoraxLogger::warn(
                "Failed to scan corpus from directory \"$corpus\", directory does not exist or permission denied."
            );
        }
        CoraxStatistic::$corpus_name = $this->corpus->list();

        $this->ready();
        $this->dry_run_inputs();
        if (!$dry_run) $this->fuzz_loop();
    }

    /**
     * The main tainting entrypoint.
     * 
     * @param mixed $dry_run Dry run local hits but not start taint. Defaults to false.
     */
    public function taint($dry_run = false)
    {
        if ($this->hunter === null) {
            CoraxLogger::warn('Not Corax hunter assigned, using default hunter.');
            $this->hunter = new CoraxHunter();
        }

        $this->ready();
        $this->dry_run_hits();
        if (!$dry_run) $this->taint_loop();
    }

    /**
     * Shutdown Corax. This should be called thronging "register_shutdown_function".
     */
    public function shutdown()
    {
        CoraxStatistic::stop(true);  // Shutdown statistic.
        CoraxLogger::start();  // Reenable logger in UI mode.
        CoraxLogger::info('Corax-' . $this->key . ' is shutting down...');
        if ($this->server_running) {
            CoraxLogger::info('Shutting down Corax server...', 1);
            $count = 10;
            while (--$count) {
                $ret = $this->common_http_client->post($this->nest . "$this->key.php", [$this->key => 'shutdown']);
                if ($ret['code'] === 200) {
                    if ($ret['content'] === 'ok') break;
                    else CoraxLogger::warn('Shutdown Corax server failed! Server returned "' .
                        $ret['content'] . "\". Retrying($count)...");
                } else CoraxLogger::warn('Shutdown Corax server failed! Server returned status code ' .
                    $ret['code'] . " not 200. Retrying($count)...");
                sleep(1);
            }
            if ($count) {
                $this->server_running = false;
                CoraxLogger::success('Corax-' . $this->key . ' server has been shuted down.', 2);
            } else CoraxLogger::warn('Shutting down Corax server failed! All retries failed!');
        }

        CoraxLogger::info('Shutting down HTTP clients...', 1);
        CoraxHTTPClient::shutdown();
        CoraxLogger::info('Shutting down Logger...', 1);
        CoraxLogger::info('Bye. Have a nice day.');
        CoraxLogger::shutdown();
    }
}
