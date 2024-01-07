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
 * @Filename: CoraxStatistic.php
 * @Description: 
 *   Recording Corax running statistics.
 * ================================================================================
 */

namespace Corax\Common;

use Corax\CoraxMain;
use Corax\Fuzz\CoraxHit;


class CoraxStatistic
{
    public static $enable_report = false;
    public static $enable_ui = true;
    public static $enable_dump_statistics = false;
    public static $dump_statistics_file = null;

    // Corax runtime statistics.
    public static $start_time = 0;
    public static $shutdown_time = PHP_INT_MAX;
    public static $cycles = 0;
    public static $cycle_time = 0;
    public static $cycle_total = 0;
    public static $cycle_count = 0;
    public static $processed_count = 0;

    // Fuzzing runtime statistics.
    public static $current_fuzzing_input_file = 'N/A';
    public static $current_fuzzing_parser = 'N/A';
    public static $current_fuzzing_mutator = 'N/A';
    public static $current_fuzzing_target = 'N/A';
    public static $current_fuzzing_value_len = 0;

    // Tainting runtime statistics.
    public static $current_tainting_hit_file = 'N/A';
    public static $current_tainting_hit_target = 'N/A';
    public static $current_tainting_hunter = 'N/A';
    public static $current_tainting_vuln = 'N/A';
    public static $current_tainting_value_len = 0;

    // Input statistics.
    public static $total_input_fuzzed = 0;
    public static $last_sync_input_count = 0;
    public static $last_sync_input_hash = null;

    // Corpus statistics.
    public static $corpus_name = [];
    public static $last_sync_corpus_count = 0;
    public static $last_sync_corpus_hash = null;

    // Path statistics.
    public static $last_path_time = 0;
    public static $coverage_edges = 0;
    public static $coverage_blocks = -1;
    public static $visited_blocks = [];
    public static $total_blocks = 0;

    // Hit statistics.
    public static $last_hit_time = 0;
    public static $total_hit_tainted = 0;

    // Vulnerability statistics.
    public static $processed_payload_count = 0;
    public static $last_vuln_time = 0;

    // Network statistics.
    public static $sent_bytes = 0;
    public static $recv_bytes = 0;
    public static $req_count = 0;
    public static $bad_req_count = 0;
    public static $trans_time = 0;
    public static $trans_count = 0;
    public static $bad_trans_count = 0;
    public static $server_running_cpu = 0;

    // Report statistics.
    private static $start_cpu_time = 0;
    private static $last_report_time = 0;
    private static $ui_fuzz_report_template = '';
    private static $cli_fuzz_report_template = '';
    private static $report_caches = null;
    private static $next_dump_time = 0;
    private static $dump_statistics_interval = -1;

    /**
     * Initialize corax statistic.
     * 
     * @param bool $enable_ui Enable UI report mode. Defaults to true.
     * @param bool $dump_statistics_interval Time interval for dumping statistics. Defaults to -1.
     * @param int $shutdown_time Corax will be shutdown after the seconds. Given null will disable this. Default sto null.
     */
    public static function init($enable_ui = true, $dump_statistics_interval = -1, $shutdown_time = null)
    {
        $now = microtime(true);
        self::$last_report_time =
            self::$next_dump_time =
            self::$cycle_time =
            self::$start_time =
            self::$last_path_time =
            self::$last_hit_time =
            self::$last_vuln_time = $now;

        if ($shutdown_time !== null) self::$shutdown_time = $shutdown_time;

        $ru = getrusage();
        self::$start_cpu_time = ($ru['ru_utime.tv_sec'] + $ru['ru_utime.tv_usec'] / 1e6 +
            $ru['ru_stime.tv_sec'] + $ru['ru_stime.tv_usec'] / 1e6);

        self::$cycles =
            self::$cycle_count =
            self::$cycle_total =
            self::$total_input_fuzzed =
            self::$total_hit_tainted =
            self::$sent_bytes =
            self::$recv_bytes =
            self::$req_count =
            self::$bad_req_count =
            self::$trans_time =
            self::$trans_count =
            self::$bad_trans_count =
            self::$server_running_cpu =
            self::$coverage_edges = 0;
        self::$coverage_blocks = -1;

        self::$enable_ui = $enable_ui;
        if (self::$enable_dump_statistics = ($dump_statistics_interval > -1))
            self::$dump_statistics_interval = $dump_statistics_interval;

        // Enable UI report mode.
        if ($enable_ui) {
            if (!defined('CORAX_ENABLE_UI')) {
                define('CORAX_ENABLE_UI', true);
                // Similar with AFL UI tech.
                define('CORAX_UI_START_G1', "\x1b)0");
                define('CORAX_UI_END_G1', "\x1b)0");
                define('CORAX_UI_ENTER_G1', "\x0e");
                define('CORAX_UI_QUIT_G1', "\x0f");
                // xx
                // --
                // xx
                define('CORAX_UI_HOR', "q");
                // xx | xx
                // xx | xx
                define('CORAX_UI_VERT', "x");
                // +---
                // | xx
                define('CORAX_UI_LTCOR', "l");
                // ---+
                // xx |
                define('CORAX_UI_RTCOR', "k");
                // | xx
                // +---
                define('CORAX_UI_LBCOR', "m");
                // xx |
                // ---+
                define('CORAX_UI_RBCOR', "j");
                // xx | xx
                // ---+---
                // xx | xx
                define('CORAX_UI_CROS', "n");
                // | xx
                // |---
                // | xx
                define('CORAX_UI_VERTR', "t");
                // xx |
                // ---|
                // xx |
                define('CORAX_UI_VERTL', "u");
                // xx | xx
                // -------
                define('CORAX_UI_HORT', "v");
                // -------
                // xx | xx
                define('CORAX_UI_HORB', "w");

                define('CORAX_UI_LOE', CORAX_UI_ENTER_G1 . CORAX_UI_VERT . "\n  ");
                define('CORAX_UI_EOL', "\n  " . CORAX_UI_VERT . CORAX_UI_QUIT_G1);
                define('CORAX_UI_VRT_EOL', CORAX_UI_ENTER_G1 . CORAX_UI_VERT . CORAX_UI_EOL);
                define('CORAX_UI_SPLIT', CORAX_UI_ENTER_G1 . CORAX_UI_VERT . CORAX_UI_QUIT_G1);
            }

            $title = '<[ Corax ' . CoraxMain::$version . ' ]>';
            $tmp = 73 - strlen($title);
            $left = $tmp >> 1;
            self::$ui_fuzz_report_template = "\x1b[H\x1b[?25l\n  " .  CORAX_UI_ENTER_G1 . CORAX_UI_LTCOR .
                // Title.
                str_repeat(CORAX_UI_HOR, $left) . CORAX_UI_QUIT_G1 . $title . CORAX_UI_ENTER_G1 .
                str_repeat(CORAX_UI_HOR, $tmp - $left) . CORAX_UI_RTCOR . CORAX_UI_EOL .
                // Main panel.
                '              Date: %-53s' . CORAX_UI_VRT_EOL .
                sprintf(
                    '        Start Time: %-53s',
                    date('m/d/Y H:i:s', self::$start_time)
                ) . CORAX_UI_VRT_EOL .
                ($shutdown_time !== null ? (sprintf(
                    '     Shutdown Time: %-53s',
                    date('m/d/Y H:i:s', $now + self::$shutdown_time)
                ) . CORAX_UI_VRT_EOL) : '') .
                '      Running Time: %-53s' . CORAX_UI_VRT_EOL .
                '      Running Mode: %-53s' . CORAX_UI_VRT_EOL .
                '       Fuzzing Key: %-53s' . CORAX_UI_VRT_EOL .
                '        Remote URL: %-53s' . CORAX_UI_VRT_EOL .
                '%s  Source Directory: %-53s' . CORAX_UI_VRT_EOL .
                ' Working Directory: %-53s' . CORAX_UI_LOE . CORAX_UI_VERTR . CORAX_UI_QUIT_G1 .
                ' Runtime ' . CORAX_UI_ENTER_G1 . str_repeat(CORAX_UI_HOR, 43) . CORAX_UI_HORB . CORAX_UI_QUIT_G1 .
                ' Local Data ' . CORAX_UI_ENTER_G1 . str_repeat(CORAX_UI_HOR, 8) . CORAX_UI_VERTL . CORAX_UI_EOL .
                // Runtime panel.
                '     Cycles Done: %-34s' . CORAX_UI_SPLIT . ' Corpus: %-11s' . CORAX_UI_VRT_EOL .
                '      Cycle Time: %-34s' . CORAX_UI_SPLIT . ' Inputs: %-11s' . CORAX_UI_VRT_EOL .
                ' Last Path Found: %-34s' . CORAX_UI_SPLIT . '  Paths: %-11s' . CORAX_UI_VRT_EOL .
                '  Last Hit Found: %-34s' . CORAX_UI_SPLIT . '   Hits: %-11s' . CORAX_UI_VRT_EOL .
                ' Last Vuln Found: %-34s' . CORAX_UI_SPLIT . ' V-Hits: %-11s' . CORAX_UI_VRT_EOL .
                '   Process Count: %-34s' . CORAX_UI_SPLIT . '  Vulns: %-11s' . CORAX_UI_LOE . CORAX_UI_VERTR . CORAX_UI_QUIT_G1 .
                // Fuzzing panel.
                ' Fuzzing ' . CORAX_UI_ENTER_G1 . str_repeat(CORAX_UI_HOR, 43) . CORAX_UI_HORT .
                str_repeat(CORAX_UI_HOR, 20) . CORAX_UI_VERTL . CORAX_UI_EOL .
                '    Total Fuzzed: %-55s' . CORAX_UI_VRT_EOL .
                ' Total Coverages: %-55s' . CORAX_UI_VRT_EOL .
                '     Target File: %-55s' . CORAX_UI_VRT_EOL .
                '   Focused Field: %-55s' . CORAX_UI_VRT_EOL .
                ' Current Mutator: %-55s' . CORAX_UI_LOE . CORAX_UI_VERTR . CORAX_UI_QUIT_G1 .
                // Tainting panel.
                ' Tainting ' . CORAX_UI_ENTER_G1 . str_repeat(CORAX_UI_HOR, 63) . CORAX_UI_VERTL . CORAX_UI_EOL .
                '   Total Tainted: %-55s' . CORAX_UI_VRT_EOL .
                '   Payloads Sent: %-55s' . CORAX_UI_VRT_EOL .
                '     Target File: %-55s' . CORAX_UI_VRT_EOL .
                ' Target Function: %-55s' . CORAX_UI_VRT_EOL .
                '      Hunting by: %-55s' . CORAX_UI_VRT_EOL .
                '    Testing Vuln: %-55s' . CORAX_UI_LOE . CORAX_UI_VERTR . CORAX_UI_QUIT_G1 .
                ' Network ' . CORAX_UI_ENTER_G1 . str_repeat(CORAX_UI_HOR, 38) . CORAX_UI_HORB . CORAX_UI_QUIT_G1 .
                ' System ' . CORAX_UI_ENTER_G1 . str_repeat(CORAX_UI_HOR, 17) . CORAX_UI_VERTL . CORAX_UI_EOL .
                // Network panel.
                ' Total Requests: %-30s' . CORAX_UI_SPLIT . '  Corax PID: %-12s' . CORAX_UI_VRT_EOL .
                ' Corax Requests: %-30s' . CORAX_UI_SPLIT . ' Server CPU: %-12s' . CORAX_UI_VRT_EOL .
                '   Bad Requests: %-30s' . CORAX_UI_SPLIT . '  Local CPU: %-12s' . CORAX_UI_VRT_EOL .
                ' Website Health: %-30s' . CORAX_UI_SPLIT . '  Local Mem: %-12s' . CORAX_UI_VRT_EOL .
                '      Data Sent: %-30s' .  CORAX_UI_ENTER_G1 . CORAX_UI_LBCOR . str_repeat(CORAX_UI_HOR, 25) .
                CORAX_UI_VERTL . CORAX_UI_EOL .
                '  Data Received: %-56s' . CORAX_UI_VRT_EOL .
                '    Async Count: %-56s' . CORAX_UI_VRT_EOL .
                '   Average Time: %-56s' .
                CORAX_UI_LOE . CORAX_UI_LBCOR . str_repeat(CORAX_UI_HOR, 73) . CORAX_UI_RBCOR .
                CORAX_UI_QUIT_G1 . CORAX_UI_END_G1 . "\x1b[?25h\n\n";
        } else self::$cli_fuzz_report_template = implode("\n", [
            // Title.
            '+' . str_repeat('-', 20) . '=<[ Corax ' . CoraxMain::$version . ' Report %s ]>=' . str_repeat('-', 20) . "+",
            // Main report.
            '|- Corax(%s): running in %d days, %d hrs, %d mins, %d secs',
            '|    starts at ' . date('m/d/Y H:i:s', self::$start_time) . '.',
            '|    with key "%s" to "%s".',
            '|    from src "%s".',
            '|    working at "%s".',
            // Runtime report.
            '|- Runtime: cycle %d in %d days, %d hrs, %d mins, %d secs',
            '|    coverage %s edges (%s edges/s), %s/%s (%s%%) blocks (%s blocks/s)',
            '|    %d inputs processed of %d total inputs in this cycle (%s%%).',
            '|    %s corpus, %s inputs, %s paths, %s hits, %s vuln-hits, %s vulns.',
            '|    last path found in %d days, %d hrs, %d mins, %d secs.',
            '|    last hit found in %d days, %d hrs, %d mins, %d secs.',
            '|    last vulnerability found in %d days, %d hrs, %d mins, %d secs.',
            '|    totally %s processed (%s counts/s).',
            // Fuzzing report.
            '|- Fuzzing: %s',
            '|    parsed by %s, mutated by %s.',
            '|    trying %s (%d bytes).',
            '|    totally %s fuzzed (%s inputs/s).',
            // Tainting report.
            '|- Tainting: %s',
            '|    hunting "%s" by %s.',
            '|    trying "%s" (%d bytes).',
            '|    totally %s tainted (%s hits/s), %s payloads sent (%s payloads/s).',
            // Network report.
            '|- Network: totally %s requests (%s req/s)%s',
            '|    %s corax requests (%s req/s), %s bad requests (%s req/s).',
            '|    %s%% request health, %s%% server health%s.',
            '|    Data sent %s MB (%s mb/s), received %s MB (%s mb/s).',
            '|    %d fuzzing async count, %d tainting async count.',
            '|    %d sync input async count, %d sync corpus async count.',
            '|    %s s/req request time, %s s/req corax requests time.',
            // System report.
            '|- System: server cpu %s%%/req, cpu %s%%, mem %s MB, pid(%d).',
            '+' . str_repeat('-', 90) . "+"
        ]);
    }

    /**
     * Start recording statistics.
     */
    public static function start()
    {
        self::$enable_report = true;
    }

    /**
     * Stop recording statistics.
     * 
     * @param bool $shutdown Enable totally shutdown CoraxStatistic, including stop dump statistic data 
     *   to file. Defaults to false.
     */
    public static function stop($shutdown = false)
    {
        self::$enable_report = false;
        if ($shutdown) {
            self::$enable_dump_statistics = false;
            if (self::$dump_statistics_file) @fclose(self::$dump_statistics_file);
        }
    }

    /**
     * Report Corax status to terminal.
     * 
     * @param \Corax\Fuzz\CoraxFuzzer $fuzzer The Corax fuzzer.
     */
    public static function corax_fuzz_report($fuzzer)
    {
        $now = microtime(true);
        if ($now - self::$last_report_time < (self::$enable_ui ? 0.3 : 10)) return;
        self::$last_report_time = $now;
        $running_time = $now - self::$start_time;

        // Data statistics.
        $corpus_count = $fuzzer->corpus->count();
        $input_count = $fuzzer->inputs->count();
        $path_count = $fuzzer->path->count();
        $hit_count = $fuzzer->hits->count();
        $vuln_hit_count = $fuzzer->vuln_hits->count();
        $vuln_count = $fuzzer->vulns->count();

        $coverage_blocks = self::$coverage_blocks === -1 ? 0 : self::$coverage_blocks;

        // Network statistics.
        $request_health = round(100 - (self::$req_count === 0 ? 0 : (100 * self::$bad_req_count /
            (self::$bad_req_count + self::$req_count))), 3);
        $server_health = round(100 - (self::$trans_count === 0 ? 0 : (100 * self::$bad_trans_count /
            (self::$bad_trans_count + self::$trans_count))), 3);
        $http_fuzz_async_count = $fuzzer->fuzz_http_client->get_max_async_count();
        $http_taint_async_count = $fuzzer->taint_http_client->get_max_async_count();
        $http_sync_input_async_count = $fuzzer->sync_input_http_client->get_max_async_count();
        $http_sync_corpus_async_count = $fuzzer->sync_corpus_http_client->get_max_async_count();

        // System statistics.
        $ru = getrusage();
        $server_cpu = self::$trans_count === 0 ? 0 : round(self::$server_running_cpu / self::$trans_count, 3);
        $local_cpu = (100 * round(
            (($ru['ru_utime.tv_sec'] + $ru['ru_utime.tv_usec'] / 1e6 +
                $ru['ru_stime.tv_sec'] + $ru['ru_stime.tv_usec'] / 1e6) -
                self::$start_cpu_time) / $running_time,
            3
        ));
        $local_mem = round(memory_get_usage() / 0x100000, 3);

        if (self::$enable_report) {
            // Report caches.
            if (empty(self::$report_caches)) {
                if (CoraxMain::$config['fuzz'] && CoraxMain::$config['taint']) $mode = 'fuzzing/tainting';
                elseif (CoraxMain::$config['fuzz']) $mode = 'fuzzing';
                elseif (CoraxMain::$config['taint']) $mode = 'tainting';
                else $mode = 'N/A';
                $url = $fuzzer->get_url();
                if (strlen($url) > 51) $src_dir = substr($url, 0, 50) . '...';
                $src_dir = $fuzzer->get_src_dir() ?: 'N/A';
                if (strlen($src_dir) > 51) $src_dir = substr($src_dir, 0, 50) . '...';
                $work_dir = $fuzzer->get_work_dir();
                if (strlen($work_dir) > 51) $work_dir = substr($work_dir, 0, 50) . '...';
                self::$report_caches = [
                    $fuzzer->get_key(), $mode, $url, CoraxHTTPClient::$proxy,
                    $src_dir, $work_dir, getmypid()
                ];
            }
            list($fuzzing_key, $mode, $fuzzing_url, $fuzzing_proxy, $src_dir, $work_dir, $pid) = self::$report_caches;
            list($days, $hours, $minutes, $seconds) = CoraxUtils::seconds_to_time($running_time);
            list($cy_days, $cy_hours, $cy_minutes, $cy_seconds) = CoraxUtils::seconds_to_time($now - self::$cycle_time);
            list($ph_days, $ph_hours, $ph_minutes, $ph_seconds) = CoraxUtils::seconds_to_time($now - self::$last_path_time);
            list($ht_days, $ht_hours, $ht_minutes, $ht_seconds) = CoraxUtils::seconds_to_time($now - self::$last_hit_time);
            list($vl_days, $vl_hours, $vl_minutes, $vl_seconds) = CoraxUtils::seconds_to_time($now - self::$last_vuln_time);

            // UI report.
            if (self::$enable_ui) {
                $fuzzing_target = self::$current_fuzzing_parser . ': ' . self::$current_fuzzing_target;
                echo sprintf(
                    self::$ui_fuzz_report_template,
                    // Main panel.
                    date('m/d/Y H:i:s', $now),
                    "$days d, $hours h, $minutes m, $seconds s",
                    $mode,
                    $fuzzing_key,
                    $fuzzing_url,
                    ($fuzzing_proxy ? (sprintf('             Proxy: %-53s', $fuzzing_proxy) . CORAX_UI_VRT_EOL) : ''),
                    $src_dir,
                    $work_dir,
                    // Runtime panel.
                    self::$cycles . ' (' . self::$cycle_count .  '/' . self::$cycle_total . ', ' .
                        (self::$cycle_total === 0 ? 0 : round(self::$cycle_count * 100 / self::$cycle_total, 3)) . '%)',
                    self::num_unit_trans($corpus_count),
                    "$cy_days d, $cy_hours h, $cy_minutes m, $cy_seconds s",
                    self::num_unit_trans($input_count),
                    "$ph_days d, $ph_hours h, $ph_minutes m, $ph_seconds s",
                    self::num_unit_trans($path_count),
                    "$ht_days d, $ht_hours h, $ht_minutes m, $ht_seconds s",
                    self::num_unit_trans($hit_count),
                    "$vl_days d, $vl_hours h, $vl_minutes m, $vl_seconds s",
                    self::num_unit_trans($vuln_hit_count),
                    self::num_unit_trans(self::$processed_count) .
                        ' (' . round(self::$processed_count / $running_time, 3) . ' counts/s)',
                    self::num_unit_trans($vuln_count),
                    // Fuzzing panel.
                    self::num_unit_trans(self::$total_input_fuzzed) .
                        ' (' . round(self::$total_input_fuzzed / $running_time, 3) . ' inputs/s)',
                    self::num_unit_trans(self::$coverage_edges) . ' edges, ' .
                        self::num_unit_trans($coverage_blocks) .
                        '/' . self::num_unit_trans(self::$total_blocks) .
                        ' blocks (' . round(100 * $coverage_blocks / self::$total_blocks, 3) . '%)',
                    strlen(self::$current_fuzzing_input_file) > 51 ?
                        substr(self::$current_fuzzing_input_file, 0, 51) . '...' : self::$current_fuzzing_input_file,
                    (strlen($fuzzing_target) > 51 ? substr($fuzzing_target, 0, 51) . '...' : $fuzzing_target),
                    self::$current_fuzzing_mutator . ' (' . self::$current_fuzzing_value_len . ' bytes)',
                    // Tainting panel.
                    self::num_unit_trans(self::$total_hit_tainted) .
                        ' (' . round(self::$total_hit_tainted / $running_time, 3) . ' hits/s)',
                    self::num_unit_trans(self::$processed_payload_count) .
                        ' (' . round(self::$processed_payload_count / $running_time, 3) . ' payloads/s)',
                    strlen(self::$current_tainting_hit_file) > 51 ?
                        substr(self::$current_tainting_hit_file, 0, 51) . '...' : self::$current_tainting_hit_file,
                    self::$current_tainting_hit_target,
                    self::$current_tainting_hunter . ' (' . self::$current_tainting_value_len . ' bytes)',
                    self::$current_tainting_vuln,
                    // Network panel.
                    self::num_unit_trans(self::$req_count) .
                        ' (' . round(self::$req_count / $running_time, 3) . ' req/s)',
                    $pid,
                    self::num_unit_trans(self::$trans_count) .
                        ' (' . (self::$trans_time === 0 ?: round(self::$trans_count / self::$trans_time, 3)) . ' req/s)',
                    $server_cpu . '%/req',
                    self::num_unit_trans(self::$bad_trans_count) .
                        ' (' . round(self::$bad_trans_count / $running_time, 3) . ' req/s)',
                    $local_cpu . '%',
                    ("$server_health%/$request_health%") .
                        (($request_health < 80 || $server_health < 20) ? ' (Broken Website?)' : ''),
                    $local_mem . ' MB',
                    round(self::$sent_bytes / 0x100000, 3) . ' MB' .
                        ' (' . round(self::$sent_bytes / 0x100000 / $running_time, 3) . ' mb/s)',
                    round(self::$recv_bytes / 0x100000, 3) . ' MB' .
                        ' (' . round(self::$recv_bytes / 0x100000 / $running_time, 3) . ' mb/s)',
                    'f-' . $http_fuzz_async_count .
                        ($fuzzer->fuzz_http_client->stabilizing ? ' (Stabilizing...)' : '') .
                        ' / t-' . $http_taint_async_count .
                        ($fuzzer->taint_http_client->stabilizing ? ' (Stabilizing...)' : '') .
                        '/ i-' . $http_sync_input_async_count .
                        ' / c-' . $http_sync_corpus_async_count,
                    (self::$req_count === 0 ? 0 : round($running_time / self::$req_count, 3)) . ' s/req, ' .
                        (self::$trans_count === 0 ? 0 : round(self::$trans_time / self::$trans_count, 3)) . ' s/corax-req'
                );
            } else {
                // Terminal Reports
                CoraxLogger::info(sprintf(
                    self::$cli_fuzz_report_template,
                    // Title.
                    date('m/d/Y H:i:s', $now),
                    // Main report.
                    $mode,
                    $days,
                    $hours,
                    $minutes,
                    $seconds,
                    $fuzzing_key,
                    $fuzzing_url,
                    $src_dir,
                    $work_dir,
                    // Runtime report.
                    self::$cycles,
                    $cy_days,
                    $cy_hours,
                    $cy_minutes,
                    $cy_seconds,
                    self::num_unit_trans(self::$coverage_edges),
                    round(self::$coverage_edges / $running_time, 3),
                    self::num_unit_trans($coverage_blocks),
                    self::num_unit_trans(self::$total_blocks),
                    round($coverage_blocks / self::$total_blocks, 3),
                    round($coverage_blocks / $running_time, 3),
                    self::$cycle_count,
                    self::$cycle_total,
                    self::$cycle_total === 0 ? 0 : round(self::$cycle_count * 100 / self::$cycle_total, 3),
                    self::num_unit_trans($corpus_count),
                    self::num_unit_trans($input_count),
                    self::num_unit_trans($path_count),
                    self::num_unit_trans($hit_count),
                    self::num_unit_trans($vuln_hit_count),
                    self::num_unit_trans($vuln_count),
                    $ph_days,
                    $ph_hours,
                    $ph_minutes,
                    $ph_seconds,
                    $ht_days,
                    $ht_hours,
                    $ht_minutes,
                    $ht_seconds,
                    $vl_days,
                    $vl_hours,
                    $vl_minutes,
                    $vl_seconds,
                    self::num_unit_trans(self::$processed_count),
                    round(self::$processed_count / $running_time, 3),
                    // Fuzzing report.
                    self::$current_fuzzing_input_file,
                    self::$current_fuzzing_parser,
                    self::$current_fuzzing_mutator,
                    self::$current_fuzzing_target,
                    self::$current_fuzzing_value_len,
                    self::num_unit_trans(self::$total_input_fuzzed),
                    round(self::$total_input_fuzzed / $running_time, 3),
                    // Tainting report.
                    self::$current_tainting_hit_file,
                    self::$current_tainting_hit_target,
                    self::$current_tainting_hunter,
                    self::$current_tainting_vuln,
                    self::$current_tainting_value_len,
                    self::num_unit_trans(self::$total_hit_tainted),
                    round(self::$total_hit_tainted / $running_time, 3),
                    self::num_unit_trans(self::$processed_payload_count),
                    round(self::$processed_payload_count / $running_time, 3),
                    // Network report.
                    self::num_unit_trans(self::$req_count),
                    round(self::$req_count / $running_time, 3),
                    $fuzzing_proxy ? "\n|    proxy to \"$fuzzing_proxy\"." : '',
                    self::num_unit_trans(self::$trans_count),
                    self::$trans_time === 0 ? 0 : round(self::$trans_count / self::$trans_time, 3),
                    self::num_unit_trans(self::$bad_trans_count),
                    round(self::$bad_trans_count / $running_time, 3),
                    $server_health,
                    $request_health,
                    ($request_health < 80 || $server_health < 20) ? ' (Broken Website?)' : '',
                    round(self::$sent_bytes / 0x100000, 3),
                    round(self::$sent_bytes / 0x100000 / $running_time, 3),
                    round(self::$recv_bytes / 0x100000, 3),
                    round(self::$recv_bytes / 0x100000 / $running_time, 3),
                    $http_fuzz_async_count,
                    $http_taint_async_count,
                    $http_sync_input_async_count,
                    $http_sync_corpus_async_count,
                    self::$req_count === 0 ? 0 : round($running_time / self::$req_count, 3),
                    self::$trans_count === 0 ? 0 : round(self::$trans_time / self::$trans_count, 3),
                    // System report.
                    $server_cpu,
                    $local_cpu,
                    $local_mem,
                    $pid
                ));
            }
        }

        // Dump statics to file.
        if (self::$enable_dump_statistics && $now >= self::$next_dump_time) {
            self::$next_dump_time = $now + self::$dump_statistics_interval;
            fwrite(self::$dump_statistics_file, json_encode([
                // Runtime info.
                'time' => $now,
                'running_time' => $running_time,
                'cycle' => self::$cycles,
                'coverage_edges' => self::$coverage_edges,
                'coverage_blocks' => $coverage_blocks,
                'fuzzed' => self::$total_input_fuzzed,
                'tainted' => self::$total_hit_tainted,
                'payloads' => self::$processed_payload_count,
                'processed' => self::$processed_count,
                // Network info.
                'requests' => self::$req_count,
                'bad_requests' => self::$bad_req_count,
                'corax_requests_time' => self::$trans_time,
                'corax_requests' => self::$trans_count,
                'corax_bad_requests' => self::$bad_trans_count,
                'request_health' => $request_health,
                'server_health' => $server_health,
                'data_sent' => self::$sent_bytes,
                'data_received' => self::$recv_bytes,
                'http_fuzz_thread' => $http_fuzz_async_count,
                'http_taint_thread' => $http_taint_async_count,
                'http_sync_input_thread' => $http_sync_input_async_count,
                'http_sync_corpus_thread' => $http_sync_corpus_async_count,
                // System info.
                'server_cpu' => $server_cpu,
                'local_cpu' => $local_cpu,
                'local_mem' => $local_mem,
                // Data info.
                'corpus' => $corpus_count,
                'inputs' => $input_count,
                'paths' => $path_count,
                'hits' => $hit_count,
                'vuln_hits' => $vuln_hit_count,
                'vulns' => $vuln_count,
            ]) . PHP_EOL);
        }

        if ((self::$req_count > 100 && $request_health < 0) || (self::$trans_count > 100 && $server_health < 0)) {
            CoraxLogger::warn('Broken website detected! Rebuild website or restart web server to fix it!');
        }

        // Shutdown corax.
        if ($running_time >= self::$shutdown_time) {
            CoraxLogger::start();
            CoraxLogger::info('Corax has reach the end of its life cycle, it will be shutdown soon...');
            exit(0);
        }
    }

    public static function corax_instrument_report()
    {
        // TODO: Report instrumenting status at runtime.
    }

    /**
     * Generate markdown formation report for a vulnerability hit to a file.
     * 
     * @param string $report_name Report name.
     * @param \Corax\Fuzz\CoraxHit $hit The hit to report.
     * @param \Corax\Fuzz\CoraxFuzzer $fuzzer The Corax fuzzer instance.
     */
    public static function corax_markdown_report($report_name, $hit, $fuzzer)
    {
        $filename = $fuzzer->get_reports_dir() . $report_name . '.md';
        if (($fp = fopen($filename, 'w')) === false) {
            CoraxLogger::warn("Generate corax report file \"$filename\" failed!");
            return;
        }

        $path = $hit->get_path();
        $input = $path->get_input();
        $raw_input = $path->get_raw_input();
        $fuzz_key = $fuzzer->get_key();
        $hit_name = $hit->get_name();
        $source_code_dir = $fuzzer->get_src_dir();

        // Report title.
        fwrite($fp, sprintf(
            '# Corax Report for `%s`

> Report Time: `%s`
> Notice: This report may include dangers vulnerabilities of a web application, DO NOT publish it on Internet.
> Corax found these vulnerabilities only for warning to the web application owner or developer and fix these vulnerabilities.
> Please do not use this report to attack any other web application.

',
            $hit_name,
            date('Y-m-d H:i:s', time())
        ));

        //  Runtime report.
        $func_file = $hit->get_file();
        $func_name = $hit->get_func_name();
        $input_value_path = implode('` -> `', $input->get_value_path());
        $input_script_name = $raw_input['info']['script_name'];
        $input_url = $fuzzer->get_host() . $input_script_name;
        fwrite($fp, sprintf(
            '## Runtime

- Report name: `%s`
- Corax name: `Corax-%s`
- Corax version: `%s`
- Target remote url: `%s`
- Local working directory: `%s`
- Source code directory: `%s`
- Running time: `%s`
- Report for function `%s` in file `%s` with `%d` vulnerabilities of input `%s` to `%s`.

---

## Vulnerabilities

',
            $report_name,
            CoraxMain::$version,
            $fuzz_key,
            $fuzzer->get_url(),
            $fuzzer->get_work_dir(),
            $source_code_dir,
            implode(':', CoraxUtils::seconds_to_time(microtime(true) - self::$start_time)),
            $func_name,
            $func_file,
            $hit->count_vulns(),
            $input_value_path,
            $input_url
        ));

        // Vulnerabilities report.
        $i = 0;
        foreach ($hit->get_vulns() as $hunter => $vulns) {
            $msg = "- `$hunter` (`" . count($vulns) . "`)\n";  // Vulnerability title.
            $j = 0;
            foreach ($vulns as $type => $vuln_name) {
                $vuln = $fuzzer->vulns->load($vuln_name);
                if ($vuln === null) continue;
                $payload = $vuln->get_payload();
                $arg_value = $vuln->get_value();
                // $hit = $vuln->get_hit();  // TODO: Record hit info for this vuln.
                $msg .= sprintf(
                    '  - Vulnerability `%d-%d` named `%s` of type `%s` in argument `%d` with payload (`%s` bytes):

    ```php
    "%s"
    ```

    in value (`%d` bytes, decoded):

    ```php
    "%s"
    ```

',
                    $i,
                    $j++,
                    $vuln_name,
                    $type,
                    $vuln->get_arg_pos(),
                    strlen($payload),
                    str_replace("\n", "\n    ", addcslashes($payload, "\0..\10\\\"\13\14\16..\37`\177..\377")),
                    strlen($arg_value),
                    str_replace("\n", "\n    ", addcslashes($arg_value, "\0..\10\\\"\13\14\16..\37`\177..\377"))
                );
            }
            fwrite($fp, $msg);
            $i++;
        }

        // Hit report.
        $func_args = $hit->get_args();
        $func_args_count = count($func_args);
        $func_start_line = $hit->get_start_line();
        $func_end_line = $hit->get_end_line();
        $func_prev_block = $hit->get_prev_block();
        list($func_prev_file, $func_prev_pos, $func_prev_line) = $fuzzer->find_fileinfo($func_prev_block);
        $filtered_payloads = $hit->get_filtered();
        fwrite($fp, sprintf(
            '  - Filtered payloads (`%d`): `%s`

---

## Hit

- Name `%s` of feature `%s`.
- Function `%s` with `%d` arguments in file `%s` at position in `%d` - `%d` and line in `%d` - `%d`:

```php
// ...
%s
// ...
```

- Came **from** block `%d` in file `%s` at position `%d` on **line** `%d`:

```php
// ...
%s
// ...
```

- Arguments (`%d`):
',
            count($filtered_payloads),
            $filtered_payloads ? implode('`, `', $filtered_payloads) : ' ',
            $hit_name,
            $hit->get_feature(),
            $func_name,
            $func_args_count,
            $func_file,
            $hit->get_start_pos(),
            $hit->get_end_pos(),
            $func_start_line,
            $func_end_line,
            CoraxUtils::get_source_code($source_code_dir . $func_file, $func_start_line - 3, $func_end_line + 3),
            $func_prev_block,
            $func_prev_file,
            $func_prev_pos,
            $func_prev_line,
            CoraxUtils::get_source_code($source_code_dir . $func_file, $func_prev_line - 3, $func_prev_line + 3),
            $func_args_count
        ));

        // Hit arguments report.
        $i = 0;
        foreach ($func_args as $arg) fwrite($fp, sprintf(
            '  - Argument `%d` (PHP dumped value):

    ```php
    %s
    ```

',
            $i++,
            str_replace("\n", "\n    ", $arg)
        ));

        // Hit returns report.
        $func_callstack = $hit->get_callstack();
        fwrite($fp, sprintf(
            '- Returns (PHP dumped value):

```php
%s
```

- Call stacks (`%d`):
',
            $hit->get_ret(),
            count($func_callstack)
        ));

        // Hit callstack report.
        $i = 0;
        foreach ($func_callstack as $callstack) {
            $line = $callstack['line'];
            $file = $callstack['file'];
            fwrite($fp, sprintf(
                '  - Call stack `%d` of function `%s` in file `%s` on line near `%d` - `%d`:

    ```php
    %s
    ```
',
                $i++,
                $callstack['func'],
                $file,
                $line - 3,
                $line + 3,
                str_replace("\n",  "\n    ", CoraxUtils::get_source_code(
                    $source_code_dir . $file,
                    $line - 3,
                    $line + 3
                ))
            ));
        }

        // Input report.
        $input_get_keys = $raw_input['info']['get_keys'];
        fwrite($fp, sprintf(
            '
---

## Input

- Raw HTTP input `%s` of feature `%s`:
  - Request method `%s` to `%s` in file `%s`.
  - Request **GET** (`%d` parameters):
',
            $path->get_input_name(),
            $raw_input['info']['feature'],
            $raw_input['info']['request_method'],
            $input_url,
            $input_script_name,
            count($input_get_keys)
        ));

        // Input get report.
        foreach ($input_get_keys as $keys) {
            $value = array_pop($keys);
            fwrite($fp, sprintf(
                '    - Key of `%s` (`%d` bytes):

      ```php
      "%s"
      ```

',
                implode('` -> `', $keys),
                strlen($value),
                str_replace("\n", "\n      ", addcslashes($value, "\0..\10\\\"\13\14\16..\37`\177..\377"))
            ));
        }

        // Input post report.
        $input_post_keys = $raw_input['info']['post_keys'];
        fwrite($fp, '  - Request **POST** (`' . count($input_post_keys) . "` parameters):\n");
        foreach ($input_post_keys as $keys) {
            $value = array_pop($keys);
            fwrite($fp, sprintf(
                '    - Key of `%s` (`%d` bytes):

      ```php
      "%s"
      ```

',
                implode('` -> `', $keys),
                strlen($value),
                str_replace("\n", "\n      ", addcslashes($value, "\0..\10\\\"\13\14\16..\37`\177..\377"))
            ));
        }

        // Input path, raw post report.
        $input_path = $raw_input['data']['path'];
        $input_post_data = $raw_input['data']['raw_post'];
        $input_files = $raw_input['data']['files'];
        fwrite($fp, sprintf(
            '  - Request **PATH** (`%d` parameters): `%s`
  - Request **RAW POST** (`%d` bytes):

    ```php
    "%s"
    ```

  - Request **UPLOAD FILES** (`%d` files):
',
            count($input_path),
            implode('/', $input_path) ?: ' ',
            strlen($input_post_data),
            str_replace("\n", "\n    ", addcslashes($input_post_data, "\0..\10\\\"\13\14\16..\37`\177..\377")),
            count($input_files)
        ));

        // Input files report.
        foreach ($input_files as $name => $fileinfo) {
            $file_content = $fileinfo['content'];
            fwrite($fp, sprintf(
                '    - File `%s` of filename `%s` with content type `%s` (`%d` bytes):

      ```php
      "%s"
      ```

',
                $name,
                $fileinfo['filename'],
                $fileinfo['type'],
                strlen($file_content),
                str_replace("\n", "\n      ", addcslashes($file_content, "\0..\10\\\"\13\14\16..\37`\177..\377"))
            ));
        }

        // Input cookies report.
        $input_cookies = $raw_input['data']['cookies'];
        fwrite($fp, '  - Request **COOKIES** (`' . count($input_cookies) . "` parameters):\n");
        foreach ($input_cookies as $key => $value) fwrite($fp, sprintf(
            '    - Key of `%s` (`%d` bytes):

      ```php
      "%s"
      ```

',
            $key,
            strlen($value),
            str_replace("\n", "\n      ", addcslashes($value, "\0..\10\\\"\13\14\16..\37`\177..\377"))
        ));

        // Input headers report.
        $input_headers = $raw_input['data']['headers'];
        fwrite($fp, '  - Request **HEADERS** (`' . count($input_headers) . "` parameters):\n");
        foreach ($input_headers as $key => $value) fwrite($fp, sprintf(
            '    - Key of `%s` (`%d` bytes):

      ```php
      "%s"
      ```

',
            $key,
            strlen($value),
            str_replace("\n", "\n      ", addcslashes($value, "\0..\10\\\"\13\14\16..\37`\177..\377"))
        ));

        // Input server info report.
        $input_triggered_hits = $raw_input['info']['hits'];
        fwrite($fp, sprintf(
            '  - Request server info of **QUERY_STRING**: `%s`
  - Request server info of **PHP_SELF**: `%s`
  - Request server info of **SCRIPT_NAME**: `%s`
  - Request server info of **SCRIPT_FILENAME**: `%s`
  - Request server info of **WEB_ROOT**: `%s`
  - Request server info of **SITE_ROOT**: `%s`
  - Request server info of **REQUEST_URI**: `%s`
  - Request server info of **GATEWAY_INTERFACE**: `%s`
  - Request server info of **SERVER_PROTOCOL**: `%s`
  - Input traveled path: `%s`
  - Input coverage edges: `%s`
  - Input triggered hits (`%d`):
',
            $raw_input['info']['query_string'] ?: ' ',
            $raw_input['info']['php_self'],
            $raw_input['info']['script_name'],
            $raw_input['info']['script_filename'],
            $raw_input['info']['web_root'],
            $raw_input['info']['site_root'],
            $raw_input['info']['request_uri'],
            $raw_input['info']['gateway_interface'],
            $raw_input['info']['server_protocol'],
            $raw_input['info']['path_name'],
            $raw_input['info']['coverage_edges'],
            count($input_triggered_hits)
        ));

        // Input triggered hits report.
        foreach ($input_triggered_hits as $hit_name => $names)
            fwrite($fp, "    - Hit of `$hit_name` (`" . count($names) . '`): `' . implode('`, `', $names) . "`\n");

        // Input mutate history report.
        $raw_input_mutated_history =  $raw_input['info']['mutated'];
        fwrite($fp, '  - Mutated history (`' . count($raw_input_mutated_history) . "`)\n");
        foreach ($raw_input_mutated_history as $mutator => $value_path)
            fwrite($fp, "    - Mutated by `$mutator` for `" . implode('` -> `', $value_path) . "`\n");

        // Input value, response report.
        $input_original_value = $input->get_original_value();
        $input_original_value_decoded = $input->decode_value($input_original_value);
        $input_value = $input->get_value($raw_input, false);
        $input_value_decoded = $input->get_value($raw_input, true);
        $encoding = $input->get_encoding();
        $encoder = $decoder = 'null';
        if ($encoding) {
            $encoder = $input->get_encoder();
            $decoder = $input->get_decoder();
        } else $encoding = 'null';
        $input_mutated_history = $input->get_mutate_history();
        $response = $path->get_response();
        $response_headers = $response['headers'];
        fwrite($fp, sprintf(
            '- Input field `%s` of feature `%s` parsed by parser `%s`.
  - Field original value (`%d` bytes) of encoding `%s` with encoder `%s` and decoder `%s`:

    ```php
    "%s"
    ```

  - Field original **decoded*** value (`%d` bytes):

    ```php
    "%s"
    ```

  - Field current value (`%d` bytes):

    ```php
    "%s"
    ```

  - Field current **decoded** value (`%d` bytes):

    ```php
    "%s"
    ```

  - Mutated history (`%d`): `%s`
- Raw request:

  ```text
  %s
  ```

- Response of this request:
  - Responded time: `%.3f` s
  - Status code: `%d`
  - Response error: `%s`
  - Response headers (`%d` parameters):
',
            $input_value_path,
            $input->get_feature(),
            $input->get_type(),
            strlen($input_original_value),
            $encoding,
            $encoder,
            $decoder,
            str_replace("\n", "\n    ", addcslashes($input_original_value, "\0..\10\\\"\13\14\16..\37`\177..\377")),
            strlen($input_original_value_decoded),
            str_replace("\n", "\n    ", addcslashes($input_original_value_decoded, "\0..\10\\\"\13\14\16..\37`\177..\377")),
            strlen($input_value),
            str_replace("\n", "\n    ", addcslashes($input_value, "\0..\10\\\"\13\14\16..\37`\177..\377")),
            strlen($input_value_decoded),
            str_replace("\n", "\n    ", addcslashes($input_value_decoded, "\0..\10\\\"\13\14\16..\37`\177..\377")),
            count($input_mutated_history),
            implode('` -> `', $input_mutated_history),
            str_replace("\n", "\n  ", addcslashes(self::build_request_text($raw_input), "\0..\10\\\"\13\14\16..\37`\177..\377")),
            $response['time'],
            $response['code'],
            $response['error'] ?: 'No error',
            count($response_headers)
        ));

        // Input response headers report.
        foreach ($response_headers as $key => $value) fwrite($fp, sprintf(
            '    - Key of `%s` (`%d` bytes):

      ```php
      "%s"
      ```

',
            $key,
            strlen($value),
            str_replace("\n", "\n      ", addcslashes($value, "\0..\10\\\"\13\14\16..\37`\177..\377"))
        ));

        // Path report.
        $response_content = $response['content'];
        $raw_path = $path->get_raw_path(false, false);
        fwrite($fp, sprintf(
            '  - Response content (`%d` bytes):

    ```php
    "%s"
    ```

- Raw response:

  ```text
  %s
  ```

---

## Path

- Name `%s` of feature `%s` (`%d` edges):

```json
%s
```

- Path rode map:
',
            strlen($response_content),
            str_replace("\n", "\n    ", addcslashes($response_content, "\0..\10\\\"\13\14\16..\37`\177..\377")),
            str_replace("\n", "\n  ", addcslashes(
                self::build_response_text($response, $raw_input['info']['server_protocol']),
                "\0..\10\\\"\13\14\16..\37`\177..\377"
            )),
            $path->get_name(),
            $path->get_feature(),
            count($raw_path),
            json_encode($raw_path)
        ));

        foreach ($fuzzer->extract_path($raw_path, true) as
            list(
                $edge, $from_index, $from_file, $from_file_pos, $from_file_line,
                $to_index, $to_file, $to_file_pos, $to_file_line, $count
            )) fwrite($fp, sprintf(
            '  - Path `%d` **from** block `%d` in file `%s` at position `%d` on **line** `%d` **to** block `%d` in file `%s` at position `%d` on **line** `%d` (passed `%d` times):

    ```php
    // ...
    %s
    // ...
    ```

',
            $edge,
            $from_index,
            $from_file,
            $from_file_pos,
            $from_file_line,
            $to_index,
            $to_file,
            $to_file_pos,
            $to_file_line,
            $count,
            str_replace("\n",  "\n    ", CoraxUtils::get_source_code(
                $source_code_dir . $to_file,
                $to_file_line - 3,
                $to_file_line + 3
            ))
        ));

        // Appendix report.
        fwrite($fp, sprintf(
            '---

## Appendix

- Raw hit **encoded** json data:

> Including all of the above data, such as hit array, path array, http input array and input field data.
> You can manually extract and analysis all of the data from this json.

```json
%s
```

- This json data was **encoded**, decode by using:

```php
function decode_array($arr)
{
    $result = [];
    foreach ($arr as $key => $value) {
        if (is_array($value)) $value = decode_array($value);
        elseif (is_string($value)) $value = base64_decode($value);
        $result[$key] = $value;
    }
    return $result;
}

$hit = decode_array(json_decode("{...}", true));
```

---

> Generated by `Corax-%s`. Corax, made by `Srpopty`, 2022-%s All Rights Reserved.
',
            CoraxHit::serialize($hit),
            $fuzz_key,
            date('Y', time())
        ));

        fclose($fp);
    }

    /**
     * Build the raw http request text.
     * 
     * @param array &$raw_input The raw http input array.
     * @return string The built http request text.
     */
    private static function build_request_text(&$raw_input)
    {
        $headers = $raw_input['data']['headers'];
        $data = '';
        if (isset($headers['Content-Type'])) {
            if ($raw_input['data']['raw_post']) $data = $raw_input['data']['raw_post'];
            else {
                if ($raw_input['data']['files']) {
                    $boundary = '----CoraxHTTPFileUploadBoundary' . CoraxRandom::random_id();
                    $headers['Content-Type'] = 'multipart/form-data; boundary=' . $boundary;
                    if ($raw_input['data']['post']) {
                        foreach ($raw_input['data']['post'] as $name => $value) {
                            $data .= "--$boundary\n";
                            $data .= "Content-Disposition: form-data; name=\"$name\"\n\n$value\n";
                        }
                    }
                    foreach ($raw_input['data']['files'] as $name => $file) {
                        $data .= "--$boundary\n";
                        $data .= "Content-Disposition: form-data; name=\"$name\"; filename=\"" . $file['filename'] . "\"\n";
                        $data .= 'Content-Type: ' . $file['type'] . "\n\n" . $file['content'];
                    }
                    $data .= $boundary . '--';
                } elseif ($raw_input['data']['post']) $data = http_build_query($raw_input['data']['post']);
            }
            $headers['Content-Length'] = strlen($data);
        }

        $uri = $raw_input['info']['script_name'];
        if ($raw_input['data']['path']) $uri .= implode('/', $raw_input['data']['path']);
        if ($raw_input['data']['get']) $uri .= '?' . http_build_query($raw_input['data']['get']);
        $text = sprintf("%s %s %s\n", $raw_input['info']['request_method'], $uri, $raw_input['info']['server_protocol']);
        foreach ($headers as $key => $value) $text .= "$key: $value\n";

        return $text . "\n" . $data;
    }

    /**
     * Build the raw http response text.
     * 
     * @param array &$response The raw http response array.
     * @param string $http_version The HTTP version of response. Defaults to "HTTP/1.1".
     * @return string The built http response text.
     */
    private static function build_response_text(&$response, $http_version = 'HTTP/1.1')
    {
        $text = sprintf(
            "%s %d %s\n",
            $http_version,
            $response['code'],
            CoraxDictionary::$status_code_msg[$response['code']] ?? '(Unknown)'
        );
        foreach ($response['headers'] as $key => $value) $text .= "$key: $value\n";
        return $text . "\n" . $response['content'];;
    }

    /**
     * Transform number unit.
     * 
     * @param int $num The number to transform.
     * @return string|int The transformed number or string.
     */
    private static function num_unit_trans($num)
    {
        return ($num < 1000) ? $num : round($num / 1000, 3) . ' k';
    }
}
