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
 * @Filename: CoraxUtils.php
 * @Description: 
 *   Some common utils used in Corax.
 * ================================================================================
 */

namespace Corax\Common;


final class CoraxUtils
{
    /**
     * Recursively scan a directory to get files and directories path.
     * 
     * @param string $path Path to be scanned.
     * @param bool $file_only Only scan files but not empty directory. Defaults to false.
     * @return array Files and directories path.
     */
    public static function scandir($path, $file_only = false)
    {
        if (!file_exists($path)) return [];
        if ($path[-1] !== DIRECTORY_SEPARATOR) $path .= DIRECTORY_SEPARATOR;

        $files = scandir($path);
        if ($files === false) return [];
        else $files = array_filter($files, function ($f) {
            return $f !== '.' && $f !== '..';
        });

        $results = [];
        if ($files) {
            foreach ($files as $f) {
                $p = $path . $f;
                if (is_dir($p)) $results = array_merge($results, self::scandir($p . DIRECTORY_SEPARATOR, $file_only));
                else $results[] = $p;
            }
        } elseif (!$file_only) $results[] = $path;  // Empty directory.

        return $results;
    }

    /**
     * Create a file with a file mode, automatically create a non-existed directory.
     * If change mode failed, but the file will be still created.
     * 
     * @param string $filename Filename to create.
     * @param string $content File content.
     * @param int $permissions File permissions. Defaults to 0777.
     * @param int $flags Same as php builtin function `file_put_contents` flags.
     * @return bool If create file and change permissions successfully.
     */
    public static function file_put_contents($filename, $content, $permissions = 0777, $flags = 0)
    {
        if (!self::mkdir(dirname($filename))) return false;
        if (file_put_contents($filename, $content, $flags) !== false) {
            @chmod($filename, $permissions);
            return true;
        } else return false;
    }

    /**
     * Recursively make directory with right permissions.
     * 
     * @param string $dir The directory path.
     * @param int $permissions File permissions. Defaults to 0777.
     * @return bool If make directory and change permissions successfully.
     */
    public static function mkdir($dir, $permissions = 0777)
    {
        if (file_exists($dir)) return true;

        $d = dirname($dir);
        if (!file_exists($d)) {
            $dirs = [basename($d)];
            $d = dirname($d);
            while (!file_exists($d)) {
                $dirs[] = basename($d);
                $d = dirname($d);
            }

            for ($i = count($dirs) - 1; $i >= 0; $i--) {
                $d .= DIRECTORY_SEPARATOR . $dirs[$i];
                // The mkdir permission is not committed, call chmod on more time.
                if (!(mkdir($d) && chmod($d, $permissions))) return false;
            }
        }

        return @mkdir($dir) && chmod($dir, $permissions);
    }

    /**
     * Delete a file or directory, no matter if it is empty.
     * 
     * @param string $path Path to be deleted.
     * @param bool $empty Only clean the directory but not delete it. Defaults to false.
     * @return bool If delete successfully.
     */
    public static function delete_path($path, $empty = false)
    {
        if (!file_exists($path)) return true;
        if (!is_dir($path)) return @unlink($path);

        $dir = realpath($path) . DIRECTORY_SEPARATOR;
        $d = opendir($dir);
        if ($d === false) return false;

        $result = true;
        while ($f = readdir($d)) {
            if ($f === '.' || $f === '..') continue;
            $p = $dir . $f;
            if (is_dir($p)) $result = self::delete_path($p) && $result;
            else $result = @unlink($p) && $result;
        }
        closedir($d);

        if (!$empty) $result = @rmdir($dir) && $result;
        return $result;
    }

    /**
     * Transform a absolute path to relative path.
     * 
     * For example:
     *   From the path "/a/b/c/d/tmp.txt"
     *   To the path "/a"
     *   Result is "../../../../a"
     * 
     *   From the path "/a/b/c/d/tmp.txt"
     *   To the path "/x/y/z"
     *   Result is "../../../../x/y/z"
     * 
     * @param string $from Start path.
     * @param string $to End path.
     * @return string The relative path from start path to end path.
     */
    public static function a2r($from, $to)
    {
        $from = explode(DIRECTORY_SEPARATOR, trim($from, DIRECTORY_SEPARATOR));
        $to = explode(DIRECTORY_SEPARATOR, trim($to, DIRECTORY_SEPARATOR));

        $i = 0;
        $a = (count($from) <= count($to)) ? $to : $from;
        // Find the same prefix position.
        foreach (((count($from) > count($to)) ? $to : $from) as $k => $v) {
            if ($v === $a[$k]) $i++;
            else break;
        }

        // Replace same prefix to "../".
        array_splice($from, 0, $i);
        array_splice($to, 0, $i);

        return str_repeat('..' . DIRECTORY_SEPARATOR, max(count($from) - 1, 0)) . implode(DIRECTORY_SEPARATOR, $to);
    }

    /**
     * Highlight PHP code with html tags.
     * 
     * @param string $code The code to be highlighted.
     * @return string Highlighted code.
     */
    public static function highlight_code($code)
    {
        $code = trim($code);
        if (substr($code, 0, 6) === '<?php ')
            return highlight_string($code, true);

        // "<?php" is required.
        $code = highlight_string("<?php " . $code, true);
        $code = trim($code);
        $code = preg_replace("|^\\<code\\>\\<span style\\=\"color\\: #[a-fA-F0-9]{0,6}\"\\>|", "", $code, 1);
        $code = preg_replace("|\\</code\\>\$|", "", $code, 1);
        $code = trim($code);
        $code = preg_replace("|\\</span\\>\$|", "", $code, 1);
        $code = trim($code);
        $code = preg_replace(
            "|^(\\<span style\\=\"color\\: #[a-fA-F0-9]{0,6}\"\\>)(&lt;\\?php&nbsp;)(.*?)(\\</span\\>)|",
            "\$1\$3\$4",
            $code
        );

        return $code;
    }

    /**
     * Format seconds to days, hours, minutes and seconds.
     * 
     * @param int|float $seconds The seconds to change.
     * @return array Including days, hours, minutes and seconds with front-zero string format.
     */
    public static function seconds_to_time($seconds)
    {
        $m = intval($seconds / 60);
        $s = $seconds % 60;
        $h = intval($m / 60);
        $m = $m % 60;
        $d = intval($h / 24);
        $h = $h % 24;

        if ($d < 10) $d = "0$d";
        if ($h < 10) $h = "0$h";
        if ($m < 10) $m = "0$m";
        if ($s < 10) $s = "0$s";

        return [$d, $h, $m, $s];
    }

    /**
     * Read lines in a file to an array.
     * 
     * @param string $file The file to read.
     * @param int $start_line The start line to read.
     * @param int $end_line The end lien to read.
     * @return array|false Lines of the file, key is line no and value is the line. 
     *   False will be returned if read failed.
     */
    public static function get_lines($file, $start_line, $end_line)
    {
        if (!file_exists($file)) return false;
        $lines = [];
        $i = 1;
        if ($fp = fopen($file, 'r')) {
            while (!@feof($fp)) {
                if ($i < $start_line) fgets($fp);
                elseif ($i > $end_line) break;
                else $lines[$i] = fgets($fp);
                $i++;
            }
            fclose($fp);
        }
        return $lines;
    }

    /**
     * Read source code from file between start line and end line and format it.
     * For example:
     * /* 1 * / xxxxx;
     * /* 2 * / yyyy;
     * /* 3 * / zzzz;
     * 
     * @param string $file The file to read.
     * @param int $start_line The start line to read.
     * @param int $end_line The end lien to read.
     * @return string The formatted source code. If read failed, "// No source code found!" will be returned.
     */
    public static function get_source_code($file, $start_line, $end_line)
    {
        if (($lines = self::get_lines($file, $start_line, $end_line)) === false)
            return '// No source code found!';
        $source_code = '';
        foreach ($lines as $no => $line) $source_code .= "/* $no */ $line";
        if (isset($source_code[0])) $source_code[-1] = ' ';
        return $source_code;
    }
}
