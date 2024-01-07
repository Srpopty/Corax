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
 * @Filename: CoraxWorker.php
 * @Description: 
 *   Derive many Corax workers to process job. The basic of CoraxPlugin.
 * ================================================================================
 */

namespace Corax\Common;

use Corax\Common\CoraxLogger;


class CoraxWorker
{
    public $plugin = null;

    protected $prefix;
    protected $plugin_test;
    protected $workers;
    protected $disable;

    /**
     * Initialize a worker. It could load user custom plugin. The custom plugin template is:
     * <?php
     * namespace Corax;
     *  
     * 
     * class CoraxPlugin
     * {
     *      public function prefix_my_worker(...){
     *          ...
     *      }
     * }
     * 
     * @param string $prefix The worker function name prefix. All functions which start with the 
     *   prefix will be added to worker. Defaults to an empty string.
     * @param \Corax\CoraxPlugin|null $plugin User custom plugin. Defaults to null.
     * @param callable|null $plugin_test Test plugin worker functionally, accept one argument 
     *   which is the loaded worker function and return null or a string which is the test error message. 
     *   Defaults to null.
     * @param array $disable Manually disable some workers. Supports regex. Defaults to an empty array.
     */
    public function __construct($prefix = '', $plugin = null, $plugin_test = null, $disable = [])
    {
        $this->prefix = $prefix;
        $this->plugin_test = $plugin_test;
        $this->workers = [];
        $this->disable = $disable ? '/^' . implode('|', $disable) . '$/um' : null;
        $this->reload($plugin);
    }

    /**
     * Reload workers including plugin.
     * 
     * @param \Corax\CoraxPlugin|null $plugin User custom plugin. Defaults to null.
     */
    public function reload($plugin = null)
    {
        $this->workers = [];
        foreach (get_class_methods($this) as $method) {
            if (substr($method, 0, 2) === $this->prefix) {
                $name = substr($method, 2);
                $this->workers[$name] = [
                    'enable' => $this->disable ? (preg_match($this->disable, $name) ? false : true) : true,
                    'worker' => [$this, $method]
                ];
            }
        }

        if ($plugin) {
            CoraxLogger::info("Loading workers from plugin...");
            foreach (get_class_methods($plugin) as $method) {
                if (substr($method, 0, 2) === $this->prefix) {
                    $name = substr($method, 2);
                    if ($this->register($name, [$plugin, $method]))
                        CoraxLogger::info("User custom worker \"$name\" loaded.", 1);
                }
            }
        }
    }

    /**
     * Check if a worker exists.
     * 
     * @param string $name The worker to check.
     * @return bool Check result.
     */
    public function exists($name)
    {
        return isset($this->workers[$name]);
    }

    /**
     * Get all or enabled worker names.
     * 
     * @param $enabled_only Only get enabled worker names. Defaults to false.
     * @param bool $random Get worker names in random orders. Defaults to false.
     * @return array Worker names.
     */
    public function get_names($enabled_only = false, $random = false)
    {
        $result = [];
        if ($enabled_only) {
            foreach ($this->workers as $name => $worker) if ($worker['enable']) $result[] = $name;
            return $result;
        } else $result = array_keys($this->workers);
        if ($random) shuffle($result);
        return $result;
    }

    /**
     * Check if a worker is enabled.
     * 
     * @param string $name Worker name.
     * @return bool Check result.
     */
    public function is_enable($name)
    {
        return $this->workers[$name]['enable'] ?? false;
    }

    /**
     * To check if a worker is available to use.
     * 
     * @param string $name Worker name.
     * @return bool Check result.
     */
    public function is_available($name)
    {
        return isset($this->workers[$name]) && $this->workers[$name]['enable'];
    }

    /**
     * Register a new worker. Same worker will be overwrote.
     * 
     * @param string $name New worker name.
     * @param callable $worker The callable worker.
     * @return bool If register successfully.
     */
    public function register($name, $worker)
    {
        if ($this->plugin_test && $error = ($this->plugin_test)($worker)) {
            CoraxLogger::warn("Register worker \"$name\" failed. Worker runtime error: $error");
            return false;
        }
        if (isset($this->workers[$name])) CoraxLogger::warn("Register an existed worker \"$name\".");
        $this->workers[$name] = [
            'enable' => $this->disable ? (preg_match($this->disable, $name) ? false : true) : true,
            'worker' => $worker
        ];
        return true;
    }

    /**
     * Removed a worker.
     * 
     * @param string $name Worker name.
     * @return bool If removed successfully.
     */
    public function remove($name)
    {
        if (isset($this->workers[$name])) {
            unset($this->workers[$name]);
            return true;
        }
        return false;
    }

    /**
     * Disable one or all workers.
     * 
     * @param string|null $name Worker name. Given null will disable all workers. Defaults to null.
     * @return bool If disable successfully.
     */
    public function disable($name = null)
    {
        if ($name === null) foreach ($this->workers as $name => $_) $this->workers[$name]['enable'] = false;
        elseif (isset($this->workers[$name])) $this->workers[$name]['enable'] = false;
        else return false;
        return true;
    }

    /**
     * Enable one or all workers.
     * 
     * @param string|null $name Worker name. Given null will enable all workers. Defaults to null.
     * @return bool If enable successfully.
     */
    public function enable($name = null)
    {
        if ($name === null) foreach ($this->workers as $name => $_) $this->workers[$name]['enable'] = true;
        elseif (isset($this->workers[$name])) $this->workers[$name]['enable'] = true;
        else return false;
        return true;
    }


    /**
     * Get an enabled worker or a random worker.
     * 
     * @param string $name The worker name. Given null will randomly choice an enabled worker. Defaults to null.
     * @param bool $force Force using the worker no matter if it is enabled. Defaults to false.
     * @return callable|null The found worker, if has no worker to use, null will be returned.
     */
    public function get_worker($name = null, $force = false)
    {
        if ($name) {
            if (!(isset($this->workers[$name]) && ($this->workers[$name]['enable'] || $force))) return null;
        } else {
            if ($workers = $this->get_names(true, !$force)) $name = CoraxRandom::random_choice($workers);
            else return null;
        }
        return $this->workers[$name]['worker'];
    }

    /**
     * Get enabled or all workers.
     * 
     * @param bool $random Get workers in random orders. Defaults to false.
     * @param bool $force Force using all workers no matter if they are enabled. Defaults to false.
     * @yield string => callable The worker name and the worker.
     */
    public function get_workers($random = false, $force = false)
    {
        foreach ($this->get_names(!$force, $random) as $name)
            yield $name => $this->workers[$name]['worker'];
    }
}
