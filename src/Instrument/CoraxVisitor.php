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
 * @Filename: CoraxVisitor.php
 * @Description: 
 *   Visitor is used to analyze AST node and instrument code while the instrumenter
 * using PhpParser traveling the AST node. The visitor will instrument 3 lines:
 * 
 *   $_key = (Corax_key::$prev << 28) | BLOCK_INDEX;
 *   Corax_keyContext::$edges[$___key] = (Corax_key::$edges[$_key] ?? 0) + 1;
 *   Corax_key::$prev = BLOCK_INDEX;
 * 
 *   And in each instrumented file, visitor will insert an require code in first 
 * line, the require code will import the runtime global static class "Corax_key" 
 * to capture user input, record fuzzing path and hits.
 * 
 *   Also, visitor supports insert watching code to target functions in order to
 * realize runtime watching function arguments and saving to a file. To avoid 
 * memory copy side effect, it will using "eval" to build temporary reference
 * variables to shallow copy the function arguments, just make sure each argument 
 * will only keep one object in memory.
 * ================================================================================
 */

namespace Corax\Instrument;

use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;

use Corax\Common\CoraxRandom;
use Corax\Common\CoraxLogger;
use PhpParser\NodeTraverser;


final class CoraxVisitor extends NodeVisitorAbstract
{
    private $index = 1;

    private $key;
    private $lazy_mode;
    private $watching_regex;
    private $corpus;

    private $block_stub;

    private $want_watch = false;
    private $context_path = '';
    private $filename = '<unknown>';
    private $code = '';
    private $watching = [];
    private $index2pos = [];
    private $modify = [];  // [[id, pos, len, newString, order]]
    private $conflicts = [];

    // The right orders are important!
    // The bigger order number, the higher order.
    private static $orders = [
        'step' => 100,
        'before_require' => PHP_INT_MAX >> 1,
        'before_stub' => PHP_INT_MAX >> 2,
        'append' => 0,
        'trace' => 20,
        'watch' => 40,
        'insert_block' => 60,
    ];

    // These PHP builtin functions can not be watched.
    private static $unsupported = ['__halt_compiler', 'unset', 'isset', 'array', 'list'];

    /**
     * Initialize a visitor.
     * 
     * @param string $key The Corax fuzzing key.
     * @param bool $lazy If enable lazy instrument mode. Defaults to false.
     * @param string|null $watching Watch function. Supports regex. Defaults to null.
     */
    public function __construct($key, $lazy = false, $watching = null)
    {
        $this->key = $key;
        $this->lazy_mode = $lazy;
        $this->watching_regex = $watching;

        // We generate the following code:
        //   $___key = (Context::$p << 28) | BLOCK_INDEX;
        //   Context::$edges[$___key] = (Context::$edges[$___key] ?? 0) + 1;
        //   Context::$p = BLOCK_INDEX;
        // We use a 28-bit block index to leave 8-bits to encode a logarithmic trip count.
        $this->block_stub = "%s\$_$key = (\\Corax_$key::\$prev << 28) | %d; " .
            "\\Corax_$key::\$edges[\$_$key] = (\\Corax_$key::\$edges[\$_$key] ?? 0) + 1; " .
            "\\Corax_$key::\$prev = %d;%s";
    }

    /**
     * Only for dumping and debugging instrumented code while instrument.
     * 
     * @param \PhpParser\Node|null $node The node to debug. If given this, 
     *   the whole node and node code will be dumped. Defaults to null.
     * @param int|null $start Code start file position.
     * @param int|null $end Code end file position.
     * @param bool $exit Exit php after dumped. Defaults to false.
     */
    private function debug_code($node = null, $start = null, $end = null, $exit = false)
    {
        if ($node) {
            var_dump($node);
            $start = $node->getStartFilePos();
            $end = $node->getEndFilePos();
        }
        var_dump(substr($this->code, $start, $end - $start + 1));
        if ($exit) exit;
    }

    /**
     * Assign all child nodes of a node with a new order.
     * 
     * @param \PhpParser\Node $node The node to assign.
     * @param int $order The new order.
     */
    private static function assign_order($node, $order)
    {
        foreach ($node->getSubNodeNames() as $name) {
            $subnode = $node->$name;
            if ($subnode instanceof Node) $subnode->setAttribute('order', $order);
            elseif (is_array($subnode))
                foreach ($subnode as $n) if ($n instanceof Node) $n->setAttribute('order', $order);
        }
    }

    /**
     * Check if the node has been instrumented.
     * 
     * @param \PhpParser\Node $node The node to check.
     * @return bool Check result.
     */
    private function has_modified($node)
    {
        $id = $this->get_node_id($node);
        foreach ($this->modify as $v) if ($v[0] === $id) return true;
        return false;
    }

    /**
     * Undo the modified node.
     * 
     * @param \PhpParser\Node $node The node to check.
     */
    private function undo_modify($node)
    {
        $_modify = $this->modify;
        $id = $this->get_node_id($node);
        foreach ($_modify as $k => $v) if ($v[0] === $id) unset($this->modify[$k]);
        if (isset($this->watching[$id])) unset($this->watching[$id]);
    }

    /**
     * Replace a code fragment to a new string.
     * 
     * @param \PhpParser\Node $node The node of the code.
     * @param int $pos Code position.
     * @param int $len Replace length.
     * @param string $string New string to replace.
     * @param int $order The replacement order. Defaults to 0.
     */
    private function replace_code($node, $pos, $len, $string, $order = 0)
    {
        $this->modify[] = [self::get_node_id($node), $pos, $len, $string, $order];
    }

    /**
     * Insert code fragment.
     * 
     * @param \PhpParser\Node $node The node of the code.
     * @param int $pos Code position.
     * @param string $string New code fragment.
     * @param int $order The insertion order. Defaults to 0.
     */
    private function insert_code($node, $pos, $string, $order = 0)
    {
        $this->replace_code($node, $pos, 0, $string, $order);
    }

    /**
     * Get a new block index and record a position.
     * 
     * @param int $pos Block position.
     * @param int $line Block line.
     * @return int The new block index.
     */
    private function get_index($pos, $line)
    {
        $index = $this->index++;
        $this->index2pos[$index] = $pos << 32 | $line;
        return $index;
    }

    /**
     * Get a new stub code for instrumenting a block.
     * 
     * @param int $pos Block position.
     * @param int $line Block line.
     * @param string $prefix Stub code prefix. Defaults to an empty string.
     * @param string $suffix Stub code suffix. Defaults to an empty string.
     * @return string The new stub code.
     */
    private function get_stub($pos, $line, $prefix = '', $suffix = '')
    {
        $index = $this->get_index($pos, $line);
        return sprintf($this->block_stub, $prefix, $index, $index, $suffix);
    }

    /**
     * Get unique id of a node.
     * 
     * @param \PhpParser\Node $node Target node.
     * @return string Node id.
     */
    private static function get_node_id($node)
    {
        $start = $node->getStartFilePos();
        $end = $node->getEndFilePos();
        $start_line = $node->getStartLine();
        $end_line = $node->getEndLine();
        return "$start.$end.$start_line.$end_line";
    }

    /**
     * To solve PHP-Parser bug: <?php 123 ?> can not be parsed normally.
     * In this case, the PHP-Parser will given the end position at ">" but it should be the position of "3".
     * This function could fix the end pos error and update the right end pos to node.
     * 
     * @param \PhpParser\Node $node Node to fix.
     * @return bool If fix successfully.
     */
    private function fix_ending_tag($node)
    {
        $start = $node->getStartFilePos();
        $end = $node->getEndFilePos();
        // We do this additional steps only for this case: <?php if(1) 123 ? >.
        if (preg_match('/\?>\s*$/', substr($this->code, $start, $end - $start + 1))) {
            while ($end > $start) {
                // PHP-Parser bug: "<?php 123 //123 ? >\n" will parse to ">\n" instead of "? >".
                if ($this->code[$end--] === '>') {
                    if ($this->code[$end] === '?') {
                        $node->setAttribute('endFilePos', $end - 1);
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Check if the function is watching target and get function name and arguments from a node.
     * 
     * @param \PhpParser\Node $node The function node.
     * @return array|null function name and function arguments in an array.
     */
    private function get_func_info($node)
    {
        $func = null;
        $args = [];
        if ($node instanceof Node\Expr\FuncCall) {
            $name = $node->name;
            $start = $name->getStartFilePos();
            $func = substr($this->code, $start, $name->getEndFilePos() - $start + 1);
            $args = $node->args;
        } elseif ($node instanceof Node\Expr\New_) {
            $class = $node->class;
            $start = $class->getStartFilePos();
            $func = substr($this->code, $start, $class->getEndFilePos() - $start + 1);
            $args = $node->args;
        } elseif ($node instanceof Node\Expr\MethodCall) {
            $start = $node->var->getStartFilePos();
            $func = substr($this->code, $start, $node->name->getEndFilePos() - $start + 1);
            $args = $node->args;
        } elseif ($node instanceof Node\Expr\StaticCall) {
            $start = $node->class->getStartFilePos();
            $func = substr($this->code, $start, $node->name->getEndFilePos() - $start + 1);
            $args = $node->args;
        } elseif ($node instanceof Node\Expr\Include_) {
            $start = $node->getStartFilePos();
            $func = substr($this->code, $start, 7);
            if (substr($this->code, $start + 7, 5) === '_once') $func .= '_once';
            $args = [new Node\Arg(
                $node->expr,
                false,
                false,
                [
                    'startFilePos' => $node->expr->getStartFilePos(),
                    'endFilePos' => $node->expr->getEndFilePos(),
                    'startLine' => $node->expr->getStartLine(),
                    'endLine' => $node->expr->getEndLine()
                ]
            )];
        } elseif ($node instanceof Node\Stmt\Echo_) {
            // Special for "echo" statement.
            $func = 'echo';
            if ($this->code[$node->getStartFilePos()] === '<')
                // <?= xxx ? >.
                $node->setAttribute('startFilePos', $node->getStartFilePos() + 2);

            if ($this->code[$node->getEndFilePos()] === ';')
                // PHP-Parser bug.
                $node->setAttribute('endFilePos', $node->getEndFilePos() - 1);

            $start = $node->getStartFilePos();
            foreach ($node->exprs as $expr) {
                $arg = new Node\Arg(
                    $expr,
                    false,
                    false,
                    [
                        'startFilePos' => $expr->getStartFilePos(),
                        'endFilePos' => $expr->getEndFilePos(),
                        'startLine' => $expr->getStartLine(),
                        'endLine' => $expr->getEndLine()
                    ]
                );

                // Fix start file pos.
                $real_start = $arg->getStartFilePos();
                $pos = $real_start - 1;
                $count = 0;
                while ($pos >= $start) {
                    if ($this->code[$pos--] === '(') {
                        $real_start = $pos + 1;
                        $count++;
                    }
                }
                $arg->setAttribute('startFilePos', $real_start);

                // Fix end file pos by the "(" count.
                $real_end = $arg->getEndFilePos();
                $pos = $real_end + 1;
                while ($count) {
                    if ($this->code[$pos++] === ')') {
                        $real_end = $pos - 1;
                        $count--;
                    }
                }
                $arg->setAttribute('endFilePos', $real_end);
                $start = $expr->getEndFilePos() + 1;

                $args[] = $arg;
            }
        } elseif ($node instanceof Node\Expr\Print_) {
            $func = 'print';
            $args = [new Node\Arg(
                $node->expr,
                false,
                false,
                [
                    'startFilePos' => $node->expr->getStartFilePos(),
                    'endFilePos' => $node->expr->getEndFilePos(),
                    'startLine' => $node->expr->getStartLine(),
                    'endLine' => $node->expr->getEndLine()
                ]
            )];
        } elseif ($node instanceof Node\Expr\Eval_) {
            $func = 'eval';
            $args = [new Node\Arg(
                $node->expr,
                false,
                false,
                [
                    'startFilePos' => $node->expr->getStartFilePos(),
                    'endFilePos' => $node->expr->getEndFilePos(),
                    'startLine' => $node->expr->getStartLine(),
                    'endLine' => $node->expr->getEndLine()
                ]
            )];
        } elseif ($node instanceof Node\Expr\Empty_) {
            $func = 'empty';
            $args = [new Node\Arg(
                $node->expr,
                false,
                false,
                [
                    'startFilePos' => $node->expr->getStartFilePos(),
                    'endFilePos' => $node->expr->getEndFilePos(),
                    'startLine' => $node->expr->getStartLine(),
                    'endLine' => $node->expr->getEndLine()
                ]
            )];
        } elseif ($node instanceof Node\Expr\Exit_) {
            $func = (substr($this->code, $node->getStartFilePos(), 3) === 'die') ? 'die' : 'exit';
            if ($node->expr) {
                $args = [new Node\Arg(
                    $node->expr,
                    false,
                    false,
                    [
                        'startFilePos' => $node->expr->getStartFilePos(),
                        'endFilePos' => $node->expr->getEndFilePos(),
                        'startLine' => $node->expr->getStartLine(),
                        'endLine' => $node->expr->getEndLine()
                    ]
                )];
            }
        }
        // Special for `command`.
        elseif ($node instanceof Node\Expr\ShellExec) {
            $func = 'shell_exec';
            if ($node->parts) {
                $args = [new Node\Arg(
                    new Node\Scalar\Encapsed($node->parts, [
                        'startFilePos' => $node->getStartFilePos(),
                        'endFilePos' => $node->getEndFilePos(),
                        'startLine' => $node->getStartLine(),
                        'endLine' => $node->getEndLine()
                    ]),
                    false,
                    false,
                    [
                        'startFilePos' => $node->getStartFilePos() + 1,
                        'endFilePos' => $node->getEndFilePos() - 1,
                        'startLine' => $node->getStartLine(),
                        'endLine' => $node->getEndLine()
                    ]
                )];
            }
        }
        // TODO: Is these are necessary for watching?
        // elseif ($node instanceof Node\Stmt\HaltCompiler) {
        //     $func = '__halt_compiler';
        // } elseif ($node instanceof Node\Stmt\Unset_) {
        //     $func = 'unset';
        //     // PHP-Parser bug.
        //     $node->setAttribute('endFilePos', $node->getEndFilePos() - 1);
        // } elseif ($node instanceof Node\Expr\Isset_) {
        //     $func = 'isset';
        // } elseif ($node instanceof Node\Expr\Array_) {
        //     $func = 'array';
        // } elseif ($node instanceof Node\Expr\List_) {
        //     $func = 'list';
        // }

        if ($func === null || preg_match($this->watching_regex, $func) !== 1) return null;
        return [$func, $args];
    }

    /**
     * Check if a node is a const value or expression.
     * 
     * @param \PhpParser\Node $node
     * @return bool Check result.
     */
    private static function is_const($node)
    {
        return $node instanceof Node\Scalar\LNumber ||
            $node instanceof Node\Scalar\DNumber ||
            $node instanceof Node\Scalar\String_ ||
            $node instanceof Node\Expr\ConstFetch ||
            $node instanceof Node\Scalar\EncapsedStringPart;
        // Even though the leaf node is const, but still the parent node may still return a different value.
        // Just like $_GET['a'] or a('a'), but "a" is a function which returns the $_GET['a'].
        // else {  // TODO: Is this is necessary?
        //     $end_node = true;
        //     foreach ($node->getSubNodeNames() as $name) {
        //         $subnode = $node->$name;
        //         if ($subnode instanceof Node) {
        //             $end_node = false;
        //             if (!self::is_const($subnode)) return false;
        //         } elseif (is_array($subnode)) foreach ($subnode as $n) if ($n instanceof Node) {
        //             $end_node = false;
        //             if (!self::is_const($n)) return false;
        //         }
        //     }
        //     return !$end_node;
        // }
    }

    /**
     * Insert the watching code for target function.
     * 
     * @param \PhpParser\Node $node The function node.
     * @param int $order The insertion order. Defaults to 0.
     * @return bool If watch the function successfully.
     */
    private function insert_watch_point($node, $order = 0)
    {
        $func_info = $this->get_func_info($node);
        if ($func_info === null) return;

        $func = $func_info[0];
        if (in_array($func, self::$unsupported)) {
            CoraxLogger::warn("PHP statement or function \"$func\" is unsupported to instrument!");
            return;
        }

        // Fix the ending tag bug for PHPParser.
        self::fix_ending_tag($node);

        $args = $func_info[1];
        $start = $node->getStartFilePos();
        $end = $node->getEndFilePos();
        $start_line = $node->getStartLine();
        $end_line = $node->getEndLine();
        $unpack = 0;

        // Do not check const in lazy mode.
        $const = !$this->lazy_mode;

        // Count the unpack arguments count, and check const arguments by the way.
        if ($args) {
            foreach ($args as $arg) {
                if ($arg->unpack) $unpack++;
                if ($const) $const = self::is_const($arg->value);
            }

            // All arguments are const value.
            if ($const) return;
        } elseif (!$this->lazy_mode) return;  // Empty arguments will not be instrumented in lazy mode.

        // Insert the watching code.
        $feature = md5(implode('.', [$func, $this->filename, $start, $end, $start_line, $end_line]));
        $start_watching_code = "\\Corax_$this->key::watching(";
        $start_watch_code = "\\Corax_$this->key::watch('" . addcslashes($func, '\\\'') .
            "', '$this->filename', $start, $end, $start_line, $end_line, $unpack, '$feature', null, ";
        $end_watch_code = '), ';
        $end_watching_code = ')';

        if ($args) {
            // To avoid the side effect, using temporary array for keeping each argument only once.
            $capture_tmp_var = "\$_{$this->key}_" . CoraxRandom::random_id();
            $start_capture_code = "$capture_tmp_var = @[";
            $end_capture_code = ']';
            $args_start_pos = $args[0]->getStartFilePos();
            $args_end_pos = $args[count($args) - 1]->getEndFilePos();

            $this->replace_code(
                $node,
                $start,
                $args_start_pos - $start,
                $start_watching_code . $start_watch_code . $start_capture_code,
                -$order
            );

            // Special for "`", which is the alias of "shell_exec".
            if ($func === 'shell_exec' && $this->code[$start] === '`') {
                $this->insert_code($node, $args_start_pos, "<<<EOF\n", -$order + 10);
                $this->insert_code($node, $args_end_pos + 1, "\nEOF\n", $order - 10);
            } else {
                // Fix capture args.
                foreach ($args as $arg) {
                    $s = $arg->getStartFilePos();

                    // Replace expandable arguments "...".
                    if ($arg->unpack) {
                        $this->replace_code($node, $s, 3, '', -$order + 1);
                        $s += 3;
                    }

                    // Match a php variable and add reference.
                    // $var $var::$var->var $var::$var::$var $var->var->var Class::$var::$var
                    // $var->var(....)->var
                    if (($arg->value instanceof Node\Expr\Variable ||
                        $arg->value instanceof Node\Expr\PropertyFetch ||
                        $arg->value instanceof Node\Expr\StaticPropertyFetch
                        // $arg->value instanceof Node\Expr\ArrayDimFetch
                    ) && preg_match(
                        // '/^([a-zA-Z_\x7f-\xff]+::)?\$+[a-zA-Z_\x7f-\xff]+((::\$+|->\$*)[a-zA-Z_\x7f-\xff]+)*$/',
                        '/^([a-zA-Z_\x7f-\xff]+::)?\$+[a-zA-Z_\x7f-\xff]+.*$/',
                        substr($this->code, $s, $arg->getEndFilePos() - $s + 1)
                    )) $this->insert_code($node, $s, '&', -$order + 2);

                    // A new line is required after the docstring.
                    if ($arg->value->getAttribute('docLabel'))
                        $this->insert_code($node, $arg->getEndFilePos() + 1, "\n", $order - 5);
                }
            }

            // Temporary var capture.
            if ($func === 'shell_exec' && $this->code[$start] === '`') {
                // Special for `command`.
                $s = 'shell_exec(';
                $e = ')';
            } elseif ($func === 'echo' && $this->code[$start] === '=') {
                // Special for <?= xxx ? >.
                $s = 'echo ';
                $e = '';
            } else {
                // TODO: watching the function a(1 ?: $a)->func($a); 
                // $fix_offset = function ($node, $offset) use (&$fix_offset) {
                //     $node->setAttribute('startFilePos', $node->getStartFilePos() + $offset);
                //     $node->setAttribute('endFilePos', $node->getEndFilePos() + $offset);
                //     foreach ($node->getSubNodeNames() as $name) {
                //         $subnode = $node->$name;
                //         if ($subnode instanceof Node) $fix_offset($subnode, $offset);
                //         elseif (is_array($subnode))
                //             foreach ($subnode as $n) if ($n instanceof Node) $fix_offset($n, $offset);
                //     }
                // };
                // if ($node instanceof Node\Expr\MethodCall) $fix_offset($node->var, $offset);
                // elseif ($node instanceof Node\Expr\StaticCall) $fix_offset($node->class, $offset);
                // elseif ($node instanceof Node\Expr\FuncCall && !($node->name instanceof Node\Name)) 
                //     $fix_offset($node->name, $offset);

                $s = substr($this->code, $start, $args_start_pos - $start);
                $e = substr($this->code, $args_end_pos + 1, $end - $args_end_pos);

                // Avoid this: <?php x(123) //1231312312 ? >
                if (substr($e, -2) === '?>') $e = substr($e, 0, -2);
            }

            $runtime_args = [];
            // Build runtime arguments from capture argument.
            for ($i = 0, $j = count($args), $k = $j - $unpack; $i < $j; $i++) {
                $c = "{$capture_tmp_var}[$i]";
                // Build unpack arguments.
                if ($i === $k) {
                    $c = '...' . $c;
                    $k++;
                }
                $runtime_args[] = $c;
            }
            $runtime_code = $s . implode(', ', $runtime_args) . $e;

            // Insert watching code.
            $this->replace_code(
                $node,
                $args_end_pos + 1,
                $end - $args_end_pos,
                $end_capture_code . $end_watch_code .
                    // The echo does not behave like a function so we can not put the echo statement in a
                    // function argument, the good solution is to append the echo statement after the watching code.
                    ($func === 'echo' ?  "null$end_watching_code;$runtime_code" : ($runtime_code . $end_watching_code)),
                $order
            );
        } else {
            // Watching an empty arguments function.
            $this->insert_code($node, $start, $start_watching_code . $start_watch_code .
                'null, []' . $end_watch_code, -$order);
            $this->insert_code($node, $end + 1, $end_watching_code, $order);
        }

        $this->watching[self::get_node_id($node)] = $func;
    }

    /**
     * Insert a stub to block.
     * 
     * @param \PhpParser\Node $node The node to insert.
     * @param int $order The insertion order. Defaults to 0.
     * @param string $prefix Stub code prefix. Defaults to a space.
     * @param string $suffix Stub code suffix. Defaults to a space.
     */
    private function insert_block_stub($node, $order = 0, $prefix = ' ', $suffix = ' ')
    {
        self::fix_ending_tag($node);

        $start = $node->getStartFilePos();
        $end = $node->getEndFilePos();

        // The do-while loops have odd structure, insert_code stub before the start,
        // which is control-equivalent to within the do block.
        if ($node instanceof Node\Stmt\Do_) {
            $this->ahead_stub($node, $order, $prefix, $suffix);
            return;
        }

        if (!isset($node->stmts)) return;

        $stmt = null;
        // Skip comment nodes.
        if ($node->stmts) {
            foreach ($node->stmts as $s) {
                if (!($s instanceof Node\Stmt\Nop)) {
                    $stmt = $s;
                    break;
                }
            }
        }

        if ($stmt) {
            // Wrap the statement in {} in case this is a single "stmt;" block.
            // Add a new line before the stub in case of this: if (1){//123 \n}.
            // Skip comment.
            $prefix = '{ ';
            $suffix = ' }';

            // TODO: Is this necessary?
            // if ($stmt instanceof Node\Stmt\Nop) {
            //     $stmt = $stmt->getComments()[0];
            //     $suffix = "\n" . $suffix;
            // }

            $start = $stmt->getStartFilePos();

            if (
                $stmt instanceof Node\Stmt\InlineHTML ||
                // To avoid:  <?php if (1): ? ><?= 123? >
                $this->code[$start] === '<'
            ) {
                $this->ahead_stub($stmt, $order, '<?php ', ' ?>');
                return;
            }

            $this->insert_stub($stmt, $start, -$order, $prefix, '');

            $end = $stmt->getEndFilePos();

            // For fixing PHPParser bug; <?php 123 ? >
            if (self::fix_ending_tag($stmt)) {
                // Refresh end is required after fixing the ending tag.
                $end = $stmt->getEndFilePos();
                $suffix = ";$suffix";
            } elseif (preg_match(
                // Match the end of docstring, new line is required.
                '/\n[ \t]*[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*\s*;*$/',
                substr($this->code, $start, $end - $start + 1)
            )) $suffix = "\n$suffix";

            // The order must larger than append_stub order.
            $this->insert_code($stmt, $end + 1, $suffix, $order);

            return;
        }

        // Fix the end of "if" statement, if the "if" statement has no any stmts 
        // but it has "elseif" or "else", we will never know the empty statement's position. 
        // The endFilePos is "elseif" or "else " file position.
        if ($node instanceof Node\Stmt\If_) {
            $end = $node->cond->getEndFilePos();
            while (!in_array($this->code[++$end], [':', ';', '}']));
        }

        // We have an empty statement list. This may be represented as "{}", ";"
        // or, in case of a "case" statement, nothing.
        switch ($this->code[$end]) {
            case '}':
                $this->insert_stub($node, $end, $order, $prefix, $suffix);
                break;
            case ';':
                switch ($this->code[$end - 1]) {
                    case 'f':
                        if ($node instanceof Node\Stmt\If_) {
                            // endif;
                            $this->insert_stub($node, $end - 5, $order);
                            return;
                        }
                        // elseif;
                        break;
                    case 'r':
                        // endfor;
                        $this->insert_stub($node, $end - 6, $order);
                        return;
                    case 'e':
                        if ($this->code[$end - 2] === 'l') {
                            // endwhile;
                            $this->insert_stub($node, $end - 8, $order);
                            return;
                        } elseif ($this->code[$end - 2] === 'r') {
                            // enddeclare;
                            $this->insert_stub($node, $end - 10, $order);
                            return;
                        }
                        // else;
                        break;
                    case 'h':
                        // endforeach;
                        if ($this->code[$end - 3] === 'a') $this->insert_stub($node, $end - 10, $order);
                        // endswitch;
                        else $this->insert_stub($node, $end - 9, $order);
                        return;
                    default:
                        break;
                }

                // case\s*;
                if ($node instanceof Node\Stmt\Case_) $this->insert_stub($node, $end + 1, $order, '{ ', ' }');
                else $this->replace_code($node, $end, 1, $this->get_stub($end, $node->getStartLine(), '{ ', ' }'), $order);

                break;
            case ':':
                $this->insert_stub($node, $end + 1, $order, $prefix, $suffix);
                break;
            default:
                break;
        }
    }

    /**
     * Insert a stub to a node.
     * 
     * @param \PhpParser\Node $node The node to insert.
     * @param int $pos Code position.
     * @param int $order The insertion order. Defaults to 0.
     * @param string $prefix Stub code prefix. Defaults to a space.
     * @param string $suffix Stub code suffix. Defaults to a space.
     */
    private function insert_stub($node, $pos, $order = 0, $prefix = ' ', $suffix = ' ')
    {
        $this->insert_code($node, $pos, $this->get_stub($pos, $node->getStartLine(), $prefix, $suffix), $order);
    }

    /**
     * Ahead a stub before a node.
     * 
     * @param \PhpParser\Node $node The node to insert.
     * @param int $order The insertion order. Defaults to 0.
     * @param string $prefix Stub code prefix. Defaults to a space.
     * @param string $suffix Stub code suffix. Defaults to a space.
     */
    private function ahead_stub($node, $order = 0, $prefix = ' ', $suffix = ' ')
    {
        $start = $node->getStartFilePos();
        $this->insert_code($node, $start, $this->get_stub($start, $node->getStartLine(), $prefix, $suffix), $order);
    }

    /**
     * Append a stub after a node.
     * 
     * @param \PhpParser\Node $node The node to insert.
     * @param int $order The insertion order. Defaults to 0.
     * @param string $prefix Stub code prefix. Defaults to a space.
     * @param string $suffix Stub code suffix. Defaults to a space.
     */
    private function append_stub($node, $order = 0, $prefix = ' ', $suffix = ' ')
    {
        $end = $node->getEndFilePos();
        if (!in_array($this->code[$end], [';', ':', '}'])) $prefix = ';' . $prefix;
        $this->insert_code($node, $end + 1, $this->get_stub($end, $node->getStartLine(), $prefix, $suffix), $order);
    }

    /**
     * Insert trace stub code.
     * 
     * @param \PhpParser\Node $node The node to insert.
     * @param int $order The insertion order. Defaults to 0.
     */
    private function insert_trace($node, $order = 0)
    {
        $start = $node->getStartFilePos();
        $index = $this->get_index($start, $node->getStartLine());

        // The "-$order" will make the trace order so big, which means the first part
        // "trace(" will be inserted last in some situation such as "if (1) yield 1;".
        $this->insert_code($node, $start, "\\Corax_$this->key::trace($index, ", -$order);
        // And the second part ")" will be inserted first.
        $this->insert_code($node, $node->getEndFilePos() + 1, ')', $order);
    }

    /**
     * Insert the require global context Corax server code before each traverse.
     * 
     * @param array $nodes The node list.
     */
    public function beforeTraverse($nodes)
    {
        if ($nodes) {
            $order = 0;
            // Reset node orders of the first level.
            foreach ($nodes as $node) {
                if ($node instanceof Node) $node->setAttribute('order', $order);
            }

            $code = "{ require_once(realpath('$this->context_path')); }";
            foreach ($nodes as $node) {
                if (
                    $node instanceof Node\Stmt\Declare_ ||
                    $node instanceof Node\Stmt\InlineHTML || $node instanceof Node\Stmt\Nop
                ) continue;


                if ($node instanceof Node\Stmt\Namespace_) {
                    if ($node->stmts) $node = $node->stmts[0];
                    // Empty namespace simply skip.
                    else continue;
                }

                // Ahead of comments.
                if ($node->hasAttribute('comments')) {
                    $comments = $node->getAttribute('comments')[0];
                    if ($comments) {
                        if (is_array($comments)) $node = $comments[0];
                        else $node = $comments;
                    }
                }

                // In case of "<?= ... ? >".
                if ($this->code[$node->getStartFilePos()] === '<') {
                    $this->insert_code(
                        $node,
                        $node->getStartFilePos(),
                        "<?php $code ?>",
                        $order - self::$orders['before_require']
                    );
                    $this->ahead_stub($node, $order - self::$orders['before_stub'], '<?php ', ' ?>');
                } else {
                    $this->insert_code(
                        $node,
                        $node->getStartFilePos(),
                        $code,
                        $order - self::$orders['before_require']
                    );
                    $this->ahead_stub($node, $order - self::$orders['before_stub'], '{ ', " }");
                }
                return;
            }
        }
    }

    /**
     * The main entry function for visitor. Instrument block for each node.
     * 
     * @param \PhpParser\Node $node Node to instrument.
     */
    public function enterNode($node)
    {
        $order = $node->getAttribute('order');
        self::assign_order($node, $order - self::$orders['step']);

        // Skip class static property.
        if ($node instanceof Node\Stmt\Property && $node->isStatic()) return NodeTraverser::DONT_TRAVERSE_CHILDREN;

        if (
            $node instanceof Node\Expr\Closure ||
            $node instanceof Node\Stmt\Case_ ||
            $node instanceof Node\Stmt\Catch_ ||
            $node instanceof Node\Stmt\ClassMethod ||
            $node instanceof Node\Stmt\Else_ ||
            $node instanceof Node\Stmt\ElseIf_ ||
            $node instanceof Node\Stmt\Finally_ ||
            $node instanceof Node\Stmt\Function_ ||
            $node instanceof Node\Stmt\While_
        ) {
            $this->insert_block_stub($node, $order - self::$orders['insert_block']);
        } elseif (
            // In these cases we should additionally insert_code one after the node.
            $node instanceof Node\Stmt\Do_ ||
            $node instanceof Node\Stmt\If_ ||
            $node instanceof Node\Stmt\For_ ||
            $node instanceof Node\Stmt\Foreach_
        ) {
            $this->insert_block_stub($node, $order - self::$orders['insert_block']);
            $this->append_stub($node, $order - self::$orders['append']);
        } elseif (
            // In these cases we need to insert_code one after the node only.
            $node instanceof Node\Stmt\Label ||
            $node instanceof Node\Stmt\Switch_ ||
            $node instanceof Node\Stmt\TryCatch
        ) {
            $this->append_stub($node, $order - self::$orders['append']);
        } elseif (
            // For short-circuiting operators, insert_code a tracing call into one branch.
            $node instanceof Node\Expr\BinaryOp\BooleanAnd ||
            $node instanceof Node\Expr\BinaryOp\BooleanOr ||
            $node instanceof Node\Expr\BinaryOp\LogicalAnd ||
            $node instanceof Node\Expr\BinaryOp\LogicalOr ||
            $node instanceof Node\Expr\BinaryOp\Coalesce
        ) {
            $this->insert_trace($node->right, $order - self::$orders['trace']);
        } elseif (
            $node instanceof Node\Expr\AssignOp\Coalesce ||
            $node instanceof Node\Expr\ArrowFunction
        ) {
            $this->insert_trace($node->expr, $order - self::$orders['trace']);
        } elseif ($node instanceof Node\Expr\Ternary) {
            // Same as previous case, just different subnode name.
            $this->insert_trace($node->else, $order - self::$orders['trace']);
        } elseif (
            // Wrap the yield, so that a tracing call occurs after the yield resumes.
            $node instanceof Node\Expr\Yield_ ||
            $node instanceof Node\Expr\YieldFrom
        ) {
            $this->insert_trace($node, $order - self::$orders['trace']);
        } elseif ($this->want_watch && $this->watching_regex)
            $this->insert_watch_point($node, $order - self::$orders['watch']);

        if (
            $node instanceof Node\Scalar\String_ ||
            $node instanceof Node\Scalar\Encapsed ||
            $node instanceof Node\Expr\ShellExec
        ) {
            // Record const string value as corpus.
            if (isset($node->parts)) {
                $value = '';
                foreach ($node->parts as $n)
                    if ($n instanceof Node\Scalar\EncapsedStringPart) $value .= $n->value;
            } else $value = $node->value;
            if (!isset($value[1024])) $this->corpus[] = $value;
        }
    }

    /**
     * Manually reset this visitor.
     * 
     * @param string $filename Instrument filename.
     * @param string $code The raw code.
     * @param string $context_path Instrument context file path.
     * @param bool $want_watch Enable watching this file.
     */
    public function init($filename, $code, $context_path, $want_watch)
    {
        $this->filename = $filename;
        $this->code = $code;
        $this->context_path = $context_path;
        $this->want_watch = $want_watch;
        $this->index2pos = [];
        $this->modify = [];
        $this->conflicts = [];
        $this->watching = [];
        $this->corpus = [];
    }

    /**
     * Get curren instrumented index.
     * 
     * @return int Current instrument index.
     */
    public function current_index()
    {
        return $this->index;
    }

    /**
     * Get file info after instrumenting.
     * 
     * @return array File info.
     */
    public function get_fileinfo()
    {
        return $this->index2pos;
    }

    /**
     * Get watch function info after instrumenting.
     * 
     * @return array Watch info.
     */
    public function get_watchinfo()
    {
        return $this->watching;
    }

    public function get_conflict()
    {
        return $this->conflicts;
    }

    /**
     * Get instrumented code.
     * 
     * @return string Instrumented code.
     */
    public function get_code()
    {
        // Sort by ending position.
        usort(
            $this->modify,
            function ($a, $b) {
                return ($a[1] + $a[2] <=> $b[1] + $b[2]) ?: ($a[4] <=> $b[4]);
            }
        );

        $result = '';
        $start = 0;
        foreach ($this->modify as list($id, $pos, $len, $string)) {
            if ($pos < $start || isset($this->conflicts[$id])) {
                // TODO: Watching this function: a(1 ?: $a)->func($a);
                // Modify conflicted.
                CoraxLogger::warn("Conflicting code modification, skipped!");
                list($s, $e, $sl, $el) = explode('.', $id);
                $source_code = substr($this->code, (int)$s, (int)$e - (int)$s + 1);
                $modify_code = substr($this->code, $pos, $len);
                if (isset($this->conflicts[$id]))
                    $this->conflicts[$id][] = [$s, $e, $sl, $el, $pos, $len, $source_code, $modify_code, $string];
                else $this->conflicts[$id] = [[$s, $e, $sl, $el, $pos, $len, $source_code, $modify_code, $string]];
                continue;
            }

            $result .=  substr($this->code, $start, $pos - $start) . $string;
            $start = $pos + $len;
        }
        return $result . substr($this->code, $start);
    }

    /**
     * Get collected corpus during the instrument.
     * 
     * @return array Contains all const strings from this code.
     */
    public function get_corpus()
    {
        $corpus = [];
        foreach ($this->corpus as $c) {
            $name = md5($c);
            if (!isset($corpus[$name])) $corpus[$name] = $c;
        }
        return $corpus;
    }
}
