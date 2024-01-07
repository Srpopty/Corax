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
 * @Filename: CoraxDictionary.php
 * @Description: 
 *   Some word lists used in Corax are stored in here.
 * ================================================================================
 */

namespace Corax\Common;


final class CoraxDictionary
{
    public static $status_code_msg = [
        100 => "Continue", 101 => "Switching Protocols",
        200 => "OK", 201 => "Created", 202 => "Accepted", 203 => "Non-Authoritative Information", 204 => "No Content",
        205 => "Reset Content", 206 => "Partial Content", 300 => "Multiple Choices", 301 => "Moved Permanently",
        302 => "Found", 303 => "See Other", 304 => "Not Modified", 305 => "Use Proxy", 306 => "(Unused)",
        307 => "Temporary Redirect", 400 => "Bad Request", 401 => "Unauthorized", 402 => "Payment Required",
        403 => "Forbidden", 404 => "Not Found", 405 => "Method Not Allowed", 406 => "Not Acceptable",
        407 => "Proxy Authentication Required", 408 => "Request Timeout", 409 => "Conflict", 410 => "Gone",
        411 => "Length Required", 412 => "Precondition Failed", 413 => "Request Entity Too Large",
        414 => "Request-URI Too Long", 415 => "Unsupported Media Type", 416 => "Requested Range Not Satisfiable",
        417 => "Expectation Failed", 500 => "Internal Server Error", 501 => "Not Implemented", 502 => "Bad Gateway",
        503 => "Service Unavailable", 504 => "Gateway Timeout", 505 => "HTTP Version Not Supported"
    ];

    public static $signals = [
        SIGHUP => 'SIGHUP', SIGINT => 'SIGINT', SIGQUIT => 'SIGQUIT', SIGILL => 'SIGILL',
        SIGABRT => 'SIGABRT', SIGSEGV => 'SIGSEGV', SIGPIPE => 'SIGPIPE', SIGALRM => 'SIGALRM',
        SIGTERM => 'SIGTERM', SIGSTKFLT => 'SIGSTKFLT', SIGTSTP => 'SITSTP', SIGTTIN => 'SIGTTIN',
        SIGTTOU => 'SIGTTOUT', SIGVTALRM => 'SIGVTALRM'
    ];

    public static $errors = [
        E_ERROR => 'Error', E_WARNING => 'Warning', E_PARSE => 'Parse', E_NOTICE => 'Notice',
        E_USER_ERROR => 'UserError', E_USER_WARNING => 'UserWarning', E_USER_NOTICE => 'UserNotice',
        E_STRICT => 'Script', E_RECOVERABLE_ERROR => 'RecoverableError', E_DEPRECATED => 'Deprecated',
        E_USER_DEPRECATED => 'UserDeprecated', E_ALL => 'All'
    ];

    public static $context_types = [
        'application/x-cals', 'application/x-bot', 'application/x-hgl', 'video/x-ms-wmx',
        'application/x-cit', 'application/postscript', 'application/x-pc5', 'image/png', 'application/x-x509-ca-cert',
        'application/x-dbx', 'application/pics-rules', 'video/x-ms-wvx', 'text/plain', 'audio/vnd.rn-realaudio',
        'application/sdp', 'application/x-plt', 'video/vnd.rn-realvideo', 'message/rfc822', 'application/vnd.iphone',
        'application/vnd.adobetext/xml', 'audio/x-musicnet-download', 'application/x-wpg',
        'application/vnd.rn-realsystem-rmx', 'application/vnd.adobeapplication/vnd.adobe.xfdf',
        'application/vnd.rn-realmedia-vbr', 'application/x-tdf', 'application/x-gl2', 'application/x-ws',
        'application/x-sam', 'application/x-iff', 'audio/x-pn-realaudio', 'application/x-vsd', 'application/x-ltr',
        'application/x-x_t', 'application/msaccess', 'application/x-pcl', 'application/x-mi', 'application/x-red',
        'application/x-pci', 'text/css', 'application/x-sat', 'application/vnd.rn-realsystem-rmj', 'application/x-tg4',
        'application/x-prn', 'application/vnd.rn-realsystem-rjt', 'application/x-netcdf', 'application/x-stuffit',
        'application/vnd.fdf', 'text/html', 'Model/vndapplication/x-dwf', 'application/x-hmr',
        'application/vnd.adobe.rmf', 'application/pkcs10', 'audio/mid', 'application/vndapplication/vnd.visio',
        'application/vnd.ms-project', 'application/x-ms-wmz', 'application/vnd.adobeapplication/x-pkcs12',
        'application/x-ico', 'text/xml', 'application/x-wb3', 'application/x-wb1', 'audio/x-liquid-file',
        'application/x-dxb', 'application/x-bmp', 'application/x-emf', 'application/x-icb', 'audio/x-mei-aac',
        'application/vnd.adobe.workflow', 'application/x-c4t', 'application/x-dgn', 'audio/x-musicnet-stream',
        'application/vnd.visio', 'application/x-icq', 'application/x-wk4', 'application/x-wk3', 'audio/scpls',
        'application/x-shockwave-flash', 'application/x-wp6', 'application/x-png', 'image/fax',
        'application/streamingmedia', 'application/x-001', 'application/vnd.symbian.install', 'audio/x-ms-wax',
        'application/x-g4', 'video/mpg', 'application/x-jpe', 'application/x-mmxp', 'application/x-dwg',
        'application/x-bittorrent', 'application/pkcs7-feature', 'image/pnetvue', 'video/x-ms-asf', 'application/x-ps',
        'audio/aiff', 'application/x-', 'application/x-pr', 'application/octet-stream', 'application/x-sty',
        'application/x-ras', 'video/x-mpg', 'application/x-gp4', 'application/x-x_b', 'application/vnd.ms-wpl',
        'application/x-wks', 'application/x-troff-man', 'application/x-wkq', 'application/vnd.ms-pkitext/html',
        'application/vnd.ms-pki.certstore', 'audio/x-la-lms', 'text/vnd.rn-realtext3d',
        'audio/x-pn-realaudio-plugin', 'application/x-internet-signup', 'application/x-hpl', 'application/x-anv',
        'image/vnd.rn-realpix', 'application/x-ptn', 'application/x-img', 'application/vnd.android.package-archive',
        'application/x-prt', 'application/x-cmx', 'application/x-wpd', 'application/x-drw', 'application/x-906',
        'text/x-ms-odc', 'application/vnd.rn-rsml', 'video/x-ms-wm', 'text/scriptlet', 'video/mpeg4',
        'application/x-frm', 'audio/wav', 'application/x-cut', 'text/x-component', 'application/x-dib',
        'application/x-laplayer-reg', 'video/avi', 'application/pdf', 'text/iuls', 'text/asa', 'application/x-nrf',
        'application/x-rtf', 'application/vnd.rn-realsystem-rjs', 'application/hta', 'application/x-out',
        'application/x-a11', 'text/h323', 'application/x-mac', 'drawing/x-slk', 'application/x-msdownload',
        'image/gif', 'application/x-smk', 'application/x-mdb', 'application/x-vda', 'application/x-pkcs7-certreqresp',
        'application/x-cmp', 'application/pkcs7-mime', 'application/x-mil', 'image/tiff', 'application/x-pkcs12',
        'application/vnd.rn-realmedia-secure', 'application/x-rgb', 'application/vnd.ms-powerpoint',
        'application/vnd.adobe.edn', 'application/x-wq1', 'text/vnd.wap.wml', 'application/x-javascript',
        'text/vnd.rn-realtext', 'application/x-dxf', 'application/x-pgl', 'application/vnd.rn-recording',
        'application/rat-file', 'application/x-lbm', 'application/x-sdw', 'application/x-hrf', 'application/x-wri',
        'application/x-wrk', 'image/x-icon', 'text/asp', 'video/mpeg', 'video/x-mpeg', 'application/x-latex',
        'application/x-tga', 'audio/basic', 'application/x-csi', 'application/x-wmf', 'application/mac-binhex40',
        'java/*', 'audio/x-ms-wma', 'image/jpeg', 'application/fractals', 'application/pkix-crl', 'drawing/x-top',
        'application/x-epi', 'application/x-igs', 'application/x-xwd', 'application/vnd.rn-realplayer',
        'application/x-iphone', 'application/x-wr1', 'application/x-pcx', 'application/x-xls', 'application/x-301',
        'application/x-xlw', 'application/x-ms-wmd', 'audio/mpegurl', 'application/futuresplash', 'image/vnd.wap.wbmp',
        'audio/mp3', 'audio/mp2', 'audio/mp1', 'application/x-rlc', 'video/x-ivf', 'application/x-dcx',
        'audio/x-liquid-secure', 'application/vnd.ms-excel', 'application/x-cgm', 'application/x-cot',
        'application/smil', 'video/x-sgi-movie', 'application/x-ppm', 'application/x-vpeg005', 'video/x-ms-wmv',
        'application/x-pkcs7-certificates', 'application/x-gbr', 'application/x-cel', 'application/x-wb2',
        'text/x-vcard', 'application/vndtext/xml', 'application/x-silverlight-app',
        'application/vnd.rn-rn_music_package', 'application/x-cdr', 'application/x-dbf',
        'application/vnd.ms-pki.seccat', 'drawing/907', 'application/x-jpg', 'application/x-dbm', 'application/x-tif',
        'application/x-rle', 'application/vnd.ms-pkiapplication/x-perl', 'application/x-ppt',
        'application/vndapplication/x-vst', 'application/vnd.rn-realmedia', 'application/x-c90', 'text/webviewhtml',
        'application/x-slb', 'application/x-ebx', 'application/msword', 'audio/rn-mpeg', 'application/x-pic',
        'application/x-sld', 'application/x-hpgl'
    ];

    public static $hex_file_headers = [
        "\xFF\xD8\xFF\xE1", "\x89\x50\x4E\x47", "\x47\x49\x46\x38", "\x49\x49\x2A\x00", "\x42\x4D\xC0\x01",
        "\x50\x4B\x03\x04", "\x52\x61\x72\x21", "\x38\x42\x50\x53", "\x7B\x5C\x72\x74\x66", "\x3C\x3F\x78\x6D\x6C",
        "\x25\x50\x44\x46\x2D\x31\x2E", "\x57\x41\x56\x45", "\x4D\x3C\x2B\x1A", "\x41\x43\x31\x30"
    ];

    public static $file_exts = [
        'php', 'php3', 'php4', 'php5', 'php2', 'html', 'htm', 'phtml', 'pht', 'jsp', 'jspa', 'jspx', 'jsw',
        'jsv', 'jspf', 'jtml', 'asp', 'aspx', 'asa', 'asax', 'ascx', 'ashx', 'asmx', 'cer', 'swf', 'htaccess',
        'ini', 'png', 'jpg', 'gif', 'jpeg', 'txt', 'doc', 'pdf', 'mp3', 'mp4', 'docx', 'm4a', 'jar', 'xml',
        'xlm', 'iso', 'bin', 'zip', 'rar', 'arj', 'z', '7z', 'phar', 'py', 'c', 'go', 'css', 'js', 'class',
        'rb', "php\0.jpg", "php\0.png", "php\0.gif", 'gif.php', 'pdf.php', 'jpg.php', 'zip.php', 'mp3.php',
        'sh'
    ];

    public static $special_numbers = [
        0, -1, -127, 128, -254, 255, -1023, 1024, 32767, -32768, -65536, 65535, -2147483648, 2147483647, 9223372036854775807,
        -9223372036854775808, 4.9E-324, 1.7976931348623157E308, 1.4E-45, 3.4028235E38, 0.0000001
    ];

    public static $special_chars = '!@#$%^&*()_+=`~{}|[]\\:";\',./<>?';
    public static $space_chars = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13" .
        "\x14\x15\x16\x17\x18\x19\x20\x1a\x1b\x1c\x1d\x1f";

    public static $html_single_tags = [
        'input', 'img', 'isindex', 'area', 'base', 'basefont', 'bgsound', 'col', 'embed', 'keygen', 'link', 'meta',
        'nextid', 'param', 'wbr', 'br', 'plaintext', 'spacer', 'frame'
    ];
    public static $html_paired_tags = [
        'code', 'kbd', 'tbody', 'font', 'noscript', 'style', 'title', 'menu', 'tt',
        'tr', 'li', 'source', 'tfoot', 'th', 'td', 'main', 'dl', 'blockquote', 'fieldset', 'big', 'dd', 'meter',
        'optgroup', 'dt', 'button', 'summary', 'p', 'small', 'output', 'div', 'dir', 'em', 'datalist', 'frame',
        'video', 'rt', 'canvas', 'rp', 'sub', 'bdo', 'bdi', 'label', 'template', 'sup', 'progress', 'body', 'acronym',
        'base', 'address', 'article', 'strong', 'legend', 'ol', 'caption', 's', 'dialog', 'h1', 'h6', 'header',
        'table', 'select', 'noframes', 'span', 'script', 'mark', 'dfn', 'strike', 'cite', 'thead', 'head', 'option',
        'form', 'hr', 'var', 'ruby', 'b', 'colgroup', 'ul', 'applet', 'del', 'iframe', 'pre', 'frameset', 'figure',
        'ins', 'aside', 'html', 'nav', 'details', 'u', 'samp', 'map', 'track', 'object', 'figcaption', 'a', 'center',
        'textarea', 'footer', 'i', 'q', 'command', 'time', 'audio', 'section', 'abbr'
    ];

    public static $html_attrs = [
        'href', 'lowsrc', 'background', 'bgsound', 'action', 'dynsrc'
    ];
    public static $js_events = [
        'onloadeddata', 'ontoggle', 'onwaiting', 'onredo', 'onerror', 'onprogress', 'ondragenter', 'onreset',
        'onended', 'onplay', 'onmousedown', 'onforminput', 'onsubmit', 'onpause', 'onmousewheel', 'onchange',
        'onafterprint', 'oninvalid', 'onloadstart', 'onabort', 'onload', 'oninput', 'onmouseout', 'ondragover',
        'onsuspend', 'ontimeupdate', 'onratechange', 'onkeypress', 'ondragleave', 'onresize', 'onselect',
        'onmousemove', 'onclick', 'onundo', 'onemptied', 'onfocus', 'ondrag', 'oncanplay', 'onstorage', 'onformchange',
        'onblur', 'onhashchange', 'ondragstart', 'onoffline', 'ondrop', 'onbeforeonload', 'ononline', 'onkeydown',
        'onpageshow', 'onvolumechange', 'onmouseover', 'onpopstate', 'oncontextmenu', 'onscroll', 'onunload',
        'onloadedmetadata', 'ondragend', 'onshow', 'onseeking', 'onbeforeprint', 'oncanplaythrough',
        'ondurationchange', 'onpagehide', 'onmouseup', 'onkeyup', 'onmessage', 'onplaying', 'ondblclick',
        'onseeked', 'onreadystatechange', 'onstalled'
    ];

    public static $quotes = ['\'', '"', ''];

    public static $http_protocol = ['http', 'https', 'php', 'zlib', 'data', 'glob', 'phar', 'ssh2', 'rar', 'ogg', 'expect', 'data', 'ftp', 'dict', 'gopher', 'file'];

    public static $command_spaces = [' ', "\t", "\r", "\n", '${IFS}', '$IFS$9', ',', ''];
    public static $command_names = [
        'whoami', 'cat', 'uid', 'ls', 'ping', 'curl', 'cd', 'dir', 'type', 'touch',
        'more', 'less', 'head', 'tail', 'sleep', 'rev', 'sh', 'bash', 'diff', 'nl',
        'uniq', 'file', 'echo'
    ];
    public static $command_splits = ['""', '\'\'', '\\', '$9', '${not_exists}'];
    public static $command_truncates = [';', '|', '&', '&&', '||', "\r\n"];

    public static $sql_chars = '\'"?&*%_ `|^~<>=,()\\;#-';
    public static $xss_chars = '<>(),\'"=%&#';

    public static $sql_keywords = [
        'select', 'from', 'union', 'into', 'and', 'or', 'update', 'delete', 'create', 'where', 'order', 'group', 'by',
        'join', 'outfile', 'dumpfile', 'load_file', 'xp_cmdshell'
    ];
    public static $xss_keywords = ['script', 'alert', 'src', 'onerror', 'img', 'a', 'href'];
}
