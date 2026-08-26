<?php

/**
 * DNS Checker & Webmail Client Discovery API
 * Advanced Heuristic-Based Detection Engine with MX Server Probing
 * 
 * Multi-stage detection to differentiate between:
 * - Zimbra
 * - cPanel/WHM Mail
 * - Roundcube (on any server)
 * - Microsoft 365 / OWA
 * - Mimecast
 * - Rackspace
 * - SmarterMail
 * - Horde
 * - Gmail / Google
 * - Yahoo / Prodigy
 * - AOL Mail
 * - FastMail
 * - ProtonMail
 * - Zoho Mail
 * - AWS SES
 * - SendGrid
 * - MailChimp
 * - Mailgun
 * - Mandrill
 * - And more...
 * 
 * @author DNS Checker API
 * @version 3.0.0
 */

error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', dirname(__FILE__) . '/dnsChecker_errors.log');

class DNSChecker
{
    private $domain;
    private $timeout = 3;
    private $port_timeout = 2;
    private $scores = [];
    private $evidence = [];
    private $dns_records = [];
    private $detected_provider = null;
    private $confidence = 0;
    private $mx_hosts = [];

    // Comprehensive Provider Detection Patterns
    private $provider_signatures = [
        'microsoft_365' => [
            'mx_patterns' => ['protection.outlook.com', 'outlook.com', 'microsoft.com'],
            'html_indicators' => ['microsoft 365', 'outlook.office365', 'outlook.live.com', 'office365'],
            'keywords' => ['office365', 'outlook.com', 'protection.outlook.com'],
            'headers' => ['X-OWA-Version', 'X-FEServer'],
            'min_score' => 20,
            'weight' => 40
        ],
        'owa' => [
            'paths' => ['/owa/', '/ecp/', '/autodiscover.xml'],
            'html_indicators' => ['outlook web app', 'owa.css', '/owa/auth', 'OWA-CANARY'],
            'keywords' => ['microsoft exchange', 'outlook web access'],
            'cookies' => ['OWA-CANARY', 'X-OWA-CANARY'],
            'headers' => ['X-OWA-Version', 'X-FEServer', 'X-CalculatedBETarget'],
            'min_score' => 20,
            'weight' => 35
        ],
        'mimecast' => [
            'mx_patterns' => ['mimecast.com', 'eu-smtp-inbound', 'us-smtp-inbound', 'au-smtp-inbound', 'jp-smtp-inbound'],
            'html_indicators' => ['mimecast', 'mimecast-admin', 'gateway.mimecast.com'],
            'keywords' => ['mimecast'],
            'cookies' => ['mimecast_session', 'MIMECAST'],
            'min_score' => 15,
            'weight' => 35
        ],
        'rackspace' => [
            'mx_patterns' => ['emailsrvr.com', 'rackspace.com', 'rackspacemail'],
            'html_indicators' => ['rackspace email', 'apps.rackspace.com', 'webmail.rackspace.com'],
            'keywords' => ['rackspace', 'emailsrvr.com'],
            'min_score' => 15,
            'weight' => 30
        ],
        'smartermail' => [
            'paths' => ['/login.aspx', '/default.aspx', '/webmail'],
            'html_indicators' => ['smartermail', 'smartertools', 'SmarterMail'],
            'keywords' => ['smartermail', 'smartertools'],
            'headers' => ['Server: SmarterMail'],
            'min_score' => 15,
            'weight' => 25
        ],
        'zimbra' => [
            'mx_patterns' => ['zimbra.com', 'synacor.com', 'carbonio'],
            'paths' => ['/modern/', '/zimbra/', '/service/soap', '/service/preauth'],
            'html_indicators' => ['zimbra collaboration', 'carbonio', 'ZmSettings', 'ZmMsg', 'zm-web-client', '/modern/', 'zimbraVersion'],
            'keywords' => ['zimbra', 'carbonio', 'synacor'],
            'cookies' => ['ZM_AUTH_TOKEN', 'ZM_TEST'],
            'min_score' => 20,
            'weight' => 35
        ],
        'roundcube' => [
            'paths' => ['/roundcube/', '/mail/', '/webmail/', '/rc/'],
            'html_indicators' => ['roundcube webmail', 'rcmail', '_task=login', '_action=login', 'skins/elastic', 'skins/larry', '/program/js/app.js'],
            'keywords' => ['roundcube', 'rcmail'],
            'cookies' => ['roundcube_sessid'],
            'min_score' => 15,
            'weight' => 30
        ],
        'cpanel' => [
            'ports' => [2095, 2096],
            'paths' => ['/webmail', '/mail/', '/horde/', '/roundcube/'],
            'html_indicators' => ['cpanel', 'whm', 'cpsession', '/webmail/'],
            'keywords' => ['cpanel', 'whm', 'autodiscover.xml'],
            'cookies' => ['cpsession', 'horde_imp_key'],
            'min_score' => 12,
            'weight' => 25
        ],
        'horde' => [
            'paths' => ['/horde/', '/imp/', '/mail/'],
            'html_indicators' => ['horde', 'imp webmail', 'horde_imp_key'],
            'keywords' => ['horde', 'imp webmail'],
            'cookies' => ['horde_imp_key'],
            'min_score' => 12,
            'weight' => 20
        ],
        'gmail' => [
            'mx_patterns' => ['gmail-smtp-in.l.google.com', 'aspmx.l.google.com', 'google.com', 'gmail.com'],
            'html_indicators' => ['gmail', 'google mail', 'accounts.google.com'],
            'keywords' => ['gmail', 'google.com'],
            'min_score' => 20,
            'weight' => 40
        ],
        'yahoo' => [
            'mx_patterns' => ['mta5.am0.yahoodns.net', 'mta6.am0.yahoodns.net', 'yahoodns.net', 'yahoo.com'],
            'html_indicators' => ['yahoo mail', 'mail.yahoo.com', 'prodigy'],
            'keywords' => ['yahoo', 'yahoodns.net'],
            'min_score' => 20,
            'weight' => 40
        ],
        'protonmail' => [
            'mx_patterns' => ['mail.protonmail.ch', 'mailsec.protonmail.ch', 'protonmail.ch'],
            'html_indicators' => ['protonmail', 'protonemail', 'mail.protonmail.com'],
            'keywords' => ['protonmail', 'protonemail'],
            'min_score' => 15,
            'weight' => 35
        ],
        'zoho' => [
            'mx_patterns' => ['smtpin.zoho.com', 'smtpin2.zoho.com', 'zoho.com', 'zohomail'],
            'html_indicators' => ['zoho mail', 'zohomail', 'zoho.com'],
            'keywords' => ['zoho', 'zohomail.com'],
            'min_score' => 15,
            'weight' => 35
        ],
        'aol' => [
            'mx_patterns' => ['mx.aol.com', 'aol.com'],
            'html_indicators' => ['aol mail', 'mail.aol.com'],
            'keywords' => ['aol', 'aol.com'],
            'min_score' => 15,
            'weight' => 35
        ],
        'fastmail' => [
            'mx_patterns' => ['in1.messagingengine.com', 'in2.messagingengine.com', 'fastmail.fm'],
            'html_indicators' => ['fastmail', 'messagingengine.com'],
            'keywords' => ['fastmail', 'messagingengine.com'],
            'min_score' => 15,
            'weight' => 30
        ],
        'aws_ses' => [
            'mx_patterns' => ['amazonses.com', 'bounce.amazonses.com', 'outbound-smtp.amazonses.com'],
            'html_indicators' => ['amazon ses', 'amazonses.com'],
            'keywords' => ['amazonses', 'aws'],
            'min_score' => 15,
            'weight' => 35
        ],
        'sendgrid' => [
            'mx_patterns' => ['sendgrid.net', 'sg-ats.sendgrid.net'],
            'html_indicators' => ['sendgrid', 'sendgrid.net'],
            'keywords' => ['sendgrid'],
            'min_score' => 15,
            'weight' => 30
        ],
        'mailgun' => [
            'mx_patterns' => ['mxa.mailgun.org', 'mxb.mailgun.org'],
            'html_indicators' => ['mailgun', 'mailgun.org'],
            'keywords' => ['mailgun'],
            'min_score' => 15,
            'weight' => 30
        ],
        'mailchimp' => [
            'mx_patterns' => ['mailchimp.com'],
            'html_indicators' => ['mailchimp', 'mandrill'],
            'keywords' => ['mailchimp', 'mandrill'],
            'min_score' => 15,
            'weight' => 30
        ],
        'mandrill' => [
            'mx_patterns' => ['mandrill.com', 'mx.mandrill.com'],
            'html_indicators' => ['mandrill', 'mandrillapp.com'],
            'keywords' => ['mandrill'],
            'min_score' => 15,
            'weight' => 30
        ]
    ];

    public function __construct($domain)
    {
        $this->domain = trim(strtolower($domain));
        
        // Extract domain from email if needed
        if (strpos($this->domain, '@') !== false) {
            $parts = explode('@', $this->domain);
            $this->domain = end($parts);
        }

        if (filter_var($this->domain, FILTER_VALIDATE_DOMAIN) === false) {
            throw new Exception("Invalid domain: {$this->domain}");
        }

        // Initialize scores
        foreach ($this->provider_signatures as $provider => $config) {
            $this->scores[$provider] = 0;
        }
    }

    /**
     * Execute comprehensive detection scan
     */
    public function scan()
    {
        try {
            // Stage 1: MX Record Analysis (HIGH CONFIDENCE)
            $this->performDNSLookups();

            // Stage 2: Probe MX Server(s) - CRITICAL FOR DIFFERENTIATION
            $this->probeMXServers();

            // Stage 3: HTTP Redirect Detection
            $this->detectHTTPRedirects();

            // Stage 4: HTML Content Analysis
            $this->analyzeHTMLContent();

            // Stage 5: Cookie and Header Analysis
            $this->analyzeCookiesAndHeaders();

            // Stage 6: SMTP Banner Analysis
            $this->probeSMTPBanners();

            // Stage 7: Determine Best Match
            $this->determineBestMatch();

            return $this->generateReport();
        } catch (Exception $e) {
            error_log("DNS Checker Error: " . $e->getMessage());
            return [
                'success' => false,
                'error' => $e->getMessage(),
                'domain' => $this->domain
            ];
        }
    }

    /**
     * Stage 1: MX Record Analysis
     */
    private function performDNSLookups()
    {
        try {
            $mx_records = [];
            if (@dns_get_mx($this->domain, $mx_records)) {
                if (!empty($mx_records) && is_array($mx_records)) {
                    foreach ($mx_records as $record) {
                        $host = strtolower($record['host']);
                        $this->mx_hosts[] = $host;
                        $this->addEvidence("MX Record", $host, 'high');
                        
                        // Score based on known MX providers
                        foreach ($this->provider_signatures as $provider => $config) {
                            if (!isset($config['mx_patterns'])) {
                                continue;
                            }
                            foreach ($config['mx_patterns'] as $pattern) {
                                if (stripos($host, $pattern) !== false) {
                                    $weight = $config['weight'] ?? 30;
                                    $this->scores[$provider] += $weight;
                                    $this->addEvidence("MX Match", "$provider: $pattern", 'high');
                                }
                            }
                        }
                    }
                    $this->dns_records['mx'] = $mx_records;
                }
            } else {
                $this->addEvidence("DNS", "No MX records found", 'low');
            }
        } catch (Exception $e) {
            error_log("DNS Lookup Error: " . $e->getMessage());
        }
    }

    /**
     * Stage 2: Probe MX Server - DIFFERENTIATE BETWEEN LOCAL PROVIDERS
     */
    private function probeMXServers()
    {
        if (empty($this->mx_hosts)) {
            return;
        }

        $mx_host = $this->mx_hosts[0];
        $this->addEvidence("MX Host Probing", "Probing $mx_host", 'medium');

        // Probe various ports and paths on the MX server
        $this->probeMailServerPorts($mx_host);
    }

    /**
     * Probe MX server on various ports for platform identification
     */
    private function probeMailServerPorts($mx_host)
    {
        // SMTP Banner Detection (port 25, 587, 465)
        $smtp_ports = [25, 587, 465];
        foreach ($smtp_ports as $port) {
            $banner = $this->getSMTPBanner($mx_host, $port);
            if ($banner) {
                $this->analyzeMailServerBanner($banner);
            }
        }

        // HTTP/HTTPS Webmail Interfaces
        $webmail_ports = [80, 443, 8080, 8443, 2095, 2096];
        foreach ($webmail_ports as $port) {
            $protocol = in_array($port, [443, 2096, 8443]) ? 'https' : 'http';
            $url = "$protocol://$mx_host:$port";
            
            $this->probeWebmailInterface($url);
        }

        // Common webmail paths on the domain itself
        foreach ($this->provider_signatures as $provider => $config) {
            if (!isset($config['paths'])) {
                continue;
            }

            foreach ($config['paths'] as $path) {
                $url = "http://{$this->domain}$path";
                $response = $this->probeURL($url);
                
                if ($response && $response['status'] === 200) {
                    $this->analyzeWebmailResponse($response, $provider);
                }
            }
        }
    }

    /**
     * Get SMTP banner for server identification
     */
    private function getSMTPBanner($host, $port)
    {
        $timeout = 2;
        $sock = @fsockopen($host, $port, $errno, $errstr, $timeout);
        
        if (!$sock) {
            return null;
        }

        stream_set_timeout($sock, $timeout);
        $banner = @fgets($sock, 1024);
        @fclose($sock);

        return $banner ? trim($banner) : null;
    }

    /**
     * Analyze SMTP banner for platform indicators
     */
    private function analyzeMailServerBanner($banner)
    {
        $banner_lower = strtolower($banner);

        // Zimbra SMTP banner
        if (stripos($banner, 'zimbra') !== false || stripos($banner, 'synacor') !== false) {
            $this->scores['zimbra'] += 25;
            $this->addEvidence("SMTP Banner", "Zimbra detected: $banner", 'high');
        }

        // cPanel/Exim (common on cPanel)
        if (stripos($banner, 'exim') !== false) {
            $this->scores['cpanel'] += 15;
            $this->addEvidence("SMTP Banner", "Exim (cPanel): $banner", 'high');
        }

        // Postfix (common on Roundcube/standalone)
        if (stripos($banner, 'postfix') !== false) {
            $this->scores['roundcube'] += 10;
            $this->addEvidence("SMTP Banner", "Postfix: $banner", 'medium');
        }

        // Sendmail
        if (stripos($banner, 'sendmail') !== false) {
            $this->scores['roundcube'] += 8;
            $this->addEvidence("SMTP Banner", "Sendmail: $banner", 'medium');
        }

        // Microsoft Exchange
        if (stripos($banner, 'microsoft') !== false || stripos($banner, 'exchange') !== false) {
            $this->scores['owa'] += 20;
            $this->scores['microsoft_365'] += 15;
            $this->addEvidence("SMTP Banner", "Microsoft Exchange: $banner", 'high');
        }

        // SmarterMail
        if (stripos($banner, 'smartermail') !== false) {
            $this->scores['smartermail'] += 25;
            $this->addEvidence("SMTP Banner", "SmarterMail: $banner", 'high');
        }
    }

    /**
     * Probe webmail interface
     */
    private function probeWebmailInterface($url)
    {
        $response = $this->probeURL($url);
        if (!$response || $response['status'] !== 200) {
            return;
        }

        $body_lower = strtolower($response['body'] ?? '');
        $headers = $response['headers'] ?? [];

        // Check server header
        if (isset($headers['server'])) {
            $server_lower = strtolower($headers['server']);
            if (stripos($server_lower, 'zimbra') !== false) {
                $this->scores['zimbra'] += 20;
                $this->addEvidence("Webmail Server", "Zimbra webmail found at $url", 'high');
            }
            if (stripos($server_lower, 'roundcube') !== false) {
                $this->scores['roundcube'] += 25;
                $this->addEvidence("Webmail Server", "Roundcube webmail found at $url", 'high');
            }
            if (stripos($server_lower, 'microsoft') !== false || stripos($server_lower, 'exchange') !== false) {
                $this->scores['owa'] += 20;
                $this->addEvidence("Webmail Server", "OWA detected at $url", 'high');
            }
        }

        // Check body content
        if (stripos($body_lower, 'zimbraversion') !== false) {
            $this->scores['zimbra'] += 30;
            $this->addEvidence("Webmail Content", "Zimbra version detected at $url", 'high');
        }
        if (stripos($body_lower, 'zmsettings') !== false) {
            $this->scores['zimbra'] += 25;
            $this->addEvidence("Webmail Content", "Zimbra JS config found at $url", 'high');
        }
        if (stripos($body_lower, 'roundcube') !== false && stripos($body_lower, '_task=') !== false) {
            $this->scores['roundcube'] += 25;
            $this->addEvidence("Webmail Content", "Roundcube interface found at $url", 'high');
        }
        if (stripos($body_lower, 'cpanel') !== false) {
            $this->scores['cpanel'] += 15;
            $this->addEvidence("Webmail Content", "cPanel interface found at $url", 'medium');
        }
        if (stripos($body_lower, 'owa') !== false || stripos($body_lower, 'outlook web') !== false) {
            $this->scores['owa'] += 25;
            $this->addEvidence("Webmail Content", "OWA interface found at $url", 'high');
        }
    }

    /**
     * Analyze webmail response
     */
    private function analyzeWebmailResponse($response, $provider)
    {
        $body_lower = strtolower($response['body'] ?? '');
        $headers = $response['headers'] ?? [];

        if (!isset($this->provider_signatures[$provider]['html_indicators'])) {
            return;
        }

        // Check for provider-specific indicators
        if (isset($this->provider_signatures[$provider]['html_indicators'])) {
            foreach ($this->provider_signatures[$provider]['html_indicators'] as $indicator) {
                if (stripos($body_lower, strtolower($indicator)) !== false) {
                    $this->scores[$provider] += 15;
                    $this->addEvidence("Webmail Match", "$provider: $indicator", 'high');
                }
            }
        }
    }

    /**
     * Stage 3: HTTP Redirect Detection
     */
    private function detectHTTPRedirects()
    {
        $base_url = "http://{$this->domain}";

        foreach ($this->provider_signatures as $provider => $config) {
            if (!isset($config['paths'])) {
                continue;
            }

            foreach ($config['paths'] as $path) {
                $url = $base_url . $path;
                $response = $this->probeURL($url);

                if (!$response) {
                    continue;
                }

                if (in_array($response['status'], [301, 302, 303, 307])) {
                    $this->scores[$provider] += 15;
                    $this->addEvidence("HTTP Redirect", "$provider: $path", 'high');
                }

                if ($response['status'] === 200) {
                    $this->scores[$provider] += 12;
                    $this->addEvidence("HTTP 200", "$provider: $path", 'medium');
                }
            }
        }
    }

    /**
     * Stage 4: HTML Content Analysis
     */
    private function analyzeHTMLContent()
    {
        $html = $this->fetchHTML("http://{$this->domain}");

        if (!$html) {
            return;
        }

        $html_lower = strtolower($html);

        foreach ($this->provider_signatures as $provider => $config) {
            if (!isset($config['html_indicators'])) {
                continue;
            }

            foreach ($config['html_indicators'] as $indicator) {
                if (stripos($html_lower, strtolower($indicator)) !== false) {
                    $this->scores[$provider] += 10;
                    $this->addEvidence("HTML Indicator", "$provider: $indicator", 'medium');
                }
            }
        }

        $this->parseAdvancedPatterns($html);
    }

    /**
     * Parse advanced patterns
     */
    private function parseAdvancedPatterns($html)
    {
        // Roundcube form detection
        if (preg_match('/name=["\']_task["\']\s+value=["\']([^"\']+)["\']/', $html, $m)) {
            if (isset($m[1]) && in_array($m[1], ['login', 'mail'])) {
                $this->scores['roundcube'] += 10;
                $this->addEvidence("Roundcube Form", "_task={$m[1]}", 'high');
            }
        }

        // Zimbra JS variables
        if (preg_match('/ZmSettings|ZmMsg|ZmAction|zimbraVersion/', $html)) {
            $this->scores['zimbra'] += 15;
            $this->addEvidence("Zimbra JS", "Zm* variables", 'high');
        }

        // cPanel port detection
        if (preg_match('/https?:\/\/[^\/]*:20(95|96)/', $html)) {
            $this->scores['cpanel'] += 15;
            $this->addEvidence("cPanel Ports", "2095/2096", 'high');
        }

        // OWA detection
        if (preg_match('/outlook.*web.*app|owa.*canary|x-owa-version/i', $html)) {
            $this->scores['owa'] += 20;
            $this->addEvidence("OWA Pattern", "Outlook Web Access detected", 'high');
        }
    }

    /**
     * Stage 5: Cookie and Header Analysis
     */
    private function analyzeCookiesAndHeaders()
    {
        $response = $this->probeURL("http://{$this->domain}");

        if (!$response) {
            return;
        }

        $headers = $response['headers'] ?? [];

        foreach ($headers as $header_name => $header_value) {
            $header_name_lower = strtolower($header_name);

            if (strpos($header_name_lower, 'set-cookie') !== false) {
                if (stripos($header_value, 'roundcube_sessid') !== false) {
                    $this->scores['roundcube'] += 20;
                    $this->addEvidence("Cookie", "roundcube_sessid", 'high');
                }
                if (stripos($header_value, 'zm_auth_token') !== false) {
                    $this->scores['zimbra'] += 20;
                    $this->addEvidence("Cookie", "Zimbra session", 'high');
                }
                if (stripos($header_value, 'cpsession') !== false) {
                    $this->scores['cpanel'] += 20;
                    $this->addEvidence("Cookie", "cpsession", 'high');
                }
                if (stripos($header_value, 'owa-canary') !== false) {
                    $this->scores['owa'] += 20;
                    $this->addEvidence("Cookie", "OWA-CANARY", 'high');
                }
            }

            if ($header_name_lower === 'server') {
                if (stripos($header_value, 'zimbra') !== false) {
                    $this->scores['zimbra'] += 15;
                    $this->addEvidence("Server", "Zimbra", 'high');
                }
                if (stripos($header_value, 'exim') !== false || stripos($header_value, 'cpanel') !== false) {
                    $this->scores['cpanel'] += 15;
                    $this->addEvidence("Server", "cPanel/Exim", 'high');
                }
                if (stripos($header_value, 'microsoft') !== false || stripos($header_value, 'exchange') !== false) {
                    $this->scores['owa'] += 15;
                    $this->scores['microsoft_365'] += 10;
                    $this->addEvidence("Server", "Microsoft Exchange", 'high');
                }
            }
        }
    }

    /**
     * Stage 6: SMTP Banner Analysis
     */
    private function probeSMTPBanners()
    {
        if (empty($this->mx_hosts)) {
            return;
        }

        $smtp_ports = [25, 587, 465];
        foreach ($smtp_ports as $port) {
            $banner = $this->getSMTPBanner($this->mx_hosts[0], $port);
            if ($banner) {
                $this->analyzeMailServerBanner($banner);
                break; // Only need one successful connection
            }
        }
    }

    /**
     * Fetch HTML content from URL
     */
    private function fetchHTML($url)
    {
        $response = $this->probeURL($url);
        return $response ? ($response['body'] ?? '') : null;
    }

    /**
     * Probe URL with timeout and error handling
     */
    private function probeURL($url)
    {
        $ch = curl_init();
        
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0');
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);

        $response = @curl_exec($ch);
        $info = curl_getinfo($ch);
        curl_close($ch);

        if ($response === false || empty($response)) {
            return null;
        }

        $parts = explode("\r\n\r\n", $response, 2);
        $headers_text = $parts[0] ?? '';
        $body = $parts[1] ?? '';
        $headers = [];

        foreach (explode("\r\n", $headers_text) as $line) {
            if (strpos($line, ':') !== false) {
                list($name, $value) = explode(':', $line, 2);
                $headers[strtolower(trim($name))] = trim($value);
            }
        }

        return [
            'status' => $info['http_code'] ?? 0,
            'headers' => $headers,
            'body' => $body
        ];
    }

    /**
     * Determine best match based on scores
     */
    private function determineBestMatch()
    {
        arsort($this->scores);

        foreach ($this->scores as $provider => $score) {
            $min_score = $this->provider_signatures[$provider]['min_score'] ?? 10;

            if ($score >= $min_score) {
                $this->detected_provider = $provider;
                $this->confidence = min(100, ($score / 50) * 100);
                $this->addEvidence("Detection", "$provider (score: $score)", 'high');
                return;
            }
        }

        // Fallback: Use highest score even if below threshold
        $this->detected_provider = array_key_first($this->scores);
        $top_score = reset($this->scores);
        $this->confidence = max(0, min(100, ($top_score / 50) * 100));
        if ($top_score > 0) {
            $this->addEvidence("Detection", "Fallback: {$this->detected_provider} (score: $top_score)", 'medium');
        } else {
            $this->detected_provider = 'unknown';
            $this->confidence = 0;
            $this->addEvidence("Detection", "No provider detected - setting to unknown", 'low');
        }
    }

    /**
     * Add evidence for audit trail
     */
    private function addEvidence($type, $value, $severity = 'medium')
    {
        $this->evidence[] = [
            'type' => $type,
            'value' => $value,
            'severity' => $severity
        ];
    }

    /**
     * Generate final report
     */
    private function generateReport()
    {
        $high_evidence = array_filter($this->evidence, function($e) {
            return $e['severity'] === 'high';
        });

        return [
            'success' => true,
            'domain' => $this->domain,
            'provider' => $this->detected_provider ?? 'unknown',
            'confidence' => round($this->confidence, 2),
            'scores' => $this->scores,
            'mx_records' => !empty($this->dns_records['mx']) ? array_map(function($r) { return $r['host']; }, $this->dns_records['mx']) : [],
            'evidence' => array_map(function($e) { return $e['value']; }, array_slice($high_evidence, 0, 15)),
            'evidence_count' => count($this->evidence)
        ];
    }
}

/**
 * API Endpoint Handler
 */
class DNSCheckerAPI
{
    public static function handleRequest()
    {
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type');
        header('Content-Type: application/json; charset=utf-8');

        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(200);
            exit();
        }

        $domain = trim($_GET['domain'] ?? $_POST['domain'] ?? '');

        if (empty($domain)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Domain required']);
            exit();
        }

        try {
            $checker = new DNSChecker($domain);
            $result = $checker->scan();
            http_response_code(200);
            echo json_encode($result);
        } catch (Exception $e) {
            error_log("API Error: " . $e->getMessage());
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage(),
                'domain' => $domain
            ]);
        }
    }
}

if (php_sapi_name() !== 'cli') {
    DNSCheckerAPI::handleRequest();
}

if (php_sapi_name() === 'cli' && isset($argv[1])) {
    $checker = new DNSChecker($argv[1]);
    echo json_encode($checker->scan());
}
?>
