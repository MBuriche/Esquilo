<?php
require_once __DIR__ . '/cache_config.php';
/**
 * Security Configuration for REST API
 * Proteções contra SQL Injection, XSS, CSRF e outros ataques
 */

// Configurações de segurança
define('SECURITY_CONFIG', [
    'max_request_size'    => 1048576,          // 1MB
    'allowed_content_types' => ['application/json'],
    'rate_limit_requests' => 100,              // requests por minuto
    'rate_limit_window'   => 60,               // segundos
    'session_timeout'     => 3600,             // 1 hora
    'max_login_attempts'  => 5,
    'lockout_duration'    => 900,              // 15 minutos
    'password_min_length' => 8,
    'require_special_chars' => false,
    // Hosts confiáveis permitidos para requisições cross-origin
    'allowed_origins' => [
        'weizhen.games',
        'localhost',
    ]
]);

/**
 * Sanitização e validação de entrada
 */
class SecurityValidator {

    /**
     * Sanitizar string removendo caracteres perigosos
     */
    public static function sanitizeString($input, $maxLength = 255) {
        if (!is_string($input)) {
            return null;
        }

        // Remover caracteres de controle exceto \n, \r, \t
        $input = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $input);

        // Converter para UTF-8 se necessário
        if (!mb_check_encoding($input, 'UTF-8')) {
            $input = mb_convert_encoding($input, 'UTF-8', 'ISO-8859-1');
        }

        // Normalizar espaços em branco
        $input = preg_replace('/\s+/', ' ', trim($input));

        // Limitar comprimento
        if (mb_strlen($input) > $maxLength) {
            $input = mb_substr($input, 0, $maxLength);
        }

        return $input;
    }

    /**
     * Validar email
     */
    public static function validateEmail($email) {
        if (!is_string($email)) {
            return false;
        }

        $email = filter_var($email, FILTER_SANITIZE_EMAIL);
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    /**
     * Validar senha
     */
    public static function validatePassword($password) {
        if (!is_string($password)) {
            return false;
        }

        $config = SECURITY_CONFIG;

        if (mb_strlen($password) < $config['password_min_length']) {
            return false;
        }

        if ($config['require_special_chars']) {
            // Deve conter pelo menos: 1 maiúscula, 1 minúscula, 1 número, 1 caractere especial
            if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/', $password)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Validar telefone (formato brasileiro)
     */
    public static function validatePhone($phone) {
        if (!is_string($phone)) {
            return false;
        }

        // Remover caracteres não numéricos
        $phone = preg_replace('/[^0-9]/', '', $phone);

        // Validar formato brasileiro (10 ou 11 dígitos)
        return preg_match('/^[0-9]{10,11}$/', $phone);
    }

    /**
     * Validar CPF
     */
    public static function validateCPF($cpf) {
        if (!is_string($cpf)) {
            return false;
        }

        // Remover caracteres não numéricos
        $cpf = preg_replace('/[^0-9]/', '', $cpf);

        // Verificar se tem 11 dígitos
        if (strlen($cpf) != 11) {
            return false;
        }

        // Verificar se todos os dígitos são iguais
        if (preg_match('/^(\d)\1{10}$/', $cpf)) {
            return false;
        }

        // Validar dígitos verificadores
        for ($t = 9; $t < 11; $t++) {
            for ($d = 0, $c = 0; $c < $t; $c++) {
                $d += $cpf[$c] * (($t + 1) - $c);
            }
            $d = ((10 * $d) % 11) % 10;
            if ($cpf[$c] != $d) {
                return false;
            }
        }

        return true;
    }

    /**
     * Validar valor monetário
     */
    public static function validateAmount($amount) {
        if (!is_numeric($amount)) {
            return false;
        }

        $amount = (int) $amount;

        // Validar limites (em centavos)
        return $amount > 0 && $amount <= 100000000; // Máximo R$ 1.000.000,00
    }

    /**
     * Validar UUID
     */
    public static function validateUUID($uuid) {
        if (!is_string($uuid)) {
            return false;
        }

        return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $uuid);
    }

    /**
     * Sanitizar array de dados
     */
    public static function sanitizeArray($data) {
        if (!is_array($data)) {
            return [];
        }

        $sanitized = [];
        foreach ($data as $key => $value) {
            $sanitizedKey = self::sanitizeString($key, 100);
            if ($sanitizedKey !== null) {
                if (is_string($value)) {
                    $sanitized[$sanitizedKey] = self::sanitizeString($value);
                } elseif (is_array($value)) {
                    $sanitized[$sanitizedKey] = self::sanitizeArray($value);
                } else {
                    $sanitized[$sanitizedKey] = $value;
                }
            }
        }

        return $sanitized;
    }
}

/**
 * Rate Limiting
 */
class RateLimiter {
    private static $redis = null;

    /**
     * Verificar rate limit por IP
     */
    public static function checkRateLimit($ip, $limit = null, $window = null) {
        $config = SECURITY_CONFIG;
        $limit  = $limit  ?: $config['rate_limit_requests'];
        $window = $window ?: $config['rate_limit_window'];

        $key = "rate_limit_{$ip}";
        $count = self::increment($key, $window);

        return $count <= $limit;
    }
    /**
     * Limpar cache antigo
     */
    public static function cleanup() {
        $redis = self::getBackend();
        $it = null;
        while (($keys = $redis->scan($it, 'rate_limit_*')) !== false) {
            foreach ($keys as $key) {
                if ($redis->ttl($key) < 0) {
                    $redis->del($key);
                }
            }
            if ($it === 0) {
                break;
            }
        }
    }

    private static function getBackend() {
        if (self::$redis === null) {
            $config = CACHE_CONFIG;
            $url = $config['redis_url'];
            $parts = parse_url($url);
            $host = $parts['host'] ?? '127.0.0.1';
            $port = $parts['port'] ?? 6379;
            $redis = new Redis();
            $redis->connect($host, $port);
            if (isset($parts['pass'])) {
                $redis->auth($parts['pass']);
            }
            self::$redis = $redis;
        }
        return self::$redis;
    }

    public static function increment($key, $ttl) {
        $redis = self::getBackend();
        $count = $redis->incr($key);
        if ($count === 1) {
            $redis->expire($key, $ttl);
        }
        return $count;
    }
}

/**
 * Proteção contra ataques
 */
class SecurityProtection {

    // Redis backend instance
    private static $redis = null;

    // Removido método duplicado validateRequest

    private static function getBackend() {
        if (self::$redis === null) {
            $config = CACHE_CONFIG;
            $url = $config['redis_url'];
            $parts = parse_url($url);
            $host = $parts['host'] ?? '127.0.0.1';
            $port = $parts['port'] ?? 6379;
            $redis = new Redis();
            $redis->connect($host, $port);
            if (isset($parts['pass'])) {
                $redis->auth($parts['pass']);
            }
            self::$redis = $redis;
        }
        return self::$redis;
    }

    public static function increment($key, $ttl) {
        $redis = self::getBackend();
        $count = $redis->incr($key);
        if ($count === 1) {
            $redis->expire($key, $ttl);
        }
        return $count;
    }

    public static function validateRequest() {
        // Verificar método HTTP
        $method = $_SERVER['REQUEST_METHOD'] ?? '';
        if (!in_array($method, ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'])) {
            return false;
        }

        // Verificar Content-Type para POST/PATCH
        if (in_array($method, ['POST', 'PATCH'])) {
            $contentType  = $_SERVER['CONTENT_TYPE'] ?? '';
            $allowedTypes = SECURITY_CONFIG['allowed_content_types'];

            $isValidType = false;
            foreach ($allowedTypes as $type) {
                if (strpos($contentType, $type) === 0) {
                    $isValidType = true;
                    break;
                }
            }

            if (!$isValidType) {
                return false;
            }
        }

        // Verificar tamanho da requisição
        $contentLength = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
        if ($contentLength > SECURITY_CONFIG['max_request_size']) {
            return false;
        }

        return true;
    }

    /**
     * Verificar origem da requisição
     */
    public static function validateOrigin() {
        $origin  = $_SERVER['HTTP_ORIGIN']  ?? '';
        $referer = $_SERVER['HTTP_REFERER'] ?? '';

        $allowedHosts = SECURITY_CONFIG['allowed_origins'];
        $originHost   = parse_url($origin, PHP_URL_HOST);

        // Verificar Origin header
        if ($originHost && !in_array($originHost, $allowedHosts, true)) {
            return false;
        }

        // Verificar Referer header (opcional, mas recomendado)
        if ($referer) {
            $refererHost = parse_url($referer, PHP_URL_HOST);
            if ($refererHost && !in_array($refererHost, $allowedHosts, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Gerar token CSRF
     */
    public static function generateCSRFToken() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $token = bin2hex(random_bytes(32));
        $_SESSION['csrf_token'] = $token;

        return $token;
    }

    /**
     * Verificar token CSRF
     */
    public static function validateCSRFToken($token) {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $storedToken = $_SESSION['csrf_token'] ?? '';

        if (empty($storedToken) || empty($token)) {
            return false;
        }

        return hash_equals($storedToken, $token);
    }

    /**
     * Log de segurança
     */
    public static function logSecurityEvent($event, $details = []) {
        $logData = [
            'timestamp'  => date('Y-m-d H:i:s'),
            'ip'         => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'event'      => $event,
            'details'    => $details
        ];

        $logFile  = __DIR__ . '/security.log';
        $logEntry = json_encode($logData) . "\n";

        file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
    }
}

/**
 * Headers de segurança
 */
class SecurityHeaders {

 /**
     * Nonces used for inline scripts and styles
     */
    private static $scriptNonce;
    private static $styleNonce;

    /**
     * Aplicar headers de segurança
     */
    public static function apply() {
        // Headers básicos de segurança
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('X-XSS-Protection: 1; mode=block');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

        // HSTS (HTTP Strict Transport Security)
        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
            header('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload');
        }

        // Content Security Policy
        $csp = "default-src 'self'; " .
                "script-src 'self' 'nonce-" . self::getScriptNonce() . "'; " .
               "style-src 'self' 'nonce-" . self::getStyleNonce() . "'; " .
               "img-src 'self' data: https:; " .
               "font-src 'self' data:; " .
               "connect-src 'self'; " .
               "frame-ancestors 'none';";

        header("Content-Security-Policy: {$csp}");
    }
/**
     * Return nonce for inline scripts
     */
    public static function getScriptNonce() {
        if (!self::$scriptNonce) {
            self::$scriptNonce = base64_encode(random_bytes(16));
        }
        return self::$scriptNonce;
    }

    /**
     * Return nonce for inline styles
     */
    public static function getStyleNonce() {
        if (!self::$styleNonce) {
            self::$styleNonce = base64_encode(random_bytes(16));
        }
        return self::$styleNonce;
    }

    /**
     * Headers CORS seguros
     */
    public static function applyCORS($allowedOrigins = null) {
        $origins    = $allowedOrigins ?: SECURITY_CONFIG['allowed_origins'];
        $origin     = $_SERVER['HTTP_ORIGIN'] ?? '';
        $originHost = parse_url($origin, PHP_URL_HOST);

        if ($originHost && in_array($originHost, $origins, true)) {
            $scheme        = parse_url($origin, PHP_URL_SCHEME) ?: 'https';
            $allowedOrigin = $scheme . '://' . $originHost;
            header("Access-Control-Allow-Origin: {$allowedOrigin}");
            header('Vary: Origin');
        }

        header('Access-Control-Allow-Methods: GET, POST, PATCH, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token');
        header('Access-Control-Max-Age: 86400'); // 24 horas
        header('Access-Control-Allow-Credentials: true');
    }
}

/**
 * Inicializar proteções de segurança
 */
function initializeSecurity() {
    // Aplicar headers de segurança
    SecurityHeaders::apply();
    SecurityHeaders::applyCORS();

    // Validar requisição
    if (!SecurityProtection::validateRequest()) {
        http_response_code(400);
        echo json_encode(['error' => 'Requisição inválida']);
        exit;
    }

    // Validar origem
    if (!SecurityProtection::validateOrigin()) {
        http_response_code(403);
        echo json_encode(['error' => 'Origem não permitida']);
        exit;
    }

    // Verificar rate limit
    $clientIP = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (!RateLimiter::checkRateLimit($clientIP)) {
        http_response_code(429);
        echo json_encode(['error' => 'Muitas requisições. Tente novamente em alguns minutos.']);
        SecurityProtection::logSecurityEvent('rate_limit_exceeded', ['ip' => $clientIP]);
        exit;
    }

   // Limpeza das chaves expiradas
    RateLimiter::cleanup();
}
