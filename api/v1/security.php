<?php
/**
 * Security Configuration for REST API
 * Proteções contra SQL Injection, XSS, CSRF e outros ataques
 */

// Configurações de segurança
define('SECURITY_CONFIG', [
    'max_request_size' => 1048576, // 1MB
    'allowed_content_types' => ['application/json'],
    'rate_limit_requests' => 100, // requests por minuto
    'rate_limit_window' => 60, // segundos
    'session_timeout' => 3600, // 1 hora
    'max_login_attempts' => 5,
    'lockout_duration' => 900, // 15 minutos
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
@@ -269,79 +269,67 @@ class SecurityProtection {
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
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        $referer = $_SERVER['HTTP_REFERER'] ?? '';

        $allowedHosts = SECURITY_CONFIG['allowed_origins'];
        $originHost = parse_url($origin, PHP_URL_HOST);

        // Verificar Origin header
        if ($originHost && !in_array($originHost, $allowedHosts, true)) {
            return false;
        }

        // Verificar Referer header (opcional, mas recomendado)
        if ($referer) {
            $refererHost = parse_url($referer, PHP_URL_HOST);
            if ($refererHost && !in_array($refererHost, $allowedHosts, true)) {
