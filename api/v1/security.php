 (cd "$(git rev-parse --show-toplevel)" && git apply --3way <<'EOF' 
diff --git a/api/v1/security.php b/api/v1/security.php
index 60375969b3ea9bbc83b0a5a84b682ada25cba63a..9aa6277263f3b158da87b09e171f9c0ed92b435e 100644
--- a/api/v1/security.php
+++ b/api/v1/security.php
@@ -1,46 +1,46 @@
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
+    // Hosts confiáveis permitidos para requisições cross-origin
     'allowed_origins' => [
-        'https://asthec.site/',
-        'https://asthec.site',
-        'https://localhost',
+        'weizhen.games',
+        'localhost',
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
diff --git a/api/v1/security.php b/api/v1/security.php
index 60375969b3ea9bbc83b0a5a84b682ada25cba63a..9aa6277263f3b158da87b09e171f9c0ed92b435e 100644
--- a/api/v1/security.php
+++ b/api/v1/security.php
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
-        
-        $allowedOrigins = SECURITY_CONFIG['allowed_origins'];
-        
+
+        $allowedHosts = SECURITY_CONFIG['allowed_origins'];
+        $originHost = parse_url($origin, PHP_URL_HOST);
+
         // Verificar Origin header
-        if ($origin && !in_array($origin, $allowedOrigins)) {
+        if ($originHost && !in_array($originHost, $allowedHosts, true)) {
             return false;
         }
-        
+
         // Verificar Referer header (opcional, mas recomendado)
         if ($referer) {
-            $parsedReferer = parse_url($referer);
-            $refererHost = $parsedReferer['host'] ?? '';
-            
-            $isValidReferer = false;
-            foreach ($allowedOrigins as $allowedOrigin) {
-                $parsedAllowed = parse_url($allowedOrigin);
-                $allowedHost = $parsedAllowed['host'] ?? '';
-                
-                if ($refererHost === $allowedHost) {
-                    $isValidReferer = true;
-                    break;
-                }
-            }
-            
-            if (!$isValidReferer) {
+            $refererHost = parse_url($referer, PHP_URL_HOST);
+            if ($refererHost && !in_array($refererHost, $allowedHosts, true)) {
                 return false;
             }
         }
-        
+
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
         
diff --git a/api/v1/security.php b/api/v1/security.php
index 60375969b3ea9bbc83b0a5a84b682ada25cba63a..9aa6277263f3b158da87b09e171f9c0ed92b435e 100644
--- a/api/v1/security.php
+++ b/api/v1/security.php
@@ -390,68 +378,73 @@ class SecurityHeaders {
         header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
         
         // HSTS (HTTP Strict Transport Security)
         if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
             header('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload');
         }
         
         // Content Security Policy
         $csp = "default-src 'self'; " .
                 "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " .
                 "style-src 'self' 'unsafe-inline'; " .
                 "img-src 'self' data: https:; " .
                 "font-src 'self' data:; " .
                 "connect-src 'self'; " .
                 "frame-ancestors 'none';";
         
         header("Content-Security-Policy: {$csp}");
     }
     
     /**
      * Headers CORS seguros
      */
     public static function applyCORS($allowedOrigins = null) {
         $origins = $allowedOrigins ?: SECURITY_CONFIG['allowed_origins'];
         $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
-        
-        if (in_array($origin, $origins)) {
-            header("Access-Control-Allow-Origin: {$origin}");
+        $originHost = parse_url($origin, PHP_URL_HOST);
+
+        if ($originHost && in_array($originHost, $origins, true)) {
+            $scheme = parse_url($origin, PHP_URL_SCHEME) ?: 'https';
+            $allowedOrigin = $scheme . '://' . $originHost;
+            header("Access-Control-Allow-Origin: {$allowedOrigin}");
+            header('Vary: Origin');
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
+    SecurityHeaders::applyCORS();
     
     // Validar requisição
     
     
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
     
     // Limpar cache antigo periodicamente
     if (rand(1, 100) === 1) {
         RateLimiter::cleanup();
     }
 } 
 
EOF
)
