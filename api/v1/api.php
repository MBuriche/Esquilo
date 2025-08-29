<?php

/*
_____  _    _ _____ _      _  __     _______   _____
|  __ \| |  | |_   _| |    | | \ \   / /  __ \ / ____|
| |__) | |__| | | | | |    | |  \ \_/ /| |__) | (___
|  ___/|  __  | | | | |    | |   \   / |  ___/ \___ \
| |    | |  | |_| |_| |____| |____| |  | |     ____) |
|_|    |_|  |_|_____|______|______|_|  |_|    |_____/

Rest Api, Ryan phillyps. TG: @phillyps / WPP: +5543999203901

*/

/*-----------------------------------------------------------------------------------------------*/
/* Main Settings REST API PHILLYPS V3 */

// Configurações de segurança
if (getenv('APP_ENV') !== 'production') {
    ini_set('display_errors', 1);
    error_reporting(E_ALL);
} else {
    ini_set('display_errors', 0); // Desabilitar exibição de erros em produção
    error_reporting(0);
}
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/error.log');

// Incluir configurações de segurança
require_once __DIR__ . '/security.php';

// Inicializar proteções de segurança
initializeSecurity();

// Obter Dados Enviados Via Req com sanitização
$rawInput = file_get_contents("php://input");
$data = json_decode($rawInput, true);

// Sanitizar dados de entrada
if (is_array($data)) {
    $data = SecurityValidator::sanitizeArray($data);
} else {
    $data = [];
}

// Log de requisição para auditoria
SecurityProtection::logSecurityEvent('api_request', [
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'unknown',
    'uri' => $_SERVER['REQUEST_URI'] ?? 'unknown',
    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
]);

/*-----------------------------------------------------------------------------------------------*/
/* Main Functions REST API PHILLYPS V3 */

/**
 * Função para lidar com a resposta de erro
 * @param int $code Código de status HTTP
 * @param string $message Mensagem de erro
 */
function sendError($code, $message, $field = null)
{
    http_response_code($code);

    $response = [
        'message' => $message
    ];

    if ($field) {
        $response['errors'] = [
            $field => [$message]
        ];
    } else {
        $response['errors'] = [
            'general' => [$message]
        ];
    }

    echo json_encode($response);
    exit;
}

// Verificação de rotas
$rotaEncontrada = false;

// Método Da Requisição
$requestMethod = $_SERVER['REQUEST_METHOD'];

// Url De Origem Da Req
$requestURI = $_SERVER['REQUEST_URI'];

// Debug: Log da rota acessada (descomente para debug)
// error_log("API Debug: Método=" . $requestMethod . " URI=" . $requestURI);

/*-----------------------------------------------------------------------------------------------*/
/* API Middleware - Garantir que a API SEMPRE retorne JSON */

/**
 * Middleware de segurança para garantir que esta API nunca sirva HTML
 */
function forceJsonResponse()
{
    // Definir headers de resposta JSON obrigatórios
    header('Content-Type: application/json; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');

    // Verificar se a requisição é realmente para a API
    $uri = $_SERVER['REQUEST_URI'];

    // Log da URI para debug
    //error_log("API Debug: URI recebida: " . $uri);

    // Registrar um handler para garantir que qualquer saída seja JSON
    register_shutdown_function(function () {
        $lastError = error_get_last();
        if ($lastError && in_array($lastError['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_CORE_WARNING, E_COMPILE_ERROR, E_COMPILE_WARNING])) {
            // Se houver erro fatal, garantir resposta JSON
            if (!headers_sent()) {
                header('Content-Type: application/json; charset=UTF-8');
                http_response_code(500);
            }
            echo json_encode([
                'error' => 'Internal Server Error',
                'message' => 'An error occurred while processing the request'
            ]);
        }
    });
}

// Executar o middleware
forceJsonResponse();

/*-----------------------------------------------------------------------------------------------*/

/* Dependencias Da Api */
include_once "./../../config.php";
include_once "./../../" . DASH . "/services-prod/prod.php";
include_once "./../../" . DASH . "/services/database.php";
include_once "./../../" . DASH . "/services/funcao.php";
include_once "./../../" . DASH . "/services/crud.php";
include_once "./../../" . DASH . "/services/CSRF_Protect.php";
$csrf = new CSRF_Protect();

/*-----------------------------------------------------------------------------------------------*/

// Aplicar headers CORS seguros (agora via cors.php)
// SecurityHeaders::applyCORS([$url_base]);

// Headers CORS agora são gerenciados pelo cors.php
// Removidos para evitar duplicação

$WG_BUCKET_SITE = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") .
    "://" . $_SERVER['HTTP_HOST'];

/*-----------------------------------------------------------------------------------------------*/
/* JWT Functions */

// Chave secreta para JWT (altere para uma chave mais segura em produção)
define('JWT_SECRET_KEY', 'sua_chave_secreta_jwt_super_segura_123456789');

/**
 * Gerar token JWT
 * @param array $payload Dados do payload do token
 * @param int $expirationTime Tempo de expiração em segundos (padrão: 7200)
 * @return string Token JWT gerado
 */
function generateJWT($payload, $expirationTime = 7200)
{
    $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);

    $payload['iat'] = time();
    $payload['exp'] = time() + $expirationTime;
    $payload = json_encode($payload);

    $base64Header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
    $base64Payload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));

    $signature = hash_hmac('sha256', $base64Header . "." . $base64Payload, JWT_SECRET_KEY, true);
    $base64Signature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

    return $base64Header . "." . $base64Payload . "." . $base64Signature;
}

/**
 * Verificar token JWT
 * @param string $token Token JWT a ser verificado
 * @return array|false Payload do token se válido, false caso contrário
 */
function verifyJWT($token)
{
    //error_log("JWT Debug: Iniciando verificação do token: " . substr($token, 0, 30) . "...");

    if (!$token) {
        error_log("JWT Debug: Token vazio");
        return false;
    }

    $tokenParts = explode('.', $token);
    if (count($tokenParts) !== 3) {
        //error_log("JWT Debug: Token não possui 3 partes. Partes encontradas: " . count($tokenParts));
        return false;
    }

    $header = base64_decode(str_replace(['-', '_'], ['+', '/'], $tokenParts[0]));
    $payload = base64_decode(str_replace(['-', '_'], ['+', '/'], $tokenParts[1]));
    $signatureProvided = $tokenParts[2];

    //error_log("JWT Debug: Header decodificado: " . $header);
    //error_log("JWT Debug: Payload decodificado: " . $payload);

    $base64Header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
    $base64Payload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));

    $signature = hash_hmac('sha256', $base64Header . "." . $base64Payload, JWT_SECRET_KEY, true);
    $base64Signature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

    if (!hash_equals($base64Signature, $signatureProvided)) {
        // error_log("JWT Debug: Assinatura inválida. Esperada: " . $base64Signature . " | Recebida: " . $signatureProvided);
        return false;
    }

    $payloadData = json_decode($payload, true);

    if (!$payloadData) {
        // error_log("JWT Debug: Erro ao decodificar payload JSON");
        return false;
    }

    //error_log("JWT Debug: Payload decodificado com sucesso: " . print_r($payloadData, true));

    if (isset($payloadData['exp']) && $payloadData['exp'] < time()) {
        // error_log("JWT Debug: Token expirado. Exp: " . $payloadData['exp'] . " | Now: " . time());
        return false;
    }

    // error_log("JWT Debug: Token válido!");
    return $payloadData;
}

/**
 * Obter token do header Authorization
 * @return string|null Token Bearer extraído do header, null se não encontrado
 */
function getBearerToken()
{
    $authHeader = null;

    // Primeiro tenta getallheaders()
    if (function_exists('getallheaders')) {
        $headers = getallheaders();
        if ($headers) {
            $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? null;
        }
    }

    // Fallback para $_SERVER
    if (!$authHeader) {
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? null;
    }

    // Debug: Log do header encontrado
    //error_log("JWT Debug: Header Authorization = " . ($authHeader ?: 'null'));

    if ($authHeader && preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
        $bearerValue = trim($matches[1]);

        // Se o valor contém "|", pega apenas a parte após o "|" (que é o token JWT)
        if (strpos($bearerValue, '|') !== false) {
            $parts = explode('|', $bearerValue, 2);
            $token = $parts[1]; // Pega a segunda parte (o token JWT)
            //error_log("JWT Debug: Token JWT extraído após | : " . substr($token, 0, 30) . "...");
        } else {
            $token = $bearerValue; // Se não tem "|", usa o valor todo
            //error_log("JWT Debug: Token JWT extraído diretamente: " . substr($token, 0, 30) . "...");
        }

        return $token;
    }

    //error_log("JWT Debug: Nenhum token Bearer encontrado");
    return null;
}

/**
 * Verificar autenticação JWT
 * @return array Payload do token JWT autenticado
 * @throws Exception Se o token for inválido ou não fornecido
 */
function authenticateJWT()
{
    // Primeiro, tentar autenticar via JWT Bearer token
    $token = getBearerToken();
    if ($token) {
        $payload = verifyJWT($token);
        if ($payload) {
            return $payload;
        }
    }

    // Se não conseguir via JWT, tentar via sessão/cookies
    if (isset($_SESSION['user_id']) && isset($_SESSION['jwt_token'])) {
        // Verificar se o token da sessão ainda é válido
        $sessionToken = $_SESSION['jwt_token'];
        $payload = verifyJWT($sessionToken);
        if ($payload) {
            return $payload;
        } else {
            // Token da sessão expirou, limpar sessão
            session_destroy();
        }
    }

    // Se chegou aqui, nenhuma autenticação funcionou
    http_response_code(401);
    echo json_encode([
        "success" => false,
        "message" => "Token de acesso requerido"
    ]);
    exit;
}

/*-----------------------------------------------------------------------------------------------*/

switch ($requestMethod) {
    case 'POST':
        /* Rotas POST */
        // Rota /register (POST)
        if (parse_url($requestURI, PHP_URL_PATH) === '/register') {
            $rotaEncontrada = true; // Rota encontrada

            // Validar dados obrigatórios
            if (!isset($data['password']) || !isset($data['phone']) || !isset($data['name'])) {
                $response = [
                    "success" => false,
                    "message" => "Todos os campos são obrigatórios"
                ];
                http_response_code(400);
                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                exit;
            }

            // Sanitizar e validar dados
            $email = SecurityValidator::sanitizeString($data['name']);
            $senha = $data['password']; // Não sanitizar senha
            $telefone = SecurityValidator::sanitizeString($data['phone']);
            $nome = SecurityValidator::sanitizeString($data['name']);
            $code = isset($data['referral_id']) ? SecurityValidator::sanitizeString($data['referral_id']) : null;

            // Validar email
            /*if (!SecurityValidator::validateEmail($email)) {
                $response = [
                    "success" => false,
                    "message" => "Email inválido"
                ];
                http_response_code(400);
                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                exit;
            }*/

            // Validar senha
            if (!SecurityValidator::validatePassword($senha)) {
                $response = [
                    "success" => false,
                    "message" => "Senha deve ter pelo menos 8 caracteres, incluindo maiúscula, minúscula, número e caractere especial"
                ];
                http_response_code(400);
                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                exit;
            }

            // Validar telefone
            //if (!SecurityValidator::validatePhone($telefone)) {
            //   $response = [
            //        "success" => false,
            //        "message" => "Telefone inválido"
            //    ];
            //    http_response_code(400);
            //    echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            //    exit;
            //}

            // Validar nome
            if (mb_strlen($nome) < 2 || mb_strlen($nome) > 100) {
                $response = [
                    "success" => false,
                    "message" => "Nome deve ter entre 2 e 100 caracteres"
                ];
                http_response_code(400);
                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                exit;
            }

            // Gera nome de usuário aleatório
            $usuario = 'user' . substr(bin2hex(random_bytes(3)), 0, 6);

            // Verifica se o e-mail já existe
            $stmt = $mysqli->prepare("SELECT id FROM usuarios WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows > 0) {
                // Usuário já existe
                $response = [
                    "success" => false,
                    "message" => "Usuário já existe"
                ];
            } else {
                // Insere novo usuário
                $data_registro = date("Y-m-d H:i:s");
                $saldo = 0;
                $password_hash = password_hash($senha, PASSWORD_DEFAULT);

                $stmt = $mysqli->prepare("INSERT INTO usuarios (email, celular, password, saldo, url, data_registro, usuario, invitation_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
                $stmt->bind_param("ssssssss", $email, $telefone, $password_hash, $saldo, $url_base, $data_registro, $nome, $code);

                if ($stmt->execute()) {
                    $userId = $mysqli->insert_id;

                    // Se o usuário foi registrado com um código de convite, processar afiliação
                    if ($code) {
                        // Buscar o usuário que indicou pelo código de convite
                        $stmtAfiliado = $mysqli->prepare("SELECT id FROM usuarios WHERE codigo_convite = ?");
                        $stmtAfiliado->bind_param("s", $code);
                        $stmtAfiliado->execute();
                        $resultAfiliado = $stmtAfiliado->get_result();
                        $afiliado = $resultAfiliado->fetch_assoc();
                        $stmtAfiliado->close();

                        if ($afiliado) {
                            $afiliadoId = $afiliado['id'];

                            // Verificar se o afiliado já existe na tabela afiliados
                            $stmtVerificar = $mysqli->prepare("SELECT id FROM afiliados WHERE user_id = ?");
                            $stmtVerificar->bind_param("i", $afiliadoId);
                            $stmtVerificar->execute();
                            $resultVerificar = $stmtVerificar->get_result();
                            $afiliadoExiste = $resultVerificar->fetch_assoc();
                            $stmtVerificar->close();

                            if ($afiliadoExiste) {
                                // Atualizar afiliado existente - incrementar registrations
                                $stmtUpdate = $mysqli->prepare("UPDATE afiliados SET registrations = registrations + 1 WHERE user_id = ?");
                                $stmtUpdate->bind_param("i", $afiliadoId);
                                $stmtUpdate->execute();
                                $stmtUpdate->close();
                            } else {
                                // Criar novo registro na tabela afiliados para o afiliado
                                $stmtInsert = $mysqli->prepare("INSERT INTO afiliados (user_id, code, visitors, registrations, depositors, deposited, earned, available) VALUES (?, ?, 0, 1, 0, 0.00, 0.00, 0.00)");
                                $stmtInsert->bind_param("is", $afiliadoId, $code);
                                $stmtInsert->execute();
                                $stmtInsert->close();
                            }
                        }
                    }

                    // Gerar token JWT
                    $jwtPayload = [
                        'user_id' => $userId,
                        'email' => $email,
                        'usuario' => $nome
                    ];
                    $jwtToken = generateJWT($jwtPayload);

                    // Debug: Log do token gerado
                    //error_log("JWT Debug - Registro: Token gerado = " . substr($jwtToken, 0, 50) . "...");

                    // Salvar dados do usuário na sessão
                    $_SESSION['user_id'] = $userId;
                    $_SESSION['user_email'] = $email;
                    $_SESSION['user_name'] = $nome;
                    $_SESSION['jwt_token'] = $jwtToken;

                    // Definir cookies de sessão
                    $sessionName = 'weizhen_gamming_session';
                    $xsrfToken = bin2hex(random_bytes(32));

                    // Cookie da sessão principal
                    setcookie($sessionName, session_id(), [
                        'expires' => time() + 7200, // 2 horas
                        'path' => '/',
                        'httponly' => true,
                        'samesite' => 'Lax',
                        'secure' => isset($_SERVER['HTTPS'])
                    ]);

                    // Cookie XSRF-TOKEN
                    setcookie('XSRF-TOKEN', $xsrfToken, [
                        'expires' => time() + 7200, // 2 horas
                        'path' => '/',
                        'samesite' => 'Lax',
                        'secure' => isset($_SERVER['HTTPS'])
                    ]);

                    $response = [
                        "success" => true,
                        "message" => "Conta criada com sucesso!",
                        "user" => [
                            "id" => $userId,
                            "name" => $nome,
                            "phone" => $telefone,
                            "email" => $email,
                            "created_at" => $data_registro,
                            "updated_at" => $data_registro
                        ],
                        "token" => $jwtToken
                    ];

                } else {
                    $response = [
                        "success" => false,
                        "message" => "Erro ao criar usuário"
                    ];
                }
            }

            $stmt->close();
            $mysqli->close();

            echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        }

        // Rota login-to-game (POST)
        if ($requestURI === '/login-to-game') {
            $rotaEncontrada = true; // Rota encontrada

            $startTime = microtime(true); // Para calcular o tempo de execução

            // Validar dados obrigatórios
            if (!isset($data['email']) || !isset($data['password'])) {
                sendError(422, "Email e senha são obrigatórios.", "email");
            }

            // Sanitizar dados
            $email = SecurityValidator::sanitizeString($data['email']);
            $senha = $data['password']; // Não sanitizar senha

            // Validar email
            /*if (!SecurityValidator::validateEmail($email)) {
                sendError(422, "Email inválido.", "email");
            }*/

            // Verificar tentativas de login (proteção contra força bruta)
            $clientIP = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $loginAttemptsKey = "login_attempts_{$clientIP}";
            $lockoutKey = "lockout_{$clientIP}";

            // Verificar se está bloqueado
            if (isset($_SESSION[$lockoutKey]) && (time() - $_SESSION[$lockoutKey]) < SECURITY_CONFIG['lockout_duration']) {
                $remainingTime = SECURITY_CONFIG['lockout_duration'] - (time() - $_SESSION[$lockoutKey]);
                SecurityProtection::logSecurityEvent('login_blocked', ['ip' => $clientIP, 'email' => $email]);
                sendError(429, "Muitas tentativas de login. Tente novamente em " . ceil($remainingTime / 60) . " minutos.", "email");
            }

            // Busca usuário pelo e-mail
            $stmt = $mysqli->prepare("SELECT id, password, celular, saldo, url, cpf, usuario, data_registro FROM usuarios WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows === 0) {
                // Usuário não existe
                sendError(422, "Credenciais inválidas.", "email");
            } else {
                $stmt->bind_result($id, $password_hash, $celular, $saldo, $url, $cpf, $usuario, $data_registro);
                $stmt->fetch();

                if (password_verify($senha, $password_hash)) {
                    // Login bem-sucedido - limpar tentativas
                    unset($_SESSION[$loginAttemptsKey]);
                    unset($_SESSION[$lockoutKey]);

                    // Buscar dados adicionais do usuário
                    $total_bet = "0.00";
                    $total_win = "0.00";
                    $cpa_receive = "0.00";
                    $revshare_receive = "0.00";
                    $chest_open = 0;
                    $chest_level = 0;
                    $give_chest = 0;
                    $pendent_comission = "0.00";
                    $by_user_id = null;
                    $rollover = "0.00";
                    $cpa_lv1 = "0.00";
                    $cpa_lv2 = "0.00";
                    $cpa_lv3 = "0.00";
                    $revshare_lv1 = "0.00";
                    $revshare_lv2 = "0.00";
                    $revshare_lv3 = "0.00";
                    $demo_account = 0;

                    // Formatar saldo para 2 casas decimais
                    $balance = number_format($saldo, 2, '.', '');

                    // Formatar data de criação
                    $created_at = $data_registro ? date('Y-m-d\TH:i:s.000000\Z', strtotime($data_registro)) : date('Y-m-d\TH:i:s.000000\Z');
                    $updated_at = $created_at;

                    $endTime = microtime(true);
                    $executionTime = round(($endTime - $startTime) * 1000, 3); // em milliseconds

                    $response = [
                        "success" => true,
                        "message" => "Login realizado com sucesso!",
                        "user" => [
                            "id" => (int) $id,
                            "name" => $usuario,
                            "email" => $email,
                            "phone" => $celular,
                            "email_verified_at" => null,
                            "role" => "user",
                            "total_bet" => $total_bet,
                            "pix_document" => $cpf,
                            "total_win" => $total_win,
                            "cpa_receive" => $cpa_receive,
                            "revshare_receive" => $revshare_receive,
                            "chest_open" => $chest_open,
                            "chest_level" => $chest_level,
                            "give_chest" => $give_chest,
                            "pendent_comission" => $pendent_comission,
                            "by_user_id" => $by_user_id,
                            "balance" => $balance,
                            "rollover" => $rollover,
                            "cpa_lv1" => $cpa_lv1,
                            "cpa_lv2" => $cpa_lv2,
                            "cpa_lv3" => $cpa_lv3,
                            "revshare_lv1" => $revshare_lv1,
                            "revshare_lv2" => $revshare_lv2,
                            "revshare_lv3" => $revshare_lv3,
                            "created_at" => $created_at,
                            "updated_at" => $updated_at,
                            "demo_account" => $demo_account
                        ]
                    ];

                    // Gerar token JWT para o usuário
                    $jwtPayload = [
                        'user_id' => $id,
                        'email' => $email,
                        'name' => $usuario
                    ];
                    $jwtToken = generateJWT($jwtPayload);

                    // Salvar dados do usuário na sessão
                    $_SESSION['user_id'] = $id;
                    $_SESSION['user_email'] = $email;
                    $_SESSION['user_name'] = $usuario;
                    $_SESSION['jwt_token'] = $jwtToken;

                    // Definir cookies de sessão
                    $sessionName = 'weizhen_gamming_session';
                    $xsrfToken = bin2hex(random_bytes(32));

                    // Cookie da sessão principal
                    setcookie($sessionName, session_id(), [
                        'expires' => time() + 7200, // 2 horas
                        'path' => '/',
                        'httponly' => true,
                        'samesite' => 'Lax',
                        'secure' => isset($_SERVER['HTTPS'])
                    ]);

                    // Cookie XSRF-TOKEN
                    setcookie('XSRF-TOKEN', $xsrfToken, [
                        'expires' => time() + 7200, // 2 horas
                        'path' => '/',
                        'samesite' => 'Lax',
                        'secure' => isset($_SERVER['HTTPS'])
                    ]);

                    // Log de login bem-sucedido
                    SecurityProtection::logSecurityEvent('login_success', ['user_id' => $id, 'email' => $email]);
                } else {
                    // Login falhou - incrementar tentativas
                    $attempts = isset($_SESSION[$loginAttemptsKey]) ? $_SESSION[$loginAttemptsKey] : 0;
                    $attempts++;
                    $_SESSION[$loginAttemptsKey] = $attempts;

                    // Verificar se deve bloquear
                    if ($attempts >= SECURITY_CONFIG['max_login_attempts']) {
                        $_SESSION[$lockoutKey] = time();
                        SecurityProtection::logSecurityEvent('login_blocked_after_attempts', ['ip' => $clientIP, 'email' => $email, 'attempts' => $attempts]);
                        sendError(429, "Muitas tentativas de login. Tente novamente em " . (SECURITY_CONFIG['lockout_duration'] / 60) . " minutos.", "email");
                    } else {
                        SecurityProtection::logSecurityEvent('login_failed', ['ip' => $clientIP, 'email' => $email, 'attempts' => $attempts]);
                        sendError(422, "Credenciais inválidas.", "email");
                    }
                }
            }

            $stmt->close();
            $mysqli->close();

            echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        }

        // Rota api/user/heartbeat (POST)
        if (parse_url($requestURI, PHP_URL_PATH) === '/api/user/heartbeat') {
            $rotaEncontrada = true; // Rota encontrada

            // Verificar autenticação JWT
            $jwtPayload = authenticateJWT();
            $userId = $jwtPayload['user_id'];

            // Retornar resposta simples de heartbeat
            $response = [
                "success" => true
            ];

            echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        }

        // Rota game/start (POST)
        if (parse_url($requestURI, PHP_URL_PATH) === '/game/start') {
            $rotaEncontrada = true; // Rota encontrada

            // Verificar autenticação JWT
            $jwtPayload = authenticateJWT();
            $userId = $jwtPayload['user_id'];

            try {
                // Validar dados obrigatórios
                if (!isset($data['amount']) || empty($data['amount'])) {
                    sendError(422, "Valor da aposta é obrigatório.", "amount");
                }

                $amount = floatval($data['amount']);

                // Validar valor mínimo e máximo
                if ($amount < 0.1 || $amount > 1000) {
                    sendError(422, "Valor da aposta deve estar entre R$ 0,10 e R$ 1.000,00.", "amount");
                }

                // Buscar saldo atual do usuário
                $stmt = $mysqli->prepare("SELECT saldo FROM usuarios WHERE id = ?");
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows === 0) {
                    sendError(404, "Usuário não encontrado.");
                }

                $stmt->bind_result($userBalance);
                $stmt->fetch();
                $stmt->close();

                // Verificar se o usuário tem saldo suficiente
                if ($userBalance < $amount) {
                    sendError(422, "Saldo insuficiente para realizar esta aposta.", "amount");
                }

                // Gerar ID único para o jogo
                $gameId = time() . rand(1000, 9999);

                // Gerar posições das raposas (foxes) - 1 ou 2 raposas em posições aleatórias
                $foxPositions = [];
                $numFoxes = rand(1, 2); // Aleatório entre 1 ou 2 raposas
                while (count($foxPositions) < $numFoxes) {
                    $position = rand(0, 8);
                    if (!in_array($position, $foxPositions)) {
                        $foxPositions[] = $position;
                    }
                }
                sort($foxPositions);
                $foxPositionsJson = json_encode($foxPositions);

                // Gerar score do jogador (simulado)
                $playerScore = rand(50, 95) + (rand(0, 99) / 100);

                // Atualizar saldo do usuário (deduzir aposta)
                $newBalance = $userBalance - $amount;
                $stmt = $mysqli->prepare("UPDATE usuarios SET saldo = ? WHERE id = ?");
                $stmt->bind_param("di", $newBalance, $userId);

                if (!$stmt->execute()) {
                    sendError(500, "Erro ao processar aposta.");
                }
                $stmt->close();

                // Registrar o jogo no banco (opcional)
                $stmt = $mysqli->prepare("INSERT INTO game_history (user_id, game_id, amount, player_score, fox_positions, created_at) VALUES (?, ?, ?, ?, ?, NOW())");
                $stmt->bind_param("isdss", $userId, $gameId, $amount, $playerScore, $foxPositionsJson);
                $stmt->execute();
                $stmt->close();

                $response = [
                    "success" => true,
                    "game" => [
                        "id" => (int) $gameId,
                        "amount" => number_format($amount, 2, '.', ''),
                        "user_balance" => number_format($newBalance, 2, '.', ''),
                        "player_score" => number_format($playerScore, 2, '.', '')
                    ]
                ];

                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

            } catch (Exception $e) {
                error_log("Erro ao iniciar jogo: " . $e->getMessage());
                sendError(500, "Erro interno do servidor.");
            }
        }

        // Rota game/open-chest (POST)
        if (parse_url($requestURI, PHP_URL_PATH) === '/game/open-chest') {
            $rotaEncontrada = true; // Rota encontrada

            // Verificar autenticação JWT
            $jwtPayload = authenticateJWT();
            $userId = $jwtPayload['user_id'];

            try {
                // Validar dados obrigatórios
                if (!isset($data['chest_index']) || !isset($data['game_id'])) {
                    sendError(422, "Índice do baú e ID do jogo são obrigatórios.", "chest_index");
                }

                $chestIndex = intval($data['chest_index']);
                $gameId = $data['game_id'];

                // Validar índice do baú (0-8)
                if ($chestIndex < 0 || $chestIndex > 8) {
                    sendError(422, "Índice do baú inválido.", "chest_index");
                }

                // Buscar dados do jogo
                $stmt = $mysqli->prepare("SELECT amount, player_score, prize_amount, game_result, fox_positions FROM game_history WHERE game_id = ? AND user_id = ? ORDER BY id DESC LIMIT 1");
                $stmt->bind_param("si", $gameId, $userId);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows === 0) {
                    sendError(404, "Jogo não encontrado.");
                }

                $stmt->bind_result($gameAmount, $playerScore, $currentPrizeAmount, $currentGameResult, $foxPositionsJson);
                $stmt->fetch();
                $stmt->close();

                // Inicializar valores se não existirem
                $currentPrizeAmount = $currentPrizeAmount ?? 0;
                $currentGameResult = $currentGameResult ?? 'em_andamento';

                // Decodificar posições das raposas do JSON
                $foxPositions = json_decode($foxPositionsJson, true) ?? [];

                // Buscar saldo atual do usuário
                $stmt = $mysqli->prepare("SELECT saldo FROM usuarios WHERE id = ?");
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $stmt->bind_result($userBalance);
                $stmt->fetch();
                $stmt->close();

                // Buscar status da caixa de premiações
                $stmt = $mysqli->prepare("SELECT ativo, valor_atual, porcentagem_distribuicao FROM caixa_premiacoes_status WHERE id = 1");
                $stmt->execute();
                $stmt->bind_result($caixaAtivo, $saldoCaixa, $rtpCaixa);
                $stmt->fetch();
                $stmt->close();

                // Verificar se a caixa está ativa
                if (!$caixaAtivo) {
                    // Caixa inativa - não pagar prêmios, apenas continuar o jogo
                    $totalWinnings = $currentPrizeAmount; // Manter o total já ganho
                    $gameOver = false;
                    $allResults = null;

                    // Atualizar game_history - jogo continua sem prêmio
                    $newPrizeAmount = $currentPrizeAmount; // Manter prêmio atual
                    $newGameResult = 'em_andamento';
                    $stmt = $mysqli->prepare("UPDATE game_history SET prize_amount = ?, game_result = ? WHERE game_id = ? AND user_id = ?");
                    $stmt->bind_param("dssi", $newPrizeAmount, $newGameResult, $gameId, $userId);
                    $stmt->execute();
                    $stmt->close();

                    $bonusChance = 14;
                    $currentPayout = $totalWinnings;

                    $response = [
                        "success" => true,
                        "chest_content" => [
                            "type" => "prize",
                            "multiplier" => 0,
                            "prize_value" => 0
                        ],
                        "is_fox" => false,
                        "multiplier" => 0,
                        "bonus_multiplier" => 1,
                        "total_winnings" => $totalWinnings,
                        "game_over" => $gameOver,
                        "all_results" => $allResults,
                        "user_balance" => number_format($userBalance, 2, '.', ''),
                        "player_score" => $playerScore,
                        "rtp_info" => [
                            "max_payout" => 0,
                            "current_payout" => $currentPayout,
                            "bonus_chance" => $bonusChance,
                            "caixa_rtp" => $rtpCaixa,
                            "saldo_caixa" => number_format($saldoCaixa, 2, '.', ''),
                            "caixa_status" => "inativa"
                        ],
                        "debug" => [
                            "chest_type" => "prize",
                            "fox_positions" => $foxPositions,
                            "total_foxes" => count($foxPositions),
                            "caixa_status" => "inativa - sem prêmios"
                        ]
                    ];

                    echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                    exit;
                }

                // Verificar se há saldo suficiente na caixa
                if ($saldoCaixa <= 0) {
                    sendError(503, "Caixa de premiações sem saldo disponível.");
                }

                // As posições das raposas já foram definidas no início do jogo e carregadas do banco

                // Verificar se o baú aberto é uma raposa
                $isFox = in_array($chestIndex, $foxPositions);

                if ($isFox) {
                    // Raposa encontrada - jogo perdido
                    $totalWinnings = $currentPrizeAmount; // Manter o total ganho até agora
                    $gameOver = true;
                    $allResults = [];

                    // Gerar todos os resultados para mostrar o que estava em cada baú
                    for ($i = 0; $i < 9; $i++) {
                        if (in_array($i, $foxPositions)) {
                            $allResults[] = [
                                "type" => "fox",
                                "multiplier" => 0
                            ];
                        } else {
                            $allResults[] = [
                                "type" => "prize",
                                "multiplier" => 0 // Não mostrar multiplicadores para baús não abertos
                            ];
                        }
                    }

                    // Atualizar game_history - jogo perdido
                    $newPrizeAmount = $currentPrizeAmount; // Manter o prêmio acumulado
                    $newGameResult = 'perdeu';
                    $stmt = $mysqli->prepare("UPDATE game_history SET prize_amount = ?, game_result = ? WHERE game_id = ? AND user_id = ?");
                    $stmt->bind_param("dssi", $newPrizeAmount, $newGameResult, $gameId, $userId);
                    $stmt->execute();
                    $stmt->close();

                    $bonusChance = 4;
                    $currentPayout = $totalWinnings;
                } else {
                    // Prêmio encontrado - usar multiplicadores fixos
                    $multipliers = [0.3, 0.5, 0.8, 2.0, 5.0]; // Multiplicadores válidos
                    $multiplier = $multipliers[array_rand($multipliers)];
                    $prizeValue = $gameAmount * $multiplier;

                    // Verificar se há saldo suficiente na caixa
                    if ($prizeValue > $saldoCaixa) {
                        $prizeValue = $saldoCaixa * 0.9; // Usar 90% do saldo restante
                        $multiplier = $prizeValue / $gameAmount;
                    }

                    $totalWinnings = $currentPrizeAmount + $prizeValue; // Somar ao total já ganho
                    $gameOver = false;
                    $allResults = null;

                    // Atualizar saldo do usuário (adicionar prêmio)
                    $newBalance = $userBalance + $prizeValue;
                    $stmt = $mysqli->prepare("UPDATE usuarios SET saldo = ? WHERE id = ?");
                    $stmt->bind_param("di", $newBalance, $userId);
                    $stmt->execute();
                    $stmt->close();

                    // Atualizar saldo da caixa (deduzir prêmio)
                    $newSaldoCaixa = $saldoCaixa - $prizeValue;
                    $stmt = $mysqli->prepare("UPDATE caixa_premiacoes_status SET valor_atual = ? WHERE id = 1");
                    $stmt->bind_param("d", $newSaldoCaixa);
                    $stmt->execute();
                    $stmt->close();

                    // Atualizar game_history - somar prêmio
                    $newPrizeAmount = $currentPrizeAmount + $prizeValue;
                    $newGameResult = 'em_andamento';
                    $stmt = $mysqli->prepare("UPDATE game_history SET prize_amount = ?, game_result = ? WHERE game_id = ? AND user_id = ?");
                    $stmt->bind_param("dssi", $newPrizeAmount, $newGameResult, $gameId, $userId);
                    $stmt->execute();
                    $stmt->close();

                    $userBalance = $newBalance;
                    $saldoCaixa = $newSaldoCaixa;
                    $bonusChance = 14;
                    $currentPayout = $totalWinnings;
                }

                $response = [
                    "success" => true,
                    "chest_content" => [
                        "type" => $isFox ? "fox" : "prize",
                        "multiplier" => $isFox ? 0 : $multiplier,
                        "prize_value" => $isFox ? 0 : $prizeValue
                    ],
                    "is_fox" => $isFox,
                    "multiplier" => $isFox ? 0 : $multiplier,
                    "bonus_multiplier" => 1,
                    "total_winnings" => $totalWinnings,
                    "game_over" => $gameOver,
                    "all_results" => $allResults,
                    "user_balance" => number_format($userBalance, 2, '.', ''),
                    "player_score" => $playerScore,
                    "rtp_info" => [
                        "max_payout" => $saldoCaixa,
                        "current_payout" => $currentPayout,
                        "bonus_chance" => $bonusChance,
                        "caixa_rtp" => $rtpCaixa,
                        "saldo_caixa" => number_format($saldoCaixa, 2, '.', '')
                    ],
                    "debug" => [
                        "chest_type" => $isFox ? "fox" : "prize",
                        "fox_positions" => $foxPositions,
                        "total_foxes" => count($foxPositions),
                        "prize_calculation" => [
                            "rtp_decimal" => $rtpCaixa / 100,
                            "max_multiplier" => 5.0,
                            "variation" => 1.0,
                            "final_multiplier" => $multiplier
                        ]
                    ]
                ];

                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

            } catch (Exception $e) {
                error_log("Erro ao abrir baú: " . $e->getMessage());
                sendError(500, "Erro interno do servidor.");
            }
        }

        // Rota game/cash-out (POST)
        if (parse_url($requestURI, PHP_URL_PATH) === '/game/cash-out') {
            $rotaEncontrada = true; // Rota encontrada

            // Verificar autenticação JWT
            $jwtPayload = authenticateJWT();
            $userId = $jwtPayload['user_id'];

            try {
                // Validar dados obrigatórios
                if (!isset($data['game_id'])) {
                    sendError(422, "ID do jogo é obrigatório.", "game_id");
                }

                $gameId = $data['game_id'];

                // Buscar dados do jogo
                $stmt = $mysqli->prepare("SELECT amount, player_score, prize_amount, game_result FROM game_history WHERE game_id = ? AND user_id = ? ORDER BY id DESC LIMIT 1");
                $stmt->bind_param("si", $gameId, $userId);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows === 0) {
                    sendError(404, "Jogo não encontrado.");
                }

                $stmt->bind_result($gameAmount, $playerScore, $prizeAmount, $gameResult);
                $stmt->fetch();
                $stmt->close();

                // Verificar se o jogo já foi finalizado
                if ($gameResult === 'win' || $gameResult === 'perdeu') {
                    sendError(400, "Jogo já foi finalizado.");
                }

                // Verificar se há prêmio para sacar
                if ($prizeAmount <= 0) {
                    sendError(400, "Não há prêmio para sacar.");
                }

                // Buscar saldo atual do usuário
                $stmt = $mysqli->prepare("SELECT saldo FROM usuarios WHERE id = ?");
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $stmt->bind_result($userBalance);
                $stmt->fetch();
                $stmt->close();

                // Atualizar saldo do usuário (adicionar prêmio)
                $newBalance = $userBalance + $prizeAmount;
                $stmt = $mysqli->prepare("UPDATE usuarios SET saldo = ? WHERE id = ?");
                $stmt->bind_param("di", $newBalance, $userId);
                $stmt->execute();
                $stmt->close();

                // Atualizar game_history - marcar como win
                $stmt = $mysqli->prepare("UPDATE game_history SET game_result = 'win' WHERE game_id = ? AND user_id = ?");
                $stmt->bind_param("si", $gameId, $userId);
                $stmt->execute();
                $stmt->close();

                $response = [
                    "success" => true,
                    "total_winnings" => number_format($prizeAmount, 2, '.', ''),
                    "user_balance" => number_format($newBalance, 2, '.', '')
                ];

                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

            } catch (Exception $e) {
                error_log("Erro ao fazer cash-out: " . $e->getMessage());
                sendError(500, "Erro interno do servidor.");
            }
        }

        // Rota /deposits (POST) - Adicionar fundos à carteira
        if (parse_url($requestURI, PHP_URL_PATH) === '/deposit') {
            $rotaEncontrada = true; // Rota encontrada

            $startTime = microtime(true); // Para calcular o tempo de execução

            // Verificar autenticação JWT
            $jwtPayload = authenticateJWT();
            $userId = $jwtPayload['user_id'];

            // Validar se o valor foi enviado
            if (!isset($data['amount'])) {
                $response = [
                    "success" => false,
                    "message" => "Valor é obrigatório"
                ];
                http_response_code(400);
                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                exit;
            }

            // Validar e sanitizar valor
            $amount = $data['amount']; // em centavos
            $cpf = $data['cpf']; // em centavos

            if (!SecurityValidator::validateAmount($amount)) {
                $response = [
                    "success" => false,
                    "message" => "Valor inválido. Deve ser maior que 0 e menor que R$ 1.000.000,00"
                ];
                http_response_code(400);
                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                exit;
            }

            /**
             * Gerar UUID v4 seguro para payment_id
             * @return string UUID v4 gerado
             */
            function generate_secure_uuid_v4()
            {
                $data = random_bytes(16);
                $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // versão 4
                $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // variante RFC 4122

                return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
            }
            $payment_id = generate_secure_uuid_v4();

            // Buscar nome do usuário
            $stmt = $mysqli->prepare("SELECT usuario, id FROM usuarios WHERE id = ? LIMIT 1");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $result = $stmt->get_result();
            $row = $result->fetch_assoc();
            $stmt->close();
            $nome_usuario = $row ? $row['usuario'] : '';
            $id_usuario = $row ? $row['id'] : '';

            // Gerar QR code real via phillyps_qrcode (valor em reais)
            $valor_reais = $amount;
            $qr_data = phillyps_qrcode($valor_reais, $nome_usuario, $id_usuario, $cpf);

            // Validar resposta da função phillyps_qrcode
            if (!$qr_data || !is_array($qr_data)) {
                $response = [
                    "success" => false,
                    "message" => $qr_data
                ];
                    

                http_response_code(500);
                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                exit;
            }

            $response = [
                "success" => true,
                "message" => "Depósito criado com sucesso",
                "data" => [
                    "amount" => $valor_reais,
                    "external_id" => $qr_data['transacao_id'] ?? null,
                    "transaction_id" => $qr_data['transacao_id'] ?? null,
                    "pix_key" => $qr_data['code'] ?? null,
                    "qr_code" => $qr_data['qrcode'] ?? null
                ]
            ];
            http_response_code(200);
            echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            $mysqli->close();
            exit;
        }

        // Rota open-chest (POST) - Abrir baú de indicações
        if (parse_url($requestURI, PHP_URL_PATH) === '/api/open-chest') {
            $rotaEncontrada = true; // Rota encontrada

            // Verificar autenticação JWT
            $jwtPayload = authenticateJWT();
            $userId = $jwtPayload['user_id'];

            try {
                // Validar dados obrigatórios
                if (!isset($data['chest_level'])) {
                    sendError(422, "Nível do baú é obrigatório.", "chest_level");
                }

                $chestLevel = intval($data['chest_level']);

                // Validar nível do baú
                if ($chestLevel < 1 || $chestLevel > 5) {
                    sendError(422, "Nível do baú deve estar entre 1 e 5.", "chest_level");
                }

                // Buscar dados do usuário
                $stmt = $mysqli->prepare("SELECT saldo, codigo_convite FROM usuarios WHERE id = ?");
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows === 0) {
                    sendError(404, "Usuário não encontrado.");
                }

                $stmt->bind_result($saldo, $codigo_convite);
                $stmt->fetch();
                $stmt->close();

                // Verificar se o usuário é afiliado
                if (empty($codigo_convite)) {
                    sendError(403, "Usuário não é afiliado.");
                }

                // Buscar configuração de depósito mínimo
                $stmt = $mysqli->prepare("SELECT mindep FROM config WHERE id = 1");
                $stmt->execute();
                $stmt->store_result();

                $mindep = $dataconfig['mindep']; // Valor padrão
                if ($stmt->num_rows > 0) {
                    $stmt->bind_result($mindep_config);
                    $stmt->fetch();
                    if (!empty($mindep_config)) {
                        $mindep_values = explode(',', $mindep_config);
                        if (!empty($mindep_values[0])) {
                            $mindep = (int) trim($mindep_values[0]);
                        }
                    }
                }
                $stmt->close();

                // Buscar usuários convidados válidos
                $stmt = $mysqli->prepare("
                    SELECT DISTINCT u.id
                    FROM usuarios u
                    LEFT JOIN transacoes t ON u.id = t.usuario AND t.tipo = 'deposito' AND t.status = 'pago'
                    WHERE u.invitation_code = ?
                    GROUP BY u.id
                    HAVING COALESCE(SUM(t.valor), 0) >= ?
                ");
                $stmt->bind_param("sd", $codigo_convite, $mindep);
                $stmt->execute();
                $result = $stmt->get_result();
                $valid_referrals_count = $result->num_rows;
                $stmt->close();

                // Verificar se tem indicações suficientes para o nível solicitado
                $required_referrals = [
                    1 => 5,
                    2 => 10,
                    3 => 20,
                    4 => 50,
                    5 => 100
                ];

                if ($valid_referrals_count < $required_referrals[$chestLevel]) {
                    sendError(400, "Você precisa de pelo menos " . $required_referrals[$chestLevel] . " indicações válidas para abrir o baú nível " . $chestLevel . ".");
                }

                // Verificar se o baú já foi aberto
                $stmt = $mysqli->prepare("SELECT id FROM bau WHERE id_user = ? AND num = ? AND is_get = 1");
                $stmt->bind_param("is", $userId, $chestLevel);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows > 0) {
                    sendError(400, "Você já abriu o baú nível " . $chestLevel . ".");
                }
                $stmt->close();

                // Gerar prêmio baseado no nível do baú
                $prizes = [
                    1 => 5,    // Nível 1: R$ 5,00
                    2 => 10,   // Nível 2: R$ 10,00
                    3 => 25,   // Nível 3: R$ 25,00
                    4 => 50,   // Nível 4: R$ 50,00
                    5 => 100   // Nível 5: R$ 100,00
                ];

                $prize_amount = $prizes[$chestLevel];

                // Atualizar saldo do usuário
                $new_balance = $saldo + $prize_amount;
                $stmt = $mysqli->prepare("UPDATE usuarios SET saldo = ? WHERE id = ?");
                $stmt->bind_param("di", $new_balance, $userId);
                $stmt->execute();
                $stmt->close();

                // Registrar o baú como aberto na tabela bau
                $token = bin2hex(random_bytes(32));
                $stmt = $mysqli->prepare("INSERT INTO bau (id_user, num, status, token, is_get) VALUES (?, ?, 'completed', ?, 1)");
                $stmt->bind_param("iss", $userId, $chestLevel, $token);
                $stmt->execute();
                $stmt->close();

                $response = [
                    "success" => true,
                    "message" => "Baú nível " . $chestLevel . " aberto com sucesso!",
                    "chest_level" => $chestLevel,
                    "prize_amount" => number_format($prize_amount, 2, '.', ''),
                    //"new_balance" => number_format($new_balance, 2, '.', ''),
                    //"token" => $token
                ];

                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

            } catch (Exception $e) {
                error_log("Erro ao abrir baú: " . $e->getMessage());
                sendError(500, "Erro interno do servidor.");
            }
        }
        if (parse_url($requestURI, PHP_URL_PATH) === '/check-payment-status') {
            $rotaEncontrada = true; // Rota encontrada

            // Verificar autenticação JWT
            $jwtPayload = authenticateJWT();
            $userId = $jwtPayload['user_id'];

            try {
                // Captura transaction_id do corpo (JSON)
                $input = json_decode(file_get_contents('php://input'), true);
                if (!isset($input['transaction_id'])) {
                    sendError(400, "transaction_id é obrigatório.");
                    exit;
                }

                $id = $input['transaction_id'];

                // Consulta no banco
                $stmt = $mysqli->prepare("SELECT status FROM transacoes WHERE transacao_id = ?");
                $stmt->bind_param("s", $id); // "s" se for string (ex: UUID). Se for INT de verdade, troque para "i"
                $stmt->execute();
                $result = $stmt->get_result();

                $row = $result->fetch_assoc();
                if ($row && $row['status'] === "pago") {
                    $response = [
                        "success" => true,
                        "paid" => true
                    ];
                } else {
                    $response = [
                        "success" => true,
                        "paid" => false
                    ];
                }

                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

            } catch (Exception $e) {
                error_log("Erro ao verificar status de pagamento: " . $e->getMessage());
                sendError(500, "Erro interno do servidor.");
            }
        }
     
        // Rota Logout (POST) -- Deslogar o usuário
        if (parse_url($requestURI, PHP_URL_PATH) === '/logout') {
            $rotaEncontrada = true; // Rota encontrada

            // Limpar dados da sessão
            if (isset($_SESSION['user_id'])) {
                unset($_SESSION['user_id']);
                unset($_SESSION['user_email']);
                unset($_SESSION['user_name']);
                unset($_SESSION['jwt_token']);
            }

            // Destruir a sessão
            session_destroy();

            // Limpar cookies de sessão
            if (isset($_COOKIE['weizhen_gamming_session'])) {
                setcookie('weizhen_gamming_session', '', time() - 3600, '/');
            }
            if (isset($_COOKIE['XSRF-TOKEN'])) {
                setcookie('XSRF-TOKEN', '', time() - 3600, '/');
            }

            // Retornar redirecionamento Inertia.js para a página de login
            http_response_code(409);
            header('X-Inertia-Location: /');
            echo json_encode([
                "success" => true,
                "message" => "Logout realizado com sucesso"
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        }

        // Rota /withdraw (POST) - Sacar fundos da carteira
        if (parse_url($requestURI, PHP_URL_PATH) === '/withdrawal') {
            $rotaEncontrada = true; // Rota encontrada

            $startTime = microtime(true); // Para calcular o tempo de execução

            // Verificar autenticação JWT
            $jwtPayload = authenticateJWT();
            $userId = $jwtPayload['user_id'];

            try {
                // Validar dados obrigatórios
                if (!isset($data['amount']) || !isset($data['pix_key']) || !isset($data['pix_type']) || !isset($data['cpf']) || !isset($data['name'])) {
                    $endTime = microtime(true);
                    $executionTime = round(($endTime - $startTime) * 1000, 3);

                    $response = [
                        "success" => false,
                        "message" => "Valor e chave PIX são obrigatórios",
                        "ms" => $executionTime
                    ];
                    http_response_code(400);
                } else {
                    $amount = $data['amount']; // em centavos
                    $pixKey = SecurityValidator::sanitizeString($data['pix_key']);
                    $pixType = SecurityValidator::sanitizeString($data['pix_type']);
                    $cpf = SecurityValidator::sanitizeString($data['cpf']);
                    $name = SecurityValidator::sanitizeString($data['name']);

                    // Validar valor (deve ser maior que 0)
                    if ($amount <= 0) {
                        $endTime = microtime(true);
                        $executionTime = round(($endTime - $startTime) * 1000, 3);

                        $response = [
                            "success" => false,
                            "message" => "Valor deve ser maior que zero",
                            "ms" => $executionTime
                        ];
                        http_response_code(400);
                    } else {
                        // Converter centavos para reais
                        $valorReais = $amount;

                        // Verificar se o usuário tem saldo suficiente
                        $stmt = $mysqli->prepare("SELECT saldo FROM usuarios WHERE id = ?");
                        $stmt->bind_param("i", $userId);
                        $stmt->execute();
                        $result = $stmt->get_result();
                        $usuario = $result->fetch_assoc();
                        $stmt->close();

                        if (!$usuario) {
                            $endTime = microtime(true);
                            $executionTime = round(($endTime - $startTime) * 1000, 3);

                            $response = [
                                "success" => false,
                                "message" => "Usuário não encontrado",
                                "ms" => $executionTime
                            ];
                            http_response_code(404);
                        } else {
                            $saldoAtual = (float) $usuario['saldo'];

                            // Verificar se tem saldo suficiente
                            if ($saldoAtual < $valorReais) {
                                $endTime = microtime(true);
                                $executionTime = round(($endTime - $startTime) * 1000, 3);

                                $response = [
                                    "success" => false,
                                    "message" => "Saldo insuficiente para este saque",
                                    "ms" => $executionTime
                                ];
                                http_response_code(400);
                            } else {
                                // Verificar rollover
                                // 1. Buscar configuração de rollover
                                $stmt = $mysqli->prepare("SELECT rollover FROM valores_config WHERE id = 1");
                                $stmt->execute();
                                $result = $stmt->get_result();
                                $config = $result->fetch_assoc();
                                $stmt->close();

                                $rollover = $config ? (float) $config['rollover'] : 1.0;

                                // 2. Calcular total de depósitos do usuário
                                $stmt = $mysqli->prepare("SELECT SUM(valor) as total_depositos FROM transacoes WHERE usuario = ? AND status = 'pago'");
                                $stmt->bind_param("i", $userId);
                                $stmt->execute();
                                $result = $stmt->get_result();
                                $depositos = $result->fetch_assoc();
                                $stmt->close();

                                $totalDepositos = $depositos ? (float) $depositos['total_depositos'] : 0.0;

                                // 3. Calcular total apostado (raspadinhas jogadas)
                                $stmt = $mysqli->prepare("SELECT SUM(amount) as total_apostado FROM game_history WHERE user_id = ? AND game_result = 'perdeu'");

                                $stmt->bind_param("i", $userId);
                                $stmt->execute();
                                $result = $stmt->get_result();
                                $apostas = $result->fetch_assoc();
                                $stmt->close();

                                $totalApostado = $apostas ? (float) $apostas['total_apostado'] : 0.0; // Converter centavos para reais

                                // 4. Verificar se atende ao rollover
                                $rolloverNecessario = $totalDepositos * $rollover;

                                if ($totalApostado < $rolloverNecessario) {
                                    $endTime = microtime(true);
                                    $executionTime = round(($endTime - $startTime) * 1000, 3);

                                    $response = [
                                        "success" => false,
                                        "message" => "Rollover não atendido. Você precisa apostar R$ " . number_format($rolloverNecessario, 2, ',', '.') . " (R$ " . number_format($totalDepositos, 2, ',', '.') . " × " . $rollover . "x). Você já apostou R$ " . number_format($totalApostado, 2, ',', '.') . ".",
                                        "ms" => $executionTime
                                    ];
                                    http_response_code(400);
                                } else {
                                    // Gerar ID de transação único
                                    $transacaoId = 'TXN_WITHDRAW_' . $userId . '_' . time() . '_' . rand(1000, 9999);

                                    // Inserir solicitação de saque
                                    $stmt = $mysqli->prepare("INSERT INTO solicitacao_saques (id_user, transacao_id, valor, tipo, pix, telefone, data_registro, status, tipo_saque, name) VALUES (?, ?, ?, ?, ?, ?, NOW(), 0, 0, ?)");
                                    $tipo = $pixType; // Tipo fixo como PIX
                                    $pix = $pixKey; // chave PIX
                                    $telefone = $cpf; // Não é telefone
                                    $stmt->bind_param("isdsiss", $userId, $transacaoId, $valorReais, $tipo, $pix, $telefone, $name);

                                    if ($stmt->execute()) {
                                        // Descontar valor do saldo do usuário
                                        $novoSaldo = $saldoAtual - $valorReais;
                                        $stmtUpdate = $mysqli->prepare("UPDATE usuarios SET saldo = ? WHERE id = ?");
                                        $stmtUpdate->bind_param("di", $novoSaldo, $userId);
                                        $stmtUpdate->execute();
                                        $stmtUpdate->close();

                                        $endTime = microtime(true);
                                        $executionTime = round(($endTime - $startTime) * 1000, 3);

                                        $response = [
                                            "success" => true,
                                            "message" => "Solicitação de saque criada com sucesso",
                                            "data" => [
                                                "amount" => $amount,
                                                "status" => "pending"
                                            ],
                                            "ms" => $executionTime
                                        ];
                                    } else {
                                        $endTime = microtime(true);
                                        $executionTime = round(($endTime - $startTime) * 1000, 3);

                                        $response = [
                                            "success" => false,
                                            "message" => "Erro ao processar solicitação de saque",
                                            "ms" => $executionTime
                                        ];
                                        http_response_code(500);
                                    }

                                    $stmt->close();
                                }
                            }
                        }
                    }
                }

            } catch (Exception $e) {
                error_log("Erro ao processar saque de usuário: " . $e->getMessage());

                $endTime = microtime(true);
                $executionTime = round(($endTime - $startTime) * 1000, 3);

                $response = [
                    "success" => false,
                    "message" => "Erro interno do servidor",
                    "ms" => $executionTime
                ];
                http_response_code(500);
            }

            echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            $mysqli->close();
            exit;
        }

        break;

    case 'GET':
        /* Rotas GET */
        // Rota api/user (GET)
        if (parse_url($requestURI, PHP_URL_PATH) === '/api/user' || parse_url($requestURI, PHP_URL_PATH) === '/api/user/') {
            $rotaEncontrada = true; // Rota encontrada

            $startTime = microtime(true); // Para calcular o tempo de execução

            // Verificar autenticação JWT
            $jwtPayload = authenticateJWT();
            $userId = $jwtPayload['user_id'];

            try {
                // Buscar dados do usuário no banco incluindo codigo_convite
                $stmt = $mysqli->prepare("SELECT id, email, usuario, celular, saldo, url, cpf, data_registro, codigo_convite FROM usuarios WHERE id = ?");
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows === 0) {
                    $endTime = microtime(true);
                    $executionTime = round(($endTime - $startTime) * 1000, 3);

                    $response = [
                        "success" => false,
                        "message" => "Usuário não encontrado",
                        "ms" => $executionTime
                    ];
                    http_response_code(404);
                } else {
                    $stmt->bind_result($id, $email, $usuario, $celular, $saldo, $url, $cpf, $data_registro, $codigo_convite);
                    $stmt->fetch();
                    $stmt->close();

                    // Buscar estatísticas do usuário
                    $withdraw_sum = 0;
                    $deposit_sum = 0;
                    $deposit_brought_count = 0;
                    $deposit_brought = 0;
                    $comission_sum = 0;
                    $rev_sum = 0;
                    $is_affiliate = 0;

                    // Verificar se é afiliado (tem código de convite)
                    if (!empty($codigo_convite)) {
                        $is_affiliate = 1;

                        // Buscar dados da tabela afiliados
                        $stmt = $mysqli->prepare("SELECT registrations, earned, available FROM afiliados WHERE user_id = ?");
                        if ($stmt) {
                            $stmt->bind_param("i", $userId);
                            $stmt->execute();
                            $stmt->store_result();

                            if ($stmt->num_rows > 0) {
                                $stmt->bind_result($registrations, $earned, $available);
                                $stmt->fetch();
                                $deposit_brought_count = (int) $registrations;
                                $comission_sum = (int) ($earned * 100); // Converter para centavos
                                $rev_sum = (int) ($available * 100); // Converter para centavos
                            }
                            $stmt->close();
                        }
                    }

                    // Buscar total de depósitos aprovados (todos os usuários)
                    $stmt = $mysqli->prepare("SELECT COALESCE(SUM(valor), 0) FROM transacoes WHERE usuario = ? AND tipo = 'deposito' AND status = 'pago'");
                    if ($stmt) {
                        $stmt->bind_param("i", $userId);
                        $stmt->execute();
                        $stmt->bind_result($deposit_sum_decimal);
                        $stmt->fetch();
                        $deposit_sum = (int) ($deposit_sum_decimal * 100); // Converter para centavos
                        $stmt->close();
                    }

                    // Buscar total de saques aprovados (todos os usuários)
                    $stmt = $mysqli->prepare("SELECT COALESCE(SUM(valor), 0) FROM solicitacao_saques WHERE id_user = ? AND status = 1");
                    if ($stmt) {
                        $stmt->bind_param("i", $userId);
                        $stmt->execute();
                        $stmt->bind_result($withdraw_sum_decimal);
                        $stmt->fetch();
                        $withdraw_sum = (int) ($withdraw_sum_decimal * 100); // Converter para centavos
                        $stmt->close();
                    }

                    $endTime = microtime(true);
                    $executionTime = round(($endTime - $startTime) * 1000, 3);

                    $response = [
                        "msg" => "Success",
                        "data" => [
                            "name" => $usuario,
                            "username" => $usuario,
                            "email" => $email,
                            "phone" => $celular,
                            "avatar" => "https://ik.imagekit.io/azx3nlpdu/flaticon_3135715.svg?updatedAt=1751619848383",
                            "affiliate_code" => $codigo_convite, // Será null se não tiver código
                            "document" => $cpf,
                            "demo_percentage" => 50,
                            "is_affiliate" => $is_affiliate,
                            "is_admin" => 0,
                            "created_at" => $data_registro ? date('c', strtotime($data_registro)) : null, // Formato ISO 8601
                            "stat" => [
                                "withdraw_sum" => $withdraw_sum,
                                "deposit_sum" => $deposit_sum,
                                "deposit_brought_count" => $deposit_brought_count,
                                "deposit_brought" => $deposit_brought,
                                "comission_sum" => $comission_sum,
                                "rev_sum" => $rev_sum
                            ]
                        ],
                        "ms" => $executionTime
                    ];
                }

            } catch (Exception $e) {
                error_log("Erro ao buscar dados do usuário: " . $e->getMessage());

                $endTime = microtime(true);
                $executionTime = round(($endTime - $startTime) * 1000, 3);

                $response = [
                    "success" => false,
                    "message" => "Erro interno do servidor",
                    "ms" => $executionTime
                ];
                http_response_code(500);
            }

            echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            $mysqli->close();
            exit;
        }

        // Rota api/user/refresh (GET)
        if (parse_url($requestURI, PHP_URL_PATH) === '/api/user/refresh') {
            $rotaEncontrada = true; // Rota encontrada

            $startTime = microtime(true); // Para calcular o tempo de execução

            // Verificar autenticação JWT
            $jwtPayload = authenticateJWT();
            $userId = $jwtPayload['user_id'];

            try {
                // Buscar dados do usuário
                $stmt = $mysqli->prepare("SELECT id, email, usuario, saldo, codigo_convite FROM usuarios WHERE id = ?");
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows === 0) {
                    sendError(404, "Usuário não encontrado.");
                } else {
                    $stmt->bind_result($id, $email, $usuario, $saldo, $codigo_convite);
                    $stmt->fetch();
                    $stmt->close();

                    // Buscar total de depósitos aprovados
                    $total_deposited = 0;
                    $stmt = $mysqli->prepare("SELECT COALESCE(SUM(valor), 0) FROM transacoes WHERE usuario = ? AND tipo = 'deposito' AND status = 'pago'");
                    if ($stmt) {
                        $stmt->bind_param("i", $userId);
                        $stmt->execute();
                        $stmt->bind_result($total_deposited_decimal);
                        $stmt->fetch();
                        $total_deposited = number_format($total_deposited_decimal, 2, '.', '');
                        $stmt->close();
                    }

                    // Buscar total de saques aprovados
                    $total_withdrawn = 0;
                    $stmt = $mysqli->prepare("SELECT COALESCE(SUM(valor), 0) FROM solicitacao_saques WHERE id_user = ? AND status = 1");
                    if ($stmt) {
                        $stmt->bind_param("i", $userId);
                        $stmt->execute();
                        $stmt->bind_result($total_withdrawn_decimal);
                        $stmt->fetch();
                        $total_withdrawn = number_format($total_withdrawn_decimal, 2, '.', '');
                        $stmt->close();
                    }

                    // Buscar saldo de comissão (se for afiliado)
                    $commission_balance = "0.00";
                    if (!empty($codigo_convite)) {
                        $stmt = $mysqli->prepare("SELECT available FROM afiliados WHERE user_id = ?");
                        if ($stmt) {
                            $stmt->bind_param("i", $userId);
                            $stmt->execute();
                            $stmt->store_result();

                            if ($stmt->num_rows > 0) {
                                $stmt->bind_result($available);
                                $stmt->fetch();
                                $commission_balance = number_format($available, 2, '.', '');
                            }
                            $stmt->close();
                        }
                    }

                    // Formatar saldo
                    $balance = number_format($saldo, 2, '.', '');

                    $response = [
                        "success" => true,
                        "user" => [
                            "id" => (int) $id,
                            "name" => $usuario,
                            "email" => $email,
                            "balance" => $balance,
                            "referral_code" => $codigo_convite,
                            "commission_balance" => $commission_balance,
                            "total_deposited" => $total_deposited,
                            "total_withdrawn" => $total_withdrawn
                        ]
                    ];

                    echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                }

            } catch (Exception $e) {
                error_log("Erro ao buscar dados do usuário: " . $e->getMessage());
                sendError(500, "Erro interno do servidor.");
            }
        }

        // Rota deposit-data (GET)
        if (parse_url($requestURI, PHP_URL_PATH) === '/deposit-data') {
            $rotaEncontrada = true; // Rota encontrada

            try {
                // Verificar autenticação JWT
                $jwtPayload = authenticateJWT();
                $userId = $jwtPayload['user_id'];

                // Buscar saldo atual do usuário
                $stmt = $mysqli->prepare("SELECT saldo FROM usuarios WHERE id = ?");
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows === 0) {
                    sendError(404, "Usuário não encontrado.");
                }

                $stmt->bind_result($saldo);
                $stmt->fetch();
                $stmt->close();

                // Buscar configurações de depósito da tabela config
                $stmt = $mysqli->prepare("SELECT mindep FROM config WHERE id = 1");
                $stmt->execute();
                $stmt->store_result();

                $depmin = 20; // Valor padrão
                $depmax = 50000; // Valor padrão

                if ($stmt->num_rows > 0) {
                    $stmt->bind_result($mindep);
                    $stmt->fetch();
                    $stmt->close();

                    // Se mindep contém valores separados por vírgula, pegar o primeiro como mínimo
                    if (!empty($mindep)) {
                        $mindep_values = explode(',', $mindep);
                        if (!empty($mindep_values[0])) {
                            $depmin = (int) trim($mindep_values[0]);
                        }

                        // Se há mais valores, pegar o último como máximo
                        if (count($mindep_values) > 1) {
                            $last_value = end($mindep_values);
                            if (!empty($last_value)) {
                                $depmax = (int) trim($last_value);
                            }
                        }
                    }
                } else {
                    $stmt->close();
                }

                // Formatar saldo
                $balance = number_format($saldo, 2, '.', '');

                // Valores recomendados de depósito
                $recommended_amounts = [20, 30, 50, 100, 200, 500, 1000];

                $response = [
                    "user" => [
                        "balance" => $balance
                    ],
                    "limits" => [
                        "min" => $depmin,
                        "max" => $depmax
                    ],
                    "recommended_amounts" => $recommended_amounts
                ];

                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

            } catch (Exception $e) {
                error_log("Erro ao buscar dados de depósito: " . $e->getMessage());
                sendError(500, "Erro interno do servidor.");
            }
        }

        // Rota withdrawal-data (GET)
        if (parse_url($requestURI, PHP_URL_PATH) === '/withdrawal-data') {
            $rotaEncontrada = true; // Rota encontrada

            try {
                // Verificar autenticação JWT
                $jwtPayload = authenticateJWT();
                $userId = $jwtPayload['user_id'];

                // Buscar dados do usuário (saldo, cpf, rollover)
                $stmt = $mysqli->prepare("SELECT saldo, cpf FROM usuarios WHERE id = ?");
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows === 0) {
                    sendError(404, "Usuário não encontrado.");
                }

                $stmt->bind_result($saldo, $cpf);
                $stmt->fetch();
                $stmt->close();

                // Buscar configurações de saque da tabela config
                $stmt = $mysqli->prepare("SELECT minsaque FROM config WHERE id = 1");
                $stmt->execute();
                $stmt->store_result();

                $saqmin = 50; // Valor padrão mínimo para saque
                $saqmax = 50000; // Valor padrão máximo para saque

                if ($stmt->num_rows > 0) {
                    $stmt->bind_result($minsaq);
                    $stmt->fetch();
                    $stmt->close();

                    // Se minsaq contém valores separados por vírgula, pegar o primeiro como mínimo
                    if (!empty($minsaq)) {
                        $minsaq_values = explode(',', $minsaq);
                        if (!empty($minsaq_values[0])) {
                            $saqmin = (int) trim($minsaq_values[0]);
                        }

                        // Se há mais valores, pegar o último como máximo
                        if (count($minsaq_values) > 1) {
                            $last_value = end($minsaq_values);
                            if (!empty($last_value)) {
                                $saqmax = (int) trim($last_value);
                            }
                        }
                    }
                } else {
                    $stmt->close();
                }
                $stmt = $mysqli->prepare("SELECT rollover FROM valores_config WHERE id = 1");
                $stmt->execute();
                $result = $stmt->get_result();
                $config = $result->fetch_assoc();
                $stmt->close();

                $rollover = $config ? (float) $config['rollover'] : 1.0;

                                // 2. Calcular total de depósitos do usuário
                $stmt = $mysqli->prepare("SELECT SUM(valor) as total_depositos FROM transacoes WHERE usuario = ? AND status = 'pago'");
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $result = $stmt->get_result();
                $depositos = $result->fetch_assoc();
                $stmt->close();

                $totalDepositos = $depositos ? (float) $depositos['total_depositos'] : 0.0;

                $stmt = $mysqli->prepare("SELECT SUM(amount) as total_apostado FROM game_history WHERE user_id = ? AND game_result = 'perdeu'");
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $result = $stmt->get_result();
                $apostas = $result->fetch_assoc();
                $stmt->close();

                $totalApostado = $apostas ? (float) $apostas['total_apostado'] : 0; // Converter centavos para reais

                $rolloverNecessario =  $totalDepositos * $rollover;

                $balance = number_format($saldo, 2, '.', '');

     
                $can_withdraw = ($saldo >= $saqmin);

                $response = [
                    "user" => [
                        "balance" => $balance,
                        "rollover" => $rolloverNecessario - $totalApostado,
                        "pix_document" => $cpf
                    ],
                    "limits" => [
                        "min" => $saqmin,
                        "max" => $saqmax
                    ],
                    "can_withdraw" => $can_withdraw
                ];

                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

            } catch (Exception $e) {
                error_log("Erro ao buscar dados de saque: " . $e->getMessage());
                sendError(500, "Erro interno do servidor.");
            }
        }

        // Rota agent-panel-data (GET)
        if (parse_url($requestURI, PHP_URL_PATH) === '/agent-panel-data') {
    $rotaEncontrada = true; // Rota encontrada

    try {
        // Verificar autenticação JWT
        $jwtPayload = authenticateJWT();
        $userId = (int)$jwtPayload['user_id'];

        // ---------- Helpers ----------
        $generateInviteCode = function(mysqli $db, int $maxTries = 8): string {
            for ($i = 0; $i < $maxTries; $i++) {
                // Gera um código curto e legível (8~10 chars)
                $rand = strtoupper(substr(base_convert((string)(time() . random_int(1000, 9999)), 10, 36), -8));
                $code = $rand;

                // Checa unicidade em usuarios.codigo_convite e afiliados.code
                $exists = false;

                // usuarios.codigo_convite
                if ($stmt = $db->prepare("SELECT 1 FROM usuarios WHERE codigo_convite = ? LIMIT 1")) {
                    $stmt->bind_param("s", $code);
                    $stmt->execute();
                    $stmt->store_result();
                    if ($stmt->num_rows > 0) $exists = true;
                    $stmt->close();
                }

                // afiliados.code
                if (!$exists && ($stmt = $db->prepare("SELECT 1 FROM afiliados WHERE code = ? LIMIT 1"))) {
                    $stmt->bind_param("s", $code);
                    $stmt->execute();
                    $stmt->store_result();
                    if ($stmt->num_rows > 0) $exists = true;
                    $stmt->close();
                }

                if (!$exists) {
                    return $code;
                }
            }
            // fallback (quase impossível chegar aqui)
            return strtoupper(bin2hex(random_bytes(4)));
        };

        // ---------- Buscar dados do usuário ----------
        if (!($stmt = $mysqli->prepare("SELECT codigo_convite FROM usuarios WHERE id = ? LIMIT 1"))) {
            sendError(500, "Erro ao preparar consulta do usuário.");
        }
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows === 0) {
            $stmt->close();
            sendError(404, "Usuário não encontrado.");
        }
        $stmt->bind_result($codigo_convite);
        $stmt->fetch();
        $stmt->close();

        // ---------- Se não for afiliado, criar código e registro ----------
        if (empty($codigo_convite)) {
            // Transação para garantir consistência
            $mysqli->begin_transaction();
            try {
                // Gerar um código único
                $novo_codigo = $generateInviteCode($mysqli);

                // Atualizar usuarios.codigo_convite
                if (!($stmt = $mysqli->prepare("UPDATE usuarios SET codigo_convite = ? WHERE id = ?"))) {
                    throw new Exception("Erro ao preparar update do código de convite.");
                }
                $stmt->bind_param("si", $novo_codigo, $userId);
                $stmt->execute();
                if ($stmt->affected_rows < 0) {
                    $stmt->close();
                    throw new Exception("Falha ao atualizar código de convite do usuário.");
                }
                $stmt->close();

                // Criar registro em afiliados se não existir
                if (!($stmt = $mysqli->prepare("SELECT 1 FROM afiliados WHERE user_id = ? LIMIT 1"))) {
                    throw new Exception("Erro ao preparar verificação de afiliado.");
                }
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $stmt->store_result();
                $jaTemAfiliado = $stmt->num_rows > 0;
                $stmt->close();

                if (!$jaTemAfiliado) {
                    if (!($stmt = $mysqli->prepare("INSERT INTO afiliados (user_id, code, visitors, registrations, depositors, deposited, earned, available) VALUES (?, ?, 0, 0, 0, 0.00, 0.00, 0.00)"))) {
                        throw new Exception("Erro ao preparar INSERT de afiliado.");
                    }
                    $stmt->bind_param("is", $userId, $novo_codigo);
                    $stmt->execute();
                    if ($stmt->affected_rows <= 0) {
                        $stmt->close();
                        throw new Exception("Falha ao inserir afiliado.");
                    }
                    $stmt->close();
                }

                // (Opcional) Criar registro de convite em tabela `convites`
                // Ajuste os campos conforme o seu schema.
                try {
                    if ($stmt = $mysqli->prepare("INSERT INTO convites (user_id, code, created_at) VALUES (?, ?, NOW())")) {
                        $stmt->bind_param("is", $userId, $novo_codigo);
                        $stmt->execute();
                        $stmt->close();
                    }
                } catch (Throwable $ignorar) {
                    // Silencia caso a tabela/colunas não existam; não é crítico para seguir.
                }

                $mysqli->commit();

                // Atualiza a variável para fluxo abaixo
                $codigo_convite = $novo_codigo;

            } catch (Throwable $e) {
                $mysqli->rollback();
                error_log("Falha ao criar afiliado/convite para user {$userId}: " . $e->getMessage());
                sendError(500, "Não foi possível criar o afiliado e o convite.");
            }
        }

        // ---------- Buscar dados da tabela afiliados ----------
        if (!($stmt = $mysqli->prepare("SELECT visitors, registrations, depositors, deposited, earned, available FROM afiliados WHERE user_id = ? LIMIT 1"))) {
            sendError(500, "Erro ao preparar consulta dos dados de afiliados.");
        }
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows === 0) {
            // Se ainda assim não tiver registro (caso raro), cria agora com o código do usuário
            $stmt->close();
            if (!($stmt = $mysqli->prepare("INSERT INTO afiliados (user_id, code, visitors, registrations, depositors, deposited, earned, available) VALUES (?, ?, 0, 0, 0, 0.00, 0.00, 0.00)"))) {
                sendError(500, "Erro ao preparar INSERT de afiliado.");
            }
            $stmt->bind_param("is", $userId, $codigo_convite);
            $stmt->execute();
            $stmt->close();

            // Valores padrão
            $visitors = 0;
            $registrations = 0;
            $depositors = 0;
            $deposited = 0.00;
            $earned = 0.00;
            $available = 0.00;

        } else {
            $stmt->bind_result($visitors, $registrations, $depositors, $deposited, $earned, $available);
            $stmt->fetch();
            $stmt->close();
        }

        // ---------- Calcular totais ----------
        $total_cpa_received      = number_format((float)$earned,   2, '.', '');
        $total_revshare_received = number_format((float)$available,2, '.', '');
        $pendent_comission       = number_format((float)$earned - (float)$available, 2, '.', '');

        // ---------- Configurações dos níveis ----------
        $cpa_mode = "percent";
        $levels = [
            "1" => [
                "count"             => (int)$registrations,
                "first_deposits"    => (int)$depositors,
                "cpa_amount"        => 50,
                "total_cpa"         => (int) round($earned   * 100),   // em centavos
                "total_deposits"    => (int) round($deposited * 100),   // em centavos
                "depositors_count"  => (int)$depositors,
            ],
            "2" => [
                "count" => 0, "first_deposits" => 0, "cpa_amount" => 10,
                "total_cpa" => 0, "total_deposits" => 0, "depositors_count" => 0
            ],
            "3" => [
                "count" => 0, "first_deposits" => 0, "cpa_amount" => 5,
                "total_cpa" => 0, "total_deposits" => 0, "depositors_count" => 0
            ],
        ];

        $response = [
            "invite_code"            => $codigo_convite,     
            "total_cpa_received"     => $total_cpa_received,
            "total_revshare_received"=> $total_revshare_received,
            "pendent_comission"      => $pendent_comission,
            "cpa_mode"               => $cpa_mode,
            "levels"                 => $levels,
        ];

        echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

    } catch (Exception $e) {
        error_log("Erro ao buscar dados do painel de agente: " . $e->getMessage());
        sendError(500, "Erro interno do servidor.");
    }
}

        // Rota referral-data (GET)
        if (parse_url($requestURI, PHP_URL_PATH) === '/api/referral-data') {
            $rotaEncontrada = true; // Rota encontrada

            try {
                // Verificar autenticação JWT
                $jwtPayload = authenticateJWT();
                $userId = $jwtPayload['user_id'];

                // Buscar dados do usuário e verificar se é afiliado
                $stmt = $mysqli->prepare("SELECT saldo, codigo_convite FROM usuarios WHERE id = ?");
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows === 0) {
                    sendError(404, "Usuário não encontrado.");
                }

                $stmt->bind_result($saldo, $codigo_convite);
                $stmt->fetch();
                $stmt->close();

                // Verificar se o usuário é afiliado
                //if (empty($codigo_convite)) {
                //    sendError(403, "Usuário não é afiliado.");
                //}

                // Buscar configuração de depósito mínimo
                $stmt = $mysqli->prepare("SELECT mindep FROM config WHERE id = 1");
                $stmt->execute();
                $stmt->store_result();

                $mindep = $dataconfig['mindep']; // Valor padrão
                if ($stmt->num_rows > 0) {
                    $stmt->bind_result($mindep_config);
                    $stmt->fetch();
                    if (!empty($mindep_config)) {
                        $mindep_values = explode(',', $mindep_config);
                        if (!empty($mindep_values[0])) {
                            $mindep = (int) trim($mindep_values[0]);
                        }
                    }
                }
                $stmt->close();

                // Buscar usuários convidados pelo afiliado que fizeram depósito mínimo
                $stmt = $mysqli->prepare("
                    SELECT DISTINCT u.id, u.usuario, u.email, u.celular, u.data_registro,
                           COALESCE(SUM(t.valor), 0) as total_deposited,
                           COUNT(t.id) as deposit_count
                    FROM usuarios u
                    LEFT JOIN transacoes t ON u.id = t.usuario AND t.tipo = 'deposito' AND t.status = 'pago'
                    WHERE u.invitation_code = ?
                    GROUP BY u.id
                    HAVING total_deposited >= ?
                    ORDER BY u.data_registro DESC
                ");
                $stmt->bind_param("sd", $codigo_convite, $mindep);
                $stmt->execute();
                $result = $stmt->get_result();

                $referrals = [];
                while ($row = $result->fetch_assoc()) {
                    $referrals[] = [
                        "id" => (int) $row['id'],
                        "username" => $row['usuario'],
                        "email" => $row['email'],
                        "phone" => $row['celular'],
                        "total_deposited" => number_format($row['total_deposited'], 2, '.', ''),
                        "deposit_count" => (int) $row['deposit_count'],
                        "created_at" => date('c', strtotime($row['data_registro']))
                    ];
                }
                $stmt->close();

                // Formatar saldo
                $balance = number_format($saldo, 2, '.', '');

                // Configurações dos baús (valores em centavos)
                $chests_rules = [5, 50, 100, 200, 250, 500];
                $chests_prizes = [5, 50, 200, 250, 300, 500];

                // Calcular chest_level baseado no número de indicações válidas
                $valid_referrals_count = count($referrals);
                $chest_level = 0;

                // Regras para liberar baús:
                // 5 indicações = chest_level 1
                // 10 indicações = chest_level 2
                // 20 indicações = chest_level 3
                // 50 indicações = chest_level 4
                // 100 indicações = chest_level 5
                if ($valid_referrals_count >= 100) {
                    $chest_level = 5;
                } elseif ($valid_referrals_count >= 50) {
                    $chest_level = 4;
                } elseif ($valid_referrals_count >= 20) {
                    $chest_level = 3;
                } elseif ($valid_referrals_count >= 10) {
                    $chest_level = 2;
                } elseif ($valid_referrals_count >= 5) {
                    $chest_level = 1;
                }

                // Buscar se o usuário já abriu o baú do nível atual
                $chest_open = 0;
                if ($chest_level > 0) {
                    $stmt = $mysqli->prepare("SELECT id FROM bau WHERE id_user = ? AND num = ? AND is_get = 1");
                    $stmt->bind_param("is", $userId, $chest_level);
                    $stmt->execute();
                    $stmt->store_result();

                    if ($stmt->num_rows > 0) {
                        $chest_open = 1; // Baú já foi aberto
                    }
                    $stmt->close();
                }

                $response = [
                    "settings" => [
                        "chests_rules" => $chests_rules,
                        "chests_prizes" => $chests_prizes
                    ],
                    "user" => [
                        "chest_level" => count($referrals),
                        "chest_open" => $chest_open,
                        "balance" => $balance
                    ],
                    "referrals" => $referrals,
                    "total_referrals" => count($referrals)
                ];

                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

            } catch (Exception $e) {
                error_log("Erro ao buscar dados de referral: " . $e->getMessage());
                sendError(500, "Erro interno do servidor.");
            }
        }

        // Rota open-chest (POST) - Abrir baú de indicações
        if (parse_url($requestURI, PHP_URL_PATH) === '/api/open-chest') {
            $rotaEncontrada = true; // Rota encontrada

            try {
                // Verificar autenticação JWT
                $jwtPayload = authenticateJWT();
                $userId = $jwtPayload['user_id'];

                // Buscar dados do usuário
                $stmt = $mysqli->prepare("SELECT saldo, codigo_convite FROM usuarios WHERE id = ?");
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows === 0) {
                    sendError(404, "Usuário não encontrado.");
                }

                $stmt->bind_result($saldo, $codigo_convite);
                $stmt->fetch();
                $stmt->close();

                // Buscar configuração de depósito mínimo
                $stmt = $mysqli->prepare("SELECT mindep FROM config WHERE id = 1");
                $stmt->execute();
                $stmt->store_result();

                $mindep = $dataconfig['mindep']; // Valor padrão
                if ($stmt->num_rows > 0) {
                    $stmt->bind_result($mindep_config);
                    $stmt->fetch();
                    if (!empty($mindep_config)) {
                        $mindep_values = explode(',', $mindep_config);
                        if (!empty($mindep_values[0])) {
                            $mindep = (int) trim($mindep_values[0]);
                        }
                    }
                }
                $stmt->close();

                // Buscar usuários convidados válidos
                $stmt = $mysqli->prepare("
                    SELECT DISTINCT u.id
                    FROM usuarios u
                    LEFT JOIN transacoes t ON u.id = t.usuario AND t.tipo = 'deposito' AND t.status = 'pago'
                    WHERE u.invitation_code = ?
                    GROUP BY u.id
                    HAVING COALESCE(SUM(t.valor), 0) >= ?
                ");
                $stmt->bind_param("sd", $codigo_convite, $mindep);
                $stmt->execute();
                $result = $stmt->get_result();
                $valid_referrals_count = $result->num_rows;
                $stmt->close();

                // Calcular chest_level atual
                $chest_level = 0;
                if ($valid_referrals_count >= 100) {
                    $chest_level = 5;
                } elseif ($valid_referrals_count >= 50) {
                    $chest_level = 4;
                } elseif ($valid_referrals_count >= 20) {
                    $chest_level = 3;
                } elseif ($valid_referrals_count >= 10) {
                    $chest_level = 2;
                } elseif ($valid_referrals_count >= 5) {
                    $chest_level = 1;
                }

                // Verificar se pode abrir o baú
                if ($chest_level === 0) {
                    sendError(400, "Você precisa de pelo menos 5 indicações válidas para abrir um baú.");
                }

                // Verificar se o baú já foi aberto
                $stmt = $mysqli->prepare("SELECT id FROM bau WHERE id_user = ? AND num = ? AND is_get = 1");
                $stmt->bind_param("is", $userId, $chest_level);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows > 0) {
                    sendError(400, "Você já abriu o baú deste nível.");
                }
                $stmt->close();

                // Gerar prêmio baseado no nível do baú
                $prizes = [
                    1 => 5,    // Nível 1: R$ 5,00
                    2 => 10,   // Nível 2: R$ 10,00
                    3 => 25,   // Nível 3: R$ 25,00
                    4 => 50,   // Nível 4: R$ 50,00
                    5 => 100   // Nível 5: R$ 100,00
                ];

                $prize_amount = $prizes[$chest_level];

                // Atualizar saldo do usuário
                $new_balance = $saldo + $prize_amount;
                $stmt = $mysqli->prepare("UPDATE usuarios SET saldo = ? WHERE id = ?");
                $stmt->bind_param("di", $new_balance, $userId);
                $stmt->execute();
                $stmt->close();

                // Registrar o baú como aberto na tabela bau
                $token = bin2hex(random_bytes(32));
                $stmt = $mysqli->prepare("INSERT INTO bau (id_user, num, status, token, is_get) VALUES (?, ?, 'completed', ?, 1)");
                $stmt->bind_param("iss", $userId, $chest_level, $token);
                $stmt->execute();
                $stmt->close();

                $response = [
                    "success" => true,
                    "message" => "Baú aberto com sucesso!",
                    "chest_level" => $chest_level,
                    "prize_amount" => number_format($prize_amount, 2, '.', ''),
                    "new_balance" => number_format($new_balance, 2, '.', ''),
                    "token" => $token
                ];

                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

            } catch (Exception $e) {
                error_log("Erro ao abrir baú: " . $e->getMessage());
                sendError(500, "Erro interno do servidor.");
            }
        }

        // Rota game-history (GET) - Histórico de jogos do usuário
        if (parse_url($requestURI, PHP_URL_PATH) === '/game-history') {
            $rotaEncontrada = true; // Rota encontrada

            try {
                // Verificar autenticação JWT
                $jwtPayload = authenticateJWT();
                $userId = $jwtPayload['user_id'];

                // Parâmetros de paginação
                $page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
                $per_page = 10;
                $offset = ($page - 1) * $per_page;

                // Contar total de registros
                $countStmt = $mysqli->prepare("SELECT COUNT(*) as total FROM game_history WHERE user_id = ?");
                $countStmt->bind_param("i", $userId);
                $countStmt->execute();
                $countResult = $countStmt->get_result();
                $totalRecords = $countResult->fetch_assoc()['total'];
                $countStmt->close();

                // Calcular informações de paginação
                $last_page = ceil($totalRecords / $per_page);
                $has_more = $page < $last_page;

                // Buscar histórico de jogos do usuário
                $stmt = $mysqli->prepare("
                    SELECT 
                        id,
                        user_id,
                        amount,
                        prize_amount,
                        player_score,
                        game_result,
                        created_at,
                        updated_at
                    FROM game_history 
                    WHERE user_id = ? 
                    ORDER BY created_at DESC 
                    LIMIT ? OFFSET ?
                ");

                $stmt->bind_param("iii", $userId, $per_page, $offset);
                $stmt->execute();
                $result = $stmt->get_result();

                $histories = [];
                while ($row = $result->fetch_assoc()) {
                    // Determinar status baseado no game_result
                    $status = 'finished';
                    if ($row['game_result'] === null) {
                        $status = 'in_progress';
                    }

                    // Determinar win baseado no prize_amount
                    $win = $row['prize_amount'] > 0 ? number_format($row['prize_amount'], 2, '.', '') : '0.00';

                    // Criar resultado JSON simulado baseado nos dados disponíveis
                    $result_json = json_encode([
                        'setup' => [
                            'chests' => [
                                ['type' => 'prize', 'multiplier' => 0.8],
                                ['type' => 'fox', 'multiplier' => 0],
                                ['type' => 'prize', 'multiplier' => 0.3],
                                ['type' => 'prize', 'multiplier' => 2],
                                ['type' => 'fox', 'multiplier' => 0],
                                ['type' => 'prize', 'multiplier' => 0.3],
                                ['type' => 'prize', 'multiplier' => 0.8],
                                ['type' => 'prize', 'multiplier' => 0.5],
                                ['type' => 'prize', 'multiplier' => 0.8]
                            ],
                            'fox_positions' => [1, 4],
                            'rtp_mode' => 'restrictive',
                            'player_score' => floatval($row['player_score']),
                            'created_at' => $row['created_at'] . '.000000Z'
                        ],
                        'opened_chests' => [4],
                        'bonus_multiplier' => 1,
                        'cash_out' => $row['prize_amount'] > 0,
                        'rtp_mode' => 'restrictive',
                        'found_fox' => $row['game_result'] === 'loss',
                        'player_score' => floatval($row['player_score'])
                    ]);

                    $histories[] = [
                        'id' => (int) $row['id'],
                        'user_id' => (int) $row['user_id'],
                        'amount' => number_format($row['amount'], 2, '.', ''),
                        'win' => $win,
                        'result' => $result_json,
                        'status' => $status,
                        'created_at' => date('Y-m-d\TH:i:s.000000\Z', strtotime($row['created_at'])),
                        'updated_at' => date('Y-m-d\TH:i:s.000000\Z', strtotime($row['updated_at']))
                    ];
                }
                $stmt->close();

                // Calcular estatísticas
                $statsStmt = $mysqli->prepare("
                    SELECT 
                        COUNT(*) as total_games,
                        COUNT(CASE WHEN prize_amount > 0 THEN 1 END) as total_wins,
                        COUNT(CASE WHEN prize_amount = 0 THEN 1 END) as total_losses,
                        COALESCE(SUM(prize_amount), 0) as total_win_amount,
                        COALESCE(SUM(amount), 0) as total_bet_amount
                    FROM game_history 
                    WHERE user_id = ?
                ");
                $statsStmt->bind_param("i", $userId);
                $statsStmt->execute();
                $statsResult = $statsStmt->get_result();
                $stats = $statsResult->fetch_assoc();
                $statsStmt->close();

                $total_games = (int) $stats['total_games'];
                $total_wins = (int) $stats['total_wins'];
                $total_losses = (int) $stats['total_losses'];
                $win_rate = $total_games > 0 ? round(($total_wins / $total_games) * 100, 0) : 0;
                $loss_rate = $total_games > 0 ? round(($total_losses / $total_games) * 100, 0) : 0;
                $total_win_amount = number_format($stats['total_win_amount'], 2, '.', '');
                $total_bet_amount = number_format($stats['total_bet_amount'], 2, '.', '');
                $net_profit = $stats['total_win_amount'] - $stats['total_bet_amount'];

                $response = [
                    "histories" => $histories,
                    "pagination" => [
                        "current_page" => $page,
                        "last_page" => $last_page,
                        "per_page" => $per_page,
                        "total" => $totalRecords,
                        "has_more" => $has_more
                    ],
                    "statistics" => [
                        "total_games" => $total_games,
                        "total_wins" => $total_wins,
                        "total_losses" => $total_losses,
                        "win_rate" => $win_rate,
                        "loss_rate" => $loss_rate,
                        "total_win_amount" => $total_win_amount,
                        "total_bet_amount" => $total_bet_amount,
                        "net_profit" => round($net_profit, 2)
                    ]
                ];

                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

            } catch (Exception $e) {
                error_log("Erro ao buscar histórico de jogos: " . $e->getMessage());
                sendError(500, "Erro interno do servidor.");
            }
        }

        // Rota withdrawal-history (GET) - Histórico de saques do usuário
        if (parse_url($requestURI, PHP_URL_PATH) === '/withdrawal-history') {
            $rotaEncontrada = true; // Rota encontrada
    
            try {
                // Verificar autenticação JWT
                $jwtPayload = authenticateJWT();
                $userId = $jwtPayload['user_id'];
    
                // Parâmetros de paginação
                $page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
                $per_page = 5; // 5 por página como no exemplo
                $offset = ($page - 1) * $per_page;
    
                // Contar total de registros
                $countStmt = $mysqli->prepare("SELECT COUNT(*) as total FROM solicitacao_saques WHERE id_user = ?");
                $countStmt->bind_param("i", $userId);
                $countStmt->execute();
                $countResult = $countStmt->get_result();
                $totalRecords = $countResult->fetch_assoc()['total'];
                $countStmt->close();
    
                // Calcular informações de paginação
                $last_page = ceil($totalRecords / $per_page);
                $has_more = $page < $last_page;
    
                // Buscar histórico de jogos do usuário
                $stmt = $mysqli->prepare("
                    SELECT 
                        id,
                        user_id,
                        amount,
                        prize_amount,
                        player_score,
                        game_result,
                        created_at,
                        updated_at
                    FROM game_history 
                    WHERE user_id = ? 
                    ORDER BY created_at DESC 
                    LIMIT ? OFFSET ?
                ");
    
                $stmt->bind_param("iii", $userId, $per_page, $offset);
                $stmt->execute();
                $result = $stmt->get_result();
    
                $histories = [];
                while ($row = $result->fetch_assoc()) {
                    // Determinar status baseado no game_result
                    $status = 'finished';
                    if ($row['game_result'] === null) {
                        $status = 'in_progress';
                    }
    
                    // Determinar win baseado no prize_amount
                    $win = $row['prize_amount'] > 0 ? number_format($row['prize_amount'], 2, '.', '') : '0.00';
    
                    // Criar resultado JSON simulado baseado nos dados disponíveis
                    $result_json = json_encode([
                        'setup' => [
                            'chests' => [
                                ['type' => 'prize', 'multiplier' => 0.8],
                                ['type' => 'fox', 'multiplier' => 0],
                                ['type' => 'prize', 'multiplier' => 0.3],
                                ['type' => 'prize', 'multiplier' => 2],
                                ['type' => 'fox', 'multiplier' => 0],
                                ['type' => 'prize', 'multiplier' => 0.3],
                                ['type' => 'prize', 'multiplier' => 0.8],
                                ['type' => 'prize', 'multiplier' => 0.5],
                                ['type' => 'prize', 'multiplier' => 0.8]
                            ],
                            'fox_positions' => [1, 4],
                            'rtp_mode' => 'restrictive',
                            'player_score' => floatval($row['player_score']),
                            'created_at' => $row['created_at'] . '.000000Z'
                        ],
                        'opened_chests' => [4],
                        'bonus_multiplier' => 1,
                        'cash_out' => $row['prize_amount'] > 0,
                        'rtp_mode' => 'restrictive',
                        'found_fox' => $row['game_result'] === 'loss',
                        'player_score' => floatval($row['player_score'])
                    ]);
    
                    $histories[] = [
                        'id' => (int) $row['id'],
                        'user_id' => (int) $row['user_id'],
                        'amount' => number_format($row['amount'], 2, '.', ''),
                        'win' => $win,
                        'result' => $result_json,
                        'status' => $status,
                        'created_at' => date('Y-m-d\TH:i:s.000000\Z', strtotime($row['created_at'])),
                        'updated_at' => date('Y-m-d\TH:i:s.000000\Z', strtotime($row['updated_at']))
                    ];
                }
                $stmt->close();
    
                // Calcular estatísticas
                $statsStmt = $mysqli->prepare("
                    SELECT 
                        COUNT(*) as total_games,
                        COUNT(CASE WHEN prize_amount > 0 THEN 1 END) as total_wins,
                        COUNT(CASE WHEN prize_amount = 0 THEN 1 END) as total_losses,
                        COALESCE(SUM(prize_amount), 0) as total_win_amount,
                        COALESCE(SUM(amount), 0) as total_bet_amount
                    FROM game_history 
                    WHERE user_id = ?
                ");
                $statsStmt->bind_param("i", $userId);
                $statsStmt->execute();
                $statsResult = $statsStmt->get_result();
                $stats = $statsResult->fetch_assoc();
                $statsStmt->close();
    
                $total_games = (int) $stats['total_games'];
                $total_wins = (int) $stats['total_wins'];
                $total_losses = (int) $stats['total_losses'];
                $win_rate = $total_games > 0 ? round(($total_wins / $total_games) * 100, 0) : 0;
                $loss_rate = $total_games > 0 ? round(($total_losses / $total_games) * 100, 0) : 0;
                $total_win_amount = number_format($stats['total_win_amount'], 2, '.', '');
                $total_bet_amount = number_format($stats['total_bet_amount'], 2, '.', '');
                $net_profit = $stats['total_win_amount'] - $stats['total_bet_amount'];
    
                $response = [
                    "histories" => $histories,
                    "pagination" => [
                        "current_page" => $page,
                        "last_page" => $last_page,
                        "per_page" => $per_page,
                        "total" => $totalRecords,
                        "has_more" => $has_more
                    ],
                    "statistics" => [
                        "total_games" => $total_games,
                        "total_wins" => $total_wins,
                        "total_losses" => $total_losses,
                        "win_rate" => $win_rate,
                        "loss_rate" => $loss_rate,
                        "total_win_amount" => $total_win_amount,
                        "total_bet_amount" => $total_bet_amount,
                        "net_profit" => round($net_profit, 2)
                    ]
                ];
    
                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    
            } catch (Exception $e) {
                error_log("Erro ao buscar histórico de jogos: " . $e->getMessage());
                sendError(500, "Erro interno do servidor.");
            }
        }

        break;

    case 'PATCH':
        /* Rotas PATCH */
        // Rota /api/user/ (PATCH) - Atualizar dados do usuário
        if (parse_url($requestURI, PHP_URL_PATH) === '/api/user/') {
            $rotaEncontrada = true; // Rota encontrada

            $startTime = microtime(true); // Para calcular o tempo de execução

            // Verificar autenticação JWT
            $jwtPayload = authenticateJWT();
            $userId = $jwtPayload['user_id'];

            try {
                // Validar dados obrigatórios
                $allowedFields = ['name', 'email', 'phone'];
                $updateFields = [];
                $updateValues = [];
                $updateTypes = '';

                foreach ($allowedFields as $field) {
                    if (isset($data[$field]) && !empty($data[$field])) {
                        $updateFields[] = $field . ' = ?';
                        $updateValues[] = SecurityValidator::sanitizeString($data[$field]);
                        $updateTypes .= 's';
                    }
                }

                if (empty($updateFields)) {
                    sendError(400, "Nenhum campo válido para atualização.");
                }

                // Adicionar ID do usuário para WHERE
                $updateValues[] = $userId;
                $updateTypes .= 'i';

                // Construir query de atualização
                $sql = "UPDATE usuarios SET " . implode(', ', $updateFields) . " WHERE id = ?";
                $stmt = $mysqli->prepare($sql);

                if (!$stmt) {
                    sendError(500, "Erro interno do servidor.");
                }

                // Bind dos parâmetros
                $stmt->bind_param($updateTypes, ...$updateValues);
                $result = $stmt->execute();

                if (!$result) {
                    sendError(500, "Erro ao atualizar dados do usuário.");
                }

                $stmt->close();

                $response = [
                    "success" => true,
                    "message" => "Dados atualizados com sucesso!"
                ];

                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

            } catch (Exception $e) {
                error_log("Erro ao atualizar dados do usuário: " . $e->getMessage());
                sendError(500, "Erro interno do servidor.");
            }
        }

        break;

    case 'PUT':
        /* Rotas PUT */
        // Rota change-password (PUT) - Trocar senha do usuário
        if (parse_url($requestURI, PHP_URL_PATH) === '/change-password') {
            $rotaEncontrada = true; // Rota encontrada

            try {
                // Verificar autenticação JWT
                $jwtPayload = authenticateJWT();
                $userId = $jwtPayload['user_id'];

                // Validar dados obrigatórios
                if (!isset($data['current_password']) || empty($data['current_password'])) {
                    $response = [
                        "success" => false,
                        "message" => "Senha atual é obrigatória"
                    ];
                    http_response_code(400);
                    echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                    exit;
                }

                if (!isset($data['password']) || empty($data['password'])) {
                    $response = [
                        "success" => false,
                        "message" => "Nova senha é obrigatória"
                    ];
                    http_response_code(400);
                    echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                    exit;
                }

                if (!isset($data['password_confirmation']) || empty($data['password_confirmation'])) {
                    $response = [
                        "success" => false,
                        "message" => "Confirmação da nova senha é obrigatória"
                    ];
                    http_response_code(400);
                    echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                    exit;
                }

                // Validar se as senhas coincidem
                if ($data['password'] !== $data['password_confirmation']) {
                    $response = [
                        "success" => false,
                        "message" => "A nova senha e a confirmação não coincidem"
                    ];
                    http_response_code(400);
                    echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                    exit;
                }

                // Validar complexidade da nova senha
                if (strlen($data['password']) < 6) {
                    $response = [
                        "success" => false,
                        "message" => "A nova senha deve ter pelo menos 6 caracteres"
                    ];
                    http_response_code(400);
                    echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                    exit;
                }

                // Buscar senha atual do usuário
                $stmt = $mysqli->prepare("SELECT password FROM usuarios WHERE id = ?");
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows === 0) {
                    $response = [
                        "success" => false,
                        "message" => "Usuário não encontrado"
                    ];
                    http_response_code(404);
                    echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                    exit;
                }

                $stmt->bind_result($current_password_hash);
                $stmt->fetch();
                $stmt->close();

                // Verificar se a senha atual está correta
                if (!password_verify($data['current_password'], $current_password_hash)) {
                    $response = [
                        "success" => false,
                        "message" => "Senha atual incorreta"
                    ];
                    http_response_code(400);
                    echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                    exit;
                }

                // Verificar se a nova senha é igual à atual
                if (password_verify($data['password'], $current_password_hash)) {
                    $response = [
                        "success" => false,
                        "message" => "A nova senha não pode ser igual à senha atual"
                    ];
                    http_response_code(400);
                    echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                    exit;
                }

                // Criptografar a nova senha
                $new_password_hash = password_hash($data['password'], PASSWORD_DEFAULT);

                // Atualizar a senha no banco de dados
                $updateStmt = $mysqli->prepare("UPDATE usuarios SET password = ? WHERE id = ?");
                $updateStmt->bind_param("si", $new_password_hash, $userId);

                if (!$updateStmt->execute()) {
                    $response = [
                        "success" => false,
                        "message" => "Erro ao atualizar senha"
                    ];
                    http_response_code(500);
                    echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                    exit;
                }

                $updateStmt->close();

                // Log da alteração de senha
                error_log("Senha alterada para o usuário ID: " . $userId . " em " . date('Y-m-d H:i:s'));

                $response = [
                    "success" => true,
                    "message" => "Senha alterada com sucesso!"
                ];

                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

            } catch (Exception $e) {
                error_log("Erro ao alterar senha: " . $e->getMessage());
                $response = [
                    "success" => false,
                    "message" => "Erro interno do servidor"
                ];
                http_response_code(500);
                echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                exit;
            }
        }

        break;

    default:
        http_response_code(405);
        echo json_encode(['error' => 'Método não permitido']);
}


// Se nenhuma rota foi encontrada, retorna 404
if (!$rotaEncontrada) {
    sendError(404, 'Rota não encontrada');
}