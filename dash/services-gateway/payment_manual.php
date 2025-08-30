<?php
ini_set('display_errors', 0);
error_reporting(E_ALL);
session_start();
header('Content-Type: application/json; charset=utf-8');

require_once '../services/database.php';
require_once '../services/funcao.php';
require_once '../services/crud.php';

if (!isset($_GET['id'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Erro ID não informado.']);
    exit;
}
$id = PHP_SEGURO($_GET['id']); // sua função

// 1) Buscar dados do saque
$stmt = $mysqli->prepare("SELECT valor, pix, tipo, name, telefone FROM solicitacao_saques WHERE transacao_id = ? LIMIT 1");
if (!$stmt) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Erro ao preparar a query do saque.']);
    exit;
}
$stmt->bind_param("s", $id);
$stmt->execute();
$res = $stmt->get_result();
$row = $res ? $res->fetch_assoc() : null;
$stmt->close();

if (!$row) {
    http_response_code(404);
    echo json_encode(['success' => false, 'message' => 'Saque não encontrado ou parâmetros inválidos.']);
    exit;
}

$valor        = (float)($row['valor'] ?? 0);
$chavepix1    = (string)($row['pix'] ?? '');
$tipoChavePix = (string)($row['tipo'] ?? '');
$nome_real    = (string)($row['name'] ?? '');
$cpf          = $row['telefone'];

if ($valor <= 0 || $chavepix1 === '' || $tipoChavePix === '') {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Dados da transação incompletos.']);
    exit;
}
$valor = number_format($valor, 2, '.', '');

// 2) Buscar credenciais do Ezzebank
$cred_stmt = $mysqli->prepare("SELECT url, client_id, client_secret FROM ezzebank WHERE id = 1 AND ativo = 1 LIMIT 1");
if (!$cred_stmt) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Erro ao preparar a query de credenciais do Ezzebank.']);
    exit;
}
$cred_stmt->execute();
$cred = $cred_stmt->get_result();
if (!$cred || !$cred->num_rows) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Credenciais do Ezzebank não configuradas.']);
    $cred_stmt->close();
    exit;
}
$data_ezzebank = $cred->fetch_assoc();
$cred_stmt->close();
$base = rtrim($data_ezzebank['url'] ?? 'https://api.ezzebank.app', '/');

$ch = curl_init($base . '/api/v1/login');
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST           => true,
    CURLOPT_HTTPHEADER     => [
        'client_id: ' . $data_ezzebank['client_id'],
        'client_secret: ' . $data_ezzebank['client_secret'],
        'Accept: application/json'
    ],
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT        => 20,
    CURLOPT_IPRESOLVE      => CURL_IPRESOLVE_V4,
]);
$loginResp = curl_exec($ch);
if ($loginResp === false) {
    $err = curl_error($ch);
    curl_close($ch);
    http_response_code(502);
    echo json_encode(['success' => false, 'message' => 'Erro cURL no login Ezzebank: ' . $err]);
    exit;
}
$loginHttp = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

$loginJson = json_decode($loginResp, true);
if ($loginHttp < 200 || $loginHttp >= 300 || !isset($loginJson['token'])) {
    http_response_code(502);
    echo json_encode(['success' => false, 'message' => 'Falha ao obter token Ezzebank', 'raw' => $loginResp]);
    exit;
}
$bearerToken = $loginJson['token'];

// 4) Pagar PIX
$external_id = $id . '_' . time();
$payload = [
    'payer' => [
        'name'   => $nome_real,
        'pix_type'=> $tipoChavePix,
        'pix_key'    => $chavepix1,
        'document'  => $cpf,
    ],
    'amount'      => $valor,       // "123.45"
    'external_id' => $external_id,
    'description' => 'Pagamento',
];

$endpoint = $base . '/api/v1/withdraw/pix';

$ch = curl_init($endpoint);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CUSTOMREQUEST  => 'POST',
    CURLOPT_POSTFIELDS     => json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
    CURLOPT_HTTPHEADER     => [
        'Authorization: Bearer ' . $bearerToken,
        'Content-Type: application/json',
        'Accept: application/json'
    ],
    CURLOPT_CONNECTTIMEOUT => 15,
    CURLOPT_TIMEOUT        => 30,
    CURLOPT_IPRESOLVE      => CURL_IPRESOLVE_V4,
]);
$payResp = curl_exec($ch);
if ($payResp === false) {
    $err = curl_error($ch);
    curl_close($ch);
    http_response_code(502);
    echo json_encode(['success' => false, 'message' => 'Erro na comunicação com Ezzebank: ' . $err]);
    exit;
}
$payHttp = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

$payJson = json_decode($payResp, true);
$ok = false;
$transaction_id_gateway = '';

if (is_array($payJson)) {
    if (($payJson['response'] ?? '') === 'OK' || ($payJson['success'] ?? false) === true) {
        $ok = true;
        $transaction_id_gateway = $payJson['id_transaction'] ?? $external_id;
    }
}
if (!$ok && strpos($payResp, 'Saque PIX processado com sucesso') !== false) {
    $ok = true;
    $transaction_id_gateway = $external_id;
}
if (!$ok || $payHttp < 200 || $payHttp >= 300) {
    http_response_code(502);
    echo json_encode([
        'success' => false,
        'message' => 'Erro do gateway',
        'raw'     => is_array($payJson) ? $payJson : $payResp
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

// 5) Atualizar status no banco
$up = $mysqli->prepare("UPDATE solicitacao_saques SET status = 1 WHERE transacao_id = ?");
if (!$up) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Erro ao preparar a query de atualização.']);
    exit;
}
$up->bind_param("s", $id);
$up->execute();
$affected = $up->affected_rows;
$up->close();

if ($affected > 0) {
    echo json_encode([
        'success' => true,
        'message' => 'Saque aprovado com sucesso.',
        'transaction_id_gateway' => $transaction_id_gateway
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
} else {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Erro ao atualizar o status do pagamento no banco de dados.']);
}