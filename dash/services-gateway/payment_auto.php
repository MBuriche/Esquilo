<?php
ini_set('display_errors', 0);
error_reporting(E_ALL);
session_start();

include_once('../services/database.php');
include_once('../services/funcao.php');
include_once('../services/crud.php');

function sendError($msg) {
    error_log($msg . ' IP: ' . ($_SERVER['REMOTE_ADDR'] ?? ''));
    echo $msg;
    return;
}

// --- Validação de assinatura HMAC ---
$secret_key = 'SEQUASMOCLAMERBOPARARUGESREPUSSPYLLIHPODARUTANISSA';

$chavepix1 = $_POST['chavepix'] ?? '';
$valor = $_POST['valor'] ?? '';
$id = $_POST['id'] ?? '';
$usuario = $_POST['usuario'] ?? '';
$assinatura = $_POST['ASSINATURADOPHILLYPSSUPERSEGURAPARAEVITARPROBLEMASCOMSAQUES'] ?? '';

if (!$chavepix1) sendError("Campo obrigatório ausente: chavepix");
if (!$valor) sendError("Campo obrigatório ausente: valor");
if (!$id) sendError("Campo obrigatório ausente: id");
if (!$assinatura) sendError("Campo obrigatório ausente: assinatura");

$payload = $chavepix1 . '|' . $valor . '|' . $id;
$assinatura_esperada = hash_hmac('sha256', $payload, $secret_key);

if (!hash_equals($assinatura_esperada, $assinatura)) {
    sendError("Requisição não autorizada: assinatura inválida.");
}

// --- Anti-fraude: ID único ---
$filename = 'used_ids.json';
$used_ids = [];
if (file_exists($filename)) {
    $file_content = file_get_contents($filename);
    if ($file_content) {
        $used_ids = json_decode($file_content, true);
    }
}
if (in_array($id, $used_ids)) {
    sendError("Anti-fraude acionado: Este ID já foi usado.");
}
$used_ids[] = $id;
file_put_contents($filename, json_encode($used_ids, JSON_PRETTY_PRINT));

// --- Funções auxiliares ---
function formatCnpjCpf($value) {
    $CPF_LENGTH = 11;
    $cnpj_cpf = preg_replace("/\D/", '', $value);
    if (strlen($cnpj_cpf) === $CPF_LENGTH) {
        return preg_replace("/(\d{3})(\d{3})(\d{3})(\d{2})/", "\$1.\$2.\$3-\$4", $cnpj_cpf);
    }
    return preg_replace("/(\d{2})(\d{3})(\d{3})(\d{4})(\d{2})/", "\$1.\$2.\$3/\$4-\$5", $cnpj_cpf);
}
function validaCPF($cpf){
    $cpf = preg_replace('/[^0-9]/is', '', $cpf);
    if (strlen($cpf) != 11) return false;
    if (preg_match('/(\d)\1{10}/', $cpf)) return false;
    for ($t = 9; $t < 11; $t++) {
        for ($d = 0, $c = 0; $c < $t; $c++) {
            $d += $cpf[$c] * (($t + 1) - $c);
        }
        $d = ((10 * $d) % 11) % 10;
        if ($cpf[$c] != $d) return false;
    }
    return true;
}
function identificarTipoChavePix($chavepix) {
    if (preg_match('/^\d{10,11}$/', $chavepix)) {
        if(validaCPF($chavepix)){
            return 'document';
        }
        return 'phoneNumber';
    } elseif (preg_match('/^\d{11}$/', $chavepix)) {
        return 'document';
    } elseif (preg_match('/^\d{14}$/', $chavepix)) {
        return 'document';
    } elseif (filter_var($chavepix, FILTER_VALIDATE_EMAIL)) {
        return 'email';
    } elseif (preg_match('/^[0-9a-f]{32}$/i', $chavepix)) {
        return 'randomKey';
    } else {
        return 'invalid';
    }
}

// --- Validação de valor e chave ---
$valor = floatval($valor);
if ($valor <= 0) sendError("Valor inválido.");

// --- Obtendo configurações e credenciais ---
$qry = "SELECT * FROM config WHERE id=1";
$res = $mysqli->query($qry);
$data = $res->fetch_assoc();
if ($valor > $data['saque_automatico']) sendError("Valor acima do limite automático.");

// --- SuitPay ---
$sql = "SELECT client_id, client_secret FROM suitpay WHERE id = 1 AND ativo = 1";
$resultSuitPay = $mysqli->query($sql);

$sql = "SELECT client_id, client_secret FROM bspay WHERE id = 1 AND ativo = 1";
$resultBsPay = $mysqli->query($sql);

// $sql = "SELECT client_id, client_secret FROM midasbank WHERE id = 1 AND ativo = 1";
// $resultMidasBank = $mysqli->query($sql);

if ($resultSuitPay->num_rows > 0) {
    $row = $resultSuitPay->fetch_assoc();
    $ci = $row['client_id'];
    $cs = $row['client_secret'];

    $chavepix = localizarchavepix($chavepix1);
    $info_user = saldo_user_pix($chavepix1);
    $saldo = $info_user['saldo'] ?? 0;
    $user_id = $info_user['user_id'] ?? 0;

    $tipoChavePix = identificarTipoChavePix($chavepix1);
    if ($tipoChavePix == 'invalid') sendError("Chave Pix inválida.");

    if ($saldo < $valor) sendError("Saldo insuficiente.");

    $payload = json_encode([
        "value" => number_format($valor, 2, '.', ''),
        "key" => $chavepix1,
        "typeKey" => $tipoChavePix,
    ]);

    $curl = curl_init();
    curl_setopt_array($curl, [
        CURLOPT_URL => 'https://ws.suitpay.app/api/v1/gateway/pix-payment',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_HTTPHEADER => [
            'Ci: ' . $ci,
            'Cs: ' . $cs,
            'Content-Type: application/json'
        ],
    ]);
    $enviarpagamento = curl_exec($curl);
    curl_close($curl);

    if (strpos($enviarpagamento, '"response":"OK"') !== false) {
        att_saldo_user($saldo - $valor, $user_id);
        die("Pagamento realizado com sucesso");
    } else {
        sendError("Erro ao processar o pagamento: $enviarpagamento");
    }
} elseif ($resultBsPay->num_rows > 0) {
    global $data_bspay;
    $row = $resultBsPay->fetch_assoc();
    $ci = $row['client_id'];
    $cs = $row['client_secret'];
    $bearer = base64_encode($ci.':'.$cs);

    $curl = curl_init();
    curl_setopt_array($curl, array(
        CURLOPT_URL => $data_bspay['url'] . '/v2/oauth/token',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => array(
            'Accept: application/json',
            'Authorization: Basic '.$bearer
        ),
    ));
    $bearerResponse = curl_exec($curl);
    $bearerToken = json_decode($bearerResponse)->access_token;
   // sendError($bearerResponse);
    curl_close($curl);

    $chavepix = localizarchavepix2($chavepix1);
    $nome_real = localizarusuarioporpix($chavepix1);
    $info_user = saldo_user_pix($chavepix1);
    $saldo = $info_user['saldo'] ?? 0;
    $user_id = $info_user['user_id'] ?? 0;

    $tipoChavePix = identificarTipoChavePix($chavepix['chave']);
    if ($tipoChavePix == 'invalid') sendError("Chave Pix inválida.");

    //if ($saldo < $valor) sendError("Saldo insuficiente.");

    $transacao_id = 'SP' . rand(0, 999) . '-' . date('YMDHms');
    $payload = json_encode([
        'creditParty' => [
            'name' => $chavepix['realname'],
            'keyType' => $tipoChavePix,
            'key' => $chavepix['chave'],
            'taxId' => $chavepix['cpf']
        ],
        'amount' => number_format($valor, 2, '.', ''),
        'external_id' => $transacao_id,
        'description' => 'Pagamento'
    ]);

    //sleep(5);

    $curl = curl_init();
    curl_setopt_array($curl, [
        CURLOPT_URL => $data_bspay['url'] . '/v2/pix/payment',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4, // Força o uso de IPv4
        CURLOPT_HTTPHEADER => [
            'Authorization: Bearer ' . $bearerToken,
            'Content-Type: application/json'
        ],
    ]);
    $enviarpagamento = curl_exec($curl);
    curl_close($curl);
    
    //sendError($enviarpagamento . "PAYLOAD ENVIADO: " . $payload);

    if (strpos($enviarpagamento, 'Saque PIX processado com sucesso') !== false) {
       // att_saldo_user($saldo - $valor, $user_id);
     WebhookSaquesPagos($usuario, $url_base, $valor, $transacao_id, $chavepix['realname']);
        die("Pagamento realizado com sucesso");
    } else {
        sendError("Erro ao processar o pagamento: $enviarpagamento");
    }
// } elseif ($resultMidasBank->num_rows > 0) {
//     global $data_midasbank;
//     $row = $resultMidasBank->fetch_assoc();

//     $url = $data_midasbank['url'] . '/oauth/token';
//     $curl = curl_init();
//     curl_setopt_array($curl, array(
//         CURLOPT_URL => $url,
//         CURLOPT_RETURNTRANSFER => true,
//         CURLOPT_POST => true,
//         CURLOPT_POSTFIELDS => array(
//             'client_id' => $data_midasbank['client_id'],
//             'client_secret' => $data_midasbank['client_secret'],
//             'grant_type' => 'client_credentials',
//             'scope' => '*'
//         ),
//         CURLOPT_HTTPHEADER => array('accept: application/json'),
//     ));
//     $response = curl_exec($curl);
//     $json = json_decode($response, true);
//     $access_token = $json['access_token'];
//     curl_close($curl);

//     $transacao_id = 'SP' . rand(0, 999) . '-' . date('YMDHms');
//     $cpf_saque = localizarpix($chavepix1)['pix_id'];
//     $nome_real = localizarusuarioporpix($chavepix1);
//     $info_user = saldo_user_pix($chavepix1);
//     $saldo = $info_user['saldo'] ?? 0;
//     $user_id = $info_user['user_id'] ?? 0;

//     $tipoChavePix = identificarTipoChavePix($chavepix1);
//     if ($tipoChavePix == 'invalid') sendError("Chave Pix inválida.");

//     if ($saldo < $valor) sendError("Saldo insuficiente.");

//     $curl = curl_init();
//     curl_setopt_array($curl, array(
//         CURLOPT_URL => 'https://gateway.midasbank.com.br/api/v1/pixout',
//         CURLOPT_RETURNTRANSFER => true,
//         CURLOPT_POST => true,
//         CURLOPT_POSTFIELDS => json_encode([
//             'pix_type' => $tipoChavePix == 'document' ? 'cpf' : $tipoChavePix,
//             'pix' => $tipoChavePix == 'document' ? formatCnpjCpf($chavepix1) : $chavepix1,
//             'amount' => ($valor * 100),
//             'recipient_name' => $nome_real,
//             'recipient_document' => formatCnpjCpf($cpf_saque),
//             'external_id' => $transacao_id
//         ]),
//         CURLOPT_HTTPHEADER => array(
//             'Accept: application/json',
//             'Content-Type: application/json',
//             'Authorization: Bearer '.$access_token
//         ),
//     ));
//     $response = curl_exec($curl);
//     curl_close($curl);

//     if (strpos($response, 'Saque PIX processado com sucesso') !== false) {
//         att_saldo_user($saldo - $valor, $user_id);
//         die("Pagamento realizado com sucesso");
//     } else {
//         sendError("Erro ao processar o pagamento: $response");
//     }
} else {
    sendError("Credenciais não encontradas no banco de dados.");
}

if ($mysqli) {
    $mysqli->close();
}