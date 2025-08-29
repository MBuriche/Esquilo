// ⚠️ ATENÇÃO:Precisamos validar isso aqui ⚠️
<?php
session_start();
include_once "../config.php";

// Defina a constante DASH antes de usá-la
if (!defined('DASH')) {
    define('DASH', 'dashboard'); // Altere 'dashboard' para o valor correto do seu projeto
}

include_once('../'.DASH.'/services/database.php');
include_once('../'.DASH.'/services/funcao.php');
include_once('../'.DASH.'/services/crud.php');
include_once('../'.DASH.'/services-prod/prod.php');

global $mysqli;

// Decode JSON payload
$payload = json_decode(file_get_contents("php://input"), true);
if ($payload === null && json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400);
    echo json_encode(['erro' => 'json inválido']);

    exit;
}

// Support payload with fields inside "data" or at root
$data = $payload['data'] ?? $payload;
$transactionId = PHP_SEGURO($data['id_da_transacao'] ?? $data['id'] ?? $data['txid'] ?? '');
$identifier     = PHP_SEGURO($data['identificador'] ?? $data['referencia'] ?? '');
$status         = strtoupper(PHP_SEGURO($data['status'] ?? ''));

if (empty($transactionId) || empty($status)) {
    http_response_code(400);
    echo json_encode(['erro' => 'dados ausentes']);

    exit;
}

function busca_valor_ipn($transacao_id)
{
    global $mysqli;

    if ( !is_string ( $transacao_id ) || empty ( $transacao_id )) {
        error_log ( 'busca_valor_ipn: transacao_id inválido' );
        return false;
    }

    $qry = "SELECT usuario, valor FROM transacoes WHERE transacao_id=?" ;
    $stmt = $mysqli -> prepare ( $qry );
    if ( ! $stmt ) {
        error_log ( 'busca_valor_ipn: ' . $mysqli -> error );
        return false;
    }
    $stmt -> bind_param ( "s" , $transacao_id );
    if ( ! $stmt -> execute ()) {
        error_log ( 'busca_valor_ipn: ' . $stmt -> error );
        $stmt -> close ();
        return false;
    }
    $stmt -> bind_result ( $usuario , $valor );
    if ( $stmt -> fetch ()) {
        $dados = [ 'usuario' => $usuario , 'valor' => $valor ];
        $stmt -> close ();

        $retornaUSER = get_user_by_id($dados['usuario']);

        // Verificar se depósito em dobro está ativado
        $valor_final = $dados['valor'];
        $config_query = "SELECT deposito_dobro FROM valores_config WHERE id=1";
        $config_res = mysqli_query($mysqli, $config_query);
        if ($config_res && mysqli_num_rows($config_res) > 0) {
            $config = mysqli_fetch_assoc($config_res);
            if ($config['deposito_dobro'] == 1) {
                $valor_final = $dados['valor'] * 2;
            }
        }

        $retorna_insert_saldo_ezzebank = enviarSaldo($retornaUSER['mobile'], $valor_final);
        return $retorna_insert_saldo_ezzebank;
    
    }
    $stmt -> close ();
    return false;
}

function get_user_by_id($user_id)
{
    global $mysqli;

    $qry = "SELECT mobile FROM usuarios WHERE id = ?";
    $stmt = $mysqli->prepare($qry);
    $stmt->bind_param("s", $user_id);
    $stmt->execute();
    $stmt->bind_result($mobile);
    $stmt->fetch();
    $stmt->close();
    return ['mobile' => $mobile];
}

function att_paymentpix($transacao_id)
{
    global $mysqli;

    $sql = $mysqli->prepare("UPDATE transacoes SET status='1' WHERE transacao_id=?");
    $sql->bind_param("s", $transacao_id);
    if ($sql->execute()) {
        $buscar = busca_valor_ipn($transacao_id);
        if ($buscar) {
            $rf = 1;
            // Processar CPA e RevShare
            processarAfiliados($transacao_id);
        } else {
            $rf = 0;
        }
    } else {
        $rf = 0;
    }
    return $rf;
}

$settledStatuses = ['PAGO', 'LIQUIDADO', 'LIQUIDACAO', 'PAGO_SAIDA', 'CONCLUIDO'];

if (in_array($status, $settledStatuses, true)) {
    $atualizado = att_paymentpix($transactionId);
    if ($atualizado) {
        http_response_code(200);
        echo json_encode(['status' => 'processed']);
    } else {
        http_response_code(500);
        echo json_encode(['status' => 'error']);
    }
} else {
    http_response_code(202);
    echo json_encode(['status' => 'ignored']);
}
?>