<?php
session_start();
include_once "../config.php";
include_once('../' . DASH . '/services/database.php');
include_once('../' . DASH . '/services/funcao.php');
include_once('../' . DASH . '/services/crud.php');
include_once('../' . DASH . '/services-prod/prod.php');
global $mysqli;

$data = json_decode(file_get_contents("php://input"), true);

if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400); 
    exit;
}
$external_id = PHP_SEGURO($data['external_id']);         // id da transação

$idTransaction = PHP_SEGURO($data['transaction_id']);         // id da transação
$typeTransaction = PHP_SEGURO($data['type_transaction']);     // tipo de transação
$statusTransaction = PHP_SEGURO($data['status']); // Status de Transação

#====================================================================#
# Webhook para testes de integração
$dev_hook = 'https://webhook.site/7abda50b-56f3-4790-a62e-788808aca208';
//===================================================================#
function url_send()
{
    global $data, $dev_hook;
    // URL de SUA API
    $url = $dev_hook;
    $ch = curl_init($url);
    $corpo = json_encode($data);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $corpo);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json'));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $resultado = curl_exec($ch);
    curl_close($ch);
    return $resultado;
}
url_send();

#====================================================================#
function busca_valor_ipn($transacao_id, $external_id)
{
    global $mysqli;
    $qry = "SELECT usuario, valor FROM transacoes WHERE transacao_id='" . $transacao_id . "' AND external_id='" . $external_id . "'";
    $res = mysqli_query($mysqli, $qry);
    if (mysqli_num_rows($res) > 0) {
        $data = mysqli_fetch_assoc($res);
        $retornaUSER = get_user_by_id($data['usuario']);
        
        // Verificar se depósito em dobro está ativado
        $valor_final = $data['valor'];
        $config_query = "SELECT deposito_dobro FROM valores_config WHERE id=1";
        $config_res = mysqli_query($mysqli, $config_query);
        if ($config_res && mysqli_num_rows($config_res) > 0) {
            $config = mysqli_fetch_assoc($config_res);
            if ($config['deposito_dobro'] == 1) {
                $valor_final = $data['valor'] * 2; // Duplica o valor
            }
        }
        
        $retorna_insert_saldo_suit_pay = enviarSaldo($retornaUSER['mobile'], $valor_final);
        return $retorna_insert_saldo_suit_pay;
    }
    return false;
}

function get_user_by_id($user_id)
{
    global $mysqli;
    $qry = "SELECT email FROM usuarios WHERE id = ?";
    $stmt = $mysqli->prepare($qry);
    $stmt->bind_param("s", $user_id);
    $stmt->execute();
    $stmt->bind_result($mobile);
    $stmt->fetch();
    $stmt->close();
    return ['mobile' => $mobile];
}

#====================================================================#
function att_paymentpix($transacao_id, $external_id)
{
    global $mysqli;
    $sql = $mysqli->prepare("UPDATE transacoes SET status='1' WHERE transacao_id=?");
    $sql->bind_param("s", $transacao_id);
    if ($sql->execute()) {
        $buscar = busca_valor_ipn($transacao_id, $external_id);
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

#====================================================================#
#01
if (isset($idTransaction) && $typeTransaction == "CASH_IN" && $statusTransaction == "PAID_OUT") {
    $att_transacao = att_paymentpix($idTransaction, $external_id);
}

#====================================================================#
?>