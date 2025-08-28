<?php
ini_set('display_errors', 0);
error_reporting(E_ALL);
date_default_timezone_set('America/Sao_Paulo');
include_once('database.php');
include_once('funcao.php');
#=====================================================#
# DATA CONFIG
function data_config()
{
	global $mysqli;
	$qry = "SELECT * FROM config WHERE id=1";
	$res = mysqli_query($mysqli, $qry);
	$data = mysqli_fetch_assoc($res);
	return $data;
}
$dataconfig = data_config();
#=====================================================#
# DATA POPUPS
function data_popups($id)
{
	global $mysqli;
	$qry = "SELECT * FROM popups WHERE id = '" . $id . "'";
	$res = mysqli_query($mysqli, $qry);
	$data = mysqli_fetch_assoc($res);
	return $data;
}
#=====================================================#
# DATA BANNERS
function data_banners($id)
{
	global $mysqli;
	$qry = "SELECT img FROM banner WHERE id = '" . $id . "'";
	$res = mysqli_query($mysqli, $qry);
	$data = mysqli_fetch_assoc($res);
	return $data['img'];
}
#=====================================================#
# DATA PROMOCOES
function data_promocoes($id)
{
	global $mysqli;
	$qry = "SELECT img FROM promocoes WHERE id = '" . $id . "'";
	$res = mysqli_query($mysqli, $qry);
	$data = mysqli_fetch_assoc($res);
	return "/uploads/" . $data['img'];
}
#=====================================================#
# DATA FLOATS
function data_floats($id)
{
	global $mysqli;
	$qry = "SELECT img FROM floats WHERE id = '" . $id . "'";
	$res = mysqli_query($mysqli, $qry);
	$data = mysqli_fetch_assoc($res);
	return $data['img'];
}

function cupom_usado($cupom, $user_id){
    global $mysqli;
    
    $sql = "SELECT id FROM cupom_usados WHERE id_cupom = '{$cupom}' AND id_user = '{$user_id}'";
    $res = mysqli_query($mysqli, $sql);
	//$data = mysqli_fetch_assoc($res);
	$qtd = mysqli_num_rows($res);
	
	return $qtd;
}

function usar_cupom($user_id, $valor){
    global $mysqli;
    
    $sql = "SELECT * FROM cupom";
    $res = mysqli_query($mysqli, $sql);
	$data = mysqli_fetch_all($res);
	$cupons = [];
	
	foreach ($data as $i => $cupom){
	    $cupons[$cupom[0]] = [
	        "valor"    => $cupom[3],
	        "qtd"    => $cupom[4],
	        "qtd_insert"    => $cupom[5],
	        "status"    => $cupom[6],
 	    ];
	}
	

	foreach ($cupons as $id => $cupom) {
	    if (intval($valor) >= intval($cupom['valor']) && $cupom['status'] == 1 && $cupom['qtd'] > 0 && cupom_usado($id, $user_id) == 0) {
	        
	        $horario = date('Y-m-d H:m:s');

	        $insert_saldo = mysqli_query($mysqli, "UPDATE usuarios SET saldo = saldo + {$cupom['qtd_insert']} WHERE id = {$user_id}");
	        $remove_cupom_usado = mysqli_query($mysqli, "UPDATE cupom SET qtd = qtd - 1 WHERE id = {$id}");
	        $insert = mysqli_query($mysqli, "INSERT INTO cupom_usados SET id_user = {$user_id}, id_cupom = {$id}, valor = \"{$cupom['qtd_insert']}\", data_time = '{$horario}'");
	        
	        return [
	            "sucesso" => true,
	            "cupom_id" => $id,
	            "mensagem" => "Cupom válido encontrado.",
	        ];
	    }/*else{
	        return [
        	    "sucesso" => false,
        	    "mensagem" => "Cupom não encontrado ou já utilizado.",
        	];
	    }*/
	}
	
	return [
	    "sucesso" => false,
	    "mensagem" => "Nenhum cupom válido encontrado para o valor especificado.",
	];
}
function enviarSaldo($email, $saldo)
{
	global $mysqli;

	// Monta a query de atualização
	$qry = "UPDATE usuarios SET saldo = saldo + '" . $saldo . "' WHERE email = '" . $email . "'";

	// Executa a consulta
	if (mysqli_query($mysqli, $qry)) {
		return 1;  // Sucesso
	} else {
		return 0;  // Falha
	}
}

#diminuir saldo na api da fiverscan
function withdrawSaldo($email, $saldo)
{
	global $mysqli;

	// Verifica o saldo atual do usuário
	$qryCheckSaldo = "SELECT saldo FROM usuarios WHERE mobile = '" . $email . "'";
	$result = mysqli_query($mysqli, $qryCheckSaldo);

	if ($result && mysqli_num_rows($result) > 0) {
		$row = mysqli_fetch_assoc($result);
		$saldoAtual = $row['saldo'];

		// Verifica se o saldo é suficiente para o saque
		if ($saldoAtual >= $saldo) {
			// Monta a query de atualização do saldo
			$qry = "UPDATE usuarios SET saldo = saldo - '" . $saldo . "' WHERE mobile = '" . $email . "'";

			// Executa a consulta de atualização
			if (mysqli_query($mysqli, $qry)) {
				return 1;  // Sucesso
			} else {
				return 0;  // Falha na execução da query
			}
		} else {
			return -1;  // Saldo insuficiente
		}
	} else {
		return 0;  // Falha ao buscar o saldo ou usuário não encontrado
	}
}


#=====================================================#
function afiliado_de_quem($refer)
{
	global $mysqli;
	$qry = "SELECT real_name FROM usuarios WHERE invite_code='" . $refer . "'";
	$res = mysqli_query($mysqli, $qry);
	$dinheiro = 'Sem afiliação'; // Valor padrão

	if ($res) {
		while ($row = mysqli_fetch_assoc($res)) {
			if (!empty($row['real_name'])) {
				$dinheiro = $row['real_name'];
			}
		}
	}

	return $dinheiro;
}
#=====================================================#
# DATA CONFIG SUITPAY
function data_ondapay()
{
	global $mysqli;
	$qry = "SELECT * FROM ondapay WHERE id=1";
	$res = mysqli_query($mysqli, $qry);
	$data = mysqli_fetch_assoc($res);
	return $data;
}
$data_ondapay = data_ondapay();

# DATA CONFIG
function data_afiliados_cpa_rev()
{
	global $mysqli;
	$qry = "SELECT * FROM afiliados_config WHERE id=1";
	$res = mysqli_query($mysqli, $qry);
	$data = mysqli_fetch_assoc($res);
	return $data;
}
$data_afiliados_cpa_rev = data_afiliados_cpa_rev();
#=====================================================#
#criar financeiro
function criar_financeiro($id)
{
	global $mysqli;
	$sql1 = $mysqli->prepare("INSERT INTO financeiro (usuario,saldo,bonus) VALUES (?,0,0)");
	$sql1->bind_param("i", $id);
	if ($sql1->execute()) {
		$tr = 1; //certo
	} else {
		$tr = 0; //erro
	}
	return $tr;
}

# count saque
function tabelasaldouser($id)
{
	global $mysqli;
	$qry = "SELECT * FROM usuarios WHERE id='" . intval($id) . "'";
	$result = mysqli_query($mysqli, $qry);
	while ($row = mysqli_fetch_assoc($result)) {
		if ($row['saldo'] > 0) {
			$dinheiro = $row['saldo'];
		} else {
			$dinheiro = '0.00';
		}
	}
	return $dinheiro;
}
#=====================================================#
#criar financeiro
function criar_tokenrefer($id)
{
	global $mysqli;
	$aftoken = 'af' . $id . token_aff();
	$sql = $mysqli->prepare("UPDATE usuarios SET token_refer=? WHERE id=?");
	$sql->bind_param("si", $aftoken, $id);
	if ($sql->execute()) {
		$tr = 1; //certo
	} else {
		$tr = 0; //erro

	}
	return $tr;
}
#=====================================================#
// request curl (fiverscan)
function enviarRequest($url, $config)
{
    $ch = curl_init();
    $headerArray = ['Content-Type: application/json'];

    // Configurando as opções do cURL
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $config);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headerArray);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Não recomendado em produção

    // Executando a requisição e obtendo a resposta
    $response = curl_exec($ch);

    // Verificando se houve erro na execução do cURL
    if ($response === false) {
        logMessage("Erro cURL: " . curl_error($ch)); // Loga o erro do cURL
    }

    // Fechando a conexão cURL
    curl_close($ch);
    return $response;
}


function logMessage($message) {
    $logFile = 'log.txt'; // Caminho para o arquivo de log
    $timestamp = date('Y-m-d H:i:s');
    file_put_contents($logFile, "[$timestamp] $message" . PHP_EOL, FILE_APPEND);
}


#=====================================================#
// saldo atual do user
function saldo_user($id)
{
	global $mysqli;
	$qry = "SELECT * FROM usuarios WHERE id='" . intval($id) . "'";
	$res = mysqli_query($mysqli, $qry);
	if (mysqli_num_rows($res) > 0) {
		$data = mysqli_fetch_assoc($res);
		$saldo_arr = array(
			"saldo" => $data['saldo'],
			"saldo_afiliado" => $data['saldo_afiliados']
		);
	} else {
		$saldo_arr = array(
			"saldo" => 0,
			"saldo_afiliado" => 0
		);
	}
	return $saldo_arr;
}

function saldo_user_email($id)
{
	global $mysqli;
	$qry = "SELECT * FROM usuarios WHERE mobile='" . $id . "'";
	$res = mysqli_query($mysqli, $qry);
	if (mysqli_num_rows($res) > 0) {
		$data = mysqli_fetch_assoc($res);
		$saldo_arr = array(
			"saldo" => $data['saldo'],
			"user_id" => $data['id'],
			"saldo_afiliado" => $data['saldo_afiliados']
		);
	} else {
		$saldo_arr = array(
			"saldo" => 0,
			"user_id" => 0,
			"saldo_afiliado" => 0
		);
	}
	return $saldo_arr;
}



function total_caixas_abertas() {
    global $mysqli;
    $qry = "SELECT COUNT(*) as total FROM historico_aberturas";
    $result = mysqli_query($mysqli, $qry);
    if ($result) {
        $row = mysqli_fetch_assoc($result);
        return intval($row['total']);
    }
    return 0;
}
#=====================================================#
// atualiza saldo do user
function att_saldo_user($saldo, $id)
{
	global $mysqli;
	$id_user = intval($id);
	$sql = $mysqli->prepare("UPDATE usuarios SET saldo= ? WHERE id=?");
	$sql->bind_param("si", $saldo, $id_user);
	if ($sql->execute()) {
		$rt = 1;
	} else {
		$rt = 0;

	}
	return $rt;
}
#=====================================================#
// financeiro user atual do user
function financeiro_saldo_user($id)
{
	global $mysqli;
	$qry = "SELECT * FROM financeiro WHERE usuario='" . intval($id) . "'";
	$res = mysqli_query($mysqli, $qry);
	if (mysqli_num_rows($res) > 0) {
		$saldo = mysqli_fetch_assoc($res);
	} else {
		$saldo = 0;
	}
	return $saldo;
}
#=====================================================#
//  se exisitr refer 1
function pegar_refer($refer)
{
	global $mysqli;
	$qry = "SELECT * FROM usuarios WHERE token_refer='" . $refer . "'";
	$res = mysqli_query($mysqli, $qry);
	if (mysqli_num_rows($res) > 0) {
		$ex_refer = 1;
	} else {
		$ex_refer = 0;
	}
	return $ex_refer;
}
#=====================================================#
#=====================================================#
//  DELETAR USER
function deletar_user($id)
{
	global $mysqli;
	$sql = $mysqli->prepare("DELETE FROM  usuarios WHERE id=?");
	$sql->bind_param("i", $id);
	$sql->execute();

	$sql99 = $mysqli->prepare("DELETE FROM  financeiro WHERE usuario=?");
	$sql99->bind_param("i", $id);
	$sql99->execute();
}
#=====================================================#
function enviarRequest_PAYMENT($url, $header, $data = null)
{
	$ch = curl_init();
	$data_json = json_encode($data);
	// Configurando as opções do cURL
	curl_setopt($ch, CURLOPT_URL, $url);
	if (!$data == null) {
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
	}
	curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

	// Executando a requisição e obtendo a resposta
	$response = curl_exec($ch);

	// Fechando a conexão cURL
	curl_close($ch);

	return $response;
}
#=====================================================#
function requestToken_PAYMENT($url, $header, $data)
{
	$ch = curl_init();

	// Configurando as opções do cURL
	curl_setopt($ch, CURLOPT_URL, $url);
	curl_setopt($ch, CURLOPT_POST, 1);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
	curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

	// Executando a requisição e obtendo a resposta
	$response = curl_exec($ch);

	// Fechando a conexão cURL
	curl_close($ch);

	return $response;
}
#=====================================================#
#request pix
function request_paymentPIX($transactionId)
{
	global $data_suitpay, $tipoAPI_SUITPAY;
	if ($tipoAPI_SUITPAY == 0) {
		$url = 'https://sandbox.ws.suitpay.app/api/v1/gateway/consult-status-transaction';
		$data = array(
			'typeTransaction' => "PIX",
			'idTransaction' => $transactionId
		);
		$header = array(
			'ci: testesandbox_1687443996536',
			'cs: 5b7d6ed3407bc8c7efd45ac9d4c277004145afb96752e1252c2082d3211fe901177e09493c0d4f57b650d2b2fc1b062d',
			'Content-Type: application/json',
		);
	} else {
		$url = $data_suitpay['url'] . '/api/v1/gateway/consult-status-transaction';
		$data = array(
			'typeTransaction' => "PIX",
			'idTransaction' => $transactionId
		);
		$header = array(
			'ci: ' . $data_suitpay['client_id'],
			'cs: ' . $data_suitpay['client_secret'],
			'Content-Type: application/json'
		);

	}
	$response = enviarRequest_PAYMENT($url, $header, $data);
	$dados = json_decode($response, true);
	return $dados;
}
#=====================================================#
# coun refer direto
function count_refer_direto($refer)
{
	global $mysqli;
	$qry = "SELECT * FROM usuarios WHERE invitation_code='" . $refer . "'";
	$res = mysqli_query($mysqli, $qry);
	$ex_refer = mysqli_num_rows($res);
	return $ex_refer;
}
#=====================================================#
# count saque
function total_saques_id($id)
{
	global $mysqli;
	$qry = "SELECT SUM(valor) as total_soma FROM solicitacao_saques WHERE id_user='" . $id . "'";
	$result = mysqli_query($mysqli, $qry);
	while ($row = mysqli_fetch_assoc($result)) {
		if ($row['total_soma'] > 0) {
			$dinheiro = $row['total_soma'];
		} else {
			$dinheiro = '0.00';
		}
	}
	return $dinheiro;
}
#=====================================================#
# count depositos
function total_dep_id($id)
{
	global $mysqli;
	$qry = "SELECT SUM(valor) as total_soma FROM transacoes WHERE usuario='" . $id . "' AND tipo='deposito'";
	$result = mysqli_query($mysqli, $qry);
	while ($row = mysqli_fetch_assoc($result)) {
		if ($row['total_soma'] > 0) {
			$dinheiro = $row['total_soma'];
		} else {
			$dinheiro = '0.00';
		}
	}
	return $dinheiro;
}

function total_dep_pagos_id($id)
{
	global $mysqli;
	$qry = "SELECT SUM(valor) as total_soma FROM transacoes WHERE usuario='" . $id . "' AND tipo='deposito' AND status='pago'";
	$result = mysqli_query($mysqli, $qry);
	while ($row = mysqli_fetch_assoc($result)) {
		if ($row['total_soma'] > 0) {
			$dinheiro = $row['total_soma'];
		} else {
			$dinheiro = '0.00';
		}
	}
	return $dinheiro;
}

function total_dep_afiliado($id)
{
	global $mysqli;
	$qry = "SELECT SUM(valor) as total_soma FROM transacoes WHERE usuario IN (SELECT id FROM usuarios where invitation_code = '" . $id . "') AND tipo='deposito' AND status='pago'";
	$result = mysqli_query($mysqli, $qry);
	while ($row = mysqli_fetch_assoc($result)) {
		if ($row['total_soma'] > 0) {
			$dinheiro = $row['total_soma'];
		} else {
			$dinheiro = '0.00';
		}
	}
	return $dinheiro;
}
#=====================================================#
# SUM TOTAL ID CPA/REV
function total_CPA_REV_id($id)
{
	global $mysqli;
	$qry = "SELECT SUM(valor) as total_soma FROM pay_valores_cassino WHERE id_user='" . $id . "' AND tipo=0 OR tipo=1";
	$result = mysqli_query($mysqli, $qry);
	while ($row = mysqli_fetch_assoc($result)) {
		if ($row['total_soma'] > 0) {
			$dinheiro = $row['total_soma'];
		} else {
			$dinheiro = '0.00';
		}
	}
	return $dinheiro;
}

function total_CPA_id($id)
{
	global $mysqli;
	$qry = "SELECT SUM(valor) as total_soma FROM pay_valores_cassino WHERE id_user='" . $id . "' AND tipo=0";
	$result = mysqli_query($mysqli, $qry);
	while ($row = mysqli_fetch_assoc($result)) {
		if ($row['total_soma'] > 0) {
			$dinheiro = $row['total_soma'];
		} else {
			$dinheiro = '0.00';
		}
	}
	return $dinheiro;
}

function total_REV_id($id)
{
	global $mysqli;
	$qry = "SELECT SUM(valor) as total_soma FROM pay_valores_cassino WHERE id_user='" . $id . "' AND tipo=1";
	$result = mysqli_query($mysqli, $qry);
	while ($row = mysqli_fetch_assoc($result)) {
		if ($row['total_soma'] > 0) {
			$dinheiro = $row['total_soma'];
		} else {
			$dinheiro = '0.00';
		}
	}
	return $dinheiro;
}

#=====================================================#
# DATA USER ID
function data_user_id($id)
{
	global $mysqli;
	$qry = "SELECT * FROM usuarios WHERE id='" . $id . "'";
	$res = mysqli_query($mysqli, $qry);
	$data = mysqli_fetch_assoc($res);
	return $data;
}

function distribution($id)
{
	global $mysqli;
	$qry = "SELECT distribution FROM games WHERE id='" . $id . "'";
	$res = mysqli_query($mysqli, $qry);
	$data = mysqli_fetch_assoc($res);
	return $data['distribution'];
}

function gamecode($id)
{
	global $mysqli;
	$qry = "SELECT game_code FROM games WHERE game_code='" . $id . "'";
	$res = mysqli_query($mysqli, $qry);
	$data = mysqli_fetch_assoc($res);
	return $data['game_code'];
}

function gameprovider($id)
{
	global $mysqli;
	$qry = "SELECT provider FROM games WHERE game_code='" . $id . "'";
	$res = mysqli_query($mysqli, $qry);
	$data = mysqli_fetch_assoc($res);
	return $data['provider'];
}

function gameapi($id)
{
	global $mysqli;
	$qry = "SELECT api FROM games WHERE game_code='" . $id . "'";
	$res = mysqli_query($mysqli, $qry);
	$data = mysqli_fetch_assoc($res);
	return $data['api'];
}





#=====================================================#
#inserir saldo
function adicionarsaldo($id, $valor)
{
	global $mysqli;
	$qry = "UPDATE financeiro SET saldo= saldo + '" . $valor . "' WHERE usuario='" . $id . "'";
	$res = mysqli_query($mysqli, $qry);
	$data = mysqli_fetch_assoc($res);
	return $data;
}

function requestaddsaldo($email, $valor)
{
	$data = array(
		'user_code' => $email,
		'valor' => $valor
	);
	$json_data = json_encode($data);
	$response = enviarRequest('https://api.zenbet.online/api/v1/adicionarsaldo', $json_data);
	$dados = json_decode($response, true);
	return $dados;
}

#=====================================================#
#inserir saldo
function insert_payment_adm($id, $email, $valor)
{
	global $mysqli;
	$tokentrans = '#pixdinamic-' . rand(99, 99999);
	$data_hora = date('Y-m-d H:i:s');
	$sql1 = $mysqli->prepare("INSERT INTO transacoes (transacao_id,usuario,valor,data_hora,tipo,status,code) VALUES (?,?,?,?,'deposito','pago','dinamico')");
	$sql1->bind_param("ssss", $tokentrans, $id, $valor, $data_hora);
	#ENVIA SALDO VIA API
	$retorna_insert_saldo_suit_pay = enviarSaldo($email, $valor);
	if ($retorna_insert_saldo_suit_pay['status'] == 1 and $retorna_insert_saldo_suit_pay['msg'] == "SUCCESS" and $sql1->execute()) {
		$ert = 1;
	} else {
		$ert = 0;
	}
	return $ert;
}


function numero_total_dep($id)
{
	global $mysqli;
	$qry = "SELECT COUNT(*) as total_count FROM transacoes WHERE usuario IN (SELECT id FROM usuarios WHERE invitation_code = '" . $id . "') AND tipo='deposito' AND status='pago'";
	$result = mysqli_query($mysqli, $qry);
	while ($row = mysqli_fetch_assoc($result)) {
		if ($row['total_count'] > 0) {
			$total_count = $row['total_count'];
		} else {
			$total_count = 0;
		}
	}
	return $total_count;
}

#retirar saldo
function retirarsaldo($email, $valor)
{
	$data = array(
		'user_code' => $email,
		'valor' => $valor
	);
	$json_data = json_encode($data);
	$response = enviarRequest('https://api.zenbet.online/api/v1/removersaldo', $json_data);
	$dados = json_decode($response, true);
	return $dados;
}
#=====================================================#
#contar visitas
function visitas_count($tipo)
{
    global $mysqli;
    $data_hoje = date("Y-m-d");
    $data_90_dias = date("Y-m-d", strtotime("-90 days"));

    try {
        if ($tipo == 'diario') {
            $qry = "SELECT COUNT(*) as total FROM visita_site WHERE DATE(data_cad) = ?";
            $stmt = $mysqli->prepare($qry);
            $stmt->bind_param("s", $data_hoje);
            $stmt->execute();
            $result = $stmt->get_result();
            $count = $result->fetch_assoc()['total'];
        } elseif ($tipo == 'total') {
            $qry = "SELECT COUNT(*) as total FROM visita_site";
            $result = $mysqli->query($qry);
            $count = $result->fetch_assoc()['total'];
        } elseif ($tipo == '90d') {
            $qry = "SELECT COUNT(*) as total FROM visita_site WHERE DATE(data_cad) >= ?";
            $stmt = $mysqli->prepare($qry);
            $stmt->bind_param("s", $data_90_dias);
            $stmt->execute();
            $result = $stmt->get_result();
            $count = $result->fetch_assoc()['total'];
        } else {
            $count = 0;
        }
    } catch (Exception $e) {
        $count = 0;
    }
    
    return (int)$count;
}

#=====================================================#
# busca por token retorn o id
function busca_id_por_refer($token)
{
	global $mysqli;

	$qry = "SELECT * FROM usuarios WHERE token_refer='" . $token . "'";
	$res = mysqli_query($mysqli, $qry);
	if (mysqli_num_rows($res) > 0) {
		$data = mysqli_fetch_assoc($res);
		$count = $data['id'];
	} else {
		$count = 0;
	}
	return $count;
}
#=====================================================#
function generateQRCode_pix($data)
{
	// Carregue a biblioteca PHP QR Code
	require_once __DIR__ . '/../libraries/phpqrcode/qrlib.php';
	// Caminho onde você deseja salvar o arquivo PNG do QRCode (opcional)
	$file = '../../uploads/qrcode.png';
	// Gere o QRCode
	QRcode::png($data, $file);
	// Carregue o arquivo PNG do QRCode
	$qrCodeImage = file_get_contents($file);
	// Converta a imagem para base64
	$base64QRCode = base64_encode($qrCodeImage);
	return $base64QRCode;
}
#=====================================================#
# busca por ALERT DEP PENDENTES id
function busca_dep_pendentes($id)
{
	global $mysqli;
	$qry = "SELECT * FROM transacoes WHERE usuario='" . $id . "' AND tipo='deposito' AND status='processamento'";
	$res = mysqli_query($mysqli, $qry);
	if (mysqli_num_rows($res) > 0) {
		$data = 1;
	} else {
		$data = 0;
	}
	return $data;
}

// Função para buscar depósitos por dia
function depositos_por_dia() {
    global $mysqli;
    // Usamos DATE() para extrair apenas a data, ignorando a hora
    $qry = "SELECT DATE(data_registro) as dia, COUNT(*) as total FROM transacoes WHERE status = 'pago' AND tipo = 'deposito' GROUP BY DATE(data_registro) ORDER BY dia DESC LIMIT 7";
    $result = mysqli_query($mysqli, $qry);
    
    $dados = [];
    if ($result && mysqli_num_rows($result) > 0) {
        while ($row = mysqli_fetch_assoc($result)) {
            $dados[] = [
                'dia' => $row['dia'],          // Retorna a data no formato YYYY-MM-DD
                'total' => intval($row['total']) // Conta a quantidade de depósitos
            ];
        }
    }
    return $dados;
}



// Função para buscar saques por dia
function saques_por_dia() {
    global $mysqli;
    $qry = "SELECT DATE(data_registro) as dia, COUNT(*) as total FROM solicitacao_saques WHERE status = 1 GROUP BY DATE(data_registro) ORDER BY dia DESC LIMIT 7";
    $result = mysqli_query($mysqli, $qry);
    
    $dados = [];
    if ($result && mysqli_num_rows($result) > 0) {
        while ($row = mysqli_fetch_assoc($result)) {
            $dados[] = [
                'dia' => $row['dia'],
                'total' => intval($row['total'])  // Conta a quantidade de saques
            ];
        }
    }
    return $dados;
}

function WebhookCadastro($nome_user, $url)
{
    global $mysqli;

    $queryWebhook = "SELECT * FROM webhook WHERE status = 1";
    $resultWebhook = mysqli_query($mysqli, $queryWebhook);
    
    while ($webhook = mysqli_fetch_assoc($resultWebhook)) {
        $bot_id = $webhook['bot_id'];
        $chat_id = $webhook['chat_id'];
        $message = "✅ Cadastro realizado com sucesso!\n";
        $message .= "🏷️ Nome: $nome_user\n";
        $message .= "🌐 URL do site: $url";
        $urlTelegram = "https://api.telegram.org/bot$bot_id/sendMessage?chat_id=$chat_id&text=" . urlencode($message);
        file_get_contents($urlTelegram);
    }
}

function WebhookPixGerado($nome_user, $url, $valor)
{
    global $mysqli;
    $valor = number_format((float)$valor, 2, '.', ''); 

    $queryWebhook = "SELECT * FROM webhook WHERE status = 1";
    $resultWebhook = mysqli_query($mysqli, $queryWebhook);
    
    while ($webhook = mysqli_fetch_assoc($resultWebhook)) {
        $bot_id = $webhook['bot_id'];
        $chat_id = $webhook['chat_id'];
        $message = "✅ Pix gerado com sucesso\n";
        $message .= "💰 Valor: R$$valor\n";
        $message .= "⏳ Status: Pendente\n";
        $message .= "🏷️ Nome: $nome_user\n";
        $message .= "🌐 URL do site: $url";
        $urlTelegram = "https://api.telegram.org/bot$bot_id/sendMessage?chat_id=$chat_id&text=" . urlencode($message);
        file_get_contents($urlTelegram);
    }
}

function WebhookPixPagos($nome_user, $url, $valor)
{
    global $mysqli;

    $valorFormatado = is_array($valor) || is_object($valor) ? $valor['valor'] : $valor;

    $queryWebhook = "SELECT * FROM webhook WHERE status = 1";
    $resultWebhook = mysqli_query($mysqli, $queryWebhook);
    
    while ($webhook = mysqli_fetch_assoc($resultWebhook)) {
        $bot_id = $webhook['bot_id'];
        $chat_id = $webhook['chat_id'];
        $message = "✅ Pix pago com sucesso\n";
        $message .= "💰 Valor: R$$valorFormatado\n";
        $message .= "⏳ Status: Pago\n";
        $message .= "🏷️ Nome: $nome_user\n";
        $message .= "🌐 URL do site: $url";
        $urlTelegram = "https://api.telegram.org/bot$bot_id/sendMessage?chat_id=$chat_id&text=" . urlencode($message);
        file_get_contents($urlTelegram);
    }
}

// Adiciona o log de adição de saldo no banco de dados
function adicao_saldo($id_user, $valor, $tipo, $data_time) {
    global $mysqli;
    
    $query = "INSERT INTO adicao_saldo (id_user, valor, tipo, data_registro) VALUES (?, ?, ?, ?)";
    $stmt = $mysqli->prepare($query);
    $stmt->bind_param("idss", $id_user, $valor, $tipo, $data_time);


	//$ft = 0;
    
    if ($stmt->execute()) {
		//$ft = 1;
        logMessage("Log de adição de saldo registrado para o usuário $id_user: $valor em $data_time");
    } else {
		//$ft = 0;
        logMessage("Erro ao registrar log de adição de saldo para o usuário $id_user: " . $stmt->error);
    }
}



function getCurrentUrl() {
    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https://' : 'http://';
    $host = $_SERVER['HTTP_HOST'];
    return $protocol . $host;
}

?>