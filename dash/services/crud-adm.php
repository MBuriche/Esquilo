<?php
    date_default_timezone_set('America/Sao_Paulo');
	include_once('database.php');
	include_once('funcao.php');
	#=====================================================#
	# DATA AVATAR
	function data_avatar(){
		global $mysqli;
		$qry = "SELECT * FROM admin_users WHERE id=1";
		$res = mysqli_query($mysqli,$qry);
		$data = mysqli_fetch_assoc($res );
		return $data;
	}
	$data_avatar = data_avatar();
	#=====================================================#
	# DATA user count
	function qtd_usuarios(){
		global $mysqli;
		$qry = "SELECT COUNT(*) as total FROM usuarios";
		$res = mysqli_query($mysqli,$qry);
		$data = mysqli_fetch_assoc($res)['total'];
		return $data;
	}
	
	function qtd_usuarios_depositantes(){
		global $mysqli;

		// Query to get the number of unique users who have made a 'pago' deposit
		$qry = "
			SELECT COUNT(DISTINCT usuario) as depositantes 
			FROM transacoes 
			WHERE tipo = 'deposito' AND status = 'pago'
		";
		$res = mysqli_query($mysqli, $qry);
		$data = mysqli_fetch_assoc($res)['depositantes'];

		return $data;
	}

	function usuarios_resumo_dashboard(){
		global $mysqli;
		$data_hoje = date('Y-m-d');
		
		// Total de usuários
		$qry_total = "SELECT COUNT(*) as total FROM usuarios";
		$result_total = mysqli_query($mysqli, $qry_total);
		$total_usuarios = mysqli_fetch_assoc($result_total)['total'];
		
		// Usuários hoje
		$qry_hoje = "SELECT COUNT(*) as hoje FROM usuarios WHERE DATE(data_registro) = ?";
		$stmt_hoje = $mysqli->prepare($qry_hoje);
		$stmt_hoje->bind_param("s", $data_hoje);
		$stmt_hoje->execute();
		$result_hoje = $stmt_hoje->get_result();
		$usuarios_hoje = mysqli_fetch_assoc($result_hoje)['hoje'];
		
		// Usuários que depositaram (pagos)
		$qry_depositantes = "SELECT COUNT(DISTINCT usuario) as depositantes FROM transacoes WHERE tipo='deposito' AND status='pago'";
		$result_depositantes = mysqli_query($mysqli, $qry_depositantes);
		$depositantes_total = mysqli_fetch_assoc($result_depositantes)['depositantes'];
		
		// Usuários que depositaram hoje (pagos)
		$qry_depositantes_hoje = "SELECT COUNT(DISTINCT usuario) as depositantes_hoje FROM transacoes WHERE tipo='deposito' AND status='pago' AND DATE(data_registro) = ?";
		$stmt_depositantes_hoje = $mysqli->prepare($qry_depositantes_hoje);
		$stmt_depositantes_hoje->bind_param("s", $data_hoje);
		$stmt_depositantes_hoje->execute();
		$result_depositantes_hoje = $stmt_depositantes_hoje->get_result();
		$depositantes_hoje = mysqli_fetch_assoc($result_depositantes_hoje)['depositantes_hoje'];
		
		// Calcular porcentagens
		$porcentagem_depositantes_hoje = $usuarios_hoje > 0 ? ($depositantes_hoje / $usuarios_hoje) * 100 : 0;
		$porcentagem_depositantes_total = $total_usuarios > 0 ? ($depositantes_total / $total_usuarios) * 100 : 0;
		
		return [
			'total_usuarios' => $total_usuarios,
			'usuarios_hoje' => $usuarios_hoje,
			'depositantes_total' => $depositantes_total,
			'depositantes_hoje' => $depositantes_hoje,
			'porcentagem_depositantes_hoje' => number_format($porcentagem_depositantes_hoje, 1),
			'porcentagem_depositantes_total' => number_format($porcentagem_depositantes_total, 1)
		];
	}
	#=====================================================#
	# DATA SALDO CASSINO
	function saldo_cassino(){
		global $mysqli;
		$qry = "SELECT SUM(valor) as total_soma FROM transacoes WHERE tipo='deposito' AND status='pago'";
		$result = mysqli_query($mysqli, $qry);
		while($row = mysqli_fetch_assoc($result)){
			if($row['total_soma'] >0){
				$deposito = $row['total_soma'];
			}else{
			   $deposito = '0.00';
			}
		}
		#-
		$qry_saques = "SELECT SUM(valor) as total_soma FROM solicitacao_saques WHERE status=1";
		$result_saques = mysqli_query($mysqli, $qry_saques);
		while($row_saques = mysqli_fetch_assoc($result_saques)){
			if($row_saques['total_soma'] >0){
				$saques = $row_saques['total_soma'];
			}else{
			   $saques = '0.00';
			}
		}
		$total = $deposito-$saques;
		return $total;
	}
	#=====================================================#
	# DATA deposito pendentes
	function depositos_pendentes(){
		global $mysqli;
		$qry = "SELECT SUM(valor) as total_soma FROM transacoes WHERE tipo='deposito' AND status='processamento'";
		$result = mysqli_query($mysqli, $qry);
		while($row = mysqli_fetch_assoc($result)){
			if($row['total_soma'] >0){
				$deposito = $row['total_soma'];
			}else{
			   $deposito = '0.00';
			}
		}
		return $deposito;
	}
	#=====================================================#
	# DATA deposito diario
	function depositos_diarios(){
		global $mysqli;
		$data = date('Y-m-d');
		$qry = "SELECT SUM(valor) as total_soma FROM transacoes WHERE tipo='deposito' AND status='processamento' AND DATE(data_registro) = ?";
		$stmt = $mysqli->prepare($qry);
		$stmt->bind_param("s", $data);
		$stmt->execute();
		$result = $stmt->get_result();
		
		$deposito = '0.00'; // Valor padrão
	
		if($row = $result->fetch_assoc()){
			if($row['total_soma'] > 0){
				$deposito = $row['total_soma'];
			}
		}
		
		return $deposito;
	}

	# DATA deposito diario
	function depositos_diarios_pagos(){
		global $mysqli;
		$data = date('Y-m-d');
		$qry = "SELECT SUM(valor) as total_soma FROM transacoes WHERE tipo='deposito' AND status='pago' AND DATE(data_registro) = ?";
		$stmt = $mysqli->prepare($qry);
		$stmt->bind_param("s", $data);
		$stmt->execute();
		$result = $stmt->get_result();
		
		$deposito = '0.00'; // Valor padrão
	
		if($row = $result->fetch_assoc()){
			if($row['total_soma'] > 0){
				$deposito = $row['total_soma'];
			}
		}
		
		return $deposito;
	}
	#=====================================================#
	# DATA deposito diario
	function depositos_total(){
		global $mysqli;
		$data = date('Y-m-d');
		$qry = "SELECT SUM(valor) as total_soma FROM transacoes WHERE tipo='deposito' AND status='pago'";
		$result = mysqli_query($mysqli, $qry);
		while($row = mysqli_fetch_assoc($result)){
			if($row['total_soma'] >0){
				$deposito = $row['total_soma'];
			}else{
			   $deposito = '0.00';
			}
		}
		return $deposito;
	}
	#=====================================================#
	# DATA saque pendentes 
	function saques_pendentes(){
		global $mysqli;
		$qry = "SELECT SUM(valor) as total_soma FROM solicitacao_saques WHERE status=0";
		$result = mysqli_query($mysqli, $qry);
		while($row = mysqli_fetch_assoc($result)){
			if($row['total_soma'] >0){
				$deposito = $row['total_soma'];
			}else{
			   $deposito = '0.00';
			}
		}
		return $deposito;
	}
	#=====================================================#
	# DATA saque diarios pagos 
	function saques_diarios_pagos(){
		global $mysqli;
		$data = date('Y-m-d');
		$qry = "SELECT SUM(valor) as total_soma FROM solicitacao_saques WHERE data_registro='".$data."' AND status=1";
		$result = mysqli_query($mysqli, $qry);
		while($row = mysqli_fetch_assoc($result)){
			if($row['total_soma'] >0){
				$deposito = $row['total_soma'];
			}else{
			   $deposito = '0.00';
			}
		}
		return $deposito;
	}
	#=====================================================#
	# DATA saque diarios pagos 
	function saques_total(){
		global $mysqli;
		$data = date('Y-m-d');
		$qry = "SELECT SUM(valor) as total_soma FROM solicitacao_saques WHERE status= '1'";
		$result = mysqli_query($mysqli, $qry);
		while($row = mysqli_fetch_assoc($result)){
			if($row['total_soma'] >0){
				$deposito = $row['total_soma'];
			}else{
			   $deposito = '0.00';
			}
		}
		return $deposito;
	}
	#=====================================================#
	#count saques pendentes
	function count_saques_pendentes(){
		global $mysqli;
		$qry = "SELECT * FROM solicitacao_saques WHERE status=0";
		$res = mysqli_query($mysqli, $qry);
		$count = mysqli_num_rows($res);
		return $count;
	}
	#=====================================================#
	# DATA user count
    function qtd_usuarios_diarios(){
        global $mysqli;
        $data = date('Y-m-d');
    
        // Query to get the total number of users registered today
        $qry = "SELECT COUNT(*) as total FROM usuarios WHERE DATE_FORMAT(data_registro, '%Y-%m-%d') = '$data'";
        $res = mysqli_query($mysqli, $qry);
        $data = mysqli_fetch_assoc($res)['total'];
    
        return $data;
    }
    
    function qtd_usuarios_depositantes_diarios(){
        global $mysqli;
        $data = date('Y-m-d');
    
        // Query to get the number of unique users who made a 'pago' deposit today
        $qry = "
            SELECT COUNT(DISTINCT usuario) as depositantes 
            FROM transacoes 
            WHERE tipo = 'deposito' AND status = 'pago' AND DATE(data_registro) = '$data'
        ";
        $res = mysqli_query($mysqli, $qry);
        $data = mysqli_fetch_assoc($res)['depositantes'];
    
        return $data;
    }
	#=====================================================#
	
    function qtd_usuarios_90d() {
        global $mysqli;
        $data_inicio = date('Y-m-d', strtotime('-90 days'));
        $qry = "SELECT * FROM usuarios WHERE data_registro >= '$data_inicio'";
        $res = mysqli_query($mysqli, $qry);
        $total = mysqli_num_rows($res);
        return $total;
    }
    
    function qtd_primeiro_deposito_usuarios_90d() {
    global $mysqli;
    $data_inicio = date('Y-m-d', strtotime('-90 days'));

    // Query to get the count of unique users who made their first deposit in the last 90 days
    $qry = "
        SELECT COUNT(DISTINCT usuario) as total
        FROM transacoes t1
        WHERE tipo = 'deposito' 
        AND status = 'pago'
        AND DATE(data_registro) >= '$data_inicio'
        AND data_registro = (
            SELECT MIN(data_registro)
            FROM transacoes t2
            WHERE t2.usuario = t1.usuario 
            AND t2.tipo = 'deposito' 
            AND t2.status = 'pago'
        )
    ";

    $res = mysqli_query($mysqli, $qry);
    $total = mysqli_fetch_assoc($res)['total'];

    return $total;
    }

    function total_jogadas() {
        global $mysqli;
        $qry = "SELECT COUNT(*) as total FROM historico_play";
        $result = mysqli_query($mysqli, $qry);
        $row = mysqli_fetch_assoc($result);
        return $row['total'];
    }
    
    function formatar_nome_jogo($nome_game) {
    return ucwords(str_replace('-', ' ', $nome_game));
    }

    function jogo_mais_jogado() {
        global $mysqli;
        $qry = "SELECT nome_game, COUNT(*) as total FROM historico_play GROUP BY nome_game ORDER BY total DESC LIMIT 1";
        $result = mysqli_query($mysqli, $qry);
        $row = mysqli_fetch_assoc($result);
    
        return $row ? formatar_nome_jogo($row['nome_game']) : 'Nenhum jogo encontrado';
    }

    function percentual_usuarios_diarios() {
        $total = qtd_usuarios();
        $diarios = qtd_usuarios_diarios();
        
        if ($total > 0) {
            $percentual = ($diarios / $total) * 100;
        } else {
            $percentual = 0;
        }
        
        return number_format($percentual, 1);
    }
    
    function percentual_usuarios_90d() {
        $total = qtd_usuarios();
        $usuarios_90d = qtd_usuarios_90d();
        
        if ($total > 0) {
            $percentual = ($usuarios_90d / $total) * 100;
        } else {
            $percentual = 0;
        }
        
        return number_format($percentual, 1);
    }
    
    function percentual_lucro() {
    $total_depositos = depositos_total();
    $total_saques = saques_total();
    
    if ($total_depositos > 0) {
        $percentual_lucro = (($total_depositos - $total_saques) / $total_depositos) * 100;
    } else {
        $percentual_lucro = 0;
    }
    
    return number_format($percentual_lucro, 1);
    }

    function count_saques_total(){
        global $mysqli;
        $qry = "SELECT COUNT(*) as total_count FROM solicitacao_saques WHERE status = '1'";
        $result = mysqli_query($mysqli, $qry);
        $row = mysqli_fetch_assoc($result);
        return $row['total_count'] ?? 0;
    }

    function saldo_usuarios_info(){
		global $mysqli;
		
		// Query para obter o valor total de saldo de todos os usuários
		$qry_total = "SELECT SUM(saldo) as total_saldo FROM usuarios WHERE saldo > 0";
		$result_total = mysqli_query($mysqli, $qry_total);
		$row_total = mysqli_fetch_assoc($result_total);
		$total_saldo = $row_total['total_saldo'] ? $row_total['total_saldo'] : 0;
		
		// Query para contar quantos usuários têm saldo maior que 0
		$qry_count = "SELECT COUNT(*) as usuarios_com_saldo FROM usuarios WHERE saldo > 0";
		$result_count = mysqli_query($mysqli, $qry_count);
		$row_count = mysqli_fetch_assoc($result_count);
		$usuarios_com_saldo = $row_count['usuarios_com_saldo'];
		
		return [
			'total_saldo' => number_format($total_saldo, 2, '.', ''),
			'usuarios_com_saldo' => $usuarios_com_saldo
		];
	}

function depositos_info()
{
	global $mysqli;
	$data_hoje = date('Y-m-d');

	// Depósitos pagos hoje - valor e quantidade
	$qry_hoje_valor = "SELECT SUM(valor) as total_hoje FROM transacoes WHERE tipo='deposito' AND status='pago' AND DATE(data_registro) = ?";
	$stmt_hoje_valor = $mysqli->prepare($qry_hoje_valor);
	$stmt_hoje_valor->bind_param("s", $data_hoje);
	$stmt_hoje_valor->execute();
	$result_hoje_valor = $stmt_hoje_valor->get_result();
	$row_hoje_valor = $result_hoje_valor->fetch_assoc();
	$total_hoje = $row_hoje_valor['total_hoje'] ? $row_hoje_valor['total_hoje'] : 0;

	$qry_hoje_qtd = "SELECT COUNT(*) as qtd_hoje FROM transacoes WHERE tipo='deposito' AND status='pago' AND DATE(data_registro) = ?";
	$stmt_hoje_qtd = $mysqli->prepare($qry_hoje_qtd);
	$stmt_hoje_qtd->bind_param("s", $data_hoje);
	$stmt_hoje_qtd->execute();
	$result_hoje_qtd = $stmt_hoje_qtd->get_result();
	$row_hoje_qtd = $result_hoje_qtd->fetch_assoc();
	$qtd_hoje = $row_hoje_qtd['qtd_hoje'];

	// Depósitos pagos total - valor e quantidade
	$qry_total_valor = "SELECT SUM(valor) as total_geral FROM transacoes WHERE tipo='deposito' AND status='pago'";
	$result_total_valor = mysqli_query($mysqli, $qry_total_valor);
	$row_total_valor = mysqli_fetch_assoc($result_total_valor);
	$total_geral = $row_total_valor['total_geral'] ? $row_total_valor['total_geral'] : 0;

	$qry_total_qtd = "SELECT COUNT(*) as qtd_total FROM transacoes WHERE tipo='deposito' AND status='pago'";
	$result_total_qtd = mysqli_query($mysqli, $qry_total_qtd);
	$row_total_qtd = mysqli_fetch_assoc($result_total_qtd);
	$qtd_total = $row_total_qtd['qtd_total'];

	return [
		'total_depositos_hoje' => $total_hoje,
		'qtd_depositos_hoje' => $qtd_hoje,
		'total_depositos' => $total_geral,
		'qtd_depositos_total' => $qtd_total
	];
}

	function saques_info(){
		global $mysqli;
		$data_hoje = date('Y-m-d');
		
		// Saques pagos hoje - valor e quantidade
		$qry_hoje_valor = "SELECT SUM(valor) as total_hoje FROM solicitacao_saques WHERE status=1 AND DATE(data_registro) = ?";
		$stmt_hoje_valor = $mysqli->prepare($qry_hoje_valor);
		$stmt_hoje_valor->bind_param("s", $data_hoje);
		$stmt_hoje_valor->execute();
		$result_hoje_valor = $stmt_hoje_valor->get_result();
		$row_hoje_valor = $result_hoje_valor->fetch_assoc();
		$total_hoje = $row_hoje_valor['total_hoje'] ? $row_hoje_valor['total_hoje'] : 0;
		
		$qry_hoje_qtd = "SELECT COUNT(*) as qtd_hoje FROM solicitacao_saques WHERE status=1 AND DATE(data_registro) = ?";
		$stmt_hoje_qtd = $mysqli->prepare($qry_hoje_qtd);
		$stmt_hoje_qtd->bind_param("s", $data_hoje);
		$stmt_hoje_qtd->execute();
		$result_hoje_qtd = $stmt_hoje_qtd->get_result();
		$row_hoje_qtd = $result_hoje_qtd->fetch_assoc();
		$qtd_hoje = $row_hoje_qtd['qtd_hoje'];
		
		// Saques pagos total - valor e quantidade
		$qry_total_valor = "SELECT SUM(valor) as total_geral FROM solicitacao_saques WHERE status=1";
		$result_total_valor = mysqli_query($mysqli, $qry_total_valor);
		$row_total_valor = mysqli_fetch_assoc($result_total_valor);
		$total_geral = $row_total_valor['total_geral'] ? $row_total_valor['total_geral'] : 0;
		
		$qry_total_qtd = "SELECT COUNT(*) as qtd_total FROM solicitacao_saques WHERE status=1";
		$result_total_qtd = mysqli_query($mysqli, $qry_total_qtd);
		$row_total_qtd = mysqli_fetch_assoc($result_total_qtd);
		$qtd_total = $row_total_qtd['qtd_total'];
		
		return [
			'total_saques_hoje' => $total_hoje,
			'qtd_saques_hoje' => $qtd_hoje,
			'total_saques' => $total_geral,
			'qtd_saques_total' => $qtd_total
		];
	}

	function pix_gerados(){
		global $mysqli;
		$data_hoje = date('Y-m-d');
		
		// Todos os depósitos hoje - valor e quantidade (todos os status)
		$qry_hoje_valor = "SELECT SUM(valor) as total_hoje FROM transacoes WHERE tipo='deposito' AND DATE(data_registro) = ?";
		$stmt_hoje_valor = $mysqli->prepare($qry_hoje_valor);
		$stmt_hoje_valor->bind_param("s", $data_hoje);
		$stmt_hoje_valor->execute();
		$result_hoje_valor = $stmt_hoje_valor->get_result();
		$row_hoje_valor = $result_hoje_valor->fetch_assoc();
		$total_hoje = $row_hoje_valor['total_hoje'] ? $row_hoje_valor['total_hoje'] : 0;
		
		$qry_hoje_qtd = "SELECT COUNT(*) as qtd_hoje FROM transacoes WHERE tipo='deposito' AND DATE(data_registro) = ?";
		$stmt_hoje_qtd = $mysqli->prepare($qry_hoje_qtd);
		$stmt_hoje_qtd->bind_param("s", $data_hoje);
		$stmt_hoje_qtd->execute();
		$result_hoje_qtd = $stmt_hoje_qtd->get_result();
		$row_hoje_qtd = $result_hoje_qtd->fetch_assoc();
		$qtd_hoje = $row_hoje_qtd['qtd_hoje'];
		
		// Todos os depósitos total - valor e quantidade (todos os status)
		$qry_total_valor = "SELECT SUM(valor) as total_geral FROM transacoes WHERE tipo='deposito'";
		$result_total_valor = mysqli_query($mysqli, $qry_total_valor);
		$row_total_valor = mysqli_fetch_assoc($result_total_valor);
		$total_geral = $row_total_valor['total_geral'] ? $row_total_valor['total_geral'] : 0;
		
		$qry_total_qtd = "SELECT COUNT(*) as qtd_total FROM transacoes WHERE tipo='deposito'";
		$result_total_qtd = mysqli_query($mysqli, $qry_total_qtd);
		$row_total_qtd = mysqli_fetch_assoc($result_total_qtd);
		$qtd_total = $row_total_qtd['qtd_total'];
		
		// Calcular porcentagem de PIX pagos hoje
		$qry_pagos_hoje = "SELECT COUNT(*) as pagos_hoje FROM transacoes WHERE tipo='deposito' AND status='pago' AND DATE(data_registro) = ?";
		$stmt_pagos_hoje = $mysqli->prepare($qry_pagos_hoje);
		$stmt_pagos_hoje->bind_param("s", $data_hoje);
		$stmt_pagos_hoje->execute();
		$result_pagos_hoje = $stmt_pagos_hoje->get_result();
		$row_pagos_hoje = $result_pagos_hoje->fetch_assoc();
		$pagos_hoje = $row_pagos_hoje['pagos_hoje'];
		
		$porcentagem_pagos_hoje = $qtd_hoje > 0 ? ($pagos_hoje / $qtd_hoje) * 100 : 0;
		
		// Calcular porcentagem de PIX pagos total
		$qry_pagos_total = "SELECT COUNT(*) as pagos_total FROM transacoes WHERE tipo='deposito' AND status='pago'";
		$result_pagos_total = mysqli_query($mysqli, $qry_pagos_total);
		$row_pagos_total = mysqli_fetch_assoc($result_pagos_total);
		$pagos_total = $row_pagos_total['pagos_total'];
		
		$porcentagem_pagos_total = $qtd_total > 0 ? ($pagos_total / $qtd_total) * 100 : 0;
		
		return [
			'total_pix_hoje' => $total_hoje,
			'qtd_pix_hoje' => $qtd_hoje,
			'total_pix' => $total_geral,
			'qtd_pix_total' => $qtd_total,
			'porcentagem_pagos_hoje' => number_format($porcentagem_pagos_hoje, 1),
			'porcentagem_pagos_total' => number_format($porcentagem_pagos_total, 1)
		];
	}

	function usuarios_estatisticas_completas(){
		global $mysqli;
		$data_hoje = date('Y-m-d');
		
		// Total de usuários cadastrados
		$qry_total_usuarios = "SELECT COUNT(*) as total FROM usuarios";
		$result_total = mysqli_query($mysqli, $qry_total_usuarios);
		$total_usuarios = mysqli_fetch_assoc($result_total)['total'];
		
		// Usuários cadastrados hoje
		$qry_usuarios_hoje = "SELECT COUNT(*) as total_hoje FROM usuarios WHERE DATE(data_registro) = ?";
		$stmt_usuarios_hoje = $mysqli->prepare($qry_usuarios_hoje);
		$stmt_usuarios_hoje->bind_param("s", $data_hoje);
		$stmt_usuarios_hoje->execute();
		$result_usuarios_hoje = $stmt_usuarios_hoje->get_result();
		$usuarios_hoje = mysqli_fetch_assoc($result_usuarios_hoje)['total_hoje'];
		
		// Total de usuários que fizeram depósito (qualquer status)
		$qry_depositantes_total = "SELECT COUNT(DISTINCT usuario) as total FROM transacoes WHERE tipo='deposito'";
		$result_depositantes_total = mysqli_query($mysqli, $qry_depositantes_total);
		$depositantes_total = mysqli_fetch_assoc($result_depositantes_total)['total'];
		
		// Usuários que fizeram depósito hoje (qualquer status)
		$qry_depositantes_hoje = "SELECT COUNT(DISTINCT usuario) as total_hoje FROM transacoes WHERE tipo='deposito' AND DATE(data_registro) = ?";
		$stmt_depositantes_hoje = $mysqli->prepare($qry_depositantes_hoje);
		$stmt_depositantes_hoje->bind_param("s", $data_hoje);
		$stmt_depositantes_hoje->execute();
		$result_depositantes_hoje = $stmt_depositantes_hoje->get_result();
		$depositantes_hoje = mysqli_fetch_assoc($result_depositantes_hoje)['total_hoje'];
		
		// Calcular porcentagens
		$porcentagem_depositantes_hoje = $usuarios_hoje > 0 ? ($depositantes_hoje / $usuarios_hoje) * 100 : 0;
		$porcentagem_depositantes_total = $total_usuarios > 0 ? ($depositantes_total / $total_usuarios) * 100 : 0;
		
		return [
			'total_usuarios' => $total_usuarios,
			'usuarios_hoje' => $usuarios_hoje,
			'depositantes_total' => $depositantes_total,
			'depositantes_hoje' => $depositantes_hoje,
			'porcentagem_depositantes_hoje' => number_format($porcentagem_depositantes_hoje, 1),
			'porcentagem_depositantes_total' => number_format($porcentagem_depositantes_total, 1)
		];
	}

	function dados_grafico_depositos_saques(){
		global $mysqli;
		
		$dados = [];
		
		// Obter dados dos últimos 7 dias
		for($i = 6; $i >= 0; $i--) {
			$data = date('Y-m-d', strtotime("-$i days"));
			$data_formatada = date('d/m', strtotime("-$i days"));
			
			// Depósitos do dia
			$qry_depositos = "SELECT COALESCE(SUM(valor), 0) as total FROM transacoes WHERE tipo='deposito' AND status='pago' AND DATE(data_registro) = ?";
			$stmt_dep = $mysqli->prepare($qry_depositos);
			$stmt_dep->bind_param("s", $data);
			$stmt_dep->execute();
			$result_dep = $stmt_dep->get_result();
			$depositos = $result_dep->fetch_assoc()['total'];
			
			// Saques do dia
			$qry_saques = "SELECT COALESCE(SUM(valor), 0) as total FROM solicitacao_saques WHERE status=1 AND DATE(data_registro) = ?";
			$stmt_saq = $mysqli->prepare($qry_saques);
			$stmt_saq->bind_param("s", $data);
			$stmt_saq->execute();
			$result_saq = $stmt_saq->get_result();
			$saques = $result_saq->fetch_assoc()['total'];
			
			$dados[] = [
				'data' => $data_formatada,
				'depositos' => (float)$depositos,
				'saques' => (float)$saques,
				'lucro' => (float)($depositos - $saques)
			];
		}
		
		return $dados;
	}

	function dados_grafico_depositos_saques_30_dias(){
		global $mysqli;
		
		$dados = [];
		
		// Obter dados dos últimos 30 dias
		for($i = 29; $i >= 0; $i--) {
			$data = date('Y-m-d', strtotime("-$i days"));
			$data_formatada = date('d/m', strtotime("-$i days"));
			
			// Depósitos do dia
			$qry_depositos = "SELECT COALESCE(SUM(valor), 0) as total FROM transacoes WHERE tipo='deposito' AND status='pago' AND DATE(data_registro) = ?";
			$stmt_dep = $mysqli->prepare($qry_depositos);
			$stmt_dep->bind_param("s", $data);
			$stmt_dep->execute();
			$result_dep = $stmt_dep->get_result();
			$depositos = $result_dep->fetch_assoc()['total'];
			
			// Saques do dia
			$qry_saques = "SELECT COALESCE(SUM(valor), 0) as total FROM solicitacao_saques WHERE status=1 AND DATE(data_registro) = ?";
			$stmt_saq = $mysqli->prepare($qry_saques);
			$stmt_saq->bind_param("s", $data);
			$stmt_saq->execute();
			$result_saq = $stmt_saq->get_result();
			$saques = $result_saq->fetch_assoc()['total'];
			
			$dados[] = [
				'data' => $data_formatada,
				'depositos' => (float)$depositos,
				'saques' => (float)$saques,
				'lucro' => (float)($depositos - $saques)
			];
		}
		
		return $dados;
	}

	function dados_grafico_resumo_semanal(){
		global $mysqli;
		
		$dados = [];
		
		// Obter dados das últimas 4 semanas
		for($i = 3; $i >= 0; $i--) {
			$data_inicio = date('Y-m-d', strtotime("-" . (($i + 1) * 7) . " days"));
			$data_fim = date('Y-m-d', strtotime("-" . ($i * 7) . " days"));
			$semana_label = "Semana " . (4 - $i);
			
			// Depósitos da semana
			$qry_depositos = "SELECT COALESCE(SUM(valor), 0) as total FROM transacoes WHERE tipo='deposito' AND status='pago' AND DATE(data_registro) BETWEEN ? AND ?";
			$stmt_dep = $mysqli->prepare($qry_depositos);
			$stmt_dep->bind_param("ss", $data_inicio, $data_fim);
			$stmt_dep->execute();
			$result_dep = $stmt_dep->get_result();
			$depositos = $result_dep->fetch_assoc()['total'];
			
			// Saques da semana
			$qry_saques = "SELECT COALESCE(SUM(valor), 0) as total FROM solicitacao_saques WHERE status=1 AND DATE(data_registro) BETWEEN ? AND ?";
			$stmt_saq = $mysqli->prepare($qry_saques);
			$stmt_saq->bind_param("ss", $data_inicio, $data_fim);
			$stmt_saq->execute();
			$result_saq = $stmt_saq->get_result();
			$saques = $result_saq->fetch_assoc()['total'];
			
			$dados[] = [
				'data' => $semana_label,
				'depositos' => (float)$depositos,
				'saques' => (float)$saques,
				'lucro' => (float)($depositos - $saques)
			];
		}
		
		return $dados;
	}
function trafego_por_fonte($periodo = '7'){
		global $mysqli;
		
		$dados = [];
		$data_hoje = date("Y-m-d");
		
		// Determinar data de início baseada no período
		switch($periodo) {
			case '30':
				$data_inicio = date("Y-m-d", strtotime("-30 days"));
				break;
			case 'all':
				$data_inicio = '2020-01-01'; // Data bem antiga para pegar tudo
				break;
			default:
				$data_inicio = date("Y-m-d", strtotime("-7 days"));
		}
		
		// Fontes principais para verificar
		$fontes = [
			'Google' => ['google', 'search'],
			'YouTube' => ['youtube', 'youtu.be'],
			'Instagram' => ['instagram', 'ig'],
			'Facebook' => ['facebook', 'fb'],
			'Twitter' => ['twitter', 'x.com'],
			'Direto' => ['direto', 'direct', ''],
			'Outros' => []
		];
		
		// Buscar visitas do período selecionado
		$total_visitas = 0;
		if ($periodo == 'all') {
			$qry_total = "SELECT COUNT(*) as total FROM visita_site";
			$stmt = $mysqli->prepare($qry_total);
		} else {
			$qry_total = "SELECT COUNT(*) as total FROM visita_site WHERE data_cad >= ?";
			$stmt = $mysqli->prepare($qry_total);
			$stmt->bind_param("s", $data_inicio);
		}
		$stmt->execute();
		$result = $stmt->get_result();
		$total_visitas = $result->fetch_assoc()['total'];
		
		if ($total_visitas == 0) {
			// Se não há dados reais, criar dados fictícios baseados em padrões típicos
			$dados = [
				'Google' => ['visitas' => 45, 'porcentagem' => 45],
				'Instagram' => ['visitas' => 25, 'porcentagem' => 25],
				'Facebook' => ['visitas' => 15, 'porcentagem' => 15],
				'YouTube' => ['visitas' => 8, 'porcentagem' => 8],
				'Twitter' => ['visitas' => 4, 'porcentagem' => 4],
				'Direto' => ['visitas' => 3, 'porcentagem' => 3]
			];
		} else {
			// Processar dados reais
			foreach ($fontes as $fonte_nome => $termos) {
				if ($fonte_nome == 'Outros') continue;
				
				$visitas = 0;
				if (!empty($termos)) {
					if ($periodo == 'all') {
						$qry = "SELECT COUNT(*) as total FROM visita_site WHERE (";
						$conditions = [];
						foreach ($termos as $termo) {
							$conditions[] = "LOWER(refer_visita) LIKE ?";
						}
						$qry .= implode(' OR ', $conditions) . ")";
						
						$stmt = $mysqli->prepare($qry);
						$params = [];
						foreach ($termos as $termo) {
							$params[] = '%' . strtolower($termo) . '%';
						}
						$stmt->bind_param(str_repeat('s', count($params)), ...$params);
					} else {
						$qry = "SELECT COUNT(*) as total FROM visita_site 
								WHERE data_cad >= ? AND (";
						
						$conditions = [];
						foreach ($termos as $termo) {
							$conditions[] = "LOWER(refer_visita) LIKE ?";
						}
						$qry .= implode(' OR ', $conditions) . ")";
						
						$stmt = $mysqli->prepare($qry);
						$params = [$data_inicio];
						foreach ($termos as $termo) {
							$params[] = '%' . strtolower($termo) . '%';
						}
						$stmt->bind_param(str_repeat('s', count($params)), ...$params);
					}
					
					$stmt->execute();
					$result = $stmt->get_result();
					$visitas = $result->fetch_assoc()['total'];
				}
				
				$porcentagem = $total_visitas > 0 ? round(($visitas / $total_visitas) * 100, 1) : 0;
				$dados[$fonte_nome] = [
					'visitas' => $visitas,
					'porcentagem' => $porcentagem
				];
			}
		}
		
		return $dados;
	}

	function estatisticas_trafego_site(){
		global $mysqli;
		
		$data_hoje = date("Y-m-d");
		$data_ontem = date("Y-m-d", strtotime("-1 day"));
		$data_7_dias = date("Y-m-d", strtotime("-7 days"));
		$data_30_dias = date("Y-m-d", strtotime("-30 days"));
		
		// Visitas hoje
		$qry_hoje = "SELECT COUNT(*) as total FROM visita_site WHERE data_cad = ?";
		$stmt = $mysqli->prepare($qry_hoje);
		$stmt->bind_param("s", $data_hoje);
		$stmt->execute();
		$visitas_hoje = $stmt->get_result()->fetch_assoc()['total'];
		
		// Visitas ontem
		$stmt->bind_param("s", $data_ontem);
		$stmt->execute();
		$visitas_ontem = $stmt->get_result()->fetch_assoc()['total'];
		
		// Visitas últimos 7 dias
		$qry_periodo = "SELECT COUNT(*) as total FROM visita_site WHERE data_cad >= ?";
		$stmt = $mysqli->prepare($qry_periodo);
		$stmt->bind_param("s", $data_7_dias);
		$stmt->execute();
		$visitas_7_dias = $stmt->get_result()->fetch_assoc()['total'];
		
		// Visitas últimos 30 dias
		$stmt->bind_param("s", $data_30_dias);
		$stmt->execute();
		$visitas_30_dias = $stmt->get_result()->fetch_assoc()['total'];
		
		// Total de visitas
		$qry_total = "SELECT COUNT(*) as total FROM visita_site";
		$result_total = $mysqli->query($qry_total);
		$visitas_total = $result_total->fetch_assoc()['total'];
		
		// Calcular crescimento
		$crescimento_diario = 0;
		if ($visitas_ontem > 0) {
			$crescimento_diario = round((($visitas_hoje - $visitas_ontem) / $visitas_ontem) * 100, 2);
		}
		
		return [
			'visitas_hoje' => $visitas_hoje,
			'visitas_ontem' => $visitas_ontem,
			'visitas_7_dias' => $visitas_7_dias,
			'visitas_30_dias' => $visitas_30_dias,
			'visitas_total' => $visitas_total,
			'crescimento_diario' => $crescimento_diario
		];
	}