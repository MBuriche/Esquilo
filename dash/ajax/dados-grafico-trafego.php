<?php
session_start();
date_default_timezone_set('America/Sao_Paulo');

// Verificar se usuário está logado
if (!isset($_SESSION['nome']) || empty($_SESSION['nome'])) {
    http_response_code(401);
    echo json_encode(['erro' => 'Não autorizado']);
    exit;
}

include_once('../services/crud-adm.php');

header('Content-Type: application/json');

try {
    // Pegar o período solicitado (padrão: 7 dias)
    $periodo = isset($_GET['periodo']) ? intval($_GET['periodo']) : 7;
    
    // Validar período
    if (!in_array($periodo, [7, 30, 28])) {
        $periodo = 7;
    }
    
    // Buscar dados do gráfico
    $dados = dados_grafico_trafego_site($periodo);
    
    // Retornar dados em JSON
    echo json_encode([
        'sucesso' => true,
        'dados' => $dados
    ], JSON_UNESCAPED_UNICODE);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'erro' => 'Erro interno do servidor',
        'detalhes' => $e->getMessage()
    ], JSON_UNESCAPED_UNICODE);
}
?>
