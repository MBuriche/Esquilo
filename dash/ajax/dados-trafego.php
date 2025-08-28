<?php
session_start();
include_once '../services/crud-adm.php';

// Verificar se o usuário está logado
if (!isset($_SESSION['2fa_verified']) || $_SESSION['2fa_verified'] !== true) {
    http_response_code(401);
    echo json_encode(['erro' => 'Não autorizado']);
    exit;
}

try {
    // Pegar período da requisição (padrão: 7 dias)
    $periodo = isset($_GET['periodo']) ? $_GET['periodo'] : '7';
    
    $trafego_dados = trafego_por_fonte($periodo);
    $estatisticas_trafego = estatisticas_trafego_site();
    
    $response = [
        'trafego' => $trafego_dados,
        'estatisticas' => $estatisticas_trafego,
        'periodo' => $periodo,
        'timestamp' => date('Y-m-d H:i:s')
    ];
    
    header('Content-Type: application/json');
    echo json_encode($response);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['erro' => 'Erro interno do servidor: ' . $e->getMessage()]);
}
?>
