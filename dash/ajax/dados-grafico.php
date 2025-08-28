<?php
session_start();
include_once '../services/crud-adm.php';

// Verificar se o usuário está logado
if (!isset($_SESSION['2fa_verified']) || $_SESSION['2fa_verified'] !== true) {
    http_response_code(401);
    echo json_encode(['erro' => 'Não autorizado']);
    exit;
}

// Verificar se o período foi enviado
if (!isset($_POST['periodo'])) {
    http_response_code(400);
    echo json_encode(['erro' => 'Período não especificado']);
    exit;
}

$periodo = $_POST['periodo'];
$dados = [];

try {
    switch($periodo) {
        case '7dias':
            $dados = dados_grafico_depositos_saques();
            break;
        case '30dias':
            $dados = dados_grafico_depositos_saques_30_dias();
            break;
        case 'semanal':
            $dados = dados_grafico_resumo_semanal();
            break;
        default:
            $dados = dados_grafico_depositos_saques();
    }
    
    header('Content-Type: application/json');
    echo json_encode($dados);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['erro' => 'Erro interno do servidor: ' . $e->getMessage()]);
}
?>
