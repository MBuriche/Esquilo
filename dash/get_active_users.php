<?php
session_start();
include_once "services/database.php";
include_once "services/funcao.php";
include_once "services/crud.php";
include_once "services/crud-adm.php";
include_once 'services/checa_login_adm.php';

// Verificar se é admin
checa_login_adm();

if ($_SESSION['data_adm']['status'] != '1') {
    http_response_code(403);
    die(json_encode(['success' => false, 'message' => 'Acesso negado']));
}

header('Content-Type: application/json');

try {
    // Buscar usuários ativos (últimos 5 minutos)
    $active_time = date('Y-m-d H:i:s', strtotime('-5 minutes'));
    
    $query = "
        SELECT 
            s.session_id,
            s.ip_address,
            s.user_agent,
            s.current_page,
            s.last_activity,
            s.user_id,
            u.usuario as username,
            u.email,
            u.saldo,
            CASE WHEN s.user_id IS NOT NULL THEN 1 ELSE 0 END as is_logged
        FROM active_sessions s
        LEFT JOIN usuarios u ON s.user_id = u.id
        WHERE s.last_activity >= ?
        ORDER BY s.last_activity DESC
    ";
    
    $stmt = $mysqli->prepare($query);
    $stmt->bind_param("s", $active_time);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $users = [];
    while ($row = $result->fetch_assoc()) {
        // Formatar data de última atividade
        $last_activity = new DateTime($row['last_activity']);
        $now = new DateTime();
        $diff = $now->diff($last_activity);
        
        if ($diff->i == 0) {
            $time_ago = "Agora mesmo";
        } elseif ($diff->i == 1) {
            $time_ago = "1 minuto atrás";
        } else {
            $time_ago = $diff->i . " minutos atrás";
        }
        
        // Limitar user agent se muito longo
        $user_agent = $row['user_agent'];
        if (strlen($user_agent) > 100) {
            $user_agent = substr($user_agent, 0, 100) . "...";
        }
        
        // Formatar saldo
        $saldo = $row['is_logged'] ? number_format($row['saldo'], 2, ',', '.') : '0,00';
        
        $users[] = [
            'session_id' => $row['session_id'],
            'ip' => $row['ip_address'],
            'user_agent' => $user_agent,
            'current_page' => $row['current_page'],
            'last_activity' => $time_ago,
            'is_logged' => (bool)$row['is_logged'],
            'username' => $row['username'] ?? '',
            'email' => $row['email'] ?? '',
            'saldo' => $saldo
        ];
    }
    
    echo json_encode([
        'success' => true,
        'users' => $users,
        'total' => count($users)
    ]);
    
} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'message' => 'Erro ao buscar usuários ativos: ' . $e->getMessage()
    ]);
}
?> 