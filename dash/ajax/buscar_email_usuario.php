<?php
#======================================#
ini_set('display_errors', 1);
error_reporting(E_ALL);
#======================================#
session_start();
include_once('../services/database.php');
include_once('../services/funcao.php');
include_once('../services/crud-adm.php');
include_once('../services/crud.php');
include_once('../logs/registrar_logs.php');
include_once('../services/checa_login_adm.php');
include_once("../services/CSRF_Protect.php");
$csrf = new CSRF_Protect();
#======================================#
#expulsa user
checa_login_adm();
#======================================#

if (isset($_GET['id'])) {
    $user_id = PHP_SEGURO($_GET['id']);
    
    // Buscar o email do usuário
    $stmt = $mysqli->prepare("SELECT email FROM usuarios WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    $stmt->close();
    
    if ($user && !empty($user['email'])) {
        echo json_encode([
            'success' => true,
            'email' => $user['email']
        ]);
    } else {
        echo json_encode([
            'success' => false,
            'message' => 'Usuário não encontrado'
        ]);
    }
} else {
    echo json_encode([
        'success' => false,
        'message' => 'ID do usuário não fornecido'
    ]);
}

$mysqli->close();
?> 