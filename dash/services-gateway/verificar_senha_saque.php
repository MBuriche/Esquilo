<?php
ini_set('display_errors', 0);
error_reporting(E_ALL);

session_start();
include_once('../services/database.php');
include_once('../services/funcao.php');
include_once('../services/crud.php');
include_once('../services/checa_login_adm.php');

// Verificar se o admin está logado
checa_login_adm();

// Verificar se é uma requisição POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(["success" => false, "message" => "Método não permitido"]);
    exit;
}

// Verificar se a senha foi enviada
if (!isset($_POST['senha_saque'])) {
    echo json_encode(["success" => false, "message" => "Senha de saque não informada"]);
    exit;
}

$senha_saque = $_POST['senha_saque'];
$admin_id = $_SESSION['admin_id'];

// Buscar a senha de saque do admin
$sql = "SELECT senha_saque FROM admin_users WHERE id = ?";
$stmt = $mysqli->prepare($sql);
$stmt->bind_param("i", $admin_id);
$stmt->execute();
$result = $stmt->get_result();
$admin = $result->fetch_assoc();
$stmt->close();

if (!$admin) {
    echo json_encode(["success" => false, "message" => "Admin não encontrado"]);
    exit;
}

// Verificar se a senha de saque está definida
if (empty($admin['senha_saque'])) {
    echo json_encode(["success" => false, "message" => "Senha de saque não configurada para este admin"]);
    exit;
}

// Verificar se a senha está correta
if (password_verify($senha_saque, $admin['senha_saque'])) {
    echo json_encode(["success" => true, "message" => "Senha de saque válida"]);
} else {
    echo json_encode(["success" => false, "message" => "Senha de saque incorreta"]);
}
?> 