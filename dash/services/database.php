<?php
// carrega credenciais centralizadas
require_once __DIR__ . '/../../config.php';

// conexão mysqli
$mysqli = @new mysqli(DB_HOST, DB_USERNAME, DB_PASSWORD, DB_NAME);

if ($mysqli->connect_error) {
    error_log('DB connect error (' . $mysqli->connect_errno . '): ' . $mysqli->connect_error);
    http_response_code(500);
    exit('Erro ao conectar no banco de dados.');
}

$mysqli->set_charset('utf8mb4');

// compat: se o restante do código usa $conn
$conn = $mysqli;
