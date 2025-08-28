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

  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $saqueId = isset($_POST['id']) ? intval($_POST['id']) : 0;
    $status = isset($_POST['status']) ? $_POST['status'] : '';

    // Verifica o valor do status e mapeia para os valores correspondentes no banco de dados
    if ($status == 'processando') {
        $statusDb = 3; // "Em Processamento" corresponde ao valor 3
    } elseif ($status == 'aceitando') {
        $statusDb = 4; // "Aceitando" corresponde ao valor 4
    } elseif ($status == 'aprovado') {
        $statusDb = 1; // "Aceitando" corresponde ao valor 4
    } else {
        $statusDb = 0; // Se o status for inválido
    }

    // Verifica se o ID é válido e se o status é um dos valores válidos
    if ($saqueId > 0 && in_array($statusDb, [3, 4, 1])) {
        // Atualiza o status do saque no banco de dados
        $query = "UPDATE solicitacao_saques SET status = ? WHERE id = ?";
        $stmt = $mysqli->prepare($query);
        $stmt->bind_param("ii", $statusDb, $saqueId); // Alterado para passar como inteiro para o banco de dados

        if ($stmt->execute()) {
            $response = [
                'success' => true,
                'message' => 'Status do saque atualizado com sucesso!'
            ];
        } else {
            $response = [
                'success' => false,
                'message' => 'Erro ao atualizar o status do saque.'
            ];
        }
        $stmt->close();
    } else {
        $response = [
            'success' => false,
            'message' => 'Dados inválidos.'
        ];
    }

    echo json_encode($response);
}
?>
