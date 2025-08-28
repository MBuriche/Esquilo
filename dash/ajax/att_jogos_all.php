<?
session_start();
include_once('../services/database.php');
include_once('../services/funcao.php');
include_once('../services/crud-adm.php');
include_once('../services/checa_login_adm.php');

checa_login_adm();

global $mysqli;

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_game_setting') {
    $id = intval($_POST['id']);
    $field = $_POST['field'];
    $value = intval($_POST['value']);

    if (in_array($field, ['status', 'popular'])) {
        $qry = $mysqli->prepare("UPDATE games SET $field = ? WHERE id = ?");
        $qry->bind_param("ii", $value, $id);

        if ($qry->execute()) {
            echo json_encode(['success' => true, 'message' => ucfirst($field) . ' atualizado com sucesso!']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Erro ao atualizar o campo ' . $field]);
        }
    } else {
        echo json_encode(['success' => false, 'message' => 'Campo inválido']);
    }
    exit;
}
?>