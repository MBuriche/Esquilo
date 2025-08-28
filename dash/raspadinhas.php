<?php

#======================================#
ini_set('display_errors', 0);
error_reporting(E_ALL);
#======================================#
session_start();
include_once "services/database.php";
include_once 'logs/registrar_logs.php';
include_once "services/funcao.php";
include_once "services/crud.php";
include_once "services/crud-adm.php";
include_once 'services/checa_login_adm.php';
include_once "services/CSRF_Protect.php";
$csrf = new CSRF_Protect();
#======================================#
#expulsa user
checa_login_adm();
#======================================#
if (!admin_has_permission('gerenciar_usuarios')) {
    include 'partes/sem-permissao.php';
    exit;
}
// Endpoint AJAX para buscar dados de uma raspadinha
if (isset($_GET['get_scratch']) && is_numeric($_GET['get_scratch'])) {
    header('Content-Type: application/json');
    $id = (int) $_GET['get_scratch'];
    $stmt = $mysqli->prepare("SELECT * FROM raspadinhas WHERE id = ?");
    $stmt->bind_param('i', $id);
    $stmt->execute();
    $res = $stmt->get_result();
    $rasp = $res ? $res->fetch_assoc() : null;
    $stmt->close();
    if ($rasp) {
        echo json_encode($rasp);
    } else {
        echo json_encode(['error' => 'Raspadinha não encontrada']);
    }
    exit;
}
// Endpoint AJAX para editar raspadinha
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax_scratch']) && $_POST['acao'] === 'editar') {
    header('Content-Type: application/json');
    $id = (int) $_POST['id'];
    $name = trim($_POST['name']);
    $description = trim($_POST['description']);
    $amount = (int) $_POST['amount'];
    $max_reward = (int) $_POST['max_reward'];
    $slug = trim($_POST['slug']);
    $banner = trim($_POST['imagem_link']); // Corrigido: usar imagem_link em vez de banner
    $start_at = !empty($_POST['start_at']) ? $_POST['start_at'] : null;
    $expires_at = !empty($_POST['expires_at']) ? $_POST['expires_at'] : null;
    $grid_size = (int) $_POST['grid_size'];
    $is_active = isset($_POST['is_active']) ? (int) $_POST['is_active'] : 1;

    $stmt = $mysqli->prepare("UPDATE raspadinhas SET name=?, description=?, amount=?, max_reward=?, slug=?, banner=?, start_at=?, expires_at=?, grid_size=?, is_active=? WHERE id=?");
    $stmt->bind_param(
        "ssiissssiii",
        $name,
        $description,
        $amount,
        $max_reward,
        $slug,
        $banner,
        $start_at,
        $expires_at,
        $grid_size,
        $is_active,
        $id
    );
    $ok = $stmt->execute();
    $stmt->close();

    if ($ok) {
        echo json_encode(['success' => true, 'message' => 'Raspadinha atualizada com sucesso!']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Erro ao atualizar raspadinha!']);
    }
    exit;
}
// Endpoint AJAX para duplicar raspadinha
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax_scratch']) && $_POST['acao'] === 'duplicar') {
    header('Content-Type: application/json');
    $id = (int) $_POST['id'];
    $stmt = $mysqli->prepare("SELECT * FROM raspadinhas WHERE id = ?");
    $stmt->bind_param('i', $id);
    $stmt->execute();
    $res = $stmt->get_result();
    $rasp = $res ? $res->fetch_assoc() : null;
    $stmt->close();
    if ($rasp) {
        // Gerar novo slug único
        $base_slug = $rasp['slug'] . '-copia';
        $slug = $base_slug;
        $i = 2;
        while (true) {
            $check = $mysqli->prepare("SELECT id FROM raspadinhas WHERE slug = ?");
            $check->bind_param('s', $slug);
            $check->execute();
            $check->store_result();
            if ($check->num_rows == 0) break;
            $slug = $base_slug . '-' . $i;
            $i++;
            $check->close();
        }
        $check->close();
        $stmt2 = $mysqli->prepare("INSERT INTO raspadinhas (name, description, amount, max_reward, slug, banner, start_at, expires_at, grid_size, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt2->bind_param(
            "ssiissssii",
            $rasp['name'],
            $rasp['description'],
            $rasp['amount'],
            $rasp['max_reward'],
            $slug,
            $rasp['banner'],
            $rasp['start_at'],
            $rasp['expires_at'],
            $rasp['grid_size'],
            $rasp['is_active']
        );
        $ok = $stmt2->execute();
        $stmt2->close();
        if ($ok) {
            echo json_encode(['success' => true, 'message' => 'Raspadinha duplicada com sucesso!']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Erro ao duplicar raspadinha!']);
        }
    } else {
        echo json_encode(['success' => false, 'message' => 'Raspadinha não encontrada!']);
    }
    exit;
}
// Endpoint AJAX para remover raspadinha
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax_scratch']) && $_POST['acao'] === 'remover') {
    header('Content-Type: application/json');
    $id = (int) $_POST['id'];
    $stmt = $mysqli->prepare("DELETE FROM raspadinhas WHERE id = ?");
    $stmt->bind_param('i', $id);
    $ok = $stmt->execute();
    $stmt->close();
    if ($ok) {
        echo json_encode(['success' => true, 'message' => 'Raspadinha removida com sucesso!']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Erro ao remover raspadinha!']);
    }
    exit;
}

// Endpoint AJAX: listar prêmios vinculados à raspadinha (com paginação)
if (isset($_GET['get_rewards_for_scratch']) && is_numeric($_GET['get_rewards_for_scratch'])) {
    header('Content-Type: application/json');
    $id = (int) $_GET['get_rewards_for_scratch'];
    $page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
    $limit = isset($_GET['limit']) ? max(1, (int)$_GET['limit']) : 10;
    $offset = ($page - 1) * $limit;
    // Contar total
    $stmt = $mysqli->prepare("SELECT COUNT(*) as total FROM raspadinhas_premios WHERE scratch_card_id = ?");
    $stmt->bind_param('i', $id);
    $stmt->execute();
    $res = $stmt->get_result();
    $total = $res->fetch_assoc()['total'];
    $stmt->close();
    // Buscar página
    $sql = "SELECT scr.id, scr.reward_id, scr.probability, scr.sort_order, scr.is_active, r.name, r.amount, r.image, r.type FROM raspadinhas_premios scr JOIN premios r ON scr.reward_id = r.id WHERE scr.scratch_card_id = ? ORDER BY scr.sort_order, scr.id LIMIT ? OFFSET ?";
    $stmt = $mysqli->prepare($sql);
    $stmt->bind_param('iii', $id, $limit, $offset);
    $stmt->execute();
    $res = $stmt->get_result();
    $out = [];
    while ($row = $res->fetch_assoc())
        $out[] = $row;
    $stmt->close();
    echo json_encode([
        'data' => $out,
        'total' => $total,
        'page' => $page,
        'limit' => $limit
    ]);
    exit;
}
// Endpoint AJAX: listar todos os prêmios ativos
if (isset($_GET['get_all_rewards'])) {
    header('Content-Type: application/json');
    $res = $mysqli->query("SELECT id, name, amount, image, type FROM premios WHERE is_active = 1 ORDER BY name");
    $out = [];
    while ($row = $res->fetch_assoc())
        $out[] = $row;
    echo json_encode($out);
    exit;
}

// Processamento para exclusão múltipla
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['bulk_delete']) && isset($_POST['selected_users'])) {
    $selected_users = $_POST['selected_users'];
    $deleted_count = 0;

    if (!empty($selected_users) && is_array($selected_users)) {
        $placeholders = str_repeat('?,', count($selected_users) - 1) . '?';
        $sql = "DELETE FROM usuarios WHERE id IN ($placeholders)";
        $stmt = $mysqli->prepare($sql);

        // Bind parameters dynamically
        $types = str_repeat('i', count($selected_users));
        $stmt->bind_param($types, ...$selected_users);

        if ($stmt->execute()) {
            $deleted_count = $stmt->affected_rows;
            $success_message = "Foram excluídos $deleted_count usuário(s) com sucesso!";
        } else {
            $error_message = "Erro ao excluir usuários: " . $mysqli->error;
        }
        $stmt->close();
    } else {
        $error_message = "Nenhum usuário foi selecionado para exclusão.";
    }
}

// Parâmetros de filtro e ordenação para raspadinhas
$order = $_GET['order'] ?? 'id';
$direction = $_GET['direction'] ?? 'DESC';
$search = $_GET['search'] ?? '';
$limit = $_GET['limit'] ?? 20;
$page = $_GET['page'] ?? 1;
$offset = ($page - 1) * $limit;

// Validar direção
$direction = in_array(strtoupper($direction), ['ASC', 'DESC']) ? strtoupper($direction) : 'DESC';

// Validar campo de ordenação
$valid_orders = ['id', 'name', 'slug', 'amount', 'max_reward', 'is_active', 'created_at', 'updated_at'];
$order = in_array($order, $valid_orders) ? $order : 'id';

// Construir query de busca
$where_clause = "";
$params = [];
$types = "";

if (!empty($search)) {
    $where_clause = "WHERE name LIKE ? OR slug LIKE ?";
    $search_param = "%{$search}%";
    $params = [$search_param, $search_param];
    $types = "ss";
}

// Query para contar total de registros
$count_sql = "SELECT COUNT(*) as total FROM raspadinhas $where_clause";
if (!empty($params)) {
    $count_stmt = $mysqli->prepare($count_sql);
    $count_stmt->bind_param($types, ...$params);
    $count_stmt->execute();
    $total_result = $count_stmt->get_result();
    $total_records = $total_result->fetch_assoc()['total'];
    $count_stmt->close();
} else {
    $total_result = $mysqli->query($count_sql);
    $total_records = $total_result->fetch_assoc()['total'];
}

// Query principal
$sql = "SELECT * FROM raspadinhas $where_clause ORDER BY $order $direction LIMIT ? OFFSET ?";
if (!empty($params)) {
    $params[] = $limit;
    $params[] = $offset;
    $types .= "ii";
    $stmt = $mysqli->prepare($sql);
    $stmt->bind_param($types, ...$params);
} else {
    $stmt = $mysqli->prepare($sql);
    $stmt->bind_param("ii", $limit, $offset);
}
$stmt->execute();
$result = $stmt->get_result();
$raspadinhas = $result->fetch_all(MYSQLI_ASSOC);
$stmt->close();
// Calcular paginação
$total_pages = ceil($total_records / $limit);

// Endpoint AJAX: adicionar prêmio à raspadinha
if (
    $_SERVER['REQUEST_METHOD'] === 'POST' &&
    isset($_POST['ajax_scratch_reward']) &&
    isset($_POST['acao']) && $_POST['acao'] === 'adicionar'
) {
    header('Content-Type: application/json');
    $scratch_card_id = isset($_POST['scratch_card_id']) ? (int)$_POST['scratch_card_id'] : 0;
    $reward_id = isset($_POST['reward_id']) ? (int)$_POST['reward_id'] : 0;
    $probability = isset($_POST['probability']) ? (float)$_POST['probability'] : 0;
    $sort_order = isset($_POST['sort_order']) ? (int)$_POST['sort_order'] : 0;
    if (!$scratch_card_id || !$reward_id || $probability <= 0) {
        echo json_encode(['success' => false, 'message' => 'Dados inválidos para adicionar prêmio.']);
        exit;
    }
    // Verifica se já existe esse prêmio vinculado
    $stmt = $mysqli->prepare("SELECT id FROM raspadinhas_premios WHERE scratch_card_id = ? AND reward_id = ?");
    $stmt->bind_param('ii', $scratch_card_id, $reward_id);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows > 0) {
        $stmt->close();
        echo json_encode(['success' => false, 'message' => 'Este prêmio já está vinculado à raspadinha.']);
        exit;
    }
    $stmt->close();
    // Inserir
    $stmt = $mysqli->prepare("INSERT INTO raspadinhas_premios (scratch_card_id, reward_id, probability, sort_order, is_active) VALUES (?, ?, ?, ?, 1)");
    $stmt->bind_param('iidi', $scratch_card_id, $reward_id, $probability, $sort_order);
    $ok = $stmt->execute();
    $stmt->close();
    if ($ok) {
        echo json_encode(['success' => true, 'message' => 'Prêmio adicionado com sucesso!']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Erro ao adicionar prêmio!']);
    }
    exit;
}
// Endpoint AJAX: editar campo de prêmio (is_active, probability, sort_order)
if (
    $_SERVER['REQUEST_METHOD'] === 'POST' &&
    isset($_POST['ajax_scratch_reward']) &&
    isset($_POST['acao']) && $_POST['acao'] === 'editar'
) {
    header('Content-Type: application/json');
    $id = isset($_POST['id']) ? (int)$_POST['id'] : 0;
    $campo = isset($_POST['campo']) ? $_POST['campo'] : '';
    $valor = isset($_POST['valor']) ? $_POST['valor'] : null;
    $permitidos = ['is_active', 'probability', 'sort_order'];
    if (!$id || !in_array($campo, $permitidos)) {
        echo json_encode(['success' => false, 'message' => 'Campo ou ID inválido.']);
        exit;
    }
    // Definir tipo de bind
    $tipo = ($campo === 'is_active' || $campo === 'sort_order') ? 'i' : 'd';
    $stmt = $mysqli->prepare("UPDATE raspadinhas_premios SET $campo = ? WHERE id = ?");
    $stmt->bind_param($tipo . 'i', $valor, $id);
    $ok = $stmt->execute();
    $stmt->close();
    echo json_encode(['success' => $ok, 'message' => $ok ? 'Atualizado com sucesso!' : 'Erro ao atualizar.']);
    exit;
}
?>

<!DOCTYPE html>
<html x-data="main" class="" :class="[$store.app.mode]">

<?php include "partes/head.php"; ?>

<body x-data="main"
    class="antialiased relative font-inter bg-white dark:bg-black text-black dark:text-white text-sm font-normal overflow-x-hidden vertical"
    :class="[ $store.app.sidebar ? 'toggle-sidebar' : '', $store.app.rightsidebar ? 'right-sidebar' : '', $store.app.menu, $store.app.layout]">
    <div x-data="{ showModal: false }">
        <!-- Start Menu Sidebar Olverlay -->
        <div x-cloak class="fixed inset-0 bg-[black]/60 z-40 lg:hidden" :class="{'hidden' : !$store.app.sidebar}"
            @click="$store.app.toggleSidebar()"></div>
        <!-- End Menu Sidebar Olverlay -->

        <!-- Start Right Sidebar Olverlay -->
        <div x-cloak class="fixed inset-0 bg-[black]/60 z-50 2xl:hidden" :class="{'hidden' : !$store.app.rightsidebar}"
            @click="$store.app.rightSidebar()"></div>
        <!-- End Right Sidebar Olverlay -->

        <!-- Modal para adicionar usuário -->
        <div x-data="{ showModal: false }" x-show="showModal" x-cloak
            class="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
            <div @click.away="showModal = false" class="bg-white dark:bg-gray-800 rounded-lg p-6 w-full max-w-md">
                <h3 class="text-lg font-semibold mb-4">Adicionar Novo Usuário</h3>
                <form method="POST" class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium mb-1">Email *</label>
                        <input type="email" name="email" required pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"
                            class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1">Usuário *</label>
                        <input type="text" name="usuario" required minlength="3" maxlength="50"
                            class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1">Celular *</label>
                        <input type="text" name="celular" required pattern="[\+]?[0-9\s\-\(\)]+"
                            placeholder="(11) 99999-9999"
                            class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1">Senha *</label>
                        <input type="password" name="password" required minlength="6"
                            class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                        <p class="text-xs text-gray-500 mt-1">Mínimo 6 caracteres</p>
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1">CPF</label>
                        <input type="text" name="cpf" maxlength="14" pattern="[0-9]{3}\.?[0-9]{3}\.?[0-9]{3}\-?[0-9]{2}"
                            placeholder="000.000.000-00"
                            class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1">Saldo Inicial</label>
                        <input type="number" step="0.01" min="0" name="saldo" value="0.00"
                            class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                    </div>
                    <div class="flex gap-2 pt-4">
                        <button type="submit" name="add_user"
                            class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2">
                            Adicionar
                        </button>
                        <button type="button" @click="showModal = false"
                            class="px-4 py-2 bg-gray-300 dark:bg-gray-600 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-400 dark:hover:bg-gray-500">
                            Cancelar
                        </button>
                    </div>
                    <p class="text-xs text-gray-500">* Campos obrigatórios</p>
                </form>
            </div>
        </div>

        <!-- Modal de confirmação de exclusão múltipla -->
        <div x-data="{ open: false }" @bulk-delete.window="open = true"
            class="fixed inset-0 bg-black/60 dark:bg-white/10 z-[999] hidden overflow-y-auto" :class="open && '!block'">
            <div class="flex items-center justify-center min-h-screen px-4" @click.self="open = false">
                <div x-show="open" x-transition x-transition.duration.300
                    class="bg-white dark:bg-black relative shadow-3xl border-0 p-0 rounded-lg overflow-hidden w-full max-w-lg my-8">
                    <div
                        class="flex bg-white dark:bg-black border-b border-black/10 dark:border-white/10 items-center justify-between px-5 py-3">
                        <h5 class="font-semibold text-lg">Confirmar Exclusão Múltipla</h5>
                        <button type="button"
                            class="text-black/40 dark:text-white/40 hover:text-black dark:hover:text-white"
                            @click="open = false">
                            <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none"
                                xmlns="http://www.w3.org/2000/svg">
                                <path
                                    d="M24.2929 6.29289L6.29289 24.2929C6.10536 24.4804 6 24.7348 6 25C6 25.2652 6.10536 25.5196 6.29289 25.7071C6.48043 25.8946 6.73478 26 7 26C7.26522 26 7.51957 25.8946 7.70711 25.7071L25.7071 7.70711C25.8946 7.51957 26 7.26522 26 7C26 6.73478 25.8946 6.48043 25.7071 6.29289C25.5196 6.10536 25.2652 6 25 6C24.7348 6 24.4804 6.10536 24.2929 6.29289Z"
                                    fill="currentcolor"></path>
                                <path
                                    d="M7.70711 6.29289C7.51957 6.10536 7.26522 6 7 6C6.73478 6 6.48043 6.10536 6.29289 6.29289C6.10536 6.48043 6 6.73478 6 7C6 7.26522 6.10536 7.51957 6.29289 7.70711L24.2929 25.7071C24.48043 25.8946 24.7348 26 25 26C25.2652 26 25.51957 25.8946 25.7071 25.7071C25.8946 25.5196 26 25.2652 26 25C26 24.7348 25.8946 24.4804 25.7071 24.2929L7.70711 6.29289Z"
                                    fill="currentcolor"></path>
                            </svg>
                        </button>
                    </div>
                    <div class="p-5">
                        <div class="text-sm text-black dark:text-white">
                            <p>Tem certeza que deseja excluir os usuários selecionados? Esta ação não pode ser desfeita.</p>
                            <p class="mt-2 font-medium" id="selected-count-text"></p>
                        </div>
                        <div class="flex justify-end items-center mt-8 gap-4">
                            <button type="button" class="btn !bg-gray-500 !text-white"
                                @click="open = false">Cancelar</button>
                            <button type="button" class="btn !bg-red-500 !text-white"
                                @click="submitBulkDelete(); open = false">Excluir Selecionados</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Modal de confirmação de exclusão individual -->
        <div x-data="{ open: false, userId: null }" @delete-user.window="open = true; userId = $event.detail.userId"
            class="fixed inset-0 bg-black/60 dark:bg-white/10 z-[999] hidden overflow-y-auto" :class="open && '!block'">
            <div class="flex items-center justify-center min-h-screen px-4" @click.self="open = false">
                <div x-show="open" x-transition x-transition.duration.300
                    class="bg-white dark:bg-black relative shadow-3xl border-0 p-0 rounded-lg overflow-hidden w-full max-w-lg my-8">
                    <div
                        class="flex bg-white dark:bg-black border-b border-black/10 dark:border-white/10 items-center justify-between px-5 py-3">
                        <h5 class="font-semibold text-lg">Confirmar Exclusão</h5>
                        <button type="button"
                            class="text-black/40 dark:text-white/40 hover:text-black dark:hover:text-white"
                            @click="open = false">
                            <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none"
                                xmlns="http://www.w3.org/2000/svg">
                                <path
                                    d="M24.2929 6.29289L6.29289 24.2929C6.10536 24.4804 6 24.7348 6 25C6 25.2652 6.10536 25.5196 6.29289 25.7071C6.48043 25.8946 6.73478 26 7 26C7.26522 26 7.51957 25.8946 7.70711 25.7071L25.7071 7.70711C25.8946 7.51957 26 7.26522 26 7C26 6.73478 25.8946 6.48043 25.7071 6.29289C25.5196 6.10536 25.2652 6 25 6C24.7348 6 24.4804 6.10536 24.2929 6.29289Z"
                                    fill="currentcolor"></path>
                                <path
                                    d="M7.70711 6.29289C7.51957 6.10536 7.26522 6 7 6C6.73478 6 6.48043 6.10536 6.29289 6.29289C6.10536 6.48043 6 6.73478 6 7C6 7.26522 6.10536 7.51957 6.29289 7.70711L24.2929 25.7071C24.48043 25.8946 24.7348 26 25 26C25.2652 26 25.51957 25.8946 25.7071 25.7071C25.8946 25.5196 26 25.2652 26 25C26 24.7348 25.8946 24.4804 25.7071 24.2929L7.70711 6.29289Z"
                                    fill="currentcolor"></path>
                            </svg>
                        </button>
                    </div>
                    <div class="p-5">
                        <div class="text-sm text-black dark:text-white">
                            <p>Tem certeza que deseja excluir este usuário? Esta ação não pode ser desfeita.</p>
                        </div>
                        <div class="flex justify-end items-center mt-8 gap-4">
                            <button type="button" class="btn !bg-gray-500 !text-white"
                                @click="open = false">Cancelar</button>
                            <button type="button" class="btn !bg-red-500 !text-white"
                                @click="window.location.href = '?delete_user=' + userId; open = false">Excluir</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Start Main Content -->
        <div class="main-container navbar-sticky flex" :class="[$store.app.navbar]">
            <!-- Start Sidebar -->
            <nav
                class="sidebar fixed top-0 bottom-0 z-40 flex-none w-[212px] border-r border-black/10 dark:border-white/10 transition-all duration-300">
                <div class="bg-white dark:bg-black h-full">
                    <?php include 'partes/menu-lateral.php'; ?>
                    <!-- End Menu -->
                </div>
            </nav>
            <!-- End sidebar -->

            <!-- Start Content Area -->
            <div class="main-content flex-1">
                <!-- Start Topbar -->
                <?php include 'partes/topbar.php'; ?>
                <!-- End Topbar -->

                <!-- Start Content -->
                <div class="h-[calc(100vh-73px)] overflow-y-auto overflow-x-hidden">
                    <div class="p-7 min-h-[calc(100vh-145px)]">
                        <div class="px-2 py-1 mb-4">
                            <p class="text-sm font-semibold">Gerenciamento de Raspadinhas</p>
                            <p class="text-xs text-gray-500">Total de raspadinhas: <?php echo $total_records; ?></p>
                        </div>

                        <?php if (isset($success_message)): ?>
                            <div
                                class="mb-4 p-4 bg-green-100 dark:bg-green-900/20 border border-green-300 dark:border-green-700 text-green-700 dark:text-green-300 rounded-lg">
                                <?php echo $success_message; ?>
                            </div>
                        <?php endif; ?>

                        <?php if (isset($error_message)): ?>
                            <div
                                class="mb-4 p-4 bg-red-100 dark:bg-red-900/20 border border-red-300 dark:border-red-700 text-red-700 dark:text-red-300 rounded-lg">
                                <?php echo $error_message; ?>
                            </div>
                        <?php endif; ?>

                        <div class="p-2 bg-lightwhite dark:bg-white/5 rounded-lg flex gap-2 justify-between mb-2">
                            <div class="flex items-center gap-4">
                                <div class="flex gap-2 items-center">
                                    <button type="button" @click="showModal = true"
                                        class="p-1 rounded-lg bg-transparent hover:bg-black/5 dark:hover:bg-white/5 transition-all duration-300"
                                        title="Adicionar Raspadinha">
                                        <svg width="20" height="20" viewBox="0 0 20 20" fill="none"
                                            xmlns="http://www.w3.org/2000/svg">
                                            <path
                                                d="M10.625 4.375C10.625 4.02982 10.3452 3.75 10 3.75C9.65482 3.75 9.375 4.02982 9.375 4.375V9.375H4.375C4.02982 9.375 3.75 9.65482 3.75 10C3.75 10.3452 4.02982 10.625 4.375 10.625H9.375V15.625C9.375 15.9702 9.65482 16.25 10 16.25C10.3452 16.25 10.625 15.9702 10.625 15.625V10.625H15.625C15.9702 10.625 16.25 10.3452 16.25 10C16.25 9.65482 15.9702 9.375 15.625 9.375H10.625V4.375Z"
                                                fill="currentcolor"></path>
                                        </svg>
                                    </button>
                                    <!-- Botão de exclusão múltipla -->
                                    <button type="button" onclick="confirmBulkDelete()"
                                        class="p-1 rounded-lg bg-transparent hover:bg-red-100 dark:hover:bg-red-900/20 text-red-600 transition-all duration-300"
                                        title="Excluir Selecionados" id="bulk-delete-btn" style="display: none;">
                                        <svg width="20" height="20" viewBox="0 0 20 20" fill="none"
                                            xmlns="http://www.w3.org/2000/svg">
                                            <path d="M6 2L10 2M2 4H14M12 4L11.5 12H4.5L4 4M7 7V10M9 7V10"
                                                stroke="currentColor" stroke-width="1.5" stroke-linecap="round"
                                                stroke-linejoin="round"></path>
                                        </svg>
                                    </button>
                                    <!-- Botões de ordenação -->
                                    <a href="?order=id&direction=<?php echo ($order == 'id' && $direction == 'ASC') ? 'DESC' : 'ASC'; ?>&search=<?php echo urlencode($search); ?>"
                                        class="p-1 rounded-lg bg-transparent hover:bg-black/5 dark:hover:bg-white/5 transition-all duration-300 flex items-center gap-1"
                                        title="Ordenar por ID">
                                        <span>ID</span>
                                        <?php if ($order == 'id'): ?>
                                            <?php if ($direction == 'ASC'): ?>
                                                <svg width="12" height="12" viewBox="0 0 20 20" fill="none"><path d="M10 6L6 10H14L10 6Z" fill="currentColor"/></svg>
                                            <?php else: ?>
                                                <svg width="12" height="12" viewBox="0 0 20 20" fill="none"><path d="M10 14L14 10H6L10 14Z" fill="currentColor"/></svg>
                                            <?php endif; ?>
                                        <?php else: ?>
                                            <svg width="12" height="12" viewBox="0 0 20 20" fill="none"><path d="M10 6L6 10H14L10 6Z" fill="#bbb"/></svg>
                                        <?php endif; ?>
                                    </a>
                                </div>
                            </div>
                            <!-- Formulário de busca -->
                            <form method="GET" class="md:flex items-center hidden">
                                <input type="hidden" name="order" value="id">
                                <input type="hidden" name="direction" value="DESC">
                                <label for="voice-search" class="sr-only">Search</label>
                                <div class="relative w-full">
                                    <div class="absolute inset-y-0 left-0 flex items-center pl-[6px] pointer-events-none">
                                        <svg class="text-black/20 dark:text-white/20" width="16" height="16"
                                            viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
                                            <path
                                                d="M14.3496 14.3563C14.2563 14.4483 14.1306 14.4999 13.9996 14.5001C13.8668 14.4995 13.7393 14.4481 13.6434 14.3563L10.9434 11.6501C9.80622 12.6052 8.34425 13.0845 6.86236 12.9879C5.38046 12.8913 3.99306 12.2264 2.98951 11.1317C1.98596 10.0371 1.44375 8.59729 1.47597 7.1126C1.50818 5.62791 2.11233 4.21298 3.16241 3.1629C4.21249 2.11282 5.62743 1.50867 7.11212 1.47645C8.59681 1.44424 10.0366 1.98645 11.1313 2.99C12.2259 3.99355 12.8908 5.38095 12.9874 6.86285C13.084 8.34474 12.6047 9.80671 11.6496 10.9438L14.3496 13.6438C14.3969 13.6904 14.4344 13.7458 14.46 13.807C14.4856 13.8681 14.4988 13.9338 14.4988 14.0001C14.4988 14.0664 14.4856 14.132 14.46 14.1932C14.4344 14.2544 14.3969 14.3098 14.3496 14.3563ZM7.24961 12.0001C8.18907 12.0001 9.10743 11.7215 9.88857 11.1996C10.6697 10.6776 11.2785 9.93579 11.638 9.06784C11.9976 8.19989 12.0916 7.24483 11.9083 6.32342C11.7251 5.40201 11.2727 4.55564 10.6084 3.89134C9.94407 3.22704 9.0977 2.77465 8.17629 2.59137C7.25488 2.40809 6.29981 2.50215 5.43186 2.86167C4.56391 3.22119 3.82206 3.83001 3.30013 4.61114C2.77819 5.39227 2.49961 6.31064 2.49961 7.2501C2.50126 8.50937 3.00224 9.71659 3.89268 10.607C4.78312 11.4975 5.99034 11.9984 7.24961 12.0001Z"
                                                fill="currentColor"></path>
                                        </svg>
                                    </div>
                                    <input type="text" name="search" value=""
                                        class="bg-black/5 dark:bg-white/5 border-0 text-sm rounded-lg block max-w-[200px] w-full pl-[26px] p-1 focus:ring-0 focus:outline-0"
                                        placeholder="Buscar raspadinhas...">
                                    <button type="submit" class="absolute inset-y-0 right-0 flex items-center pr-2">
                                        <svg class="w-4 h-4 text-black/40 dark:text-white/40 hover:text-black dark:hover:text-white"
                                            fill="currentColor" viewBox="0 0 20 20">
                                            <path fill-rule="evenodd"
                                                d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z"
                                                clip-rule="evenodd"></path>
                                        </svg>
                                    </button>
                                </div>
                            </form>
                        </div>

                        <div class="grid grid-cols-1 gap-3">
                            <div class="table-responsive">
                                <table class="table-hover">
                                    <thead>
                                        <tr>
                                            <th>ID</th>
                                            <th>Nome</th>
                                            <th>Descrição</th>
                                            <th>Valor</th>
                                            <th>Máx. Prêmio</th>
                                            <th>Slug</th>
                                            <th>Ativa</th>
                                            <th>Criada em</th>
                                            <th>Atualizada em</th>
                                            <th>Ações</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php if (empty($raspadinhas)): ?>
                                            <tr>
                                                <td colspan="10" class="text-center py-8 text-gray-500">
                                                    Nenhuma raspadinha encontrada.
                                                </td>
                                            </tr>
                                        <?php else: ?>
                                            <?php foreach ($raspadinhas as $rasp): ?>
                                                <tr
                                                    class="group text-xs border-b border-black/20 dark:border-white/5 hover:bg-gray-50 dark:hover:bg-gray-800/50">
                                                    <td class="whitespace-nowrap">
                                                        #<?php echo str_pad($rasp['id'], 4, '0', STR_PAD_LEFT); ?></td>
                                                    <td class="whitespace-nowrap font-medium">
                                                        <div class="flex items-center gap-2">
                                                            <?php if ($rasp['banner']): ?>
                                                                <img src="<?php echo htmlspecialchars($rasp['banner']); ?>" alt="Banner"
                                                                    class="w-8 h-8 object-cover rounded-full shadow" />
                                                            <?php endif; ?>
                                                            <span><?php echo htmlspecialchars($rasp['name']); ?></span>
                                                        </div>
                                                    </td>
                                                    <td class="whitespace-nowrap max-w-[200px] truncate"
                                                        title="<?php echo htmlspecialchars($rasp['description']); ?>">
                                                        <?php
                                                        $desc = htmlspecialchars($rasp['description']);
                                                        echo mb_strlen($desc) > 20 ? mb_substr($desc, 0, 20) . '...' : $desc;
                                                        ?>
                                                    </td>
                                                    <td class="whitespace-nowrap">R$
                                                        <?php echo number_format($rasp['amount'] / 100, 2, ',', '.'); ?></td>
                                                    <td class="whitespace-nowrap">R$
                                                        <?php echo number_format($rasp['max_reward'] / 100, 2, ',', '.'); ?></td>
                                                    <td class="whitespace-nowrap"><?php echo htmlspecialchars($rasp['slug']); ?>
                                                    </td>
                                                    <td class="whitespace-nowrap">
                                                        <?php if ($rasp['is_active']): ?>
                                                            <span
                                                                class="px-2 py-1 text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400 rounded">Sim</span>
                                                        <?php else: ?>
                                                            <span
                                                                class="px-2 py-1 text-xs font-medium  text-gray-800 dark:bg-gray-900/20 dark:text-gray-400 rounded">Não</span>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td class="whitespace-nowrap text-xs">
                                                        <?php echo date('d/m/Y H:i', strtotime($rasp['created_at'])); ?></td>
                                                    <td class="whitespace-nowrap text-xs">
                                                        <?php echo date('d/m/Y H:i', strtotime($rasp['updated_at'])); ?></td>
                                                    <td class="whitespace-nowrap">
                                                        <div class="flex items-center gap-1">
                                                            <button type="button"
                                                                class="p-1 text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                                                                title="Editar raspadinha"
                                                                onclick="abrirModalEditarRaspadinha(<?php echo $rasp['id']; ?>)">
                                                                <svg width="16" height="16" viewBox="0 0 16 16" fill="none"
                                                                    xmlns="http://www.w3.org/2000/svg">
                                                                    <path d="M8 12H14M2 12H6M8 12V8L12 4L14 6L10 10H8V12Z"
                                                                        stroke="currentColor" stroke-width="1.5"
                                                                        stroke-linecap="round" stroke-linejoin="round" />
                                                                </svg>
                                                            </button>
                                                            <button type="button"
                                                                class="p-1 text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300"
                                                                title="Excluir raspadinha"
                                                                onclick="abrirModalRemoverRaspadinha(<?php echo $rasp['id']; ?>)">
                                                                <svg width="16" height="16" viewBox="0 0 16 16" fill="none"
                                                                    xmlns="http://www.w3.org/2000/svg">
                                                                    <path d="M6 2L10 2M2 4H14M12 4L11.5 12H4.5L4 4M7 7V10M9 7V10"
                                                                        stroke="currentColor" stroke-width="1.5"
                                                                        stroke-linecap="round" stroke-linejoin="round" />
                                                                </svg>
                                                            </button>
                                                        </div>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>

                    </div>
                </div>
                <!-- End Content -->
            </div>
            <!-- End Content Area -->

            <!-- Start Right Sidebar -->
            <?php include 'partes/notificacao.php'; ?>
            <!-- End Right Sidebar -->
        </div>

        <?php include 'partes/footer.php'; ?>

        <div id="toast-area"
            class="fixed bottom-10 right-10 z-[999999] flex flex-col items-end gap-2 pointer-events-auto drop-shadow-2xl">
        </div>
        <script src="assets/js/toast.js"></script>

        <script>
            // Funções JavaScript para as ações
            function editUser(userId) {
                // Redirecionar para página de edição
                window.location.href = 'usuario-detalhes.php?id=' + userId + '&action=edit';
            }

            function viewUser(userId) {
                // Redirecionar para página de detalhes
                window.location.href = 'usuario-detalhes.php?id=' + userId + '&action=view';
            }

            function deleteUser(userId) {
                // Usar o modal personalizado
                window.dispatchEvent(new CustomEvent('delete-user', {
                    detail: { userId: userId }
                }));
            }

            // Funções de exclusão múltipla
            function confirmBulkDelete() {
                const selectedCheckboxes = document.querySelectorAll('input[name="selected_users[]"]:checked');
                if (selectedCheckboxes.length === 0) {
                    alert('Selecione pelo menos um usuário para excluir.');
                    return;
                }

                const countText = selectedCheckboxes.length === 1 ?
                    '1 usuário será excluído.' :
                    selectedCheckboxes.length + ' usuários serão excluídos.';
                document.getElementById('selected-count-text').textContent = countText;

                window.dispatchEvent(new CustomEvent('bulk-delete'));
            }

            function submitBulkDelete() {
                const selectedCheckboxes = document.querySelectorAll('input[name="selected_users[]"]:checked');
                const form = document.createElement('form');
                form.method = 'POST';
                form.style.display = 'none';

                // Add bulk delete input
                const bulkDeleteInput = document.createElement('input');
                bulkDeleteInput.type = 'hidden';
                bulkDeleteInput.name = 'bulk_delete';
                bulkDeleteInput.value = '1';
                form.appendChild(bulkDeleteInput);

                // Add selected user IDs
                selectedCheckboxes.forEach(function (checkbox) {
                    const hiddenInput = document.createElement('input');
                    hiddenInput.type = 'hidden';
                    hiddenInput.name = 'selected_users[]';
                    hiddenInput.value = checkbox.value;
                    form.appendChild(hiddenInput);
                });

                document.body.appendChild(form);
                form.submit();
            }

            // Seleção múltipla
            document.getElementById('all')?.addEventListener('change', function () {
                const checkboxes = document.querySelectorAll('input[name="selected_users[]"]');
                checkboxes.forEach(checkbox => {
                    checkbox.checked = this.checked;
                });
                updateBulkDeleteButton();
            });

            // Update bulk delete button visibility
            function updateBulkDeleteButton() {
                const selectedCheckboxes = document.querySelectorAll('input[name="selected_users[]"]:checked');
                const bulkDeleteBtn = document.getElementById('bulk-delete-btn');

                if (selectedCheckboxes.length > 0) {
                    bulkDeleteBtn.style.display = 'block';
                } else {
                    bulkDeleteBtn.style.display = 'none';
                }
            }

            // Add event listeners to individual checkboxes
            document.addEventListener('DOMContentLoaded', function () {
                const checkboxes = document.querySelectorAll('input[name="selected_users[]"]');
                checkboxes.forEach(function (checkbox) {
                    checkbox.addEventListener('change', updateBulkDeleteButton);
                });
            });
        </script>

        <!-- Modal de edição de raspadinha -->
        <div x-data="{ open: false, raspadinha: null }" x-show="open" x-cloak id="modal-editar-raspadinha"
            @abrir-modal-editar-raspadinha.window="open = true"
            class="fixed inset-0 bg-black/60 dark:bg-white/10 z-[999] flex items-center justify-center overflow-y-auto p-4 transition-all duration-300">
            <div @click.away="open = false"
                class="bg-white dark:bg-black relative shadow-3xl border-0 p-0 rounded-lg overflow-hidden w-full max-w-2xl sm:max-w-2xl md:max-w-3xl lg:max-w-4xl xl:max-w-5xl my-8 animate-fade-in-up">
                <div
                    class="flex bg-white dark:bg-black border-b border-black/10 dark:border-white/10 items-center justify-between px-5 py-4">
                    <h3 class="font-bold text-xl text-black dark:text-white">Editar Raspadinha</h3>
                    <button type="button" class="text-black/40 dark:text-white/40 hover:text-black dark:hover:text-white"
                        @click="open = false">
                        <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none"
                            xmlns="http://www.w3.org/2000/svg">
                            <path
                                d="M24.2929 6.29289L6.29289 24.2929C6.10536 24.4804 6 24.7348 6 25C6 25.2652 6.10536 25.5196 6.29289 25.7071C6.48043 25.8946 6.73478 26 7 26C7.26522 26 7.51957 25.8946 7.70711 25.7071L25.7071 7.70711C25.8946 7.51957 26 7.26522 26 7C26 6.73478 25.8946 6.48043 25.7071 6.29289C25.5196 6.10536 25.2652 6 25 6C24.7348 6 24.4804 6.10536 24.2929 6.29289Z"
                                fill="currentcolor"></path>
                            <path
                                d="M7.70711 6.29289C7.51957 6.10536 7.26522 6 7 6C6.73478 6 6.48043 6.10536 6.29289 6.29289C6.10536 6.48043 6 6.73478 6 7C6 7.26522 6.10536 7.51957 6.29289 7.70711L24.2929 25.7071C24.48043 25.8946 24.7348 26 25 26C25.2652 26 25.51957 25.8946 25.7071 25.7071C25.8946 25.5196 26 25.2652 26 25C26 24.7348 25.8946 24.4804 25.7071 24.2929L7.70711 6.29289Z"
                                fill="currentcolor"></path>
                        </svg>
                    </button>
                </div>
                <!-- Apenas formulário de configurações -->
                <form id="form-editar-raspadinha" class="space-y-5 px-6 py-6" enctype="multipart/form-data"
                    onsubmit="return false;">
                    <div class="flex justify-end mb-2">
                        <button type="button" class="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-semibold shadow transition"
                            onclick="window.location.href='editar-premiacoes.php?id=' + document.getElementById('form-editar-raspadinha').id.value">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V4a2 2 0 10-4 0v1.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>
                            Visualizar Prêmios
                        </button>
                    </div>
                    <input type="hidden" name="id" />
                    <div class="space-y-2">
                        <label class="form-label font-semibold">Nome *</label>
                        <input type="text" name="name"
                            class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition"
                            required>
                    </div>
                    <div class="space-y-2">
                        <label class="form-label font-semibold">Descrição</label>
                        <textarea name="description"
                            class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition"
                            rows="2"></textarea>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Valor (centavos) *</label>
                            <input type="number" name="amount"
                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg"
                                required>
                        </div>
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Máx. Prêmio (centavos) *</label>
                            <input type="number" name="max_reward"
                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg"
                                required>
                        </div>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Slug *</label>
                            <input type="text" name="slug"
                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg"
                                required>
                        </div>
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Imagem *</label>
                            <label class="w-full h-16 flex items-center justify-center cursor-pointer border-2 border-dashed border-black/20 dark:border-white/20 rounded-lg p-2 hover:bg-black/5 dark:hover:bg-white/5 transition" ondragover="event.preventDefault();" ondrop="handleBannerDrop(event)">
                                <input type="file" name="imagem" accept="image/*" class="hidden" onchange="uploadBannerImageModal(event)">
                                <span class="text-xs text-black/60 dark:text-white/60">Arraste ou clique para enviar</span>
                            </label>
                            <div id="modal-banner-preview" class="w-full flex justify-center my-2" style="display:none;">
                                <img id="modal-banner-img" src="" alt="Preview" class="w-32 h-32 object-contain rounded shadow">
                            </div>
                            <span class="text-xs text-black/40 dark:text-white/40">ou cole um link abaixo</span>
                            <input type="text" name="imagem_link" id="modal-banner-link" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg mt-1" placeholder="https://..." oninput="previewBannerLink(this.value)">
                        </div>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Ativa</label>
                            <select name="is_active"
                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg">
                                <option value="1">Sim</option>
                                <option value="0">Não</option>
                            </select>
                        </div>
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Grade</label>
                            <input type="number" name="grid_size"
                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg">
                        </div>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Início</label>
                            <input type="datetime-local" name="start_at"
                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg">
                        </div>
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Fim</label>
                            <input type="datetime-local" name="expires_at"
                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg">
                        </div>
                    </div>
                    <div class="flex gap-2 pt-4 justify-end">
                        <button type="button" onclick="duplicarRaspadinha()" class="px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 focus:ring-2 focus:ring-blue-500 font-semibold transition">Duplicar</button>
                        <button type="submit"
                            class="px-4 py-2 bg-gray-900 dark:bg-white text-white dark:text-black rounded-lg hover:bg-gray-800 dark:hover:bg-gray-200 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 font-semibold transition">
                            Salvar Alterações
                        </button>
                        <button type="button" @click="open = false"
                            class="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 font-semibold transition">
                            Cancelar
                        </button>
                    </div>
                </form>
            </div>
        </div>
        <!-- Modal de confirmação de exclusão de raspadinha -->
        <div x-data="{ open: false, id: null }" x-show="open" x-cloak id="modal-remover-raspadinha"
            @abrir-modal-remover-raspadinha.window="open = true; id = $event.detail.id"
            class="fixed inset-0 bg-black/60 dark:bg-white/10 z-[999] flex items-center justify-center overflow-y-auto p-4 transition-all duration-300">
            <div @click.away="open = false"
                class="bg-white dark:bg-black relative shadow-3xl border-0 p-0 rounded-lg overflow-hidden w-full max-w-lg my-8 animate-fade-in-up">
                <div
                    class="flex bg-white dark:bg-black border-b border-black/10 dark:border-white/10 items-center justify-between px-5 py-3">
                    <h5 class="font-semibold text-lg">Confirmar Exclusão</h5>
                    <button type="button" class="text-black/40 dark:text-white/40 hover:text-black dark:hover:text-white"
                        @click="open = false">
                        <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none"
                            xmlns="http://www.w3.org/2000/svg">
                            <path
                                d="M24.2929 6.29289L6.29289 24.2929C6.10536 24.4804 6 24.7348 6 25C6 25.2652 6.10536 25.5196 6.29289 25.7071C6.48043 25.8946 6.73478 26 7 26C7.26522 26 7.51957 25.8946 7.70711 25.7071L25.7071 7.70711C25.8946 7.51957 26 7.26522 26 7C26 6.73478 25.8946 6.48043 25.7071 6.29289C25.5196 6.10536 25.2652 6 25 6C24.7348 6 24.4804 6.10536 24.2929 6.29289Z"
                                fill="currentcolor"></path>
                            <path
                                d="M7.70711 6.29289C7.51957 6.10536 7.26522 6 7 6C6.73478 6 6.48043 6.10536 6.29289 6.29289C6.10536 6.48043 6 6.73478 6 7C6 7.26522 6.10536 7.51957 6.29289 7.70711L24.2929 25.7071C24.48043 25.8946 24.7348 26 25 26C25.2652 26 25.51957 25.8946 25.7071 25.7071C25.8946 25.5196 26 25.2652 26 25C26 24.7348 25.8946 24.4804 25.7071 24.2929L7.70711 6.29289Z"
                                fill="currentcolor"></path>
                        </svg>
                    </button>
                </div>
                <div class="p-5">
                    <div class="text-sm text-black dark:text-white">
                        <p>Tem certeza que deseja remover esta raspadinha? Esta ação não pode ser desfeita.</p>
                    </div>
                    <div class="flex justify-end items-center mt-8 gap-4">
                        <button type="button" class="btn !bg-gray-500 !text-white" @click="open = false">Cancelar</button>
                        <button type="button" class="btn !bg-red-500 !text-white"
                            @click="open = false; removerRaspadinha(id);">Remover</button>
                    </div>
                </div>
            </div>
        </div>
        <script>
            function abrirModalEditarRaspadinha(id) {
                // Buscar dados via AJAX e preencher o modal
                fetch('raspadinhas.php?get_scratch=' + id)
                    .then(r => r.json())
                    .then(data => {
                        const f = document.getElementById('form-editar-raspadinha');
                        f.id.value = data.id;
                        f.name.value = data.name;
                        f.description.value = data.description;
                        f.amount.value = data.amount;
                        f.max_reward.value = data.max_reward;
                        f.slug.value = data.slug;
                        // Corrigido: preenche o link e faz preview da imagem
                        if (f.imagem_link) {
                            f.imagem_link.value = data.banner || '';
                            // Mostrar preview da imagem se existir
                            if (data.banner) {
                                const img = document.getElementById('modal-banner-img');
                                const preview = document.getElementById('modal-banner-preview');
                                if (img && preview) {
                                    img.src = data.banner;
                                    preview.style.display = 'flex';
                                }
                            }
                        }
                        f.start_at.value = data.start_at ? data.start_at.replace(' ', 'T') : '';
                        f.expires_at.value = data.expires_at ? data.expires_at.replace(' ', 'T') : '';
                        f.grid_size.value = data.grid_size;
                        f.is_active.value = data.is_active;
                        window.dispatchEvent(new CustomEvent('abrir-modal-editar-raspadinha'));
                    });
            }
            function abrirModalRemoverRaspadinha(id) {
                window.dispatchEvent(new CustomEvent('abrir-modal-remover-raspadinha', { detail: { id } }));
            }
            let removendoRaspadinha = false;
            function removerRaspadinha(id) {
                if (removendoRaspadinha) return;
                removendoRaspadinha = true;
                const fd = new FormData();
                fd.append('ajax_scratch', 1);
                fd.append('acao', 'remover');
                fd.append('id', id);
                fetch('raspadinhas.php', { method: 'POST', body: fd })
                    .then(r => r.json())
                    .then(data => {
                        showToast(data.message, data.success ? 'success' : 'error');
                        if (data.success) location.reload();
                    })
                    .finally(() => { removendoRaspadinha = false; });
            }
            function duplicarRaspadinha() {
                const f = document.getElementById('form-editar-raspadinha');
                const id = f.id.value;
                if (!id) return;
                const fd = new FormData();
                fd.append('ajax_scratch', 1);
                fd.append('acao', 'duplicar');
                fd.append('id', id);
                fetch('raspadinhas.php', { method: 'POST', body: fd })
                    .then(r => r.json())
                    .then(data => {
                        showToast(data.message, data.success ? 'success' : 'error');
                        if (data.success) setTimeout(() => location.reload(), 1200);
                    });
            }
            document.getElementById('form-editar-raspadinha')?.addEventListener('submit', function (e) {
                e.preventDefault();
                const fd = new FormData(this);
                fd.append('ajax_scratch', 1);
                fd.append('acao', 'editar');
                fetch('raspadinhas.php', { method: 'POST', body: fd })
                    .then(r => r.json())
                    .then(data => {
                        showToast(data.message, data.success ? 'success' : 'error');
                        if (data.success) setTimeout(() => location.reload(), 1200);
                    });
            });

            // Ao abrir modal de edição, sempre abrir na aba de configurações
            window.addEventListener('abrir-modal-editar-raspadinha', function () {
                const modal = document.getElementById('form-editar-raspadinha').closest('[x-data]');
                if (modal && modal.__x) {
                    modal.__x.$data.tab = 'config';
                }
                const id = document.getElementById('form-editar-raspadinha').id.value;
                carregarPremiosRaspadinha(id);
                carregarTodosPremios();
            });

            // Renderizar tabela de prêmios
            let premiosPage = 1;
            let premiosLimit = 5; // Alterado para 5 por página
            function renderizarTabelaPremios(data) {
                const tbody = document.getElementById('premios-table-body');
                tbody.innerHTML = '';
                if (!data.data || !data.data.length) {
                    tbody.innerHTML = '<tr><td colspan="8" class="text-center text-gray-500 py-6">Nenhum prêmio vinculado.</td></tr>';
                    document.getElementById('premios-pagination').innerHTML = '';
                    return;
                }
                data.data.forEach(item => {
                    const tr = document.createElement('tr');
                    tr.className = 'border-b border-black/10 dark:border-white/10 hover:bg-blue-50 dark:hover:bg-blue-900/10 transition group';
                    tr.innerHTML = `
                        <td class='px-2 py-2'>${item.image ? `<img src='${item.image}' class='w-8 h-8 rounded-full object-cover shadow'/>` : ''}</td>
                        <td class='px-2 py-2 font-semibold text-gray-900 dark:text-white'>${item.name}</td>
                        <td class='px-2 py-2 text-gray-700 dark:text-gray-300'>${item.type}</td>
                        <td class='px-2 py-2 font-mono text-green-700 dark:text-green-400'>R$ ${(item.amount/100).toFixed(2)}</td>
                        <td class='px-2 py-2'><input type='number' step='0.000001' min='0' max='1' value='${item.probability}' class='form-input px-2 py-1 text-xs w-20 border border-blue-200 dark:border-blue-700 rounded focus:ring-2 focus:ring-blue-400 transition' data-id='${item.id}' data-field='probability'></td>
                        <td class='px-2 py-2'><input type='number' value='${item.sort_order}' class='form-input px-2 py-1 text-xs w-16 border border-blue-200 dark:border-blue-700 rounded focus:ring-2 focus:ring-blue-400 transition' data-id='${item.id}' data-field='sort_order'></td>
                        <td class='px-2 py-2'><input type='checkbox' ${item.is_active==1?'checked':''} data-id='${item.id}' data-field='is_active' class='accent-blue-600 w-4 h-4'></td>
                        <td class='px-2 py-2'>
                            <button type='button' class='inline-flex items-center gap-1 px-2 py-1 rounded bg-red-100 dark:bg-red-900/20 text-red-600 dark:text-red-400 hover:bg-red-200 dark:hover:bg-red-800/40 font-semibold text-xs shadow-sm transition' title='Remover' onclick='removerPremioRaspadinha(${item.id})'>
                                <svg class="w-3 h-3" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
                                Remover
                            </button>
                        </td>
                    `;
                    tbody.appendChild(tr);
                });
                // Paginação
                const pag = document.getElementById('premios-pagination');
                const total = data.total;
                const page = data.page;
                const limit = data.limit;
                const totalPages = Math.ceil(total / limit);
                const start = total === 0 ? 0 : (page - 1) * limit + 1;
                const end = Math.min(page * limit, total);
                let html = `<div class='flex flex-col sm:flex-row items-center justify-between gap-2'>`;
                html += `<div class='text-sm text-gray-500'>Mostrando ${start} a ${end} de ${total} resultados</div>`;
                html += `<div class='flex items-center gap-1 justify-center'>`;
                html += `<a href='#' class='px-2 py-1 rounded ${page==1?'pointer-events-none opacity-50':''}' onclick='mudarPaginaPremios(1);return false;'>First</a>`;
                html += `<a href='#' class='px-2 py-1 rounded ${page==1?'pointer-events-none opacity-50':''}' onclick='mudarPaginaPremios(${page-1});return false;'>Prev</a>`;
                for(let i=Math.max(1,page-2);i<=Math.min(totalPages,page+2);i++){
                    html += `<a href='#' class='px-2 py-1 rounded ${i==page?'bg-black text-white dark:bg-white dark:text-black font-bold':''}' onclick='mudarPaginaPremios(${i});return false;'>${i}</a>`;
                }
                html += `<a href='#' class='px-2 py-1 rounded ${page==totalPages?'pointer-events-none opacity-50':''}' onclick='mudarPaginaPremios(${page+1});return false;'>Next</a>`;
                html += `<a href='#' class='px-2 py-1 rounded ${page==totalPages?'pointer-events-none opacity-50':''}' onclick='mudarPaginaPremios(${totalPages});return false;'>Last</a>`;
                html += `</div></div>`;
                pag.innerHTML = html;
            }
            // Função para buscar e renderizar prêmios da raspadinha
            function carregarPremiosRaspadinha(scratchId, page = 1, limit = 5) {
                const premiosWrapper = document.querySelector('[x-data]');
                if (premiosWrapper && premiosWrapper.__x) premiosWrapper.__x.$data.loadingPremios = true;
                premiosPage = page;
                premiosLimit = limit;
                fetch(`raspadinhas.php?get_rewards_for_scratch=${scratchId}&page=${page}&limit=${limit}`)
                    .then(r => r.json())
                    .then(data => {
                        renderizarTabelaPremios(data);
                    })
                    .finally(() => {
                        if (premiosWrapper && premiosWrapper.__x) premiosWrapper.__x.$data.loadingPremios = false;
                    });
            }
            function mudarPaginaPremios(p) {
                const id = document.getElementById('form-editar-raspadinha').id.value;
                carregarPremiosRaspadinha(id, p, premiosLimit);
            }

            // Função para buscar todos os prêmios disponíveis
            function carregarTodosPremios() {
                fetch('raspadinhas.php?get_all_rewards=1')
                    .then(r => r.json())
                    .then(data => {
                        const sel = document.getElementById('add-reward-select');
                        sel.innerHTML = '<option value="">Selecione...</option>';
                        data.forEach(item => {
                            sel.innerHTML += `<option value='${item.id}'>${item.name} - R$ ${(item.amount/100).toFixed(2)}</option>`;
                        });
                    });
            }
            // Função para adicionar prêmio à raspadinha
            function adicionarPremioRaspadinha() {
                const scratchId = document.getElementById('form-editar-raspadinha').id.value;
                const rewardId = document.getElementById('add-reward-select').value;
                const prob = document.getElementById('add-reward-prob').value;
                const order = document.getElementById('add-reward-order').value;
                if (!rewardId || !prob) return showToast('Selecione o prêmio e a probabilidade', 'error');
                const fd = new FormData();
                fd.append('ajax_scratch_reward', 1);
                fd.append('acao', 'adicionar');
                fd.append('scratch_card_id', scratchId);
                fd.append('reward_id', rewardId);
                fd.append('probability', prob);
                fd.append('sort_order', order);
                fetch('raspadinhas.php', { method: 'POST', body: fd })
                    .then(r => r.json())
                    .then(data => {
                        showToast(data.message, data.success ? 'success' : 'error');
                        if (data.success) carregarPremiosRaspadinha(scratchId);
                    });
            }

            // Eventos para inputs da tabela
            setTimeout(() => {
                document.getElementById('premios-table-body')?.addEventListener('change', function(e) {
                    const t = e.target;
                    if (t.dataset && t.dataset.id && t.dataset.field) {
                        atualizarCampoPremio(t.dataset.id, t.dataset.field, t.type === 'checkbox' ? (t.checked ? 1 : 0) : t.value);
                    }
                });
                document.getElementById('add-reward-btn')?.addEventListener('click', adicionarPremioRaspadinha);
            }, 500);
        </script>

        <!-- Modal para adicionar raspadinha -->
        <div x-show="showModal" x-cloak id="modal-adicionar-raspadinha"
            class="fixed inset-0 bg-black/60 dark:bg-white/10 z-[999] flex items-center justify-center overflow-y-auto p-4 transition-all duration-300">
            <div @click.away="showModal = false" class="bg-white dark:bg-black relative shadow-3xl border-0 p-0 rounded-lg overflow-hidden w-full max-w-lg my-8 animate-fade-in-up">
                <div class="flex bg-white dark:bg-black border-b border-black/10 dark:border-white/10 items-center justify-between px-5 py-4">
                    <h3 class="font-bold text-xl text-black dark:text-white">Adicionar Nova Raspadinha</h3>
                    <button type="button" class="text-black/40 dark:text-white/40 hover:text-black dark:hover:text-white" @click="showModal = false">
                        <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M24.2929 6.29289L6.29289 24.2929C6.10536 24.4804 6 24.7348 6 25C6 25.2652 6.10536 25.5196 6.29289 25.7071C6.48043 25.8946 6.73478 26 7 26C7.26522 26 7.51957 25.8946 7.70711 25.7071L25.7071 7.70711C25.8946 7.51957 26 7.26522 26 7C26 6.73478 25.8946 6.48043 25.7071 6.29289C25.5196 6.10536 25.2652 6 25 6C24.7348 6 24.4804 6.10536 24.2929 6.29289Z" fill="currentcolor"></path>
                            <path d="M7.70711 6.29289C7.51957 6.10536 7.26522 6 7 6C6.73478 6 6.48043 6.10536 6.29289 6.29289C6.10536 6.48043 6 6.73478 6 7C6 7.26522 6.10536 7.51957 6.29289 7.70711L24.2929 25.7071C24.48043 25.8946 24.7348 26 25 26C25.2652 26 25.51957 25.8946 25.7071 25.7071C25.8946 25.5196 26 25.2652 26 25C26 24.7348 25.8946 24.4804 25.7071 24.2929L7.70711 6.29289Z" fill="currentcolor"></path>
                        </svg>
                    </button>
                </div>
                <form id="form-adicionar-raspadinha" class="space-y-5 px-6 py-6" onsubmit="return false;">
                    <div>
                        <label class="block text-sm font-medium mb-1">Nome *</label>
                        <input type="text" name="name" required minlength="3" maxlength="50"
                            class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg">
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1">Descrição</label>
                        <textarea name="description"
                            class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition"
                            rows="2"></textarea>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Valor (centavos) *</label>
                            <input type="number" name="amount"
                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg"
                                required>
                        </div>
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Máx. Prêmio (centavos) *</label>
                            <input type="number" name="max_reward"
                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg"
                                required>
                        </div>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Slug *</label>
                            <input type="text" name="slug"
                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg"
                                required>
                        </div>
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Imagem *</label>
                            <label class="w-full h-16 flex items-center justify-center cursor-pointer border-2 border-dashed border-black/20 dark:border-white/20 rounded-lg p-2 hover:bg-black/5 dark:hover:bg-white/5 transition" ondragover="event.preventDefault();" ondrop="handleBannerDrop(event)">
                                <input type="file" name="imagem" accept="image/*" class="hidden" onchange="uploadBannerImageModal(event)">
                                <span class="text-xs text-black/60 dark:text-white/60">Arraste ou clique para enviar</span>
                            </label>
                            <div id="modal-banner-preview" class="w-full flex justify-center my-2" style="display:none;">
                                <img id="modal-banner-img" src="" alt="Preview" class="w-32 h-32 object-contain rounded shadow">
                            </div>
                            <span class="text-xs text-black/40 dark:text-white/40">ou cole um link abaixo</span>
                            <input type="text" name="imagem_link" id="modal-banner-link" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg mt-1" placeholder="https://..." oninput="previewBannerLink(this.value)">
                        </div>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Ativa</label>
                            <select name="is_active"
                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg">
                                <option value="1">Sim</option>
                                <option value="0">Não</option>
                            </select>
                        </div>
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Grade</label>
                            <input type="number" name="grid_size"
                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg">
                        </div>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Início</label>
                            <input type="datetime-local" name="start_at"
                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg">
                        </div>
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Fim</label>
                            <input type="datetime-local" name="expires_at"
                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg">
                        </div>
                    </div>
                    <div class="flex gap-2 pt-4 justify-end">
                        <button type="submit"
                            class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2">
                            Adicionar
                        </button>
                        <button type="button" @click="showModal = false"
                            class="px-4 py-2 bg-gray-300 dark:bg-gray-600 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-400 dark:hover:bg-gray-500">
                            Cancelar
                        </button>
                    </div>
                    <p class="text-xs text-gray-500">* Campos obrigatórios</p>
                </form>
            </div>
        </div>
    </div> <!-- fechamento do x-data global -->

    <script>
    function uploadBannerImageModal(event) {
        const file = event.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = function(e) {
            document.getElementById('modal-banner-img').src = e.target.result;
            document.getElementById('modal-banner-preview').style.display = 'flex';
            document.getElementById('modal-banner-link').value = '';
        };
        reader.readAsDataURL(file);
    }

    function previewBannerLink(url) {
        const img = document.getElementById('modal-banner-img');
        const preview = document.getElementById('modal-banner-preview');
        if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
            img.src = url;
            preview.style.display = 'flex';
        } else {
            img.src = '';
            preview.style.display = 'none';
        }
        // Limpa input file se link for digitado
        if (url) {
            document.querySelector('#modal-adicionar-raspadinha input[type=file][name=imagem]').value = '';
        }
    }

    function handleBannerDrop(event) {
        event.preventDefault();
        const files = event.dataTransfer.files;
        if (files && files[0]) {
            const input = document.querySelector('#modal-adicionar-raspadinha input[type=file][name=imagem]');
            // Cria um DataTransfer para simular o input file
            const dt = new DataTransfer();
            dt.items.add(files[0]);
            input.files = dt.files;
            uploadBannerImageModal({ target: { files: dt.files } });
        }
    }

    // Highlight visual ao arrastar
    document.addEventListener('DOMContentLoaded', function() {
        const dropLabel = document.querySelector('#modal-adicionar-raspadinha label[ondragover]');
        if (!dropLabel) return;
        dropLabel.addEventListener('dragenter', function() {
            dropLabel.classList.add('ring-2', 'ring-blue-400');
        });
        dropLabel.addEventListener('dragleave', function() {
            dropLabel.classList.remove('ring-2', 'ring-blue-400');
        });
        dropLabel.addEventListener('drop', function() {
            dropLabel.classList.remove('ring-2', 'ring-blue-400');
        });
    });
    </script>

    <!-- Exemplo: ao abrir o modal, se já houver valor no campo de link, mostrar preview -->
    <script>
    document.addEventListener('abrir-modal-adicionar-raspadinha', function () {
        const link = document.getElementById('modal-banner-link').value;
        if (link) previewBannerLink(link);
    });
    </script>
</body>

</html>