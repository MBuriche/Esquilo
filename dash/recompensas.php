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

// Endpoint AJAX para buscar dados de um prêmio
if (isset($_GET['get_reward']) && is_numeric($_GET['get_reward'])) {
    header('Content-Type: application/json');
    $id = (int) $_GET['get_reward'];
    $stmt = $mysqli->prepare("SELECT * FROM premios WHERE id = ?");
    $stmt->bind_param('i', $id);
    $stmt->execute();
    $res = $stmt->get_result();
    $reward = $res ? $res->fetch_assoc() : null;
    $stmt->close();
    if ($reward) {
        echo json_encode($reward);
    } else {
        echo json_encode(['error' => 'Prêmio não encontrado']);
    }
    exit;
}
// Endpoint AJAX para editar prêmio
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax_reward']) && $_POST['acao'] === 'editar') {
    header('Content-Type: application/json');
    $id = (int) $_POST['id'];
    $name = trim($_POST['name']);
    $amount = (int) $_POST['amount'];
    $image = trim($_POST['image']);
    $type = trim($_POST['type']);
    $is_active = isset($_POST['is_active']) ? (int) $_POST['is_active'] : 1;
    
    // Validar se a imagem é uma URL válida ou está vazia
    if (!empty($image) && !filter_var($image, FILTER_VALIDATE_URL)) {
        echo json_encode(['success' => false, 'message' => 'URL da imagem inválida']);
        exit;
    }
    
    $stmt = $mysqli->prepare("UPDATE premios SET name=?, amount=?, image=?, type=?, is_active=? WHERE id=?");
    $stmt->bind_param(
        "sissii",
        $name,
        $amount,
        $image,
        $type,
        $is_active,
        $id
    );
    $ok = $stmt->execute();
    $stmt->close();
    if ($ok) {
        echo json_encode(['success' => true, 'message' => 'Prêmio atualizado com sucesso!']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Erro ao atualizar prêmio!']);
    }
    exit;
}
// Endpoint AJAX para criar prêmio
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax_reward']) && $_POST['acao'] === 'criar') {
    header('Content-Type: application/json');
    $name = trim($_POST['name']);
    $amount = (int) $_POST['amount'];
    $image = trim($_POST['image']);
    $type = trim($_POST['type']);
    $is_active = isset($_POST['is_active']) ? (int) $_POST['is_active'] : 1;
    
    // Validar se a imagem é uma URL válida ou está vazia
    if (!empty($image) && !filter_var($image, FILTER_VALIDATE_URL)) {
        echo json_encode(['success' => false, 'message' => 'URL da imagem inválida']);
        exit;
    }
    
    $stmt = $mysqli->prepare("INSERT INTO premios (name, amount, image, type, is_active) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param(
        "sissi",
        $name,
        $amount,
        $image,
        $type,
        $is_active
    );
    $ok = $stmt->execute();
    $stmt->close();
    if ($ok) {
        echo json_encode(['success' => true, 'message' => 'Prêmio criado com sucesso!']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Erro ao criar prêmio!']);
    }
    exit;
}
// Endpoint AJAX para remover prêmio
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax_reward']) && $_POST['acao'] === 'remover') {
    header('Content-Type: application/json');
    $id = (int) $_POST['id'];
    $stmt = $mysqli->prepare("DELETE FROM premios WHERE id = ?");
    $stmt->bind_param('i', $id);
    $ok = $stmt->execute();
    $stmt->close();
    if ($ok) {
        echo json_encode(['success' => true, 'message' => 'Prêmio removido com sucesso!']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Erro ao remover prêmio!']);
    }
    exit;
}

// Parâmetros de filtro e ordenação para prêmios
$order = $_GET['order'] ?? 'id';
$direction = $_GET['direction'] ?? 'DESC';
$search = $_GET['search'] ?? '';
$limit = $_GET['limit'] ?? 20;
$page = $_GET['page'] ?? 1;
$offset = ($page - 1) * $limit;

// Validar direção
$direction = in_array(strtoupper($direction), ['ASC', 'DESC']) ? strtoupper($direction) : 'DESC';

// Validar campo de ordenação
$valid_orders = ['id', 'name', 'amount', 'type', 'is_active', 'created_at', 'updated_at'];
$order = in_array($order, $valid_orders) ? $order : 'id';

// Construir query de busca
$where_clause = "";
$params = [];
$types = "";

if (!empty($search)) {
    $where_clause = "WHERE name LIKE ?";
    $search_param = "%{$search}%";
    $params = [$search_param];
    $types = "s";
}

// Query para contar total de registros
$count_sql = "SELECT COUNT(*) as total FROM premios $where_clause";
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
$sql = "SELECT * FROM premios $where_clause ORDER BY $order $direction LIMIT ? OFFSET ?";
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
$premios = $result->fetch_all(MYSQLI_ASSOC);
$stmt->close();
// Calcular paginação
$total_pages = ceil($total_records / $limit);
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

        <!-- Modal para adicionar prêmio -->
        <div x-data="{ showModal: false }" x-show="showModal" x-cloak
            class="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
            <div @click.away="showModal = false" class="bg-white dark:bg-gray-800 rounded-lg p-6 w-full max-w-md">
                <h3 class="text-lg font-semibold mb-4">Adicionar Novo Prêmio</h3>
                <form id="form-adicionar-premio" class="space-y-4" onsubmit="return false;">
                    <div>
                        <label class="block text-sm font-medium mb-1">Nome *</label>
                        <input type="text" name="name" required minlength="3" maxlength="100"
                            class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1">Valor (centavos) *</label>
                        <input type="number" name="amount" required min="0"
                            class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1">Imagem</label>
                        <input type="text" name="image" placeholder="https://..."
                            class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1">Tipo *</label>
                        <select name="type" required class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                            <option value="voucher">Voucher</option>
                            <option value="item">Item</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1">Ativo</label>
                        <select name="is_active" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                            <option value="1">Sim</option>
                            <option value="0">Não</option>
                        </select>
                    </div>
                    <div class="flex gap-2 pt-4">
                        <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2">
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

        <!-- Modal de edição de prêmio -->
        <div x-data="{ open: false, premio: null }" x-show="open" x-cloak id="modal-editar-premio"
            @abrir-modal-editar-premio.window="open = true"
            class="fixed inset-0 bg-black/60 dark:bg-white/10 z-[999] flex items-center justify-center overflow-y-auto p-4 transition-all duration-300">
            <div @click.away="open = false"
                class="bg-white dark:bg-black relative shadow-3xl border-0 p-0 rounded-lg overflow-hidden w-full max-w-lg my-8 animate-fade-in-up">
                <div
                    class="flex bg-white dark:bg-black border-b border-black/10 dark:border-white/10 items-center justify-between px-5 py-4">
                    <h3 class="font-bold text-xl text-black dark:text-white">Editar Prêmio</h3>
                    <button type="button" class="text-black/40 dark:text-white/40 hover:text-black dark:hover:text-white"
                        @click="open = false">
                        <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none"
                            xmlns="http://www.w3.org/2000/svg">
                            <path d="M24.2929 6.29289L6.29289 24.2929C6.10536 24.4804 6 24.7348 6 25C6 25.2652 6.10536 25.5196 6.29289 25.7071C6.48043 25.8946 6.73478 26 7 26C7.26522 26 7.51957 25.8946 7.70711 25.7071L25.7071 7.70711C25.8946 7.51957 26 7.26522 26 7C26 6.73478 25.8946 6.48043 25.7071 6.29289C25.5196 6.10536 25.2652 6 25 6C24.7348 6 24.4804 6.10536 24.2929 6.29289Z" fill="currentcolor"></path>
                            <path d="M7.70711 6.29289C7.51957 6.10536 7.26522 6 7 6C6.73478 6 6.48043 6.10536 6.29289 6.29289C6.10536 6.48043 6 6.73478 6 7C6 7.26522 6.10536 7.51957 6.29289 7.70711L24.2929 25.7071C24.48043 25.8946 24.7348 26 25 26C25.2652 26 25.51957 25.8946 25.7071 25.7071C25.8946 25.5196 26 25.2652 26 25C26 24.7348 25.8946 24.4804 25.7071 24.2929L7.70711 6.29289Z" fill="currentcolor"></path>
                        </svg>
                    </button>
                </div>
                <form id="form-editar-premio" class="space-y-5 px-6 py-6" enctype="multipart/form-data" onsubmit="return false;">
                    <input type="hidden" name="id" />
                    <div class="space-y-2">
                        <label class="form-label font-semibold">Nome *</label>
                        <input type="text" name="name" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition" required>
                    </div>
                    <div class="space-y-2">
                        <label class="form-label font-semibold">Valor (centavos) *</label>
                        <input type="number" name="amount" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg" required>
                    </div>
                    <div class="space-y-2">
                        <label class="form-label font-semibold">Imagem</label>
                        <input type="text" name="image" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg" placeholder="https://...">
                    </div>
                    <div class="space-y-2">
                        <label class="form-label font-semibold">Tipo *</label>
                        <select name="type" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg">
                            <option value="voucher">Voucher</option>
                            <option value="item">Item</option>
                        </select>
                    </div>
                    <div class="space-y-2">
                        <label class="form-label font-semibold">Ativo</label>
                        <select name="is_active" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg">
                            <option value="1">Sim</option>
                            <option value="0">Não</option>
                        </select>
                    </div>
                    <div class="flex gap-2 pt-4 justify-end">
                        <button type="submit" class="px-4 py-2 bg-gray-900 dark:bg-white text-white dark:text-black rounded-lg hover:bg-gray-800 dark:hover:bg-gray-200 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 font-semibold transition">
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
        <!-- Modal de confirmação de exclusão de prêmio -->
        <div x-data="{ open: false, id: null }" x-show="open" x-cloak id="modal-remover-premio"
            @abrir-modal-remover-premio.window="open = true; id = $event.detail.id"
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
                            <path d="M24.2929 6.29289L6.29289 24.2929C6.10536 24.4804 6 24.7348 6 25C6 25.2652 6.10536 25.5196 6.29289 25.7071C6.48043 25.8946 6.73478 26 7 26C7.26522 26 7.51957 25.8946 7.70711 25.7071L25.7071 7.70711C25.8946 7.51957 26 7.26522 26 7C26 6.73478 25.8946 6.48043 25.7071 6.29289C25.5196 6.10536 25.2652 6 25 6C24.7348 6 24.4804 6.10536 24.2929 6.29289Z" fill="currentcolor"></path>
                            <path d="M7.70711 6.29289C7.51957 6.10536 7.26522 6 7 6C6.73478 6 6.48043 6.10536 6.29289 6.29289C6.10536 6.48043 6 6.73478 6 7C6 7.26522 6.10536 7.51957 6.29289 7.70711L24.2929 25.7071C24.48043 25.8946 24.7348 26 25 26C25.2652 26 25.51957 25.8946 25.7071 25.7071C25.8946 25.5196 26 25.2652 26 25C26 24.7348 25.8946 24.4804 25.7071 24.2929L7.70711 6.29289Z" fill="currentcolor"></path>
                        </svg>
                    </button>
                </div>
                <div class="p-5">
                    <div class="text-sm text-black dark:text-white">
                        <p>Tem certeza que deseja remover este prêmio? Esta ação não pode ser desfeita.</p>
                    </div>
                    <div class="flex justify-end items-center mt-8 gap-4">
                        <button type="button" class="btn !bg-gray-500 !text-white" @click="open = false">Cancelar</button>
                        <button type="button" class="btn !bg-red-500 !text-white"
                            @click="open = false; removerPremio(id);">Remover</button>
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
                            <p class="text-sm font-semibold">Gerenciamento de Prêmios</p>
                            <p class="text-xs text-gray-500">Total de prêmios: <?php echo $total_records; ?></p>
                        </div>
                        <div class="p-2 bg-lightwhite dark:bg-white/5 rounded-lg flex gap-2 justify-between mb-2">
                            <div class="flex items-center gap-4">
                                <div class="flex gap-2 items-center">
                                    <button type="button" @click="showModal = true"
                                        class="p-1 rounded-lg bg-transparent hover:bg-black/5 dark:hover:bg-white/5 transition-all duration-300"
                                        title="Adicionar Prêmio">
                                        <svg width="20" height="20" viewBox="0 0 20 20" fill="none"
                                            xmlns="http://www.w3.org/2000/svg">
                                            <path
                                                d="M10.625 4.375C10.625 4.02982 10.3452 3.75 10 3.75C9.65482 3.75 9.375 4.02982 9.375 4.375V9.375H4.375C4.02982 9.375 3.75 9.65482 3.75 10C3.75 10.3452 4.02982 10.625 4.375 10.625H9.375V15.625C9.375 15.9702 9.65482 16.25 10 16.25C10.3452 16.25 10.625 15.9702 10.625 15.625V10.625H15.625C15.9702 10.625 16.25 10.3452 16.25 10C16.25 9.65482 15.9702 9.375 15.625 9.375H10.625V4.375Z"
                                                fill="currentcolor"></path>
                                        </svg>
                                    </button>
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
                                        placeholder="Buscar prêmios...">
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
                                            <th>Valor</th>
                                            <th>Tipo</th>
                                            <th>Ativo</th>
                                            <th>Criado em</th>
                                            <th>Atualizado em</th>
                                            <th>Ações</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php if (empty($premios)): ?>
                                            <tr>
                                                <td colspan="8" class="text-center py-8 text-gray-500">
                                                    Nenhum prêmio encontrado.
                                                </td>
                                            </tr>
                                        <?php else: ?>
                                            <?php foreach ($premios as $premio): ?>
                                                <tr
                                                    class="group text-xs border-b border-black/20 dark:border-white/5 hover:bg-gray-50 dark:hover:bg-gray-800/50">
                                                    <td class="whitespace-nowrap">
                                                        #<?php echo str_pad($premio['id'], 4, '0', STR_PAD_LEFT); ?></td>
                                                    <td class="whitespace-nowrap font-medium">
                                                        <div class="flex items-center gap-2">
                                                            <?php if ($premio['image']): ?>
                                                                <img src="<?php echo htmlspecialchars($premio['image']); ?>" alt="Imagem" class="w-8 h-8 object-cover rounded-full shadow" />
                                                            <?php endif; ?>
                                                            <span><?php echo htmlspecialchars($premio['name']); ?></span>
                                                        </div>
                                                    </td>
                                                    <td class="whitespace-nowrap">R$
                                                        <?php echo number_format($premio['amount'] / 100, 2, ',', '.'); ?></td>
                                                    <td class="whitespace-nowrap"><?php echo htmlspecialchars($premio['type']); ?></td>
                                                    <td class="whitespace-nowrap">
                                                        <?php if ($premio['is_active']): ?>
                                                            <span class="px-2 py-1 text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400 rounded">Sim</span>
                                                        <?php else: ?>
                                                            <span class="px-2 py-1 text-xs font-medium  text-gray-800 dark:bg-gray-900/20 dark:text-gray-400 rounded">Não</span>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td class="whitespace-nowrap text-xs">
                                                        <?php echo date('d/m/Y H:i', strtotime($premio['created_at'])); ?></td>
                                                    <td class="whitespace-nowrap text-xs">
                                                        <?php echo date('d/m/Y H:i', strtotime($premio['updated_at'])); ?></td>
                                                    <td class="whitespace-nowrap">
                                                        <div class="flex items-center gap-1">
                                                            <button type="button"
                                                                class="p-1 text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                                                                title="Editar prêmio"
                                                                onclick="abrirModalEditarPremio(<?php echo $premio['id']; ?>)">
                                                                <svg width="16" height="16" viewBox="0 0 16 16" fill="none"
                                                                    xmlns="http://www.w3.org/2000/svg">
                                                                    <path d="M8 12H14M2 12H6M8 12V8L12 4L14 6L10 10H8V12Z"
                                                                        stroke="currentColor" stroke-width="1.5"
                                                                        stroke-linecap="round" stroke-linejoin="round" />
                                                                </svg>
                                                            </button>
                                                            <button type="button"
                                                                class="p-1 text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300"
                                                                title="Excluir prêmio"
                                                                onclick="abrirModalRemoverPremio(<?php echo $premio['id']; ?>)">
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
                        <!-- Paginação -->
                        <div class="flex flex-col sm:flex-row items-center justify-between gap-2 mt-4">
                            <div class="text-sm text-gray-500">Mostrando <?php echo ($total_records == 0 ? 0 : ($page - 1) * $limit + 1); ?> a <?php echo min($page * $limit, $total_records); ?> de <?php echo $total_records; ?> resultados</div>
                            <div class="flex items-center gap-1 justify-center">
                                <a href="?page=1&limit=<?php echo $limit; ?>&order=<?php echo $order; ?>&direction=<?php echo $direction; ?>&search=<?php echo urlencode($search); ?>" class="px-2 py-1 rounded <?php echo $page==1?'pointer-events-none opacity-50':''; ?>">First</a>
                                <a href="?page=<?php echo max(1, $page-1); ?>&limit=<?php echo $limit; ?>&order=<?php echo $order; ?>&direction=<?php echo $direction; ?>&search=<?php echo urlencode($search); ?>" class="px-2 py-1 rounded <?php echo $page==1?'pointer-events-none opacity-50':''; ?>">Prev</a>
                                <?php for($i=max(1,$page-2);$i<=min($total_pages,$page+2);$i++): ?>
                                    <a href="?page=<?php echo $i; ?>&limit=<?php echo $limit; ?>&order=<?php echo $order; ?>&direction=<?php echo $direction; ?>&search=<?php echo urlencode($search); ?>" class="px-2 py-1 rounded <?php echo $i==$page?'bg-black text-white dark:bg-white dark:text-black font-bold':''; ?>"><?php echo $i; ?></a>
                                <?php endfor; ?>
                                <a href="?page=<?php echo min($total_pages, $page+1); ?>&limit=<?php echo $limit; ?>&order=<?php echo $order; ?>&direction=<?php echo $direction; ?>&search=<?php echo urlencode($search); ?>" class="px-2 py-1 rounded <?php echo $page==$total_pages?'pointer-events-none opacity-50':''; ?>">Next</a>
                                <a href="?page=<?php echo $total_pages; ?>&limit=<?php echo $limit; ?>&order=<?php echo $order; ?>&direction=<?php echo $direction; ?>&search=<?php echo urlencode($search); ?>" class="px-2 py-1 rounded <?php echo $page==$total_pages?'pointer-events-none opacity-50':''; ?>">Last</a>
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
            function abrirModalEditarPremio(id) {
                fetch('recompensas.php?get_reward=' + id)
                    .then(r => r.json())
                    .then(data => {
                        const f = document.getElementById('form-editar-premio');
                        f.id.value = data.id;
                        f.name.value = data.name;
                        f.amount.value = data.amount;
                        f.image.value = data.image || '';
                        f.type.value = data.type;
                        f.is_active.value = data.is_active;
                        window.dispatchEvent(new CustomEvent('abrir-modal-editar-premio'));
                    });
            }
            function abrirModalRemoverPremio(id) {
                window.dispatchEvent(new CustomEvent('abrir-modal-remover-premio', { detail: { id } }));
            }
            let removendoPremio = false;
            function removerPremio(id) {
                if (removendoPremio) return;
                removendoPremio = true;
                const fd = new FormData();
                fd.append('ajax_reward', 1);
                fd.append('acao', 'remover');
                fd.append('id', id);
                fetch('recompensas.php', { method: 'POST', body: fd })
                    .then(r => r.json())
                    .then(data => {
                        showToast(data.message, data.success ? 'success' : 'error');
                        if (data.success) location.reload();
                    })
                    .finally(() => { removendoPremio = false; });
            }
            document.getElementById('form-editar-premio')?.addEventListener('submit', function (e) {
                e.preventDefault();
                const fd = new FormData(this);
                fd.append('ajax_reward', 1);
                fd.append('acao', 'editar');
                fetch('recompensas.php', { method: 'POST', body: fd })
                    .then(r => r.json())
                    .then(data => {
                        showToast(data.message, data.success ? 'success' : 'error');
                        if (data.success) setTimeout(() => location.reload(), 1200);
                    });
            });
            document.getElementById('form-adicionar-premio')?.addEventListener('submit', function (e) {
                e.preventDefault();
                const fd = new FormData(this);
                fd.append('ajax_reward', 1);
                fd.append('acao', 'criar');
                fetch('recompensas.php', { method: 'POST', body: fd })
                    .then(r => r.json())
                    .then(data => {
                        showToast(data.message, data.success ? 'success' : 'error');
                        if (data.success) setTimeout(() => location.reload(), 1200);
                    });
            });
        </script>
    </div>
</body>
</html>