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
// Processamento para excluir usuário
if (isset($_GET['delete_user']) && is_numeric($_GET['delete_user'])) {
    $user_id = (int)$_GET['delete_user'];
    
    $sql = "DELETE FROM usuarios WHERE id = ?";
    $stmt = $mysqli->prepare($sql);
    $stmt->bind_param("i", $user_id);
    
    if ($stmt->execute()) {
        $success_message = "Usuário excluído com sucesso!";
    } else {
        $error_message = "Erro ao excluir usuário: " . $mysqli->error;
    }
    $stmt->close();
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

// Processamento para adicionar usuário
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['add_user'])) {
    $email = trim($_POST['email'] ?? '');
    $usuario = trim($_POST['usuario'] ?? '');
    $celular = trim($_POST['celular'] ?? '');
    $password = $_POST['password'] ?? '';
    $saldo = $_POST['saldo'] ?? 0.00;
    $cpf = trim($_POST['cpf'] ?? '');
    
    // Validação básica
    $errors = [];
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Email inválido";
    }
    if (empty($usuario) || strlen($usuario) < 3) {
        $errors[] = "Nome de usuário deve ter pelo menos 3 caracteres";
    }
    if (empty($password) || strlen($password) < 6) {
        $errors[] = "Senha deve ter pelo menos 6 caracteres";
    }
    if (empty($celular)) {
        $errors[] = "Celular é obrigatório";
    }
    
    // Verificar se email ou usuário já existem
    if (empty($errors)) {
        $check_sql = "SELECT id FROM usuarios WHERE email = ? OR usuario = ?";
        $check_stmt = $mysqli->prepare($check_sql);
        $check_stmt->bind_param("ss", $email, $usuario);
        $check_stmt->execute();
        $check_result = $check_stmt->get_result();
        if ($check_result->num_rows > 0) {
            $errors[] = "Email ou nome de usuário já existem";
        }
        $check_stmt->close();
    }
    
    if (empty($errors)) {
        $password_hash = password_hash($password, PASSWORD_DEFAULT);
        
        // Gerar código de convite único
        $codigo_convite = strtoupper(substr(md5(uniqid(rand(), true)), 0, 8));
        
        // Gerar token único
        $token = md5(uniqid(rand(), true));
        
        // Gerar URL única
        $url = strtolower(preg_replace('/[^a-zA-Z0-9]/', '', $usuario)) . rand(1000, 9999);
        
        $sql = "INSERT INTO usuarios (email, usuario, celular, password, saldo, url, codigo_convite, token, data_registro, cpf) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?)";
        
        $stmt = $mysqli->prepare($sql);
        $stmt->bind_param("ssssdssss", $email, $usuario, $celular, $password_hash, $saldo, $url, $codigo_convite, $token, $cpf);
        
        if ($stmt->execute()) {
            $success_message = "Usuário adicionado com sucesso!";
        } else {
            $error_message = "Erro ao adicionar usuário: " . $mysqli->error;
        }
        $stmt->close();
    } else {
        $error_message = implode(", ", $errors);
    }
}

// Parâmetros de filtro e ordenação
$order = $_GET['order'] ?? 'id';
$direction = $_GET['direction'] ?? 'DESC';
$search = $_GET['search'] ?? '';
$limit = $_GET['limit'] ?? 20;
$page = $_GET['page'] ?? 1;
$offset = ($page - 1) * $limit;

// Validar direção
$direction = in_array(strtoupper($direction), ['ASC', 'DESC']) ? strtoupper($direction) : 'DESC';

// Validar campo de ordenação
$valid_orders = ['id', 'usuario', 'email', 'celular', 'saldo', 'data_registro', 'total_aberto'];
$order = in_array($order, $valid_orders) ? $order : 'id';

// Construir query de busca
$where_clause = "";
$params = [];
$types = "";

if (!empty($search)) {
    if (is_numeric($search)) {
        $where_clause = "WHERE id = ? OR usuario LIKE ? OR email LIKE ? OR celular LIKE ? OR cpf LIKE ?";
        $params = [$search, "%{$search}%", "%{$search}%", "%{$search}%", "%{$search}%"];
        $types = "issss";
    } else {
        $where_clause = "WHERE usuario LIKE ? OR email LIKE ? OR celular LIKE ? OR cpf LIKE ?";
        $search_param = "%{$search}%";
        $params = [$search_param, $search_param, $search_param, $search_param];
        $types = "ssss";
    }
}

// Query para contar total de registros
$count_sql = "SELECT COUNT(*) as total FROM usuarios $where_clause";
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
$sql = "SELECT id, email, usuario, celular, saldo, data_registro, cpf, total_aberto, url, codigo_convite 
        FROM usuarios $where_clause 
        ORDER BY $order $direction 
        LIMIT ? OFFSET ?";

$stmt = $mysqli->prepare($sql);
if (!empty($params)) {
    $params[] = $limit;
    $params[] = $offset;
    $types .= "ii";
    $stmt->bind_param($types, ...$params);
} else {
    $stmt->bind_param("ii", $limit, $offset);
}

$stmt->execute();
$result = $stmt->get_result();
$usuarios = $result->fetch_all(MYSQLI_ASSOC);
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
    <!-- Start Menu Sidebar Olverlay -->
    <div x-cloak class="fixed inset-0 bg-[black]/60 z-40 lg:hidden" :class="{'hidden' : !$store.app.sidebar}"
        @click="$store.app.toggleSidebar()"></div>
    <!-- End Menu Sidebar Olverlay -->

    <!-- Start Right Sidebar Olverlay -->
    <div x-cloak class="fixed inset-0 bg-[black]/60 z-50 2xl:hidden" :class="{'hidden' : !$store.app.rightsidebar}"
        @click="$store.app.rightSidebar()"></div>
    <!-- End Right Sidebar Olverlay -->

    <!-- Modal para adicionar usuário -->
    <div x-data="{ showModal: false }" x-show="showModal" x-cloak class="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
        <div @click.away="showModal = false" class="bg-white dark:bg-gray-800 rounded-lg p-6 w-full max-w-md">
            <h3 class="text-lg font-semibold mb-4">Adicionar Novo Usuário</h3>
            <form method="POST" class="space-y-4">
                <div>
                    <label class="block text-sm font-medium mb-1">Email *</label>
                    <input type="email" name="email" required 
                           pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"
                           class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-medium mb-1">Usuário *</label>
                    <input type="text" name="usuario" required minlength="3" maxlength="50"
                           class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-medium mb-1">Celular *</label>
                    <input type="text" name="celular" required 
                           pattern="[\+]?[0-9\s\-\(\)]+"
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
                    <input type="text" name="cpf" maxlength="14" 
                           pattern="[0-9]{3}\.?[0-9]{3}\.?[0-9]{3}\-?[0-9]{2}"
                           placeholder="000.000.000-00"
                           class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-medium mb-1">Saldo Inicial</label>
                    <input type="number" step="0.01" min="0" name="saldo" value="0.00" 
                           class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md dark:bg-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                </div>
                <div class="flex gap-2 pt-4">
                    <button type="submit" name="add_user" class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2">
                        Adicionar
                    </button>
                    <button type="button" @click="showModal = false" class="px-4 py-2 bg-gray-300 dark:bg-gray-600 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-400 dark:hover:bg-gray-500">
                        Cancelar
                    </button>
                </div>
                <p class="text-xs text-gray-500">* Campos obrigatórios</p>
            </form>
        </div>
    </div>

    <!-- Modal de confirmação de exclusão múltipla -->
    <div x-data="{ open: false }" 
         @bulk-delete.window="open = true" 
         class="fixed inset-0 bg-black/60 dark:bg-white/10 z-[999] hidden overflow-y-auto" 
         :class="open && '!block'">
        <div class="flex items-center justify-center min-h-screen px-4" @click.self="open = false">
            <div x-show="open" x-transition x-transition.duration.300 class="bg-white dark:bg-black relative shadow-3xl border-0 p-0 rounded-lg overflow-hidden w-full max-w-lg my-8">
                <div class="flex bg-white dark:bg-black border-b border-black/10 dark:border-white/10 items-center justify-between px-5 py-3">
                    <h5 class="font-semibold text-lg">Confirmar Exclusão Múltipla</h5>
                    <button type="button" class="text-black/40 dark:text-white/40 hover:text-black dark:hover:text-white" @click="open = false">
                        <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M24.2929 6.29289L6.29289 24.2929C6.10536 24.4804 6 24.7348 6 25C6 25.2652 6.10536 25.5196 6.29289 25.7071C6.48043 25.8946 6.73478 26 7 26C7.26522 26 7.51957 25.8946 7.70711 25.7071L25.7071 7.70711C25.8946 7.51957 26 7.26522 26 7C26 6.73478 25.8946 6.48043 25.7071 6.29289C25.5196 6.10536 25.2652 6 25 6C24.7348 6 24.4804 6.10536 24.2929 6.29289Z" fill="currentcolor"></path>
                            <path d="M7.70711 6.29289C7.51957 6.10536 7.26522 6 7 6C6.73478 6 6.48043 6.10536 6.29289 6.29289C6.10536 6.48043 6 6.73478 6 7C6 7.26522 6.10536 7.51957 6.29289 7.70711L24.2929 25.7071C24.4804 25.8946 24.7348 26 25 26C25.2652 26 25.5196 25.8946 25.7071 25.7071C25.8946 25.5196 26 25.2652 26 25C26 24.7348 25.8946 24.4804 25.7071 24.2929L7.70711 6.29289Z" fill="currentcolor"></path>
                        </svg>
                    </button>
                </div>
                <div class="p-5">
                    <div class="text-sm text-black dark:text-white">
                        <p>Tem certeza que deseja excluir os usuários selecionados? Esta ação não pode ser desfeita.</p>
                        <p class="mt-2 font-medium" id="selected-count-text"></p>
                    </div>
                    <div class="flex justify-end items-center mt-8 gap-4">
                        <button type="button" class="btn !bg-gray-500 !text-white" @click="open = false">Cancelar</button>
                        <button type="button" class="btn !bg-red-500 !text-white" @click="submitBulkDelete(); open = false">Excluir Selecionados</button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal de confirmação de exclusão individual -->
    <div x-data="{ open: false, userId: null }" 
         @delete-user.window="open = true; userId = $event.detail.userId" 
         class="fixed inset-0 bg-black/60 dark:bg-white/10 z-[999] hidden overflow-y-auto" 
         :class="open && '!block'">
        <div class="flex items-center justify-center min-h-screen px-4" @click.self="open = false">
            <div x-show="open" x-transition x-transition.duration.300 class="bg-white dark:bg-black relative shadow-3xl border-0 p-0 rounded-lg overflow-hidden w-full max-w-lg my-8">
                <div class="flex bg-white dark:bg-black border-b border-black/10 dark:border-white/10 items-center justify-between px-5 py-3">
                    <h5 class="font-semibold text-lg">Confirmar Exclusão</h5>
                    <button type="button" class="text-black/40 dark:text-white/40 hover:text-black dark:hover:text-white" @click="open = false">
                        <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M24.2929 6.29289L6.29289 24.2929C6.10536 24.4804 6 24.7348 6 25C6 25.2652 6.10536 25.5196 6.29289 25.7071C6.48043 25.8946 6.73478 26 7 26C7.26522 26 7.51957 25.8946 7.70711 25.7071L25.7071 7.70711C25.8946 7.51957 26 7.26522 26 7C26 6.73478 25.8946 6.48043 25.7071 6.29289C25.5196 6.10536 25.2652 6 25 6C24.7348 6 24.4804 6.10536 24.2929 6.29289Z" fill="currentcolor"></path>
                            <path d="M7.70711 6.29289C7.51957 6.10536 7.26522 6 7 6C6.73478 6 6.48043 6.10536 6.29289 6.29289C6.10536 6.48043 6 6.73478 6 7C6 7.26522 6.10536 7.51957 6.29289 7.70711L24.2929 25.7071C24.4804 25.8946 24.7348 26 25 26C25.2652 26 25.5196 25.8946 25.7071 25.7071C25.8946 25.5196 26 25.2652 26 25C26 24.7348 25.8946 24.4804 25.7071 24.2929L7.70711 6.29289Z" fill="currentcolor"></path>
                        </svg>
                    </button>
                </div>
                <div class="p-5">
                    <div class="text-sm text-black dark:text-white">
                        <p>Tem certeza que deseja excluir este usuário? Esta ação não pode ser desfeita.</p>
                    </div>
                    <div class="flex justify-end items-center mt-8 gap-4">
                        <button type="button" class="btn !bg-gray-500 !text-white" @click="open = false">Cancelar</button>
                        <button type="button" class="btn !bg-red-500 !text-white" @click="window.location.href = '?delete_user=' + userId; open = false">Excluir</button>
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
                        <p class="text-sm font-semibold">Gerenciamento de Usuários</p>
                        <p class="text-xs text-gray-500">Total de usuários: <?php echo $total_records; ?></p>
                    </div>

                    <?php if (isset($success_message)): ?>
                        <div class="mb-4 p-4 bg-green-100 dark:bg-green-900/20 border border-green-300 dark:border-green-700 text-green-700 dark:text-green-300 rounded-lg">
                            <?php echo $success_message; ?>
                        </div>
                    <?php endif; ?>

                    <?php if (isset($error_message)): ?>
                        <div class="mb-4 p-4 bg-red-100 dark:bg-red-900/20 border border-red-300 dark:border-red-700 text-red-700 dark:text-red-300 rounded-lg">
                            <?php echo $error_message; ?>
                        </div>
                    <?php endif; ?>

                    <div class="p-2 bg-lightwhite dark:bg-white/5 rounded-lg flex gap-2 justify-between mb-2">
                        <div class="flex items-center gap-4">
                            <div class="flex gap-2 items-center">
                                <button type="button" @click="$el.closest('[x-data]').showModal = true"
                                    class="p-1 rounded-lg bg-transparent hover:bg-black/5 dark:hover:bg-white/5 transition-all duration-300"
                                    title="Adicionar Usuário">
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
                                    title="Excluir Selecionados"
                                    id="bulk-delete-btn" style="display: none;">
                                    <svg width="20" height="20" viewBox="0 0 20 20" fill="none"
                                        xmlns="http://www.w3.org/2000/svg">
                                        <path d="M6 2L10 2M2 4H14M12 4L11.5 12H4.5L4 4M7 7V10M9 7V10"
                                            stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
                                    </svg>
                                </button>
                                
                                <!-- Botões de ordenação -->
                                <a href="?order=id&direction=<?php echo ($order == 'id' && $direction == 'ASC') ? 'DESC' : 'ASC'; ?>&search=<?php echo urlencode($search); ?>"
                                    class="p-1 rounded-lg bg-transparent hover:bg-black/5 dark:hover:bg-white/5 transition-all duration-300"
                                    title="Ordenar por ID">
                                    <svg width="20" height="20" viewBox="0 0 20 20" fill="none"
                                        xmlns="http://www.w3.org/2000/svg">
                                        <path
                                            d="M4.19194 13.3081C4.07473 13.1908 3.91576 13.125 3.75 13.125C3.58424 13.125 3.42527 13.1908 3.30806 13.3081C3.19085 13.4253 3.125 13.5842 3.125 13.75C3.125 13.9158 3.19085 14.0747 3.30806 14.1919L5.80806 16.6919C5.92527 16.8092 6.08424 16.875 6.25 16.875C6.41576 16.875 6.57473 16.8092 6.69194 16.6919L9.19171 14.1922L9.19194 14.1919C9.30915 14.0747 9.375 13.9158 9.375 13.75C9.375 13.5842 9.30915 13.4253 9.19194 13.3081C9.07473 13.1908 8.91576 13.125 8.75 13.125C8.58424 13.125 8.42527 13.1908 8.30806 13.3081L8.30782 13.3083L6.25 15.3661L4.19194 13.3081Z"
                                            fill="currentcolor"></path>
                                        <path
                                            d="M5.625 3.75V16.25C5.625 16.5952 5.90482 16.875 6.25 16.875C6.59518 16.875 6.875 16.5952 6.875 16.25V3.75C6.875 3.40482 6.59518 3.125 6.25 3.125C5.90482 3.125 5.625 3.40482 5.625 3.75Z"
                                            fill="currentcolor"></path>
                                        <path
                                            d="M15.8077 6.69162L15.8081 6.69194C15.9253 6.80915 16.0842 6.875 16.25 6.875C16.4158 6.875 16.5747 6.80915 16.6919 6.69194C16.8092 6.57473 16.875 6.41576 16.875 6.25C16.875 6.08424 16.8092 5.92527 16.6919 5.80806L14.1919 3.30806C14.0747 3.19085 13.9158 3.125 13.75 3.125C13.5842 3.125 13.4253 3.19085 13.3081 3.30806L10.8081 5.80806C10.6908 5.92527 10.625 6.08424 10.625 6.25C10.625 6.26001 10.6252 6.27002 10.6257 6.28002C10.6332 6.43522 10.6982 6.58207 10.8081 6.69194C10.9253 6.80915 11.0842 6.875 11.25 6.875C11.4158 6.875 11.5747 6.80915 11.6919 6.69194L11.6922 6.69171L13.75 4.63388L15.8077 6.69162Z"
                                            fill="currentcolor"></path>
                                        <path
                                            d="M14.375 16.25V3.75C14.375 3.40482 14.0952 3.125 13.75 3.125C13.4048 3.125 13.125 3.40482 13.125 3.75V16.25C13.125 16.5952 13.4048 16.875 13.75 16.875C14.0952 16.875 14.375 16.5952 14.375 16.25Z"
                                            fill="currentcolor"></path>
                                    </svg>
                                </a>
                            </div>
                        </div>
                        
                        <!-- Formulário de busca -->
                        <form method="GET" class="md:flex items-center hidden">
                            <input type="hidden" name="order" value="<?php echo $order; ?>">
                            <input type="hidden" name="direction" value="<?php echo $direction; ?>">
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
                                <input type="text" name="search" value="<?php echo htmlspecialchars($search); ?>"
                                    class="bg-black/5 dark:bg-white/5 border-0 text-sm rounded-lg block max-w-[200px] w-full pl-[26px] p-1 focus:ring-0 focus:outline-0"
                                    placeholder="Buscar usuários..." />
                                <button type="submit" class="absolute inset-y-0 right-0 flex items-center pr-2">
                                    <svg class="w-4 h-4 text-black/40 dark:text-white/40 hover:text-black dark:hover:text-white" fill="currentColor" viewBox="0 0 20 20">
                                        <path fill-rule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clip-rule="evenodd"></path>
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
                                        <th class="flex items-center">
                                            <input id="all" name="select-all" type="checkbox"
                                                class="h-3 w-3 rounded border border-black/20 text-black dark:bg-transparent dark:border-white/20 focus:ring-0 focus:ring-offset-0 focus:shadow-none focus:border-black/20 dark:focus:border-white/20 focus:outline-0">
                                            <label for="all" class="ml-1.5 block cursor-pointer">
                                                <a href="?order=id&direction=<?php echo ($order == 'id' && $direction == 'ASC') ? 'DESC' : 'ASC'; ?>&search=<?php echo urlencode($search); ?>" 
                                                   class="hover:text-blue-600 dark:hover:text-blue-400">
                                                    ID <?php if($order == 'id') echo $direction == 'ASC' ? '↑' : '↓'; ?>
                                                </a>
                                            </label>
                                        </th>
                                        <th>
                                            <a href="?order=usuario&direction=<?php echo ($order == 'usuario' && $direction == 'ASC') ? 'DESC' : 'ASC'; ?>&search=<?php echo urlencode($search); ?>" 
                                               class="hover:text-blue-600 dark:hover:text-blue-400">
                                                Usuário <?php if($order == 'usuario') echo $direction == 'ASC' ? '↑' : '↓'; ?>
                                            </a>
                                        </th>
                                        <th>
                                            <a href="?order=email&direction=<?php echo ($order == 'email' && $direction == 'ASC') ? 'DESC' : 'ASC'; ?>&search=<?php echo urlencode($search); ?>" 
                                               class="hover:text-blue-600 dark:hover:text-blue-400">
                                                Email <?php if($order == 'email') echo $direction == 'ASC' ? '↑' : '↓'; ?>
                                            </a>
                                        </th>
                                        <th>
                                            <a href="?order=celular&direction=<?php echo ($order == 'celular' && $direction == 'ASC') ? 'DESC' : 'ASC'; ?>&search=<?php echo urlencode($search); ?>" 
                                               class="hover:text-blue-600 dark:hover:text-blue-400">
                                                Celular <?php if($order == 'celular') echo $direction == 'ASC' ? '↑' : '↓'; ?>
                                            </a>
                                        </th>
                                        <th>
                                            <a href="?order=saldo&direction=<?php echo ($order == 'saldo' && $direction == 'ASC') ? 'DESC' : 'ASC'; ?>&search=<?php echo urlencode($search); ?>" 
                                               class="hover:text-blue-600 dark:hover:text-blue-400">
                                                Saldo <?php if($order == 'saldo') echo $direction == 'ASC' ? '↑' : '↓'; ?>
                                            </a>
                                        </th>
                                        <th>
                                            <a href="?order=data_registro&direction=<?php echo ($order == 'data_registro' && $direction == 'ASC') ? 'DESC' : 'ASC'; ?>&search=<?php echo urlencode($search); ?>" 
                                               class="hover:text-blue-600 dark:hover:text-blue-400">
                                                Data Registro <?php if($order == 'data_registro') echo $direction == 'ASC' ? '↑' : '↓'; ?>
                                            </a>
                                        </th>
                                        <th>
                                            <a href="?order=total_aberto&direction=<?php echo ($order == 'total_aberto' && $direction == 'ASC') ? 'DESC' : 'ASC'; ?>&search=<?php echo urlencode($search); ?>" 
                                               class="hover:text-blue-600 dark:hover:text-blue-400">
                                                Total Aberto <?php if($order == 'total_aberto') echo $direction == 'ASC' ? '↑' : '↓'; ?>
                                            </a>
                                        </th>
                                        <th>Ações</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($usuarios)): ?>
                                        <tr>
                                            <td colspan="8" class="text-center py-8 text-gray-500">
                                                Nenhum usuário encontrado.
                                            </td>
                                        </tr>
                                    <?php else: ?>
                                        <?php foreach ($usuarios as $index => $usuario): ?>
                                            <tr class="group text-xs border-b border-black/20 dark:border-white/5 hover:bg-gray-50 dark:hover:bg-gray-800/50">
                                                <td class="whitespace-nowrap">
                                                    <div class="flex items-center">
                                                        <input id="user<?php echo $usuario['id']; ?>" name="selected_users[]" value="<?php echo $usuario['id']; ?>" type="checkbox"
                                                            class="h-3 w-3 rounded border-0 border-black/20 group-hover:border checked:border text-black dark:bg-transparent dark:border-white/20 focus:ring-0 focus:ring-offset-0 focus:shadow-none focus:outline-0">
                                                        <label for="user<?php echo $usuario['id']; ?>" class="ml-1.5 block">#<?php echo str_pad($usuario['id'], 6, '0', STR_PAD_LEFT); ?></label>
                                                    </div>
                                                </td>
                                                <td class="whitespace-nowrap min-w-[150px]">
                                                    <div class="flex items-center gap-2">
                                                        <div class="w-6 h-6 flex-none rounded-full bg-gradient-to-r from-blue-500 to-purple-600 flex items-center justify-center text-white text-xs font-semibold">
                                                            <?php echo strtoupper(substr($usuario['usuario'], 0, 1)); ?>
                                                        </div>
                                                        <div>
                                                            <p class="flex-1 font-medium"><?php echo htmlspecialchars($usuario['usuario']); ?></p>
                                                            <?php if (!empty($usuario['cpf'])): ?>
                                                                <p class="text-xs text-gray-500">CPF: <?php echo htmlspecialchars($usuario['cpf']); ?></p>
                                                            <?php endif; ?>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td class="whitespace-nowrap min-w-[180px]">
                                                    <p class="text-sm"><?php echo htmlspecialchars($usuario['email']); ?></p>
                                                    <?php if (!empty($usuario['codigo_convite'])): ?>
                                                        <p class="text-xs text-gray-500">Código: <?php echo htmlspecialchars($usuario['codigo_convite']); ?></p>
                                                    <?php endif; ?>
                                                </td>
                                                <td class="whitespace-nowrap">
                                                    <p><?php echo htmlspecialchars($usuario['celular']); ?></p>
                                                </td>
                                                <td class="whitespace-nowrap">
                                                    <span class="px-2 py-1 text-xs font-medium <?php echo $usuario['saldo'] > 0 ? 'text-green-800 dark:/20 dark:text-green-400' : 'text-gray-800 dark:bg-gray-900/20 dark:text-gray-400'; ?>">
                                                        R$ <?php echo number_format($usuario['saldo'], 2, ',', '.'); ?>
                                                    </span>
                                                </td>
                                                <td class="whitespace-nowrap">
                                                    <div class="flex items-center gap-1">
                                                        <svg width="16" height="16" viewBox="0 0 16 16" fill="none"
                                                            xmlns="http://www.w3.org/2000/svg">
                                                            <path fill-rule="evenodd" clip-rule="evenodd"
                                                                d="M10.5 2V1.5C10.5 1.22386 10.7239 1 11 1C11.2761 1 11.5 1.22386 11.5 1.5V2H13C13 2 13.4142 2 13.7071 2.29289C13.7071 2.29289 14 2.58579 14 3V13C14 13 14 13.4142 13.7071 13.7071C13.7071 13.7071 13.4142 14 13 14H3C3 14 2.58579 14 2.29289 13.7071C2.29289 13.7071 2 13.4142 2 13V3C2 3 2 2.58579 2.29289 2.29289C2.29289 2.29289 2.58579 2 3 2H4.5V1.5C4.5 1.22386 4.72386 1 5 1C5.27614 1 5.5 1.22386 5.5 1.5V2H10.5ZM3 6V13H13V6H3ZM13 5H3V3H4.5V3.5C4.5 3.77614 4.72386 4 5 4C5.27614 4 5.5 3.77614 5.5 3.5V3H10.5V3.5C10.5 3.77614 10.7239 4 11 4C11.2761 4 11.5 3.77614 11.5 3.5V3H13V5Z"
                                                                fill="currentColor" fill-opacity="0.4"></path>
                                                        </svg>
                                                        <p class="text-xs"><?php echo date('d/m/Y H:i', strtotime($usuario['data_registro'])); ?></p>
                                                    </div>
                                                </td>
                                                <td class="whitespace-nowrap">
                                                    <span class="px-2 py-1 text-xs font-medium <?php echo $usuario['total_aberto'] > 0 ? 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400' : 'text-gray-800 dark:bg-gray-900/20 dark:text-gray-400'; ?>">
                                                        R$ <?php echo number_format($usuario['total_aberto'], 2, ',', '.'); ?>
                                                    </span>
                                                </td>
                                                <td>
                                                    <div class="flex items-center gap-1">
                                                        <button type="button" onclick="editUser(<?php echo $usuario['id']; ?>)"
                                                            class="p-1 text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                                                            title="Editar usuário">
                                                            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"
                                                                xmlns="http://www.w3.org/2000/svg">
                                                                <path d="M8 12H14M2 12H6M8 12V8L12 4L14 6L10 10H8V12Z"
                                                                    stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
                                                            </svg>
                                                        </button>
                                                        <button type="button" onclick="viewUser(<?php echo $usuario['id']; ?>)"
                                                            class="p-1 text-green-600 hover:text-green-800 dark:text-green-400 dark:hover:text-green-300"
                                                            title="Ver detalhes">
                                                            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"
                                                                xmlns="http://www.w3.org/2000/svg">
                                                                <path d="M1 8s3-5 7-5 7 5 7 5-3 5-7 5-7-5-7-5z" 
                                                                    stroke="currentColor" stroke-width="1.5"/>
                                                                <circle cx="8" cy="8" r="2" 
                                                                    stroke="currentColor" stroke-width="1.5"/>
                                                            </svg>
                                                        </button>
                                                        <button type="button" onclick="deleteUser(<?php echo $usuario['id']; ?>)"
                                                            class="p-1 text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300"
                                                            title="Excluir usuário">
                                                            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"
                                                                xmlns="http://www.w3.org/2000/svg">
                                                                <path d="M6 2L10 2M2 4H14M12 4L11.5 12H4.5L4 4M7 7V10M9 7V10"
                                                                    stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
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

                        <!-- Paginação -->
                        <?php if ($total_pages > 1): ?>
                            <div class="flex items-center justify-between mt-4">
                                <div class="text-sm text-gray-500">
                                    Mostrando <?php echo $offset + 1; ?> a <?php echo min($offset + $limit, $total_records); ?> de <?php echo $total_records; ?> usuários
                                </div>
                                <div class="flex items-center gap-2">
                                    <?php if ($page > 1): ?>
                                        <a href="?page=<?php echo $page - 1; ?>&order=<?php echo $order; ?>&direction=<?php echo $direction; ?>&search=<?php echo urlencode($search); ?>" 
                                           class="px-3 py-1 bg-gray-200 dark:bg-gray-700 rounded hover:bg-gray-300 dark:hover:bg-gray-600">
                                            Anterior
                                        </a>
                                    <?php endif; ?>
                                    
                                    <?php
                                    $start_page = max(1, $page - 2);
                                    $end_page = min($total_pages, $page + 2);
                                    
                                    for ($i = $start_page; $i <= $end_page; $i++): ?>
                                        <a href="?page=<?php echo $i; ?>&order=<?php echo $order; ?>&direction=<?php echo $direction; ?>&search=<?php echo urlencode($search); ?>" 
                                           class="px-3 py-1 rounded <?php echo $i == $page ? 'bg-blue-600 text-white' : 'bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600'; ?>">
                                            <?php echo $i; ?>
                                        </a>
                                    <?php endfor; ?>
                                    
                                    <?php if ($page < $total_pages): ?>
                                        <a href="?page=<?php echo $page + 1; ?>&order=<?php echo $order; ?>&direction=<?php echo $direction; ?>&search=<?php echo urlencode($search); ?>" 
                                           class="px-3 py-1 bg-gray-200 dark:bg-gray-700 rounded hover:bg-gray-300 dark:hover:bg-gray-600">
                                            Próxima
                                        </a>
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php endif; ?>
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
            selectedCheckboxes.forEach(function(checkbox) {
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
        document.getElementById('all')?.addEventListener('change', function() {
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
        document.addEventListener('DOMContentLoaded', function() {
            const checkboxes = document.querySelectorAll('input[name="selected_users[]"]');
            checkboxes.forEach(function(checkbox) {
                checkbox.addEventListener('change', updateBulkDeleteButton);
            });
        });
    </script>

</body>

</html>