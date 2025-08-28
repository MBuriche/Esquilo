<?php
// admin-usuarios.php
ini_set('display_errors', 0);
error_reporting(E_ALL);
session_start();
include_once "services/database.php";
include_once 'logs/registrar_logs.php';
include_once "services/funcao.php";
include_once "services/crud.php";
include_once "services/crud-adm.php";
include_once 'services/checa_login_adm.php';
include_once "services/CSRF_Protect.php";
$csrf = new CSRF_Protect();
checa_login_adm();
if ($_SESSION['data_adm']['status'] != '1') {
    echo "<script>setTimeout(function() { window.location.href = 'bloqueado.php'; }, 0);</script>";
    exit();
}
if (!admin_has_permission('gerenciar_admins')) {
    include 'partes/sem-permissao.php';
    exit;
}
// Funções auxiliares para CRUD (simplificadas)
function get_admins($mysqli, $order = 'id', $direction = 'DESC', $search = '', $limit = 20, $offset = 0) {
    $order = in_array($order, ['id', 'nome', 'email', 'nivel', 'status']) ? $order : 'id';
    $direction = strtoupper($direction) === 'ASC' ? 'ASC' : 'DESC';
    $where = '';
    $params = [];
    $types = '';
    if (!empty($search)) {
        $where = "WHERE nome LIKE ? OR email LIKE ?";
        $search_param = "%{$search}%";
        $params = [$search_param, $search_param];
        $types = 'ss';
    }
    $sql = "SELECT * FROM admin_users $where ORDER BY $order $direction LIMIT ? OFFSET ?";
    $params[] = $limit;
    $params[] = $offset;
    $types .= 'ii';
    $stmt = $mysqli->prepare($sql);
    $stmt->bind_param($types, ...$params);
    $stmt->execute();
    $res = $stmt->get_result();
    $admins = $res ? $res->fetch_all(MYSQLI_ASSOC) : [];
    $stmt->close();
    return $admins;
}
function count_admins($mysqli, $search = '') {
    $where = '';
    $params = [];
    $types = '';
    if (!empty($search)) {
        $where = "WHERE nome LIKE ? OR email LIKE ?";
        $search_param = "%{$search}%";
        $params = [$search_param, $search_param];
        $types = 'ss';
    }
    $sql = "SELECT COUNT(*) as total FROM admin_users $where";
    $stmt = $mysqli->prepare($sql);
    if (!empty($params)) $stmt->bind_param($types, ...$params);
    $stmt->execute();
    $res = $stmt->get_result();
    $total = $res ? $res->fetch_assoc()['total'] : 0;
    $stmt->close();
    return $total;
}
$order = $_GET['order'] ?? 'id';
$direction = $_GET['direction'] ?? 'DESC';
$search = $_GET['search'] ?? '';
$limit = $_GET['limit'] ?? 20;
$page = $_GET['page'] ?? 1;
$offset = ($page - 1) * $limit;
$total_records = count_admins($mysqli, $search);
$total_pages = ceil($total_records / $limit);
$admins = get_admins($mysqli, $order, $direction, $search, $limit, $offset);

// Lista de permissões disponíveis
$permissoes_disponiveis = [
    'gerenciar_usuarios' => 'Gerenciar Usuários',
    'ver_relatorios' => 'Ver Relatórios',
    'editar_configuracoes' => 'Editar Configurações',
    'gerenciar_admins' => 'Gerenciar Administradores',
    'ver_financeiro' => 'Ver Financeiro',
    'acessar_dashboard' => 'Acessar Dashboard',
];

// Função para buscar dados do admin e permissões via AJAX
if (isset($_GET['get_admin']) && is_numeric($_GET['get_admin'])) {
    header('Content-Type: application/json');
    $id = (int)$_GET['get_admin'];
    $stmt = $mysqli->prepare("SELECT id, nome, email, nivel, status FROM admin_users WHERE id = ?");
    $stmt->bind_param('i', $id);
    $stmt->execute();
    $admin = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    $perms = [];
    $perm_stmt = $mysqli->prepare("SELECT permission FROM admin_permissions WHERE admin_id = ?");
    $perm_stmt->bind_param('i', $id);
    $perm_stmt->execute();
    $perm_result = $perm_stmt->get_result();
    while ($row = $perm_result->fetch_assoc()) $perms[] = $row['permission'];
    $perm_stmt->close();
    echo json_encode(['admin' => $admin, 'permissoes' => $perms]);
    exit;
}
// Processamento AJAX para editar admin
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['edit_admin_ajax'])) {
    header('Content-Type: application/json');
    $id = (int)$_POST['id'];
    $nome = trim($_POST['nome']);
    $email = trim($_POST['email']);
    $nivel = (int)$_POST['nivel'];
    $status = (int)$_POST['status'];
    $senha = trim($_POST['senha'] ?? '');
    $senha_saque = trim($_POST['senha_saque'] ?? '');
    $permissoes = $_POST['permissoes'] ?? [];
    $erros = [];
    if (empty($nome) || strlen($nome) < 3) $erros[] = 'Nome inválido';
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) $erros[] = 'Email inválido';
    // Verificar se email já existe para outro admin
    $stmt = $mysqli->prepare("SELECT id FROM admin_users WHERE email = ? AND id != ?");
    $stmt->bind_param('si', $email, $id);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows > 0) $erros[] = 'Email já cadastrado';
    $stmt->close();
    if (empty($erros)) {
        if (!empty($senha)) {
            if (strlen($senha) < 6) $erros[] = 'Senha deve ter pelo menos 6 caracteres';
        }
        if (!empty($senha_saque)) {
            if (strlen($senha_saque) < 6) $erros[] = 'Senha de saque deve ter pelo menos 6 caracteres';
        }
    }
    

    

    if (!empty($erros)) {
        echo json_encode(['success' => false, 'message' => implode(', ', $erros)]); exit;
    }
    // Atualizar admin
    $senha_hash = null;
    $senha_saque_hash = null;
    
    // Verificar se os campos não estão vazios (após trim)
    $tem_senha = !empty($senha);
    $tem_senha_saque = !empty($senha_saque);
    
    if ($tem_senha) {
        $senha_hash = password_hash($senha, PASSWORD_DEFAULT);
    }
    if ($tem_senha_saque) {
        $senha_saque_hash = password_hash($senha_saque, PASSWORD_DEFAULT);
    }
    
    if ($tem_senha && $tem_senha_saque) {
        $stmt = $mysqli->prepare("UPDATE admin_users SET nome=?, email=?, nivel=?, status=?, senha=?, senha_saque=? WHERE id=?");
        $stmt->bind_param('ssiiisi', $nome, $email, $nivel, $status, $senha_hash, $senha_saque_hash, $id);
    } elseif ($tem_senha) {
        $stmt = $mysqli->prepare("UPDATE admin_users SET nome=?, email=?, nivel=?, status=?, senha=? WHERE id=?");
        $stmt->bind_param('ssiiii', $nome, $email, $nivel, $status, $senha_hash, $id);
    } elseif ($tem_senha_saque) {
        $stmt = $mysqli->prepare("UPDATE admin_users SET nome=?, email=?, nivel=?, status=?, senha_saque=? WHERE id=?");
        $stmt->bind_param('ssiiis', $nome, $email, $nivel, $status, $senha_saque_hash, $id);
    } else {
        $stmt = $mysqli->prepare("UPDATE admin_users SET nome=?, email=?, nivel=?, status=? WHERE id=?");
        $stmt->bind_param('ssiii', $nome, $email, $nivel, $status, $id);
    }
    $ok = $stmt->execute();
    $stmt->close();
    // Atualizar permissões
    $mysqli->query("DELETE FROM admin_permissions WHERE admin_id = $id");
    if (!empty($permissoes)) {
        $perm_stmt = $mysqli->prepare("INSERT INTO admin_permissions (admin_id, permission) VALUES (?, ?)");
        foreach ($permissoes as $perm) {
            $perm_stmt->bind_param('is', $id, $perm);
            $perm_stmt->execute();
        }
        $perm_stmt->close();
    }
    echo json_encode(['success' => $ok, 'message' => $ok ? 'Administrador atualizado com sucesso!' : 'Erro ao atualizar administrador']);
    exit;
}
// Processamento para adicionar novo admin (agora com permissões)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['nome'], $_POST['email'], $_POST['senha'], $_POST['nivel']) && !isset($_POST['bulk_delete'])) {
    if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
        header('Content-Type: application/json');
    }
    $nome = trim($_POST['nome']);
    $email = trim($_POST['email']);
    $senha = trim($_POST['senha']);
    $senha_saque = trim($_POST['senha_saque'] ?? '');
    $nivel = (int)$_POST['nivel'];
    $permissoes = $_POST['permissoes'] ?? [];
    $erros = [];
    if (empty($nome) || strlen($nome) < 3) $erros[] = 'Nome inválido';
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) $erros[] = 'Email inválido';
    if (empty($senha) || strlen($senha) < 6) $erros[] = 'Senha deve ter pelo menos 6 caracteres';
    if (!empty($senha_saque) && strlen($senha_saque) < 6) $erros[] = 'Senha de saque deve ter pelo menos 6 caracteres';
    // Verificar se email já existe
    $stmt = $mysqli->prepare("SELECT id FROM admin_users WHERE email = ?");
    $stmt->bind_param('s', $email);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows > 0) $erros[] = 'Email já cadastrado';
    $stmt->close();
    if (empty($erros)) {
        $senha_hash = password_hash($senha, PASSWORD_DEFAULT);
        
        if (!empty($senha_saque)) {
            $senha_saque_hash = password_hash($senha_saque, PASSWORD_DEFAULT);
            $stmt = $mysqli->prepare("INSERT INTO admin_users (nome, email, senha, senha_saque, nivel, status) VALUES (?, ?, ?, ?, ?, 1)");
            $stmt->bind_param('ssssi', $nome, $email, $senha_hash, $senha_saque_hash, $nivel);
        } else {
            $stmt = $mysqli->prepare("INSERT INTO admin_users (nome, email, senha, nivel, status) VALUES (?, ?, ?, ?, 1)");
            $stmt->bind_param('sssi', $nome, $email, $senha_hash, $nivel);
        }
        if ($stmt->execute()) {
            $admin_id = $stmt->insert_id;
            // Inserir permissões
            if (!empty($permissoes)) {
                $perm_stmt = $mysqli->prepare("INSERT INTO admin_permissions (admin_id, permission) VALUES (?, ?)");
                foreach ($permissoes as $perm) {
                    $perm_stmt->bind_param('is', $admin_id, $perm);
                    $perm_stmt->execute();
                }
                $perm_stmt->close();
            }
            if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
                echo json_encode(['success' => true, 'message' => 'Administrador criado com sucesso!']);
                exit;
            } else {
                echo "<script>window.addEventListener('DOMContentLoaded',function(){showToast('Administrador criado com sucesso!','success');setTimeout(()=>window.location.reload(),1200);});</script>";
            }
        } else {
            $msg = 'Erro ao criar administrador: ' . $mysqli->error;
            if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
                echo json_encode(['success' => false, 'message' => $msg]);
                exit;
            } else {
                echo "<script>window.addEventListener('DOMContentLoaded',function(){showToast('$msg','error');});</script>";
            }
        }
        $stmt->close();
    } else {
        $msg = htmlspecialchars(implode(', ', $erros));
        if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
            echo json_encode(['success' => false, 'message' => $msg]);
            exit;
        } else {
            echo "<script>window.addEventListener('DOMContentLoaded',function(){showToast('$msg','error');});</script>";
        }
    }
}
// Exclusão individual ou múltipla de administradores
if (isset($_GET['delete_admin']) && is_numeric($_GET['delete_admin'])) {
    $id = (int)$_GET['delete_admin'];
    if ($id == $_SESSION['data_adm']['id']) {
        echo "<script>window.addEventListener('DOMContentLoaded',function(){showToast('Você não pode excluir seu próprio usuário!','error');});</script>";
    } else {
        $stmt = $mysqli->prepare("DELETE FROM admin_users WHERE id = ?");
        $stmt->bind_param('i', $id);
        $ok = $stmt->execute();
        $stmt->close();
        $mysqli->query("DELETE FROM admin_permissions WHERE admin_id = $id");
        echo "<script>window.addEventListener('DOMContentLoaded',function(){showToast('Administrador excluído com sucesso!','success');setTimeout(()=>window.location.href='admin-usuarios.php',1200);});</script>";
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['bulk_delete'], $_POST['selected_admins'])) {
    $ids = array_filter(array_map('intval', $_POST['selected_admins']));
    if (!empty($ids)) {
        $ids = array_diff($ids, [$_SESSION['data_adm']['id']]);
        if (!empty($ids)) {
            $in = implode(',', $ids);
            $mysqli->query("DELETE FROM admin_users WHERE id IN ($in)");
            $mysqli->query("DELETE FROM admin_permissions WHERE admin_id IN ($in)");
            echo "<script>window.addEventListener('DOMContentLoaded',function(){showToast('Administradores excluídos com sucesso!','success');setTimeout(()=>window.location.href='admin-usuarios.php',1200);});</script>";
        } else {
            echo "<script>window.addEventListener('DOMContentLoaded',function(){showToast('Você não pode excluir seu próprio usuário!','error');});</script>";
        }
    }
}
?>
<!DOCTYPE html>
<html x-data="{ showModal: false, showEdit: false }" class="" :class="[$store.app.mode]">
<?php include "partes/head.php"; ?>
<body
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
    <div class="main-container navbar-sticky flex" :class="[$store.app.navbar]">
        <!-- Start Sidebar -->
        <nav class="sidebar fixed top-0 bottom-0 z-40 flex-none w-[212px] border-r border-black/10 dark:border-white/10 transition-all duration-300">
            <div class="bg-white dark:bg-black h-full">
                <?php include 'partes/menu-lateral.php'; ?>
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
                        <p class="text-sm font-semibold">Gerenciamento de Administradores</p>
                        <p class="text-xs text-gray-500">Total de administradores: <?php echo $total_records; ?></p>
                    </div>
                    <div class="p-2 bg-lightwhite dark:bg-white/5 rounded-lg flex gap-2 justify-between mb-2">
                        <div class="flex items-center gap-4">
                            <button type="button" @click="showModal = true"
                                class="p-1 rounded-lg bg-transparent hover:bg-black/5 dark:hover:bg-white/5 transition-all duration-300"
                                title="Adicionar Admin">
                                <svg width="20" height="20" viewBox="0 0 20 20" fill="none"
                                    xmlns="http://www.w3.org/2000/svg">
                                    <path
                                        d="M10.625 4.375C10.625 4.02982 10.3452 3.75 10 3.75C9.65482 3.75 9.375 4.02982 9.375 4.375V9.375H4.375C4.02982 9.375 3.75 9.65482 3.75 10C3.75 10.3452 4.02982 10.625 4.375 10.625H9.375V15.625C9.375 15.9702 9.65482 16.25 10 16.25C10.3452 16.25 10.625 15.9702 10.625 15.625V10.625H15.625C15.9702 10.625 16.25 10.3452 16.25 10C16.25 9.65482 15.9702 9.375 15.625 9.375H10.625V4.375Z"
                                        fill="currentcolor"></path>
                                </svg>
                            </button>
                            <button type="button" onclick="confirmBulkDelete()"
                                class="p-1 rounded-lg bg-transparent hover:bg-red-100 dark:hover:bg-red-900/20 text-red-600 transition-all duration-300"
                                title="Excluir Selecionados" id="bulk-delete-btn" style="display: none;">
                                <svg width="20" height="20" viewBox="0 0 20 20" fill="none"
                                    xmlns="http://www.w3.org/2000/svg">
                                    <path d="M6 2L10 2M2 4H14M12 4L11.5 12H4.5L4 4M7 7V10M9 7V10"
                                        stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                            </button>
                        </div>
                        <form method="GET" class="md:flex items-center hidden">
                            <input type="hidden" name="order" value="<?php echo $order; ?>">
                            <input type="hidden" name="direction" value="<?php echo $direction; ?>">
                            <div class="relative w-full">
                                <div class="absolute inset-y-0 left-0 flex items-center pl-[6px] pointer-events-none">
                                    <svg class="text-black/20 dark:text-white/20" width="16" height="16"
                                        viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
                                        <path d="M14.3496 14.3563C14.2563 14.4483 14.1306 14.4999 13.9996 14.5001C13.8668 14.4995 13.7393 14.4481 13.6434 14.3563L10.9434 11.6501C9.80622 12.6052 8.34425 13.0845 6.86236 12.9879C5.38046 12.8913 3.99306 12.2264 2.98951 11.1317C1.98596 10.0371 1.44375 8.59729 1.47597 7.1126C1.50818 5.62791 2.11233 4.21298 3.16241 3.1629C4.21249 2.11282 5.62743 1.50867 7.11212 1.47645C8.59681 1.44424 10.0366 1.98645 11.1313 2.99C12.2259 3.99355 12.8908 5.38095 12.9874 6.86285C13.084 8.34474 12.6047 9.80671 11.6496 10.9438L14.3496 13.6438C14.3969 13.6904 14.4344 13.7458 14.46 13.807C14.4856 13.8681 14.4988 13.9338 14.4988 14.0001C14.4988 14.0664 14.4856 14.132 14.46 14.1932C14.4344 14.2544 14.3969 14.3098 14.3496 14.3563ZM7.24961 12.0001C8.18907 12.0001 9.10743 11.7215 9.88857 11.1996C10.6697 10.6776 11.2785 9.93579 11.638 9.06784C11.9976 8.19989 12.0916 7.24483 11.9083 6.32342C11.7251 5.40201 11.2727 4.55564 10.6084 3.89134C9.94407 3.22704 9.0977 2.77465 8.17629 2.59137C7.25488 2.40809 6.29981 2.50215 5.43186 2.86167C4.56391 3.22119 3.82206 3.83001 3.30013 4.61114C2.77819 5.39227 2.49961 6.31064 2.49961 7.2501C2.50126 8.50937 3.00224 9.71659 3.89268 10.607C4.78312 11.4975 5.99034 11.9984 7.24961 12.0001Z"
                                            fill="currentColor"></path>
                                    </svg>
                                </div>
                                <input type="text" name="search" value="<?php echo htmlspecialchars($search); ?>"
                                    class="bg-black/5 dark:bg-white/5 border-0 text-sm rounded-lg block max-w-[200px] w-full pl-[26px] p-1 focus:ring-0 focus:outline-0"
                                    placeholder="Buscar administradores..." />
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
                                            <a href="?order=nome&direction=<?php echo ($order == 'nome' && $direction == 'ASC') ? 'DESC' : 'ASC'; ?>&search=<?php echo urlencode($search); ?>"
                                               class="hover:text-blue-600 dark:hover:text-blue-400">
                                                Nome <?php if($order == 'nome') echo $direction == 'ASC' ? '↑' : '↓'; ?>
                                            </a>
                                        </th>
                                        <th>
                                            <a href="?order=email&direction=<?php echo ($order == 'email' && $direction == 'ASC') ? 'DESC' : 'ASC'; ?>&search=<?php echo urlencode($search); ?>"
                                               class="hover:text-blue-600 dark:hover:text-blue-400">
                                                Email <?php if($order == 'email') echo $direction == 'ASC' ? '↑' : '↓'; ?>
                                            </a>
                                        </th>
                                        <th>
                                            <a href="?order=nivel&direction=<?php echo ($order == 'nivel' && $direction == 'ASC') ? 'DESC' : 'ASC'; ?>&search=<?php echo urlencode($search); ?>"
                                               class="hover:text-blue-600 dark:hover:text-blue-400">
                                                Nível <?php if($order == 'nivel') echo $direction == 'ASC' ? '↑' : '↓'; ?>
                                            </a>
                                        </th>
                                        <th>
                                            <a href="?order=status&direction=<?php echo ($order == 'status' && $direction == 'ASC') ? 'DESC' : 'ASC'; ?>&search=<?php echo urlencode($search); ?>"
                                               class="hover:text-blue-600 dark:hover:text-blue-400">
                                                Status <?php if($order == 'status') echo $direction == 'ASC' ? '↑' : '↓'; ?>
                                            </a>
                                        </th>
                                        <th>Ações</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($admins)): ?>
                                        <tr>
                                            <td colspan="7" class="text-center py-8 text-gray-500">
                                                Nenhum administrador encontrado.
                                            </td>
                                        </tr>
                                    <?php else: ?>
                                        <?php foreach ($admins as $admin): ?>
                                            <tr class="group text-xs border-b border-black/20 dark:border-white/5 hover:bg-gray-50 dark:hover:bg-gray-800/50">
                                                <td class="whitespace-nowrap">
                                                    <div class="flex items-center">
                                                        <input id="admin<?php echo $admin['id']; ?>" name="selected_admins[]" value="<?php echo $admin['id']; ?>" type="checkbox"
                                                            class="h-3 w-3 rounded border-0 border-black/20 group-hover:border checked:border text-black dark:bg-transparent dark:border-white/20 focus:ring-0 focus:ring-offset-0 focus:shadow-none focus:outline-0">
                                                        <label for="admin<?php echo $admin['id']; ?>" class="ml-1.5 block">#<?php echo str_pad($admin['id'], 6, '0', STR_PAD_LEFT); ?></label>
                                                    </div>
                                                </td>
                                                <td class="whitespace-nowrap min-w-[150px]">
                                                    <div class="flex items-center gap-2">
                                                        <div class="w-6 h-6 flex-none rounded-full bg-gradient-to-r from-blue-500 to-purple-600 flex items-center justify-center text-white text-xs font-semibold">
                                                            <?php echo strtoupper(substr($admin['nome'], 0, 1)); ?>
                                                        </div>
                                                        <div>
                                                            <p class="flex-1 font-medium"><?php echo htmlspecialchars($admin['nome']); ?></p>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td class="whitespace-nowrap min-w-[180px]">
                                                    <p class="text-sm"><?php echo htmlspecialchars($admin['email']); ?></p>
                                                </td>
                                                <td class="whitespace-nowrap">
                                                    <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold <?php echo $admin['nivel'] == 1 ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300' : 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300'; ?>">
                                                        <?php echo $admin['nivel'] == 1 ? 'Super Admin' : 'Admin'; ?>
                                                    </span>
                                                </td>
                                                <td class="whitespace-nowrap">
                                                    <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold <?php echo $admin['status'] == 1 ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'; ?>">
                                                        <?php echo $admin['status'] == 1 ? 'Ativo' : 'Bloqueado'; ?>
                                                    </span>
                                                </td>
                                                <td>
                                                    <div class="flex items-center gap-1">
                                                        <button type="button" onclick="editAdmin(<?php echo $admin['id']; ?>)"
                                                            class="p-1 text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                                                            title="Editar admin">
                                                            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"
                                                                xmlns="http://www.w3.org/2000/svg">
                                                                <path d="M8 12H14M2 12H6M8 12V8L12 4L14 6L10 10H8V12Z"
                                                                    stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
                                                            </svg>
                                                        </button>
                                                        <button type="button" onclick="deleteAdmin(<?php echo $admin['id']; ?>)"
                                                            class="p-1 text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300"
                                                            title="Excluir admin">
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
                                    Mostrando <?php echo $offset + 1; ?> a <?php echo min($offset + $limit, $total_records); ?> de <?php echo $total_records; ?> administradores
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
            <!-- Modal para adicionar admin (AJAX) -->
            <div x-show="showModal" x-cloak class="fixed inset-0 bg-black/60 dark:bg-white/10 z-[999] flex items-center justify-center overflow-y-auto p-4 transition-all duration-300">
                <div @click.away="showModal = false" class="bg-white dark:bg-black relative shadow-3xl border-0 p-0 rounded-lg overflow-hidden w-full max-w-lg my-8 animate-fade-in-up">
                    <div class="flex bg-white dark:bg-black border-b border-black/10 dark:border-white/10 items-center justify-between px-5 py-4">
                        <h3 class="font-bold text-xl text-black dark:text-white">Adicionar Novo Administrador</h3>
                        <button type="button" class="text-black/40 dark:text-white/40 hover:text-black dark:hover:text-white" @click="showModal = false">
                            <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <path d="M24.2929 6.29289L6.29289 24.2929C6.10536 24.4804 6 24.7348 6 25C6 25.2652 6.10536 25.5196 6.29289 25.7071C6.48043 25.8946 6.73478 26 7 26C7.26522 26 7.51957 25.8946 7.70711 25.7071L25.7071 7.70711C25.8946 7.51957 26 7.26522 26 7C26 6.73478 25.8946 6.48043 25.7071 6.29289C25.5196 6.10536 25.2652 6 25 6C24.7348 6 24.4804 6.10536 24.2929 6.29289Z" fill="currentcolor"></path>
                                <path d="M7.70711 6.29289C7.51957 6.10536 7.26522 6 7 6C6.73478 6 6.48043 6.10536 6.29289 6.29289C6.10536 6.48043 6 6.73478 6 7C6 7.26522 6.10536 7.51957 6.29289 7.70711L24.2929 25.7071C24.48043 25.8946 24.7348 26 25 26C25.2652 26 25.51957 25.8946 25.7071 25.7071C25.8946 25.5196 26 25.2652 26 25C26 24.7348 25.8946 24.4804 25.7071 24.2929L7.70711 6.29289Z" fill="currentcolor"></path>
                            </svg>
                        </button>
                    </div>
                    <form id="form-add-admin" class="space-y-5 px-6 py-6">
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Nome *</label>
                            <input type="text" name="nome" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition" required>
                        </div>
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Email *</label>
                            <input type="email" name="email" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition" required>
                        </div>
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Senha *</label>
                            <input type="password" name="senha" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition" required>
                        </div>
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Senha de Saque (opcional)</label>
                            <input type="password" name="senha_saque" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition" placeholder="Senha para aprovar saques">
                        </div>
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Nível</label>
                            <select name="nivel" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition">
                                <option value="0">Admin</option>
                                <option value="1">Super Admin</option>
                            </select>
                        </div>
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Permissões</label>
                            <div class="flex flex-wrap gap-3">
                                <?php foreach ($permissoes_disponiveis as $key => $label): ?>
                                    <label class="inline-flex items-center gap-2 bg-white dark:bg-black border border-black/10 dark:border-white/10 rounded-full px-3 py-2 cursor-pointer transition">
                                        <input type="checkbox" name="permissoes[]" value="<?php echo $key; ?>" class="form-checkbox text-gray-400 dark:text-white rounded-full focus:ring-2 focus:ring-blue-200 dark:focus:ring-blue-900">
                                        <span class="text-sm text-black dark:text-white"><?php echo $label; ?></span>
                                    </label>
                                <?php endforeach; ?>
                            </div>
                        </div>
                        <div class="flex gap-2 pt-4 justify-end">
                            <button type="submit" class="px-4 py-2 bg-gray-900 dark:bg-white text-white dark:text-black rounded-lg hover:bg-gray-800 dark:hover:bg-gray-200 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 font-semibold transition">
                                Adicionar
                            </button>
                            <button type="button" @click="showModal = false" class="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 font-semibold transition">
                                Cancelar
                            </button>
                        </div>
                        <p class="text-xs text-gray-500">* Campos obrigatórios</p>
                    </form>
                </div>
            </div>
            <!-- Modal de edição de admin (AJAX) -->
            <div x-show="showEdit" x-cloak @abrir-modal-edicao.window="showEdit = true" class="fixed inset-0 bg-black/60 dark:bg-white/10 z-[999] flex items-center justify-center overflow-y-auto p-4 transition-all duration-300">
                <div @click.away="showEdit = false" class="bg-white dark:bg-black relative shadow-3xl border-0 p-0 rounded-lg overflow-hidden w-full max-w-lg my-8 animate-fade-in-up">
                    <div class="flex bg-white dark:bg-black border-b border-black/10 dark:border-white/10 items-center justify-between px-5 py-4">
                        <h3 class="font-bold text-xl text-black dark:text-white">Editar Administrador</h3>
                        <button type="button" class="text-black/40 dark:text-white/40 hover:text-black dark:hover:text-white" @click="showEdit = false">
                            <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <path d="M24.2929 6.29289L6.29289 24.2929C6.10536 24.4804 6 24.7348 6 25C6 25.2652 6.10536 25.5196 6.29289 25.7071C6.48043 25.8946 6.73478 26 7 26C7.26522 26 7.51957 25.8946 7.70711 25.7071L25.7071 7.70711C25.8946 7.51957 26 7.26522 26 7C26 6.73478 25.8946 6.48043 25.7071 6.29289C25.5196 6.10536 25.2652 6 25 6C24.7348 6 24.4804 6.10536 24.2929 6.29289Z" fill="currentcolor"></path>
                                <path d="M7.70711 6.29289C7.51957 6.10536 7.26522 6 7 6C6.73478 6 6.48043 6.10536 6.29289 6.29289C6.10536 6.48043 6 6.73478 6 7C6 7.26522 6.10536 7.51957 6.29289 7.70711L24.2929 25.7071C24.48043 25.8946 24.7348 26 25 26C25.2652 26 25.51957 25.8946 25.7071 25.7071C25.8946 25.5196 26 25.2652 26 25C26 24.7348 25.8946 24.4804 25.7071 24.2929L7.70711 6.29289Z" fill="currentcolor"></path>
                            </svg>
                        </button>
                    </div>
                    <form id="form-edit-admin" class="space-y-5 px-6 py-6">
                        <input type="hidden" name="id" />
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Nome *</label>
                            <input type="text" name="nome" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition" required>
                        </div>
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Email *</label>
                            <input type="email" name="email" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition" required>
                        </div>
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Nova Senha (opcional)</label>
                            <input type="password" name="senha" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition" placeholder="Deixe em branco para não alterar">
                        </div>
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Senha de Saque (opcional)</label>
                            <input type="password" name="senha_saque" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition" placeholder="Deixe em branco para não alterar">
                        </div>
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Nível</label>
                            <select name="nivel" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition">
                                <option value="0">Admin</option>
                                <option value="1">Super Admin</option>
                            </select>
                        </div>
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Status</label>
                            <select name="status" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition">
                                <option value="1">Ativo</option>
                                <option value="0">Bloqueado</option>
                            </select>
                        </div>
                        <div class="space-y-2">
                            <label class="form-label font-semibold">Permissões</label>
                            <div class="flex flex-wrap gap-3">
                                <?php foreach ($permissoes_disponiveis as $key => $label): ?>
                                    <label class="inline-flex items-center gap-2 bg-white dark:bg-black border border-black/10 dark:border-white/10 rounded-full px-3 py-2 cursor-pointer transition">
                                        <input type="checkbox" name="permissoes[]" value="<?php echo $key; ?>" class="form-checkbox text-gray-400 dark:text-white rounded-full focus:ring-2 focus:ring-blue-200 dark:focus:ring-blue-900">
                                        <span class="text-sm text-black dark:text-white"><?php echo $label; ?></span>
                                    </label>
                                <?php endforeach; ?>
                            </div>
                        </div>
                        <div class="flex gap-2 pt-4 justify-end">
                            <button type="submit" class="px-4 py-2 bg-gray-900 dark:bg-white text-white dark:text-black rounded-lg hover:bg-gray-800 dark:hover:bg-gray-200 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 font-semibold transition">
                                Salvar Alterações
                            </button>
                            <button type="button" @click="showEdit = false" class="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 font-semibold transition">
                                Cancelar
                            </button>
                        </div>
                    </form>
                </div>
            </div>
            <!-- Modal de confirmação de exclusão individual -->
            <div x-data="{ open: false, adminId: null }"
                 @delete-admin.window="open = true; adminId = $event.detail.adminId"
                 class="fixed inset-0 bg-black/60 dark:bg-white/10 z-[999] hidden overflow-y-auto"
                 :class="open && '!block'">
                <div class="flex items-center justify-center min-h-screen px-4" @click.self="open = false">
                    <div x-show="open" x-transition x-transition.duration.300 class="bg-white dark:bg-black relative shadow-3xl border-0 p-0 rounded-lg overflow-hidden w-full max-w-lg my-8">
                        <div class="flex bg-white dark:bg-black border-b border-black/10 dark:border-white/10 items-center justify-between px-5 py-3">
                            <h5 class="font-semibold text-lg">Confirmar Exclusão</h5>
                            <button type="button" class="text-black/40 dark:text-white/40 hover:text-black dark:hover:text-white" @click="open = false">
                                <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M24.2929 6.29289L6.29289 24.2929C6.10536 24.4804 6 24.7348 6 25C6 25.2652 6.10536 25.5196 6.29289 25.7071C6.48043 25.8946 6.73478 26 7 26C7.26522 26 7.51957 25.8946 7.70711 25.7071L25.7071 7.70711C25.8946 7.51957 26 7.26522 26 7C26 6.73478 25.8946 6.48043 25.7071 6.29289C25.5196 6.10536 25.2652 6 25 6C24.7348 6 24.4804 6.10536 24.2929 6.29289Z" fill="currentcolor"></path>
                                    <path d="M7.70711 6.29289C7.51957 6.10536 7.26522 6 7 6C6.73478 6 6.48043 6.10536 6.29289 6.29289C6.10536 6.48043 6 6.73478 6 7C6 7.26522 6.10536 7.51957 6.29289 7.70711L24.2929 25.7071C24.48043 25.8946 24.7348 26 25 26C25.2652 26 25.51957 25.8946 25.7071 25.7071C25.8946 25.5196 26 25.2652 26 25C26 24.7348 25.8946 24.4804 25.7071 24.2929L7.70711 6.29289Z" fill="currentcolor"></path>
                                </svg>
                            </button>
                        </div>
                        <div class="p-5">
                            <div class="text-sm text-black dark:text-white">
                                <p>Tem certeza que deseja excluir este administrador? Esta ação não pode ser desfeita.</p>
                            </div>
                            <div class="flex justify-end items-center mt-8 gap-4">
                                <button type="button" class="btn !bg-gray-500 !text-white" @click="open = false">Cancelar</button>
                                <button type="button" class="btn !bg-red-500 !text-white" @click="window.location.href = '?delete_admin=' + adminId; open = false">Excluir</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- Modal de confirmação de exclusão múltipla -->
            <div x-data="{ open: false, adminIds: [] }"
                 @delete-admins.window="open = true; adminIds = $event.detail.adminIds"
                 class="fixed inset-0 bg-black/60 dark:bg-white/10 z-[999] hidden overflow-y-auto"
                 :class="open && '!block'">
                <div class="flex items-center justify-center min-h-screen px-4" @click.self="open = false">
                    <div x-show="open" x-transition x-transition.duration.300 class="bg-white dark:bg-black relative shadow-3xl border-0 p-0 rounded-lg overflow-hidden w-full max-w-lg my-8">
                        <div class="flex bg-white dark:bg-black border-b border-black/10 dark:border-white/10 items-center justify-between px-5 py-3">
                            <h5 class="font-semibold text-lg">Confirmar Exclusão</h5>
                            <button type="button" class="text-black/40 dark:text-white/40 hover:text-black dark:hover:text-white" @click="open = false">
                                <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M24.2929 6.29289L6.29289 24.2929C6.10536 24.4804 6 24.7348 6 25C6 25.2652 6.10536 25.5196 6.29289 25.7071C6.48043 25.8946 6.73478 26 7 26C7.26522 26 7.51957 25.8946 7.70711 25.7071L25.7071 7.70711C25.8946 7.51957 26 7.26522 26 7C26 6.73478 25.8946 6.48043 25.7071 6.29289C25.5196 6.10536 25.2652 6 25 6C24.7348 6 24.4804 6.10536 24.2929 6.29289Z" fill="currentcolor"></path>
                                    <path d="M7.70711 6.29289C7.51957 6.10536 7.26522 6 7 6C6.73478 6 6.48043 6.10536 6.29289 6.29289C6.10536 6.48043 6 6.73478 6 7C6 7.26522 6.10536 7.51957 6.29289 7.70711L24.2929 25.7071C24.48043 25.8946 24.7348 26 25 26C25.2652 26 25.51957 25.8946 25.7071 25.7071C25.8946 25.5196 26 25.2652 26 25C26 24.7348 25.8946 24.4804 25.7071 24.2929L7.70711 6.29289Z" fill="currentcolor"></path>
                                </svg>
                            </button>
                        </div>
                        <div class="p-5">
                            <div class="text-sm text-black dark:text-white">
                                <p>Tem certeza que deseja excluir os administradores selecionados? Esta ação não pode ser desfeita.</p>
                            </div>
                            <div class="flex justify-end items-center mt-8 gap-4">
                                <button type="button" class="btn !bg-gray-500 !text-white" @click="open = false">Cancelar</button>
                                <button type="button" class="btn !bg-red-500 !text-white" @click="
                                    (() => {
                                        const form = document.createElement('form');
                                        form.method = 'POST';
                                        form.style.display = 'none';
                                        const bulkDeleteInput = document.createElement('input');
                                        bulkDeleteInput.type = 'hidden';
                                        bulkDeleteInput.name = 'bulk_delete';
                                        bulkDeleteInput.value = '1';
                                        form.appendChild(bulkDeleteInput);
                                        adminIds.forEach(function(id) {
                                            const hiddenInput = document.createElement('input');
                                            hiddenInput.type = 'hidden';
                                            hiddenInput.name = 'selected_admins[]';
                                            hiddenInput.value = id;
                                            form.appendChild(hiddenInput);
                                        });
                                        document.body.appendChild(form);
                                        form.submit();
                                    })();
                                    open = false;
                                ">Excluir</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <!-- Notificações -->
            <?php include 'partes/notificacao.php'; ?>
        </div>
        <!-- End Content Area -->
    </div>
    <?php include 'partes/footer.php'; ?>
    <div id="toast-area" class="fixed bottom-10 right-10 z-[999999] flex flex-col items-end gap-2 pointer-events-auto drop-shadow-2xl"></div>
    <script src="assets/js/toast.js"></script>
    <script>
        // Modal de criação via AJAX
        const formAdd = document.getElementById('form-add-admin');
        if(formAdd){
            formAdd.onsubmit = function(e){
                e.preventDefault();
                const fd = new FormData(formAdd);
                fetch('admin-usuarios.php', {method:'POST',body:fd,headers:{'X-Requested-With':'XMLHttpRequest'}})
                .then(r=>r.json())
                .then(data=>{
                    showToast(data.message, data.success?'success':'error');
                    if(data.success) setTimeout(()=>location.reload(),1200);
                });
            }
        }
        // Modal de edição via AJAX
        function editAdmin(id){
            window.dispatchEvent(new CustomEvent('abrir-modal-edicao'));
            fetch('admin-usuarios.php?get_admin='+id)
            .then(r=>r.json())
            .then(data=>{
                const f = document.getElementById('form-edit-admin');
                f.id.value = data.admin.id;
                f.nome.value = data.admin.nome;
                f.email.value = data.admin.email;
                f.nivel.value = data.admin.nivel;
                f.status.value = data.admin.status;
                f.senha.value = '';
                // Permissões
                f.querySelectorAll('input[type=checkbox][name="permissoes[]"]').forEach(cb=>{
                    cb.checked = data.permissoes.includes(cb.value);
                });
            });
        }
        document.getElementById('form-edit-admin')?.addEventListener('submit',function(e){
            e.preventDefault();
            const fd = new FormData(this);
            fd.append('edit_admin_ajax',1);
            fetch('admin-usuarios.php', {method:'POST',body:fd})
            .then(r=>r.json())
            .then(data=>{
                showToast(data.message, data.success?'success':'error');
                if(data.success) setTimeout(()=>location.reload(),1200);
            });
        });
        function deleteAdmin(adminId) {
            window.dispatchEvent(new CustomEvent('delete-admin', {
                detail: { adminId: adminId }
            }));
        }
        function toggleBlockAdmin(adminId, status) {
            // AJAX para bloquear/desbloquear admin
            fetch('admin-usuarios.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'toggle_block=1&id=' + adminId + '&status=' + status
            })
            .then(r => r.json())
            .then(data => {
                showToast(data.message, data.success ? 'success' : 'error');
                if (data.success) setTimeout(() => window.location.reload(), 1000);
            });
        }
        // Seleção múltipla
        document.getElementById('all')?.addEventListener('change', function() {
            const checkboxes = document.querySelectorAll('input[name="selected_admins[]"]');
            checkboxes.forEach(checkbox => {
                checkbox.checked = this.checked;
            });
            updateBulkDeleteButton();
        });
        function updateBulkDeleteButton() {
            const selectedCheckboxes = document.querySelectorAll('input[name="selected_admins[]"]:checked');
            const bulkDeleteBtn = document.getElementById('bulk-delete-btn');
            if (selectedCheckboxes.length > 0) {
                bulkDeleteBtn.style.display = 'block';
            } else {
                bulkDeleteBtn.style.display = 'none';
            }
        }
        document.addEventListener('DOMContentLoaded', function() {
            const checkboxes = document.querySelectorAll('input[name="selected_admins[]"]');
            checkboxes.forEach(function(checkbox) {
                checkbox.addEventListener('change', updateBulkDeleteButton);
            });
        });
        function confirmBulkDelete() {
            const selectedCheckboxes = document.querySelectorAll('input[name="selected_admins[]"]:checked');
            if (selectedCheckboxes.length === 0) {
                showToast('Selecione pelo menos um administrador para excluir.', 'error');
                return;
            }
            // Coleta os IDs selecionados
            const ids = Array.from(selectedCheckboxes).map(cb => cb.value);
            // Dispara o modal de exclusão múltipla
            window.dispatchEvent(new CustomEvent('delete-admins', {
                detail: { adminIds: ids }
            }));
        }
    </script>
    <style>
        @keyframes fade-in-up {
          from { opacity: 0; transform: translateY(40px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .animate-fade-in-up { animation: fade-in-up 0.3s cubic-bezier(.4,0,.2,1); }
    </style>
</body>
</html> 