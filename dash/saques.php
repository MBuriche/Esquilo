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

// Filtros adicionais
$status_filter = $_GET['status'] ?? '';
$order = $_GET['order'] ?? 'id';
$direction = $_GET['direction'] ?? 'DESC';
$search = $_GET['search'] ?? '';

// Validar direção
$direction = in_array(strtoupper($direction), ['ASC', 'DESC']) ? strtoupper($direction) : 'DESC';

// Validar campo de ordenação
$valid_orders = ['id', 'valor', 'status'];
$order = in_array($order, $valid_orders) ? $order : 'id';

// Construir query de busca
$where = [];
$params = [];
$types = "";
if (!empty($search)) {
    $where[] = "(transacao_id LIKE ? OR id_user LIKE ?)";
    $search_param = "%{$search}%";
    $params[] = $search_param;
    $params[] = $search_param;
    $types .= "ss";
}
// status: 0=pendente, 1=aprovado, 2=expirado/cancelado
$status_map = [
    'processamento' => 0,
    'pago' => 1,
    'expirado' => 2
];
if (!empty($status_filter) && isset($status_map[$status_filter])) {
    $where[] = "status = ?";
    $params[] = $status_map[$status_filter];
    $types .= "i";
}
$where_clause = $where ? ("WHERE " . implode(" AND ", $where)) : "";

// Query para contar total de registros
$count_sql = "SELECT COUNT(*) as total FROM solicitacao_saques $where_clause";
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

// Definir e validar $limit antes de qualquer uso
$limit = isset($_GET['limit']) ? (int) $_GET['limit'] : 20;
if ($limit <= 0)
    $limit = 20;
$page = $_GET['page'] ?? 1;
$offset = ($page - 1) * $limit;

// Query principal
$sql = "SELECT * FROM solicitacao_saques $where_clause ORDER BY $order $direction LIMIT ? OFFSET ?";
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
$historicos = $result->fetch_all(MYSQLI_ASSOC);
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
    <div>
        <!-- Start Menu Sidebar Olverlay -->
        <div x-cloak class="fixed inset-0 bg-[black]/60 z-40 lg:hidden" :class="{'hidden' : !$store.app.sidebar}"
            @click="$store.app.toggleSidebar()"></div>
        <!-- End Menu Sidebar Olverlay -->

        <!-- Start Right Sidebar Olverlay -->
        <div x-cloak class="fixed inset-0 bg-[black]/60 z-50 2xl:hidden" :class="{'hidden' : !$store.app.rightsidebar}"
            @click="$store.app.rightSidebar()"></div>
        <!-- End Right Sidebar Olverlay -->

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
                    <div x-data="{ 
                        modalSaqueOpen: false, 
                        modalSaqueId: null, 
                        modalConfirmAprovarOpen: false, 
                        modalConfirmRejeitarOpen: false, 
                        modalSenhaSaqueOpen: false, 
                        senhaSaque: '', 
                        saqueIdParaAprovar: null,
                        currentSaqueId: null,
                        
                        setSaqueId(id) {
                            this.currentSaqueId = id;
                        }
                    }">
                        <div class="p-7 min-h-[calc(100vh-145px)]">
                            <div class="px-2 py-1 mb-4">
                                <p class="text-sm font-semibold">Saques</p>
                                <p class="text-xs text-gray-500">Total de saques: <?php echo $total_records; ?></p>
                            </div>
                            <div
                                class="p-2 bg-lightwhite dark:bg-white/5 rounded-lg flex flex-col sm:flex-row gap-2 justify-between mb-2">
                                <div class="flex items-center gap-4">
                                    <!-- Filtro de status e ordenação -->
                                    <form method="GET" class="flex items-center gap-2"
                                        x-data="{ status: '<?php echo htmlspecialchars($status_filter); ?>', order: '<?php echo htmlspecialchars($order); ?>' }">
                                        <input type="hidden" name="search"
                                            value="<?php echo htmlspecialchars($search); ?>">
                                        <input type="hidden" name="order" :value="order" x-ref="orderSelect">
                                        <input type="hidden" name="direction"
                                            value="<?php echo htmlspecialchars($direction); ?>">
                                        <label class="text-sm font-semibold mr-1 text-white flex items-center gap-1">
                                            <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor"
                                                stroke-width="2" viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round"
                                                    d="M3 10h18M6 6h12M9 14h6" />
                                            </svg>
                                            Status:
                                        </label>
                                        <div class="relative">
                                            <select name="status" x-model="status"
                                                @change="order = $refs.orderSelect.value; $el.form.submit()"
                                                class="form-select bg-white/10 dark:bg-black/20 border-0 rounded-lg px-3 py-2 text-sm text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:focus:ring-blue-400 shadow-sm transition min-w-[120px] appearance-none pr-8">
                                                <option value="">Todos</option>
                                                <option value="processamento">Pendente</option>
                                                <option value="pago">Aprovado</option>
                                                <option value="expirado">Expirado</option>
                                            </select>
                                            <div
                                                class="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-3">
                                                <svg class="w-4 h-4 text-gray-300" fill="none" stroke="currentColor"
                                                    stroke-width="2" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round"
                                                        d="M19 9l-7 7-7-7" />
                                                </svg>
                                            </div>
                                        </div>
                                        <label
                                            class="text-sm font-semibold ml-4 mr-1 text-white flex items-center gap-1">
                                            <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor"
                                                stroke-width="2" viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round"
                                                    d="M3 6h18M3 12h18M3 18h18" />
                                            </svg>
                                            Ordenar por:
                                        </label>
                                        <div class="relative">
                                            <select name="order" x-ref="orderSelect" x-model="order"
                                                @change="$el.form.submit()"
                                                class="form-select bg-white/10 dark:bg-black/20 border-0 rounded-lg px-3 py-2 text-sm text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:focus:ring-blue-400 shadow-sm transition min-w-[120px] appearance-none pr-8">
                                                <option value="id">ID</option>
                                                <option value="valor">Valor</option>
                                                <option value="status">Status</option>
                                            </select>
                                            <div
                                                class="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-3">
                                                <svg class="w-4 h-4 text-gray-300" fill="none" stroke="currentColor"
                                                    stroke-width="2" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round"
                                                        d="M19 9l-7 7-7-7" />
                                                </svg>
                                            </div>
                                        </div>
                                    </form>
                                </div>
                                <!-- Formulário de busca -->
                                <form method="GET" class="md:flex items-center">
                                    <input type="hidden" name="order" value="<?php echo htmlspecialchars($order); ?>">
                                    <input type="hidden" name="direction"
                                        value="<?php echo htmlspecialchars($direction); ?>">
                                    <input type="hidden" name="status"
                                        value="<?php echo htmlspecialchars($status_filter); ?>">
                                    <label for="voice-search" class="sr-only">Search</label>
                                    <div class="relative w-full">
                                        <div
                                            class="absolute inset-y-0 left-0 flex items-center pl-[6px] pointer-events-none">
                                            <svg class="text-black/20 dark:text-white/20" width="16" height="16"
                                                viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
                                                <path
                                                    d="M14.3496 14.3563C14.2563 14.4483 14.1306 14.4999 13.9996 14.5001C13.8668 14.4995 13.7393 14.4481 13.6434 14.3563L10.9434 11.6501C9.80622 12.6052 8.34425 13.0845 6.86236 12.9879C5.38046 12.8913 3.99306 12.2264 2.98951 11.1317C1.98596 10.0371 1.44375 8.59729 1.47597 7.1126C1.50818 5.62791 2.11233 4.21298 3.16241 3.1629C4.21249 2.11282 5.62743 1.50867 7.11212 1.47645C8.59681 1.44424 10.0366 1.98645 11.1313 2.99C12.2259 3.99355 12.8908 5.38095 12.9874 6.86285C13.084 8.34474 12.6047 9.80671 11.6496 10.9438L14.3496 13.6438C14.3969 13.6904 14.4344 13.7458 14.46 13.807C14.4856 13.8681 14.4988 13.9338 14.4988 14.0001C14.4988 14.0664 14.4856 14.132 14.46 14.1932C14.4344 14.2544 14.3969 14.3098 14.3496 14.3563ZM7.24961 12.0001C8.18907 12.0001 9.10743 11.7215 9.88857 11.1996C10.6697 10.6776 11.2785 9.93579 11.638 9.06784C11.9976 8.19989 12.0916 7.24483 11.9083 6.32342C11.7251 5.40201 11.2727 4.55564 10.6084 3.89134C9.94407 3.22704 9.0977 2.77465 8.17629 2.59137C7.25488 2.40809 6.29981 2.50215 5.43186 2.86167C4.56391 3.22119 3.82206 3.83001 3.30013 4.61114C2.77819 5.39227 2.49961 6.31064 2.49961 7.2501C2.50126 8.50937 3.00224 9.71659 3.89268 10.607C4.78312 11.4975 5.99034 11.9984 7.24961 12.0001Z"
                                                    fill="currentColor"></path>
                                            </svg>
                                        </div>
                                        <input type="text" name="search"
                                            value="<?php echo htmlspecialchars($search); ?>"
                                            class="bg-black/5 dark:bg-white/5 border-0 text-sm rounded-lg block max-w-[200px] w-full pl-[26px] p-1 focus:ring-0 focus:outline-0"
                                            placeholder="Buscar transação...">
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
                                                <th>Usuário</th>
                                                <th>Transação</th>
                                                <th>Valor</th>
                                                <th>Status</th>
                                                <th>Data/Hora</th>
                                                <th></th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php if (empty($historicos)): ?>
                                                <tr>
                                                    <td colspan="7" class="text-center py-8 text-gray-500">
                                                        Nenhum histórico encontrado.
                                                    </td>
                                                </tr>
                                            <?php else: ?>
                                                <?php foreach ($historicos as $h): ?>
                                                    <tr
                                                        class="group text-xs border-b border-black/20 dark:border-white/5 hover:bg-gray-50 dark:hover:bg-gray-800/50"
                                                        data-saque-id="<?php echo $h['id']; ?>"
                                                        data-transacao-id="<?php echo htmlspecialchars($h['transacao_id']); ?>"
                                                        data-user-id="<?php echo $h['id_user']; ?>"
                                                        data-valor="<?php echo $h['valor']; ?>"
                                                        data-pix="<?php echo htmlspecialchars($h['pix']); ?>">
                                                        <td class="whitespace-nowrap">
                                                            #<?php echo str_pad($h['id'], 4, '0', STR_PAD_LEFT); ?></td>
                                                        <td class="whitespace-nowrap">
                                                            <?php
                                                            if (!empty($h['id_user'])) {
                                                                echo '<a href="usuarios.php?order=id&direction=DESC&search=' . urlencode($h['id_user']) . '" class="text-blue-600 hover:underline inline-flex items-center gap-1" target="_blank">' . $h['id_user'] . '
        <svg class="w-4 h-4 ml-1 text-gray-400 group-hover:text-blue-600 transition" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M18 13V19A2 2 0 0 1 16 21H5A2 2 0 0 1 3 19V8A2 2 0 0 1 5 6H11"/><path stroke-linecap="round" stroke-linejoin="round" d="M15 3H21V9"/><path stroke-linecap="round" stroke-linejoin="round" d="M10 14L21 3"/></svg>';
                                                                echo '</a>';
                                                            } else {
                                                                echo $h['id_user'];
                                                            }
                                                            ?>
                                                        </td>
                                                        <td class="whitespace-nowrap">
                                                            <?php echo htmlspecialchars($h['transacao_id']); ?>
                                                        </td>
                                                        <td class="whitespace-nowrap">R$
                                                            <?php echo number_format($h['valor'], 2, ',', '.'); ?>
                                                        </td>
                                                        <td class="whitespace-nowrap">
                                                            <?php
                                                            if ($h['status'] == 0) {
                                                                echo '<span class="px-2 py-1 text-xs font-medium bg-lightyellow-100 text-lightyellow dark:bg-lightyellow-900/20 dark:text-lightyellow rounded flex items-center gap-1">Pendente';
                                                                echo '</span>';
                                                            } elseif ($h['status'] == 1) {
                                                                echo '<span class="px-2 py-1 text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400 rounded">Pago</span>';
                                                            } elseif ($h['status'] == 2) {
                                                                echo '<span class="px-2 py-1 text-xs font-medium bg-lightred-100 text-lightred dark:bg-red-900/20 dark:text-red-400 rounded">Cancelado</span>';
                                                            } else {
                                                                echo '<span class="px-2 py-1 text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-400 rounded">Outro</span>';
                                                            }
                                                            ?>
                                                        </td>
                                                        <td class="whitespace-nowrap text-xs">
                                                            <?php echo date('d/m/Y H:i', strtotime($h['data_registro'])); ?>
                                                        </td>
                                                        <?php if ($h['status'] == 0): ?>
                                                            <td class="whitespace-nowrap text-center">
                                                                <button type="button"
                                                                    @click="modalSaqueId = <?php echo $h['id']; ?>; setSaqueId(<?php echo $h['id']; ?>); modalSaqueOpen = true"
                                                                    class="group p-0 m-0 bg-transparent border-0 cursor-pointer focus:outline-none">
                                                                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"
                                                                        fill="currentColor" viewBox="0 0 256 256"
                                                                        class="transition group-hover:scale-110">
                                                                        <path
                                                                            d="M224,48V208a16,16,0,0,1-16,16H136a8,8,0,0,1,0-16h72V48H48v96a8,8,0,0,1-16,0V48A16,16,0,0,1,48,32H208A16,16,0,0,1,224,48ZM125.66,154.34a8,8,0,0,0-11.32,0L64,204.69,45.66,186.34a8,8,0,0,0-11.32,11.32l24,24a8,8,0,0,0,11.32,0l56-56A8,8,0,0,0,125.66,154.34Z">
                                                                        </path>
                                                                    </svg>
                                                                </button>
                                                            </td>
                                                        <?php else: ?>
                                                            <td class="whitespace-nowrap text-center"></td>
                                                        <?php endif; ?>
                                                    </tr>
                                                <?php endforeach; ?>
                                            <?php endif; ?>
                                        </tbody>
                                    </table>
                                </div>

                                <?php
                                // Função para buscar nome do usuário pelo id_user (ajuste conforme seu sistema)
                                function get_nome_usuario($id_user, $mysqli)
                                {
                                    $stmt = $mysqli->prepare("SELECT usuario FROM usuarios WHERE id = ? LIMIT 1");
                                    $stmt->bind_param("i", $id_user);
                                    $stmt->execute();
                                    $result = $stmt->get_result();
                                    $row = $result->fetch_assoc();
                                    $stmt->close();
                                    return $row ? $row['usuario'] : '';
                                }
                                ?>
                                <!-- Modal de saque -->
                                <div x-show="modalSaqueOpen" x-transition x-transition.duration.300
                                    class="fixed inset-0 z-[99999] flex items-center justify-center bg-black/40 backdrop-blur-sm transition-all duration-200"
                                    @keydown.window.escape="modalSaqueOpen = false">
                                    <div
                                        class="bg-white dark:bg-black rounded-xl shadow-2xl w-full max-w-md mx-2 animate-fade-in-up border border-black/10 dark:border-white/10 relative">
                                        <div
                                            class="px-6 py-4 border-b border-black/10 dark:border-white/10 flex items-center justify-between">
                                            <h2 class="text-lg font-semibold text-black dark:text-white">Detalhes do
                                                Saque</h2>
                                            <button @click="modalSaqueOpen = false"
                                                class="text-gray-400 hover:text-black dark:hover:text-white transition"><svg
                                                    class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2"
                                                    viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round"
                                                        d="M6 18L18 6M6 6l12 12" />
                                                </svg></button>
                                        </div>
                                        <div class="px-6 py-4 space-y-4">
                                            <?php foreach ($historicos as $h): ?>
                                                <div x-show="modalSaqueId == <?php echo $h['id']; ?>" x-transition
                                                    x-transition.duration.200>
                                                    <div class="space-y-3">
                                                        <div class="flex flex-col gap-1">
                                                            <span
                                                                class="text-xs text-gray-500 dark:text-gray-400">Usuário</span>
                                                            <div class="flex items-center gap-2">
                                                                <span
                                                                    class="font-semibold text-black dark:text-white">#<?php echo $h['id_user']; ?></span>
                                                                <a href="usuarios.php?order=id&direction=DESC&search=<?php echo urlencode($h['id_user']); ?>"
                                                                    target="_blank"
                                                                    class="text-blue-600 dark:text-blue-400 hover:underline text-sm flex items-center gap-1">
                                                                    <?php echo htmlspecialchars(get_nome_usuario($h['id_user'], $mysqli)); ?>
                                                                    <svg class="w-4 h-4 ml-1" fill="none"
                                                                        stroke="currentColor" stroke-width="2"
                                                                        viewBox="0 0 24 24">
                                                                        <path stroke-linecap="round" stroke-linejoin="round"
                                                                            d="M18 13V19A2 2 0 0 1 16 21H5A2 2 0 0 1 3 19V8A2 2 0 0 1 5 6H11" />
                                                                        <path stroke-linecap="round" stroke-linejoin="round"
                                                                            d="M15 3H21V9" />
                                                                        <path stroke-linecap="round" stroke-linejoin="round"
                                                                            d="M10 14L21 3" />
                                                                    </svg>
                                                                </a>
                                                            </div>
                                                        </div>
                                                        <div class="flex flex-col gap-1">
                                                            <span
                                                                class="text-xs text-gray-500 dark:text-gray-400">Valor</span>
                                                            <span
                                                                class="font-semibold text-green-600 dark:text-green-400">R$
                                                                <?php echo number_format($h['valor'], 2, ',', '.'); ?></span>
                                                        </div>
                                                        <div class="flex flex-col gap-1">
                                                            <span class="text-xs text-gray-500 dark:text-gray-400">Chave
                                                                Pix</span>
                                                            <span
                                                                class="font-mono text-black dark:text-white break-all"><?php echo htmlspecialchars($h['pix']); ?></span>
                                                        </div>
                                                        <div class="flex flex-col gap-1">
                                                            <span
                                                                class="text-xs text-gray-500 dark:text-gray-400">Telefone</span>
                                                            <span
                                                                class="text-black dark:text-white"><?php echo htmlspecialchars($h['telefone']); ?></span>
                                                        </div>
                                                    </div>
                                                </div>
                                            <?php endforeach; ?>
                                        </div>
                                        <div
                                            class="px-6 py-3 flex flex-col sm:flex-row justify-end gap-2 border-t border-black/10 dark:border-white/10">
                                            <button @click="saqueIdParaAprovar = modalSaqueId; modalSenhaSaqueOpen = true; modalSaqueOpen = false; setSaqueId(modalSaqueId)" type="button"
                                                class="form-input px-4 py-1 rounded bg-green-600 text-white hover:bg-green-700 transition">Aprovar</button>
                                            <button @click="modalConfirmRejeitarOpen = true"
                                                type="button"
                                                class="form-input px-4 py-1 rounded bg-red-600 text-white hover:bg-red-700 transition">Rejeitar</button>
                                        </div>
                                    </div>
                                </div>
                                <!-- Modal de confirmação de aprovação -->
                                <div x-show="modalConfirmAprovarOpen" x-transition x-transition.duration.300
                                    class="fixed inset-0 bg-black/60 dark:bg-white/10 z-[999] flex items-center justify-center overflow-y-auto p-4 transition-all duration-300"
                                    @keydown.window.escape="modalConfirmAprovarOpen = false">
                                    <div class="flex items-center justify-center min-h-screen px-4 w-full"
                                        @click.self="modalConfirmAprovarOpen = false">
                                        <div
                                            class="bg-white dark:bg-black relative shadow-3xl border-0 p-0 rounded-lg overflow-hidden w-full max-w-lg my-8">
                                            <div
                                                class="flex bg-white dark:bg-black border-b border-black/10 dark:border-white/10 items-center justify-between px-5 py-3">
                                                <h5 class="font-semibold text-lg">Confirmar Aprovação</h5>
                                                <button type="button"
                                                    class="text-black/40 dark:text-white/40 hover:text-black dark:hover:text-white"
                                                    @click="modalConfirmAprovarOpen = false">
                                                    <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32"
                                                        fill="none" xmlns="http://www.w3.org/2000/svg">
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
                                                    <p>Tem certeza que deseja aprovar este saque? Esta ação não pode ser
                                                        desfeita.</p>
                                                </div>
                                                <div class="flex justify-end items-center mt-8 gap-4">
                                                    <button type="button" class="btn !bg-gray-500 !text-white"
                                                        @click="modalConfirmAprovarOpen = false">Cancelar</button>
                                                    <button type="button" class="btn !bg-green-600 !text-white"
                                                        @click="toast('Saque aprovado com sucesso!', 'success'); modalConfirmAprovarOpen = false; modalSaqueOpen = false">Aprovar</button>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                
                                <!-- Modal de senha de saque -->
                                <div x-show="modalSenhaSaqueOpen" x-transition x-transition.duration.300
                                    class="fixed inset-0 bg-black/60 dark:bg-white/10 z-[999] flex items-center justify-center overflow-y-auto p-4 transition-all duration-300"
                                    @keydown.window.escape="modalSenhaSaqueOpen = false">
                                    <div class="flex items-center justify-center min-h-screen px-4 w-full"
                                        @click.self="modalSenhaSaqueOpen = false">
                                        <div
                                            class="bg-white dark:bg-black relative shadow-3xl border-0 p-0 rounded-lg overflow-hidden w-full max-w-lg my-8">
                                            <div
                                                class="flex bg-white dark:bg-black border-b border-black/10 dark:border-white/10 items-center justify-between px-5 py-3">
                                                <h5 class="font-semibold text-lg">Senha de Saque</h5>
                                                <button type="button"
                                                    class="text-black/40 dark:text-white/40 hover:text-black dark:hover:text-white"
                                                    @click="modalSenhaSaqueOpen = false">
                                                    <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32"
                                                        fill="none" xmlns="http://www.w3.org/2000/svg">
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
                                                <div class="text-sm text-black dark:text-white mb-4">
                                                    <p>Digite sua senha de saque para aprovar este saque:</p>
                                                </div>
                                                <div class="mb-4">
                                                    <input type="password" x-model="senhaSaque" 
                                                        class="form-input w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-800 dark:text-white"
                                                        placeholder="Digite sua senha de saque"
                                                        @keyup.enter="verificarSenhaSaque()">
                                                </div>
                                                <div class="flex justify-end items-center mt-8 gap-4">
                                                    <button type="button" class="btn !bg-gray-500 !text-white"
                                                        @click="modalSenhaSaqueOpen = false; senhaSaque = ''; currentSaqueId = null">Cancelar</button>
                                                    <button type="button" class="btn !bg-green-600 !text-white"
                                                        @click="verificarSenhaSaque()">Aprovar</button>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                
                                <!-- Modal de confirmação de rejeição -->
                                <div x-show="modalConfirmRejeitarOpen" x-transition x-transition.duration.300
                                    class="fixed inset-0 bg-black/60 dark:bg-white/10 z-[999] flex items-center justify-center overflow-y-auto p-4 transition-all duration-300"
                                    @keydown.window.escape="modalConfirmRejeitarOpen = false">
                                    <div class="flex items-center justify-center min-h-screen px-4 w-full"
                                        @click.self="modalConfirmRejeitarOpen = false">
                                        <div
                                            class="bg-white dark:bg-black relative shadow-3xl border-0 p-0 rounded-lg overflow-hidden w-full max-w-lg my-8">
                                            <div
                                                class="flex bg-white dark:bg-black border-b border-black/10 dark:border-white/10 items-center justify-between px-5 py-3">
                                                <h5 class="font-semibold text-lg">Confirmar Rejeição</h5>
                                                <button type="button"
                                                    class="text-black/40 dark:text-white/40 hover:text-black dark:hover:text-white"
                                                    @click="modalConfirmRejeitarOpen = false">
                                                    <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32"
                                                        fill="none" xmlns="http://www.w3.org/2000/svg">
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
                                                    <p>Tem certeza que deseja rejeitar este saque? Esta ação não pode ser
                                                        desfeita.</p>
                                                </div>
                                                <div class="flex justify-end items-center mt-8 gap-4">
                                                    <button type="button" class="btn !bg-gray-500 !text-white"
                                                        @click="modalConfirmRejeitarOpen = false">Cancelar</button>
                                                    <button type="button" class="btn !bg-red-600 !text-white"
                                                        @click="rejeitarSaqueExterno()">Rejeitar</button>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                            </div>
                        </div>
                        <!-- Paginação -->
                        <div class="flex flex-col sm:flex-row items-center justify-between gap-2 mt-4">
                            <div class="text-sm text-gray-500">Mostrando
                                <?php echo ($total_records == 0 ? 0 : ($page - 1) * $limit + 1); ?> a
                                <?php echo min($page * $limit, $total_records); ?> de <?php echo $total_records; ?>
                                resultados
                            </div>
                            <div class="flex items-center gap-1 justify-center">
                                <a href="?page=1&limit=<?php echo $limit; ?>&order=<?php echo $order; ?>&direction=<?php echo $direction; ?>&search=<?php echo urlencode($search); ?>&status=<?php echo urlencode($status_filter); ?>"
                                    class="px-2 py-1 rounded <?php echo $page == 1 ? 'pointer-events-none opacity-50' : ''; ?>">First</a>
                                <a href="?page=<?php echo max(1, $page - 1); ?>&limit=<?php echo $limit; ?>&order=<?php echo $order; ?>&direction=<?php echo $direction; ?>&search=<?php echo urlencode($search); ?>&status=<?php echo urlencode($status_filter); ?>"
                                    class="px-2 py-1 rounded <?php echo $page == 1 ? 'pointer-events-none opacity-50' : ''; ?>">Prev</a>
                                <?php for ($i = max(1, $page - 2); $i <= min($total_pages, $page + 2); $i++): ?>
                                    <a href="?page=<?php echo $i; ?>&limit=<?php echo $limit; ?>&order=<?php echo $order; ?>&direction=<?php echo $direction; ?>&search=<?php echo urlencode($search); ?>&status=<?php echo urlencode($status_filter); ?>"
                                        class="px-2 py-1 rounded <?php echo $i == $page ? 'bg-black text-white dark:bg-white dark:text-black font-bold' : ''; ?>"><?php echo $i; ?></a>
                                <?php endfor; ?>
                                <a href="?page=<?php echo min($total_pages, $page + 1); ?>&limit=<?php echo $limit; ?>&order=<?php echo $order; ?>&direction=<?php echo $direction; ?>&search=<?php echo urlencode($search); ?>&status=<?php echo urlencode($status_filter); ?>"
                                    class="px-2 py-1 rounded <?php echo $page == $total_pages ? 'pointer-events-none opacity-50' : ''; ?>">Next</a>
                                <a href="?page=<?php echo $total_pages; ?>&limit=<?php echo $limit; ?>&order=<?php echo $order; ?>&direction=<?php echo $direction; ?>&search=<?php echo urlencode($search); ?>&status=<?php echo urlencode($status_filter); ?>"
                                    class="px-2 py-1 rounded <?php echo $page == $total_pages ? 'pointer-events-none opacity-50' : ''; ?>">Last</a>
                            </div>
                        </div>
                    </div>
                    
                    <script>
                        // Variável para controlar execução dupla de aprovação
                        let isAprovando = false;
                        
                        function aprovarSaque(saqueId) {
                            // Proteção contra execução dupla
                            if (isAprovando) {
                                console.log('Função de aprovação já em execução, ignorando...');
                                return;
                            }
                            
                            isAprovando = true;
                            
                            // Buscar o transacao_id do saque
                            const row = document.querySelector(`tr[data-saque-id="${saqueId}"]`);
                            if (!row) {
                                if (typeof toast !== 'undefined') {
                                    toast('Erro: Saque não encontrado', 'error');
                                } else {
                                    alert('Erro: Saque não encontrado');
                                }
                                isAprovando = false;
                                return;
                            }
                            
                            const transacaoId = row.getAttribute('data-transacao-id');
                            const userId = row.getAttribute('data-user-id');
                            
                            // Fazer requisição para aprovar o saque
                            fetch(`services-gateway/payment_manual.php?id=${transacaoId}&usuario=${userId}`, {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/x-www-form-urlencoded',
                                }
                            })
                            .then(response => response.json())
                            .then(data => {
                                if (data.success) {
                                    if (typeof toast !== 'undefined') {
                                        toast('Saque aprovado com sucesso!', 'success');
                                    } else {
                                        alert('Saque aprovado com sucesso!');
                                    }
                                    // Fechar modal e limpar senha
                                    const alpineElement = document.querySelector('div[x-data*="modalSaqueOpen"]');
                                    if (alpineElement) {
                                        setTimeout(() => {
                                            let alpineData = null;
                                            if (alpineElement.__x) {
                                                alpineData = alpineElement.__x.$data;
                                            } else if (alpineElement._x_dataStack) {
                                                alpineData = alpineElement._x_dataStack[0];
                                            }
                                            
                                            if (alpineData) {
                                                if (alpineData.modalSenhaSaqueOpen !== undefined) {
                                                    alpineData.modalSenhaSaqueOpen = false;
                                                }
                                                if (alpineData.senhaSaque !== undefined) {
                                                    alpineData.senhaSaque = '';
                                                }
                                            }
                                        }, 100);
                                    }
                                    // Recarregar a página após 2 segundos
                                    setTimeout(() => {
                                        window.location.reload();
                                    }, 2000);
                                } else {
                                    if (typeof toast !== 'undefined') {
                                        toast(data.message || 'Erro ao aprovar saque', 'error');
                                    } else {
                                        alert(data.message || 'Erro ao aprovar saque');
                                    }
                                }
                                isAprovando = false;
                            })
                            .catch(error => {
                                console.error('Erro:', error);
                                if (typeof toast !== 'undefined') {
                                    toast('Erro ao aprovar saque', 'error');
                                } else {
                                    alert('Erro ao aprovar saque');
                                }
                                isAprovando = false;
                            });
                        }

                        // Variável para controlar execução dupla
                        let isRejeitando = false;
                        
                        // Função para rejeitar saque externamente
                        function rejeitarSaqueExterno() {
                            // Proteção contra execução dupla
                            if (isRejeitando) {
                                console.log('Função já em execução, ignorando...');
                                return;
                            }
                            
                            isRejeitando = true;
                            
                            // Buscar o ID do saque atual do Alpine.js de forma mais segura
                            const alpineElement = document.querySelector('div[x-data*="modalSaqueOpen"]');
                            
                            // Aguardar um pouco para garantir que o Alpine.js inicializou
                            setTimeout(() => {
                                if (!alpineElement) {
                                    console.error('Erro: Elemento Alpine.js não encontrado');
                                    if (typeof toast !== 'undefined') {
                                        toast('Erro: Sistema não inicializado corretamente', 'error');
                                    } else {
                                        alert('Erro: Sistema não inicializado corretamente');
                                    }
                                    isRejeitando = false;
                                    return;
                                }
                                
                                // Tentar acessar o Alpine.js de diferentes formas
                                let alpineData = null;
                                if (alpineElement.__x) {
                                    alpineData = alpineElement.__x.$data;
                                } else if (alpineElement._x_dataStack) {
                                    alpineData = alpineElement._x_dataStack[0];
                                } else if (window.Alpine && alpineElement._x_bindings) {
                                    // Tentar acessar via Alpine global
                                    const component = window.Alpine.$data(alpineElement);
                                    if (component) {
                                        alpineData = component;
                                    }
                                }
                                
                                if (!alpineData) {
                                    console.error('Erro: Dados do Alpine.js não encontrados');
                                    if (typeof toast !== 'undefined') {
                                        toast('Erro: Sistema não inicializado corretamente', 'error');
                                    } else {
                                        alert('Erro: Sistema não inicializado corretamente');
                                    }
                                    isRejeitando = false;
                                    return;
                                }
                                
                                const currentSaqueId = alpineData.currentSaqueId;
                                
                                if (!currentSaqueId) {
                                    if (typeof toast !== 'undefined') {
                                        toast('Erro: ID do saque não encontrado', 'error');
                                    } else {
                                        alert('Erro: ID do saque não encontrado');
                                    }
                                    isRejeitando = false;
                                    return;
                                }
                                
                                // Buscar os dados do saque
                                const row = document.querySelector(`tr[data-saque-id="${currentSaqueId}"]`);
                                if (!row) {
                                    if (typeof toast !== 'undefined') {
                                        toast('Erro: Saque não encontrado', 'error');
                                    } else {
                                        alert('Erro: Saque não encontrado');
                                    }
                                    isRejeitando = false;
                                    return;
                                }
                                
                                const userId = row.getAttribute('data-user-id');
                                const valor = row.getAttribute('data-valor');
                                const pix = row.getAttribute('data-pix');
                                
                                // Buscar o email do usuário
                                fetch(`ajax/buscar_email_usuario.php?id=${userId}`)
                                .then(response => response.json())
                                .then(data => {
                                    if (data.success) {
                                        // Enviar requisição para rejeitar o saque
                                        const formData = new FormData();
                                        formData.append('att-pay', '1');
                                        formData.append('_csrf', '<?php echo $csrf->getToken(); ?>');
                                        formData.append('id_pay', currentSaqueId);
                                        formData.append('email_reprovado', data.email);
                                        formData.append('valor_reprovado', valor);
                                        
                                        fetch('ajax/recusar_saque.php', {
                                            method: 'POST',
                                            body: formData
                                        })
                                        .then(response => response.json())
                                        .then(result => {
                                            if (result.status === 'success') {
                                                if (typeof toast !== 'undefined') {
                                                    toast('Saque rejeitado com sucesso!', 'success');
                                                } else {
                                                    alert('Saque rejeitado com sucesso!');
                                                }
                                                // Fechar modais
                                                if (alpineData.modalConfirmRejeitarOpen !== undefined) {
                                                    alpineData.modalConfirmRejeitarOpen = false;
                                                }
                                                if (alpineData.modalSaqueOpen !== undefined) {
                                                    alpineData.modalSaqueOpen = false;
                                                }
                                                // Recarregar a página após 2 segundos
                                                setTimeout(() => {
                                                    window.location.reload();
                                                }, 2000);
                                            } else {
                                                if (typeof toast !== 'undefined') {
                                                    toast(result.message || 'Erro ao rejeitar saque', 'error');
                                                } else {
                                                    alert(result.message || 'Erro ao rejeitar saque');
                                                }
                                            }
                                            isRejeitando = false;
                                        })
                                        .catch(error => {
                                            console.error('Erro:', error);
                                            if (typeof toast !== 'undefined') {
                                                toast('Erro ao rejeitar saque', 'error');
                                            } else {
                                                alert('Erro ao rejeitar saque');
                                            }
                                            isRejeitando = false;
                                        });
                                    } else {
                                        if (typeof toast !== 'undefined') {
                                            toast('Erro ao buscar email do usuário', 'error');
                                        } else {
                                            alert('Erro ao buscar email do usuário');
                                        }
                                        isRejeitando = false;
                                    }
                                })
                                .catch(error => {
                                    console.error('Erro:', error);
                                    if (typeof toast !== 'undefined') {
                                        toast('Erro ao buscar email do usuário', 'error');
                                    } else {
                                        alert('Erro ao buscar email do usuário');
                                    }
                                    isRejeitando = false;
                                });
                            }, 100); // Aguardar 100ms para garantir inicialização
                        }

                        // Variável para controlar execução dupla de verificação de senha
                        let isVerificandoSenha = false;
                        
                        // Função para verificar senha de saque (mantida fora do Alpine.js para compatibilidade)
                        function verificarSenhaSaque() {
                            // Proteção contra execução dupla
                            if (isVerificandoSenha) {
                                console.log('Função de verificação de senha já em execução, ignorando...');
                                return;
                            }
                            
                            isVerificandoSenha = true;
                            
                            const senhaInput = document.querySelector('input[x-model="senhaSaque"]');
                            if (!senhaInput) {
                                if (typeof toast !== 'undefined') {
                                    toast('Erro: Campo de senha não encontrado', 'error');
                                } else {
                                    alert('Erro: Campo de senha não encontrado');
                                }
                                isVerificandoSenha = false;
                                return;
                            }
                            
                            const senha = senhaInput.value;
                            
                            if (!senha) {
                                if (typeof toast !== 'undefined') {
                                    toast('Digite a senha de saque', 'error');
                                } else {
                                    alert('Digite a senha de saque');
                                }
                                isVerificandoSenha = false;
                                return;
                            }
                            
                            // Buscar o ID do saque atual do Alpine.js
                            const alpineElement = document.querySelector('div[x-data*="modalSaqueOpen"]');
                            if (!alpineElement) {
                                console.error('Erro: Elemento Alpine.js não encontrado');
                                if (typeof toast !== 'undefined') {
                                    toast('Erro: Sistema não inicializado corretamente', 'error');
                                } else {
                                    alert('Erro: Sistema não inicializado corretamente');
                                }
                                isVerificandoSenha = false;
                                return;
                            }
                            
                            // Aguardar um pouco para garantir que o Alpine.js inicializou
                            setTimeout(() => {
                                let alpineData = null;
                                if (alpineElement.__x) {
                                    alpineData = alpineElement.__x.$data;
                                } else if (alpineElement._x_dataStack) {
                                    alpineData = alpineElement._x_dataStack[0];
                                } else if (window.Alpine && alpineElement._x_bindings) {
                                    const component = window.Alpine.$data(alpineElement);
                                    if (component) {
                                        alpineData = component;
                                    }
                                }
                                
                                if (!alpineData) {
                                    console.error('Erro: Dados do Alpine.js não encontrados');
                                    if (typeof toast !== 'undefined') {
                                        toast('Erro: Sistema não inicializado corretamente', 'error');
                                    } else {
                                        alert('Erro: Sistema não inicializado corretamente');
                                    }
                                    isVerificandoSenha = false;
                                    return;
                                }
                                
                                const currentSaqueId = alpineData.currentSaqueId;
                                
                                if (!currentSaqueId) {
                                    if (typeof toast !== 'undefined') {
                                        toast('Erro: ID do saque não encontrado', 'error');
                                    } else {
                                        alert('Erro: ID do saque não encontrado');
                                    }
                                    isVerificandoSenha = false;
                                    return;
                                }
                                
                                // Fazer requisição AJAX para verificar a senha
                                fetch('services-gateway/verificar_senha_saque.php', {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/x-www-form-urlencoded',
                                    },
                                    body: 'senha_saque=' + encodeURIComponent(senha)
                                })
                                .then(response => response.json())
                                .then(data => {
                                    if (data.success) {
                                        // Senha correta, aprovar o saque
                                        aprovarSaque(currentSaqueId);
                                    } else {
                                        if (typeof toast !== 'undefined') {
                                            toast(data.message || 'Senha de saque incorreta', 'error');
                                        } else {
                                            alert(data.message || 'Senha de saque incorreta');
                                        }
                                    }
                                    isVerificandoSenha = false;
                                })
                                .catch(error => {
                                    console.error('Erro:', error);
                                    if (typeof toast !== 'undefined') {
                                        toast('Erro ao verificar senha de saque', 'error');
                                    } else {
                                        alert('Erro ao verificar senha de saque');
                                    }
                                    isVerificandoSenha = false;
                                });
                            }, 100);
                        }
                    </script>
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
    </div>
</body>

</html>