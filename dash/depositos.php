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
    $where[] = "(transacao_id LIKE ? OR usuario LIKE ?)";
    $search_param = "%{$search}%";
    $params[] = $search_param;
    $params[] = $search_param;
    $types .= "ss";
}
if (!empty($status_filter) && in_array($status_filter, ['processamento','pago','expirado'])) {
    $where[] = "status = ?";
    $params[] = $status_filter;
    $types .= "s";
}
$where_clause = $where ? ("WHERE " . implode(" AND ", $where)) : "";

// Query para contar total de registros
$count_sql = "SELECT COUNT(*) as total FROM transacoes $where_clause";
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
$limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 20;
if ($limit <= 0) $limit = 20;
$page = $_GET['page'] ?? 1;
$offset = ($page - 1) * $limit;

// Query principal
$sql = "SELECT * FROM transacoes $where_clause ORDER BY $order $direction LIMIT ? OFFSET ?";
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
                    <div class="p-7 min-h-[calc(100vh-145px)]">
                        <div class="px-2 py-1 mb-4">
                            <p class="text-sm font-semibold">Depósitos</p>
                            <p class="text-xs text-gray-500">Total de depósitos: <?php echo $total_records; ?></p>
                        </div>
                        <div class="p-2 bg-lightwhite dark:bg-white/5 rounded-lg flex flex-col sm:flex-row gap-2 justify-between mb-2">
                            <div class="flex items-center gap-4">
                                <!-- Filtro de status e ordenação -->
                                <form method="GET" class="flex items-center gap-2" x-data="{ status: '<?php echo htmlspecialchars($status_filter); ?>', order: '<?php echo htmlspecialchars($order); ?>' }">
                                    <input type="hidden" name="search" value="<?php echo htmlspecialchars($search); ?>">
                                    <input type="hidden" name="order" :value="order" x-ref="orderSelect">
                                    <input type="hidden" name="direction" value="<?php echo htmlspecialchars($direction); ?>">
                                    <label class="text-sm font-semibold mr-1 text-white flex items-center gap-1">
                                        <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3 10h18M6 6h12M9 14h6"/></svg>
                                        Status:
                                    </label>
                                    <div class="relative">
                                        <select name="status" x-model="status" @change="order = $refs.orderSelect.value; $el.form.submit()"
                                            class="form-select bg-white/10 dark:bg-black/20 border-0 rounded-lg px-3 py-2 text-sm text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:focus:ring-blue-400 shadow-sm transition min-w-[120px] appearance-none pr-8"
                                        >
                                            <option value="">Todos</option>
                                            <option value="processamento">Pendente</option>
                                            <option value="pago">Aprovado</option>
                                            <option value="expirado">Expirado</option>
                                        </select>
                                        <div class="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-3">
                                            <svg class="w-4 h-4 text-gray-300" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7"/></svg>
                                        </div>
                                    </div>
                                    <label class="text-sm font-semibold ml-4 mr-1 text-white flex items-center gap-1">
                                        <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3 6h18M3 12h18M3 18h18"/></svg>
                                        Ordenar por:
                                    </label>
                                    <div class="relative">
                                        <select name="order" x-ref="orderSelect" x-model="order" @change="$el.form.submit()"
                                            class="form-select bg-white/10 dark:bg-black/20 border-0 rounded-lg px-3 py-2 text-sm text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:focus:ring-blue-400 shadow-sm transition min-w-[120px] appearance-none pr-8"
                                        >
                                            <option value="id">ID</option>
                                            <option value="valor">Valor</option>
                                            <option value="status">Status</option>
                                        </select>
                                        <div class="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-3">
                                            <svg class="w-4 h-4 text-gray-300" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7"/></svg>
                                        </div>
                                    </div>
                                </form>
                            </div>
                            <!-- Formulário de busca -->
                            <form method="GET" class="md:flex items-center">
                                <input type="hidden" name="order" value="<?php echo htmlspecialchars($order); ?>">
                                <input type="hidden" name="direction" value="<?php echo htmlspecialchars($direction); ?>">
                                <input type="hidden" name="status" value="<?php echo htmlspecialchars($status_filter); ?>">
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
                                                <tr class="group text-xs border-b border-black/20 dark:border-white/5 hover:bg-gray-50 dark:hover:bg-gray-800/50">
                                                    <td class="whitespace-nowrap">#<?php echo str_pad($h['id'], 4, '0', STR_PAD_LEFT); ?></td>
                                                    <td class="whitespace-nowrap">
                                                        <?php
                                                        if (!empty($h['usuario'])) {
                                                            echo '<a href="usuarios.php?order=id&direction=DESC&search=' . urlencode($h['usuario']) . '" class="text-blue-600 hover:underline inline-flex items-center gap-1" target="_blank">' . $h['usuario'] . '
        <svg class="w-4 h-4 ml-1 text-gray-400 group-hover:text-blue-600 transition" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M18 13V19A2 2 0 0 1 16 21H5A2 2 0 0 1 3 19V8A2 2 0 0 1 5 6H11"/><path stroke-linecap="round" stroke-linejoin="round" d="M15 3H21V9"/><path stroke-linecap="round" stroke-linejoin="round" d="M10 14L21 3"/></svg>';
                                                            echo '</a>';
                                                        } else {
                                                            echo $h['usuario'];
                                                        }
                                                        ?>
                                                    </td>
                                                    <td class="whitespace-nowrap"><?php echo htmlspecialchars($h['transacao_id']); ?></td>
                                                    <td class="whitespace-nowrap">R$ <?php echo number_format($h['valor'], 2, ',', '.'); ?></td>
                                                    <td class="whitespace-nowrap">
                                                        <?php if ($h['status'] == 'processamento'): ?>
                                                            <span class="px-2 py-1 text-xs font-medium bg-lightyellow-100 text-lightyellow dark:bg-lightyellow-900/20 dark:text-lightyellow rounded">Pendente</span>
                                                        <?php elseif ($h['status'] == 'pago'): ?>
                                                            <span class="px-2 py-1 text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400 rounded">Pago</span>
                                                        <?php elseif ($h['status'] == 'expirado'): ?>
                                                            <span class="px-2 py-1 text-xs font-medium bg-lightred-100 text-lightred dark:bg-red-900/20 dark:text-red-400 rounded">Cancelado</span>
                                                        <?php else: ?>
                                                            <span class="px-2 py-1 text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-400 rounded">Outro</span>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td class="whitespace-nowrap text-xs"><?php echo date('d/m/Y H:i', strtotime($h['data_registro'])); ?></td>
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
                                <a href="?page=1&limit=<?php echo $limit; ?>&order=<?php echo $order; ?>&direction=<?php echo $direction; ?>&search=<?php echo urlencode($search); ?>&status=<?php echo urlencode($status_filter); ?>" class="px-2 py-1 rounded <?php echo $page==1?'pointer-events-none opacity-50':''; ?>">First</a>
                                <a href="?page=<?php echo max(1, $page-1); ?>&limit=<?php echo $limit; ?>&order=<?php echo $order; ?>&direction=<?php echo $direction; ?>&search=<?php echo urlencode($search); ?>&status=<?php echo urlencode($status_filter); ?>" class="px-2 py-1 rounded <?php echo $page==1?'pointer-events-none opacity-50':''; ?>">Prev</a>
                                <?php for($i=max(1,$page-2);$i<=min($total_pages,$page+2);$i++): ?>
                                    <a href="?page=<?php echo $i; ?>&limit=<?php echo $limit; ?>&order=<?php echo $order; ?>&direction=<?php echo $direction; ?>&search=<?php echo urlencode($search); ?>&status=<?php echo urlencode($status_filter); ?>" class="px-2 py-1 rounded <?php echo $i==$page?'bg-black text-white dark:bg-white dark:text-black font-bold':''; ?>"><?php echo $i; ?></a>
                                <?php endfor; ?>
                                <a href="?page=<?php echo min($total_pages, $page+1); ?>&limit=<?php echo $limit; ?>&order=<?php echo $order; ?>&direction=<?php echo $direction; ?>&search=<?php echo urlencode($search); ?>&status=<?php echo urlencode($status_filter); ?>" class="px-2 py-1 rounded <?php echo $page==$total_pages?'pointer-events-none opacity-50':''; ?>">Next</a>
                                <a href="?page=<?php echo $total_pages; ?>&limit=<?php echo $limit; ?>&order=<?php echo $order; ?>&direction=<?php echo $direction; ?>&search=<?php echo urlencode($search); ?>&status=<?php echo urlencode($status_filter); ?>" class="px-2 py-1 rounded <?php echo $page==$total_pages?'pointer-events-none opacity-50':''; ?>">Last</a>
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
        function verDetalhesJogo(id) {
            alert('Funcionalidade de detalhes do jogo ainda não implementada.');
        }
        </script>
    </div>
</body>
</html>