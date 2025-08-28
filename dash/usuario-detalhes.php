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
if (!admin_has_permission('gerenciar_usuarios')) {
    include 'partes/sem-permissao.php';
    exit;
}
#======================================#
// --- INÍCIO: Endpoint para retornar saldo em tempo real ---
if (isset($_GET['get_saldo']) && $_GET['get_saldo'] == 1) {
    header('Content-Type: application/json');
    require_once "services/database.php";
    $user_id = (int) ($_GET['id'] ?? $_POST['id'] ?? 0);
    $sql = $mysqli->prepare("SELECT saldo FROM usuarios WHERE id = ?");
    $sql->bind_param("i", $user_id);
    $sql->execute();
    $sql->bind_result($saldo_atual);
    $sql->fetch();
    $sql->close();
    echo json_encode(['saldo' => $saldo_atual]);
    exit;
}
// --- FIM: Endpoint para retornar saldo em tempo real ---
#======================================#
#expulsa user
checa_login_adm();
#======================================#
//inicio do scriot expulsa usuario bloqueado
if ($_SESSION['data_adm']['status'] != '1') {
    echo "<script>setTimeout(function() { window.location.href = 'bloqueado.php'; }, 0);</script>";
    exit();
}
/// final do script --#

// Verificar se o ID foi fornecido
if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    header('Location: usuarios.php');
    exit();
}

$user_id = (int) $_GET['id'];
$action = $_GET['action'] ?? 'view';
$is_edit_mode = ($action === 'edit');

// Processar atualização do usuário
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['update_user']) && $is_edit_mode) {
    // Buscar dados atuais do usuário para preservar campos não editáveis
    $stmt = $mysqli->prepare("SELECT email, usuario, saldo, total_aberto FROM usuarios WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $stmt->bind_result($email_atual, $usuario_atual, $saldo_atual, $total_aberto_atual);
    $stmt->fetch();
    $stmt->close();
    
    // Campos editáveis do formulário
    $celular = $_POST['celular'] ?? '';
    $cpf = $_POST['cpf'] ?? '';
    $influenciador = $_POST['influenciador'] ?? 0;
    $afiliado = $_POST['afiliado'] ?? 0;
    $nova_senha = $_POST['nova_senha'] ?? '';
    $obs_admin = $_POST['obs_admin'] ?? '';
    
    // Campos de configuração de afiliados
    $cpaLvl1 = !empty($_POST['cpaLvl1']) ? floatval($_POST['cpaLvl1']) : null;
    $cpaLvl2 = !empty($_POST['cpaLvl2']) ? floatval($_POST['cpaLvl2']) : null;
    $cpaLvl3 = !empty($_POST['cpaLvl3']) ? floatval($_POST['cpaLvl3']) : null;
    $chanceCpa = !empty($_POST['chanceCpa']) ? floatval($_POST['chanceCpa']) : null;
    $revShareFalso = !empty($_POST['revShareFalso']) ? floatval($_POST['revShareFalso']) : null;
    $revShareLvl1 = !empty($_POST['revShareLvl1']) ? floatval($_POST['revShareLvl1']) : null;
    $revShareLvl2 = !empty($_POST['revShareLvl2']) ? floatval($_POST['revShareLvl2']) : null;
    $revShareLvl3 = !empty($_POST['revShareLvl3']) ? floatval($_POST['revShareLvl3']) : null;
    $minDepForCpa = !empty($_POST['minDepForCpa']) ? floatval($_POST['minDepForCpa']) : null;
    $minResgate = !empty($_POST['minResgate']) ? floatval($_POST['minResgate']) : null;
    
    // Preservar campos não editáveis
    $email = $email_atual;
    $usuario = $usuario_atual;
    $saldo = $saldo_atual;
    $total_aberto = $total_aberto_atual;

    // Preparar a query SQL baseada nos campos que serão atualizados
    $sql = "UPDATE usuarios SET email = ?, usuario = ?, celular = ?, saldo = ?, cpf = ?, total_aberto = ?, influenciador = ?, afiliado = ?, cpaLvl1 = ?, cpaLvl2 = ?, cpaLvl3 = ?, chanceCpa = ?, revShareFalso = ?, revShareLvl1 = ?, revShareLvl2 = ?, revShareLvl3 = ?, minDepForCpa = ?, minResgate = ?";
    $params = [$email, $usuario, $celular, $saldo, $cpf, $total_aberto, $influenciador, $afiliado, $cpaLvl1, $cpaLvl2, $cpaLvl3, $chanceCpa, $revShareFalso, $revShareLvl1, $revShareLvl2, $revShareLvl3, $minDepForCpa, $minResgate];
    $types = "sssdsdiidddddddddd";
    
    // Adicionar obs_admin se a coluna existir (comentado por segurança)
    // if (!empty($obs_admin)) {
    //     $sql .= ", obs_admin = ?";
    //     $params[] = $obs_admin;
    //     $types .= "s";
    // }
    
    // Se uma nova senha foi fornecida, incluí-la na atualização
    if (!empty($nova_senha)) {
        $senha_hash = password_hash($nova_senha, PASSWORD_DEFAULT);
        $sql .= ", senha = ?";
        $params[] = $senha_hash;
        $types .= "s";
    }
    
    $sql .= " WHERE id = ?";
    $params[] = $user_id;
    $types .= "i";
    
    $stmt = $mysqli->prepare($sql);
    $stmt->bind_param($types, ...$params);

    if ($stmt->execute()) {
        $success_message = "Usuário atualizado com sucesso!";
    } else {
        $error_message = "Erro ao atualizar usuário: " . $mysqli->error;
    }
    $stmt->close();
}

// --- INÍCIO: Lógica para adicionar/remover saldo via AJAX ---
if (
    $_SERVER['REQUEST_METHOD'] === 'POST' &&
    isset($_POST['ajax_saldo']) &&
    in_array($_POST['ajax_saldo'], ['add', 'remove'])
) {
    header('Content-Type: application/json');
    $valor = floatval($_POST['valor'] ?? 0);
    $tipo = $_POST['ajax_saldo'];
    if ($valor <= 0) {
        echo json_encode(['success' => false, 'message' => 'Informe um valor válido.']);
        exit;
    }
    if ($tipo === 'add') {
        $sql = $mysqli->prepare("UPDATE usuarios SET saldo = saldo + ? WHERE id = ?");
        $sql->bind_param("di", $valor, $user_id);
        if ($sql->execute()) {
            echo json_encode(['success' => true, 'message' => 'Saldo adicionado com sucesso!']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Erro ao adicionar saldo.']);
        }
        $sql->close();
    } elseif ($tipo === 'remove') {
        $sql = $mysqli->prepare("UPDATE usuarios SET saldo = saldo - ? WHERE id = ? AND saldo >= ?");
        $sql->bind_param("dii", $valor, $user_id, $valor);
        if ($sql->execute() && $sql->affected_rows > 0) {
            echo json_encode(['success' => true, 'message' => 'Saldo removido com sucesso!']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Erro ao remover saldo ou saldo insuficiente.']);
        }
        $sql->close();
    }
    exit;
}
// --- FIM: Lógica para adicionar/remover saldo via AJAX ---

// Buscar dados do usuário
$sql = "SELECT * FROM usuarios WHERE id = ?";
$stmt = $mysqli->prepare($sql);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$usuario_data = $result->fetch_assoc();
$stmt->close();

if (!$usuario_data) {
    header('Location: usuarios.php');
    exit();
}

// --- INÍCIO: Calcular porcentagem de ganho do usuário nas raspadinhas ---
$porcentagem_ganho = 0;
$stmt = $mysqli->prepare("SELECT SUM(amount_paid) AS total_pago, SUM(prize_amount) AS total_ganho FROM historico_raspadas WHERE user_id = ? AND status = 'completed'");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$stmt->bind_result($total_pago, $total_ganho);
$stmt->fetch();
$stmt->close();
if ($total_pago > 0) {
    $porcentagem_ganho = round(($total_ganho / $total_pago) * 100);
}
// --- FIM: Calcular porcentagem de ganho ---

// --- INÍCIO: Buscar históricos ---
// Depósitos
$historico_depositos = [];
// Corrigido para data_registro
$stmt = $mysqli->prepare("SELECT valor, data_registro, status FROM transacoes WHERE usuario = ? AND tipo = 'deposito' ORDER BY data_registro DESC LIMIT 20");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $historico_depositos[] = $row;
}
$stmt->close();
// Saques
$historico_saques = [];
$stmt = $mysqli->prepare("SELECT valor, data_registro, status FROM solicitacao_saques WHERE id_user = ? ORDER BY data_registro DESC LIMIT 20");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $historico_saques[] = $row;
}
$stmt->close();
// Indicados
$indicados = [];
if (!empty($usuario_data['invitation_code'])) {
    $stmt = $mysqli->prepare("SELECT id, usuario, email, data_registro FROM usuarios WHERE invitation_code = ?");
    $stmt->bind_param("s", $usuario_data['invitation_code']);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($row = $res->fetch_assoc()) {
        $indicados[] = $row;
    }
    $stmt->close();
}
// --- FIM: Buscar históricos ---

// --- INÍCIO: Endpoints AJAX para atualizar tabelas em tempo real ---
if (isset($_GET['get_tabela']) && $_GET['get_tabela'] === 'depositos') {
    ob_start();
    ?>
    <?php if (count($historico_depositos) > 0): ?>
        <div class="table-responsive">
            <table class="table-hover">
                <thead>
                    <tr>
                        <th>Valor</th>
                        <th>Data/Hora</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($historico_depositos as $dep): ?>
                        <tr>
                            <td>R$ <?php echo number_format($dep['valor'], 2, ',', '.'); ?></td>
                            <td><?php echo date('d/m/Y H:i', strtotime($dep['data_registro'])); ?></td>
                            <td><?php echo ucfirst($dep['status']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php else: ?>
        <p class="text-gray-500 dark:text-gray-400">Nenhum depósito encontrado para este usuário.</p>
    <?php endif; ?>
    <?php
    echo ob_get_clean();
    exit;
}
if (isset($_GET['get_tabela']) && $_GET['get_tabela'] === 'saques') {
    ob_start();
    ?>
    <?php if (count($historico_saques) > 0): ?>
        <div class="table-responsive">
            <table class="table-hover">
                <thead>
                    <tr>
                        <th>Valor</th>
                        <th>Data/Hora</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($historico_saques as $saq): ?>
                        <tr>
                            <td>R$ <?php echo number_format($saq['valor'], 2, ',', '.'); ?></td>
                            <td><?php echo date('d/m/Y H:i', strtotime($saq['data_registro'])); ?></td>
                            <td><?php echo $saq['status'] == 1 ? 'Pago' : ($saq['status'] == 0 ? 'Pendente' : 'Outro'); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php else: ?>
        <p class="text-gray-500 dark:text-gray-400">Nenhum saque encontrado para este usuário.</p>
    <?php endif; ?>
    <?php
    echo ob_get_clean();
    exit;
}
if (isset($_GET['get_tabela']) && $_GET['get_tabela'] === 'indicados') {
    ob_start();
    ?>
    <?php if (count($indicados) > 0): ?>
        <div class="table-responsive">
            <table class="table-hover">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Usuário</th>
                        <th>Email</th>
                        <th>Data de Registro</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($indicados as $ind): ?>
                        <tr>
                            <td><?php echo $ind['id']; ?></td>
                            <td><?php echo htmlspecialchars($ind['usuario']); ?></td>
                            <td><?php echo htmlspecialchars($ind['email']); ?></td>
                            <td><?php echo date('d/m/Y H:i', strtotime($ind['data_registro'])); ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php else: ?>
        <p class="text-gray-500 dark:text-gray-400">Nenhum indicado encontrado para este usuário.</p>
    <?php endif; ?>
    <?php
    echo ob_get_clean();
    exit;
}
// --- FIM: Endpoints AJAX para atualizar tabelas em tempo real ---

// --- INÍCIO: Buscar totais de recargas e retiradas ---
$total_recargas = 0;
$qtd_recargas = 0;
$stmt = $mysqli->prepare("SELECT COUNT(*), SUM(valor) FROM transacoes WHERE usuario = ? AND tipo = 'deposito'");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$stmt->bind_result($qtd_recargas, $total_recargas);
$stmt->fetch();
$stmt->close();
if (!$total_recargas)
    $total_recargas = 0;
if (!$qtd_recargas)
    $qtd_recargas = 0;

$total_retiradas = 0;
$qtd_retiradas = 0;
$stmt = $mysqli->prepare("SELECT COUNT(*), SUM(valor) FROM solicitacao_saques WHERE id_user = ? AND status = 1");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$stmt->bind_result($qtd_retiradas, $total_retiradas);
$stmt->fetch();
$stmt->close();
if (!$total_retiradas)
    $total_retiradas = 0;
if (!$qtd_retiradas)
    $qtd_retiradas = 0;
// --- FIM: Buscar totais de recargas e retiradas ---
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
                <div class="p-6 space-y-6">
                    <div class="flex flex-col md:flex-row md:items-center gap-2 mt-2 text-black/60 dark:text-white/60">
                        <span
                            class="bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 px-3 py-1 rounded-full btn py-[5px] px-2 text-xs text-xs font-medium">ID:
                            #<?php echo str_pad($usuario_data['id'], 6, '0', STR_PAD_LEFT); ?></span>
                        <span class="text-xs">Registrado em
                            <?php echo date('d/m/Y', strtotime($usuario_data['data_registro'])); ?></span>

                    </div>
                    <!-- Sistema de Tabs Snow -->

                    <div x-data="{activeTab:'profile'}" class="tabs flex flex-col">
                        <div class="grid grid-cols-1 md:grid-cols-3 justify-between gap-4 items-center mb-5">
                            <div class="tabs-list md:col-span-2 flex text-sm flex-nowrap overflow-auto">
                                <button @click="activeTab = 'profile'"
                                    :class="activeTab === 'profile' ? 'border-black text-black font-semibold dark:border-lightpurple-200 dark:text-lightpurple-200' : 'border-transparent text-black/40 hover:text-black hover:font-semibold dark:text-white/40 dark:hover:text-lightpurple-200'"
                                    class="border-b-2 mx-2 my-1 font-normal border-transparent text-black/40 hover:text-black hover:font-semibold dark:text-white/40 dark:hover:text-lightpurple-200">
                                    Visão Geral
                                </button>
                                <button @click="activeTab = 'settings'"
                                    :class="activeTab === 'settings' ? 'border-black text-black font-semibold dark:border-lightpurple-200 dark:text-lightpurple-200' : 'border-transparent text-black/40 hover:text-black hover:font-semibold dark:text-white/40 dark:hover:text-lightpurple-200'"
                                    class="border-b-2 mx-2 my-1 font-normal border-transparent text-black/40 hover:text-black hover:font-semibold dark:text-white/40 dark:hover:text-lightpurple-200">
                                    Configurações
                                </button>

                                <button @click="activeTab = 'financeiro'"
                                    :class="activeTab === 'financeiro' ? 'border-black text-black font-semibold dark:border-lightpurple-200 dark:text-lightpurple-200' : 'border-transparent text-black/40 hover:text-black hover:font-semibold dark:text-white/40 dark:hover:text-lightpurple-200'"
                                    class="border-b-2 mx-2 my-1 font-normal border-transparent text-black/40 hover:text-black hover:font-semibold dark:text-white/40 dark:hover:text-lightpurple-200">
                                    Financeiro
                                </button>
                                <button @click="activeTab = 'depositos'"
                                    :class="activeTab === 'depositos' ? 'border-black text-black font-semibold dark:border-lightpurple-200 dark:text-lightpurple-200' : 'border-transparent text-black/40 hover:text-black hover:font-semibold dark:text-white/40 dark:hover:text-lightpurple-200'"
                                    class="border-b-2 mx-2 my-1 font-normal border-transparent text-black/40 hover:text-black hover:font-semibold dark:text-white/40 dark:hover:text-lightpurple-200">
                                    Depósitos
                                </button>
                                <button @click="activeTab = 'saques'"
                                    :class="activeTab === 'saques' ? 'border-black text-black font-semibold dark:border-lightpurple-200 dark:text-lightpurple-200' : 'border-transparent text-black/40 hover:text-black hover:font-semibold dark:text-white/40 dark:hover:text-lightpurple-200'"
                                    class="border-b-2 mx-2 my-1 font-normal border-transparent text-black/40 hover:text-black hover:font-semibold dark:text-white/40 dark:hover:text-lightpurple-200">
                                    Saques
                                </button>
                                <button @click="activeTab = 'indicados'"
                                    :class="activeTab === 'indicados' ? 'border-black text-black font-semibold dark:border-lightpurple-200 dark:text-lightpurple-200' : 'border-transparent text-black/40 hover:text-black hover:font-semibold dark:text-white/40 dark:hover:text-lightpurple-200'"
                                    class="border-b-2 mx-2 my-1 font-normal border-transparent text-black/40 hover:text-black hover:font-semibold dark:text-white/40 dark:hover:text-lightpurple-200">
                                    Indicados
                                </button>
                                <button @click="activeTab = 'logs'"
                                    :class="activeTab === 'logs' ? 'border-black text-black font-semibold dark:border-lightpurple-200 dark:text-lightpurple-200' : 'border-transparent text-black/40 hover:text-black hover:font-semibold dark:text-white/40 dark:hover:text-lightpurple-200'"
                                    class="border-b-2 mx-2 my-1 font-normal border-transparent text-black/40 hover:text-black hover:font-semibold dark:text-white/40 dark:hover:text-lightpurple-200">
                                    Logs
                                </button>
                            </div>
                            <div class="flex gap-2 justify-center md:justify-end flex-none items-center">
                                <div class="flex flex-col gap-3 w-full md:w-auto items-center md:items-end">
                                    <a href="usuarios.php"
                                        class="btn border border-black/10 dark:border-white/10 text-black dark:text-white hover:bg-black/5 :bg-white/5 px-6 py-2 rounded-lg font-semibold transition">Voltar</a>
                                    <?php if (!$is_edit_mode): ?>
                                        <a href="?id=<?php echo $user_id; ?>&action=edit"
                                            class="btn bg-gradient-to-r from-blue-600 to-purple-600 text-white hover:from-blue-700 hover:to-purple-700 shadow-lg px-6 py-2 rounded-lg font-semibold transition flex items-center gap-2">
                                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                                    d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                                            </svg>
                                            Editar Usuário
                                        </a>
                                    <?php endif; ?>
                                </div>

                            </div>
                        </div>

                        <!-- Conteúdo das abas -->
                        <div class="tab-content mt-3 text-[13px]">
                            <div x-show="activeTab === 'profile'">
                                <!-- Bloco de informações pessoais -->
                                <div class="flex flex-col gap-7">
                                    <?php if ($is_edit_mode): ?>
                                        <!-- Formulário de edição -->
                                        <div class="bg-lightwhite dark:bg-white/5 rounded-2xl p-6">
                                            <div class="flex items-start justify-between gap-4 mb-[2px]">
                                                <h2 class="text-lg font-semibold">
                                                    <?php echo htmlspecialchars($usuario_data['usuario']); ?>
                                                </h2>
                                                <img class="w-[42px] h-[42px] flex-none rounded-full overflow-hidden object-cover"
                                                    src="assets/images/byewind-avatar.png" alt="">
                                            </div>
                                            <div class="flex flex-wrap gap-4 items-center mb-4">
                                                <div
                                                    class="flex items-center gap-1 text-xs text-black/40 dark:text-white/40">
                                                    <svg width="18" height="18" viewBox="0 0 18 18" fill="none"
                                                        xmlns="http://www.w3.org/2000/svg">
                                                        <path fill-rule="evenodd" clip-rule="evenodd"
                                                            d="M11.8465 2.26238C10.4873 1.6875 9 1.6875 9 1.6875C7.51265 1.6875 6.15347 2.26238 6.15347 2.26238C4.84109 2.81747 3.82928 3.82928 3.82928 3.82928C2.81748 4.84109 2.26238 6.15347 2.26238 6.15347C1.6875 7.51265 1.6875 9 1.6875 9C1.6875 10.4873 2.26238 11.8465 2.26238 11.8465C2.81747 13.1589 3.82928 14.1707 3.82928 14.1707C3.90704 14.2485 3.98657 14.3235 4.06715 14.3959C4.09662 14.4287 4.1301 14.4583 4.16709 14.4837C5.11036 15.2964 6.15347 15.7376 6.15347 15.7376C7.51265 16.3125 9 16.3125 9 16.3125C10.4873 16.3125 11.8465 15.7376 11.8465 15.7376C12.6786 15.3857 13.3899 14.8501 13.799 14.5053C13.8585 14.4704 13.9102 14.4253 13.9523 14.373C14.0928 14.2486 14.1707 14.1707 14.1707 14.1707C15.1825 13.1589 15.7376 11.8465 15.7376 11.8465C16.3125 10.4873 16.3125 9 16.3125 9C16.3125 7.51265 15.7376 6.15347 15.7376 6.15347C15.1825 4.84109 14.1707 3.82928 14.1707 3.82928C13.1589 2.81747 11.8465 2.26238 11.8465 2.26238ZM6.59172 14.7015C6.04988 14.4723 5.56846 14.151 5.21752 13.882C5.81067 12.9896 6.64596 12.4769 6.64596 12.4769C7.7291 11.8121 9 11.8125 9 11.8125C10.2709 11.8125 11.354 12.4769 11.354 12.4769C12.036 12.8955 12.5166 13.4997 12.7791 13.8899C12.0784 14.418 11.4083 14.7015 11.4083 14.7015C10.2592 15.1875 9 15.1875 9 15.1875C7.74079 15.1875 6.59172 14.7015 6.59172 14.7015ZM6.05746 11.5181C6.05746 11.5181 6.39649 11.3101 6.93432 11.1023C6.82429 11.0195 6.71668 10.9271 6.61351 10.824C6.61351 10.824 5.625 9.83547 5.625 8.4375C5.625 8.4375 5.625 7.03953 6.61351 6.05101C6.61351 6.05101 7.60203 5.0625 9 5.0625C9 5.0625 10.398 5.0625 11.3865 6.05101C11.3865 6.05101 12.375 7.03953 12.375 8.4375C12.375 8.4375 12.375 9.83547 11.3865 10.824C11.3865 10.824 11.2708 10.9397 11.0625 11.092C11.3547 11.2016 11.654 11.341 11.9425 11.5181C11.9425 11.5181 12.8853 12.0968 13.6153 13.1114C13.9039 12.7751 14.3886 12.148 14.7015 11.4083C14.7015 11.4083 15.1875 10.2592 15.1875 9C15.1875 9 15.1875 7.74079 14.7015 6.59172C14.7015 6.59172 14.2319 5.48143 13.3752 4.62478C13.3752 4.62478 12.5186 3.76813 11.4083 3.29851C11.4083 3.29851 10.2592 2.8125 9 2.8125C9 2.8125 7.74078 2.8125 6.59172 3.29851C6.59172 3.29851 5.48143 3.76813 4.62478 4.62478C4.62478 4.62478 3.76813 5.48143 3.29851 6.59172C3.29851 6.59172 2.8125 7.74078 2.8125 9C2.8125 9 2.8125 10.2592 3.29851 11.4083C3.29851 11.4083 3.68218 12.3154 4.38853 13.1224C4.73326 12.6405 5.2946 11.9864 6.05746 11.5181ZM10.591 10.0285C9.93198 10.6875 9 10.6875 9 10.6875C8.06802 10.6875 7.40901 10.0285 7.40901 10.0285C6.75 9.36948 6.75 8.4375 6.75 8.4375C6.75 7.50552 7.40901 6.84651 7.40901 6.84651C8.06802 6.1875 9 6.1875 9 6.1875C9.93198 6.1875 10.591 6.84651 10.591 6.84651C11.25 7.50552 11.25 8.4375 11.25 8.4375C11.25 9.36948 10.591 10.0285 10.591 10.0285Z"
                                                            fill="currentcolor"></path>
                                                    </svg>
                                                    <p><?php echo htmlspecialchars($usuario_data['celular']); ?></p>
                                                </div>
                                                <div
                                                    class="flex items-center gap-1 text-xs text-black/40 dark:text-white/40">
                                                    <svg width="18" height="18" viewBox="0 0 18 18" fill="none"
                                                        xmlns="http://www.w3.org/2000/svg">
                                                        <path fill-rule="evenodd" clip-rule="evenodd"
                                                            d="M11.8465 2.26238C10.4873 1.6875 9 1.6875 9 1.6875C7.51265 1.6875 6.15347 2.26238 6.15347 2.26238C4.84109 2.81747 3.82928 3.82928 3.82928 3.82928C2.81748 4.84109 2.26238 6.15347 2.26238 6.15347C1.6875 7.51265 1.6875 9 1.6875 9C1.6875 10.4873 2.26238 11.8465 2.26238 11.8465C2.81747 13.1589 3.82928 14.1707 3.82928 14.1707C3.90704 14.2485 3.98657 14.3235 4.06715 14.3959C4.09662 14.4287 4.1301 14.4583 4.16709 14.4837C5.11036 15.2964 6.15347 15.7376 6.15347 15.7376C7.51265 16.3125 9 16.3125 9 16.3125C10.4873 16.3125 11.8465 15.7376 11.8465 15.7376C12.6786 15.3857 13.3899 14.8501 13.799 14.5053C13.8585 14.4704 13.9102 14.4253 13.9523 14.373C14.0928 14.2486 14.1707 14.1707 14.1707 14.1707C15.1825 13.1589 15.7376 11.8465 15.7376 11.8465C16.3125 10.4873 16.3125 9 16.3125 9C16.3125 7.51265 15.7376 6.15347 15.7376 6.15347C15.1825 4.84109 14.1707 3.82928 14.1707 3.82928C13.1589 2.81747 11.8465 2.26238 11.8465 2.26238ZM6.59172 14.7015C6.04988 14.4723 5.56846 14.151 5.21752 13.882C5.81067 12.9896 6.64596 12.4769 6.64596 12.4769C7.7291 11.8121 9 11.8125 9 11.8125C10.2709 11.8125 11.354 12.4769 11.354 12.4769C12.036 12.8955 12.5166 13.4997 12.7791 13.8899C12.0784 14.418 11.4083 14.7015 11.4083 14.7015C10.2592 15.1875 9 15.1875 9 15.1875C7.74079 15.1875 6.59172 14.7015 6.59172 14.7015ZM6.05746 11.5181C6.05746 11.5181 6.39649 11.3101 6.93432 11.1023C6.82429 11.0195 6.71668 10.9271 6.61351 10.824C6.61351 10.824 5.625 9.83547 5.625 8.4375C5.625 8.4375 5.625 7.03953 6.61351 6.05101C6.61351 6.05101 7.60203 5.0625 9 5.0625C9 5.0625 10.398 5.0625 11.3865 6.05101C11.3865 6.05101 12.375 7.03953 12.375 8.4375C12.375 8.4375 12.375 9.83547 11.3865 10.824C11.3865 10.824 11.2708 10.9397 11.0625 11.092C11.3547 11.2016 11.654 11.341 11.9425 11.5181C11.9425 11.5181 12.8853 12.0968 13.6153 13.1114C13.9039 12.7751 14.3886 12.148 14.7015 11.4083C14.7015 11.4083 15.1875 10.2592 15.1875 9C15.1875 9 15.1875 7.74079 14.7015 6.59172C14.7015 6.59172 14.2319 5.48143 13.3752 4.62478C13.3752 4.62478 12.5186 3.76813 11.4083 3.29851C11.4083 3.29851 10.2592 2.8125 9 2.8125C9 2.8125 7.74078 2.8125 6.59172 3.29851C6.59172 3.29851 5.48143 3.76813 4.62478 4.62478C4.62478 4.62478 3.76813 5.48143 3.29851 6.59172C3.29851 6.59172 2.8125 7.74078 2.8125 9C2.8125 9 2.8125 10.2592 3.29851 11.4083C3.29851 11.4083 3.68218 12.3154 4.38853 13.1224C4.73326 12.6405 5.2946 11.9864 6.05746 11.5181ZM10.591 10.0285C9.93198 10.6875 9 10.6875 9 10.6875C8.06802 10.6875 7.40901 10.0285 7.40901 10.0285C6.75 9.36948 6.75 8.4375 6.75 8.4375C6.75 7.50552 7.40901 6.84651 7.40901 6.84651C8.06802 6.1875 9 6.1875 9 6.1875C9.93198 6.1875 10.591 6.84651 10.591 6.84651C11.25 7.50552 11.25 8.4375 11.25 8.4375C11.25 9.36948 10.591 10.0285 10.591 10.0285Z"
                                                            fill="currentcolor"></path>
                                                    </svg>
                                                    <p><?php echo htmlspecialchars($usuario_data['cpf']); ?></p>
                                                </div>
                                                <div
                                                    class="flex items-center gap-1 text-xs text-black/40 dark:text-white/40">
                                                    <svg width="18" height="18" viewBox="0 0 18 18" fill="none"
                                                        xmlns="http://www.w3.org/2000/svg">
                                                        <path fill-rule="evenodd" clip-rule="evenodd"
                                                            d="M1.6875 13.5V3.9375C1.6875 3.62684 1.93934 3.375 2.25 3.375H15.75C16.0607 3.375 16.3125 3.62684 16.3125 3.9375V13.5C16.3125 13.5 16.3125 13.966 15.983 14.2955C15.983 14.2955 15.6535 14.625 15.1875 14.625H2.8125C2.8125 14.625 2.34651 14.625 2.01701 14.2955C2.01701 14.2955 1.6875 13.966 1.6875 13.5ZM2.8125 13.5H15.1875V4.5H2.8125V13.5Z"
                                                            fill="currentcolor"></path>
                                                        <path
                                                            d="M2.6301 3.52285C2.52635 3.42775 2.39073 3.375 2.25 3.375C2.24185 3.375 2.23371 3.37518 2.22557 3.37553C2.07652 3.38201 1.93616 3.44743 1.83535 3.5574C1.74025 3.66115 1.6875 3.79677 1.6875 3.9375C1.6875 3.94565 1.68768 3.95379 1.68803 3.96193C1.69451 4.11098 1.75993 4.25134 1.8699 4.35215L8.6199 10.5396C8.83496 10.7368 9.16504 10.7368 9.3801 10.5396L16.1297 4.35249C16.2459 4.24595 16.3125 4.09517 16.3125 3.9375L16.3125 3.93282C16.3113 3.79371 16.2587 3.65996 16.1646 3.5574C16.0638 3.44743 15.9235 3.38201 15.7744 3.37553C15.7663 3.37518 15.7581 3.375 15.75 3.375L15.7474 3.37501C15.6076 3.37565 15.473 3.42836 15.3699 3.52285L9 9.36193L2.6301 3.52285Z"
                                                            fill="currentcolor"></path>
                                                    </svg>
                                                    <p><?php echo htmlspecialchars($usuario_data['email']); ?></p>
                                                </div>
                                            </div>
                                            <div
                                                class="grid grid-cols-1 sm:grid-cols-2 gap-8 md:gap-0 md:flex md:divide-x divide-black/10 dark:divide-white/10">
                                                <div class="md:pr-7 shrink-0">
                                                    <p class="mb-1">Porcentagem De Ganho</p>
                                                    <div
                                                        class="w-[163px] bg-black/5 dark:bg-white/5 rounded-lg overflow-hidden">
                                                        <div class="bg-lightpurple-200 whitespace-nowrap text-center px-1.5 text-lg font-semibold text-black"
                                                            style="width: <?php echo $porcentagem_ganho; ?>%;">
                                                            <?php echo $porcentagem_ganho; ?>%
                                                        </div>
                                                    </div>
                                                </div>
                                                <div class="md:px-7">
                                                    <p class="mb-1">Saldo</p>
                                                    <p class="text-lg font-semibold">R$
                                                        <?php echo number_format($usuario_data['saldo'], 2, ',', '.'); ?>
                                                    </p>
                                                </div>
                                                <div class="md:px-7">
                                                    <p class="mb-1">Recargas</p>
                                                    <p class="text-lg font-semibold">
                                                        R$<?php echo number_format($total_recargas, 2, ',', '.'); ?>
                                                        (<?php echo $qtd_recargas; ?> Recargas)
                                                    </p>
                                                </div>
                                                <div class="md:pl-7">
                                                    <p class="mb-1">Retiradas</p>
                                                    <p class="text-lg font-semibold">
                                                        R$<?php echo number_format($total_retiradas, 2, ',', '.'); ?>
                                                        (<?php echo $qtd_retiradas; ?> Retiradas)
                                                    </p>
                                                </div>
                                            </div>
                                        </div>
                                        <div class="bg-lightwhite dark:bg-white/5 rounded-2xl p-6">
                                            <div class="flex flex-wrap gap-3 items-center justify-between mb-4">
                                                <h3 class="text-sm font-semibold">Detalhes Do Usuário</h3>
                                                <a class="text-xs text-black/40 dark:text-white/40">Editar usuário >
                                                    Configurações</a>
                                            </div>
                                            <div class="max-w-2xl grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
                                                <?php
                                                // Lista de campos para exibir (exceto senha/token)
                                                $campos_exibir = [
                                                    'id' => 'ID',
                                                    'usuario' => 'Nome de Usuário',
                                                    'email' => 'Email',
                                                    'celular' => 'Celular',
                                                    'cpf' => 'CPF',
                                                    'data_registro' => 'Data de Registro',
                                                    'total_aberto' => 'Total em Aberto',
                                                    'url' => 'URL De Cadastro',
                                                    'codigo_convite' => 'Código de Convite',
                                                    'invitation_code' => 'Invitation Code',
                                                    'twofa_secret' => '2FA',
                                                    // Adicione outros campos conforme necessário
                                                ];
                                                foreach ($campos_exibir as $campo => $label) {
                                                    echo '<p class="text-xs text-black/40 dark:text-white/40">' . $label . '</p>';
                                                    if ($campo === 'saldo' || $campo === 'total_aberto') {
                                                        echo '<p class="text-sm">R$ ' . number_format($usuario_data[$campo], 2, ',', '.') . '</p>';
                                                    } elseif ($campo === 'data_registro') {
                                                        echo '<p class="text-sm">' . date('d/m/Y H:i', strtotime($usuario_data[$campo])) . '</p>';
                                                    } elseif ($campo === 'status') {
                                                        echo '<p class="text-sm">' . ($usuario_data[$campo] == 1 ? 'Ativo' : 'Inativo') . '</p>';
                                                    } elseif ($campo === 'twofa_secret') {
                                                        echo '<p class="text-sm">' . (!empty($usuario_data[$campo]) ? 'Sim' : 'Não') . '</p>';
                                                    } else {
                                                        echo '<p class="text-sm">' . htmlspecialchars($usuario_data[$campo]) . '</p>';
                                                    }
                                                }
                                                ?>
                                            </div>
                                            <div class="flex items-center gap-2 mb-2">
                                                <svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor"
                                                    viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                                        d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                                </svg>
                                                <span class="font-bold text-lg">Token de Acesso</span>
                                            </div>
                                            <div
                                                class="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg border-l-4 border-blue-500">
                                                <p class="text-xs font-mono text-gray-700 dark:text-gray-300 break-all">
                                                    <?php echo htmlspecialchars(substr($usuario_data['token'], 0, 32) . '...'); ?>
                                                </p>
                                                <p class="text-xs text-gray-500 mt-1">Token truncado por segurança</p>
                                            </div>
                                        </div>
                                    <?php endif; ?>
                                </div>
                            </div>
                            <div x-show="activeTab === 'financeiro'">
                                <!-- Bloco financeiro -->
                                <div class="bg-lightwhite dark:bg-white/5 rounded-2xl p-6 mb-6">
                                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                                        <div
                                            class="card bg-gradient-to-br from-green-500 to-green-600 text-white shadow-none md:shadow p-6 rounded-2xl flex flex-col justify-between min-h-[220px]">
                                            <div class="card-body p-0 flex flex-col justify-between h-full">
                                                <div class="flex items-center justify-between gap-4">
                                                    <div>
                                                        <p class="text-green-100 text-sm font-medium mb-1">Saldo
                                                            Disponível</p>
                                                        <p class="text-3xl font-bold">
                                                            <span data-saldo-user>R$
                                                                <?php echo number_format($usuario_data['saldo'], 2, ',', '.'); ?></span>
                                                        </p>
                                                        <p class="text-green-200 text-xs mt-2">Atualizado agora</p>
                                                    </div>
                                                    <div
                                                        class="w-14 h-14 bg-white/20 rounded-xl flex items-center justify-center">
                                                        <svg class="w-8 h-8" fill="currentColor" viewBox="0 0 20 20">
                                                            <path
                                                                d="M4 4a2 2 0 00-2 2v4a2 2 0 002 2V6h10a2 2 0 00-2-2H4zm2 6a2 2 0 012-2h8a2 2 0 012 2v4a2 2 0 01-2 2H8a2 2 0 01-2-2v-4zm6 4a2 2 0 100-4 2 2 0 000 4z" />
                                                        </svg>
                                                    </div>
                                                </div>
                                                <div class="flex flex-col gap-4 mt-6" id="saldo-forms-area">
                                                    <form id="form-add-saldo" class="flex flex-col gap-2 items-stretch">
                                                        <label class="mt-1 flex -space-x-px">
                                                            <div
                                                                class="flex items-center justify-center rounded-l-lg border border-black/10 dark:border-white/10 px-3.5 bg-white/20 dark:bg-white/10">
                                                                <span>R$</span>
                                                            </div>
                                                            <input name="add_saldo"
                                                                class="form-input w-full border border-black/10 dark:border-white/10 bg-transparent px-3 py-2.5 placeholder:text-black/60  dark:placeholder:text-white/60 hover:z-10 hover:border-black dark:hover:border-white focus:z-10 focus:border-black dark:focus:border-white"
                                                                placeholder="Digite o valor" type="number" step="0.01"
                                                                min="0">
                                                            <div
                                                                class="flex items-center justify-center rounded-r-lg border border-black/10 dark:border-white/10 px-3.5 bg-white/20 dark:bg-white/10">
                                                                <span>.00</span>
                                                            </div>
                                                        </label>
                                                        <button type="submit" class="btn btn-success w-full">Adicionar
                                                            Saldo</button>
                                                    </form>
                                                    <form id="form-remove-saldo"
                                                        class="flex flex-col gap-2 items-stretch">
                                                        <label class="mt-1 flex -space-x-px">
                                                            <div
                                                                class="flex items-center justify-center rounded-l-lg border border-black/10 dark:border-white/10 px-3.5 bg-white/20 dark:bg-white/10">
                                                                <span>R$</span>
                                                            </div>
                                                            <input name="remove_saldo"
                                                                class="form-input w-full border border-black/10 dark:border-white/10 bg-transparent px-3 py-2.5 placeholder:text-black/60  dark:placeholder:text-white/60 hover:z-10 hover:border-black dark:hover:border-white focus:z-10 focus:border-black dark:focus:border-white"
                                                                placeholder="Digite o valor" type="number" step="0.01"
                                                                min="0">
                                                            <div
                                                                class="flex items-center justify-center rounded-r-lg border border-black/10 dark:border-white/10 px-3.5 bg-white/20 dark:bg-white/10">
                                                                <span>.00</span>
                                                            </div>
                                                        </label>
                                                        <button type="submit" class="btn btn-danger w-full">Remover
                                                            Saldo</button>
                                                    </form>
                                                </div>
                                            </div>
                                        </div>
                                        <div
                                            class="card bg-gradient-to-br from-orange-500 to-red-500 text-white shadow-none md:shadow p-6 rounded-2xl flex flex-col justify-between min-h-[220px]">
                                            <div class="card-body p-0 flex flex-col justify-between h-full">
                                                <div class="flex items-center justify-between gap-4">
                                                    <div>
                                                        <p class="text-orange-100 text-sm font-medium mb-1">Total em
                                                            Aberto</p>
                                                        <p class="text-3xl font-bold">
                                                            R$
                                                            <?php echo number_format($usuario_data['total_aberto'], 2, ',', '.'); ?>
                                                        </p>
                                                        <p class="text-orange-200 text-xs mt-2">Pendências ativas</p>
                                                    </div>
                                                    <div
                                                        class="w-14 h-14 bg-white/20 rounded-xl flex items-center justify-center">
                                                        <svg class="w-8 h-8" fill="currentColor" viewBox="0 0 20 20">
                                                            <path fill-rule="evenodd"
                                                                d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z"
                                                                clip-rule="evenodd" />
                                                        </svg>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div x-show="activeTab === 'indicados'">
                                <!-- Métricas de afiliados -->
                                <?php
                                // Buscar indicados
                                $indicados = [];
                                $total_bonus = 0;
                                $total_depositos_indicados = 0;
                                $total_saques_indicados = 0;
                                if (!empty($usuario_data['codigo_convite'])) {
                                    $stmt = $mysqli->prepare("SELECT id, usuario, email, data_registro FROM usuarios WHERE invitation_code = ?");
                                    $stmt->bind_param("s", $usuario_data['codigo_convite']);
                                    $stmt->execute();
                                    $res = $stmt->get_result();
                                    while ($row = $res->fetch_assoc()) {
                                        // Para cada indicado, buscar total depositado e sacado
                                        $id_indicado = $row['id'];
                                        // Total depositado
                                        $stmt2 = $mysqli->prepare("SELECT SUM(valor) FROM transacoes WHERE usuario = ? AND tipo = 'deposito'");
                                        $stmt2->bind_param("i", $id_indicado);
                                        $stmt2->execute();
                                        $stmt2->bind_result($depositado);
                                        $stmt2->fetch();
                                        $stmt2->close();
                                        // Total sacado
                                        $stmt2 = $mysqli->prepare("SELECT SUM(valor) FROM solicitacao_saques WHERE id_user = ? AND status = 1");
                                        $stmt2->bind_param("i", $id_indicado);
                                        $stmt2->execute();
                                        $stmt2->bind_result($sacado);
                                        $stmt2->fetch();
                                        $stmt2->close();
                                        // Bônus por indicação (exemplo: buscar em transacoes tipo 'bonus_afiliado')
                                        $stmt2 = $mysqli->prepare("SELECT SUM(valor) FROM transacoes WHERE usuario = ? AND tipo = 'bonus_afiliado'");
                                        $stmt2->bind_param("i", $id_indicado);
                                        $stmt2->execute();
                                        $stmt2->bind_result($bonus);
                                        $stmt2->fetch();
                                        $stmt2->close();
                                        $row['depositado'] = $depositado ?: 0;
                                        $row['sacado'] = $sacado ?: 0;
                                        $row['bonus'] = $bonus ?: 0;
                                        $total_depositos_indicados += $row['depositado'];
                                        $total_saques_indicados += $row['sacado'];
                                        $total_bonus += $row['bonus'];
                                        $indicados[] = $row;
                                    }
                                }
                                ?>
                                <div class="bg-lightwhite dark:bg-white/5 rounded-2xl p-6 mb-6">
                                    <div class="flex flex-wrap gap-6 justify-between items-center mb-6">
                                        <div class="flex items-center gap-3">
                                            <div class="bg-green-100 dark:bg-green-900/30 rounded-full p-2">
                                                <svg class="w-6 h-6 text-green-600 dark:text-green-400" fill="none"
                                                    stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round"
                                                        stroke-width="2"
                                                        d="M17 20h5v-2a4 4 0 00-3-3.87M9 20H4v-2a4 4 0 013-3.87m13-6.13V7a4 4 0 00-3-3.87M4 7V7a4 4 0 013-3.87m0 0A4 4 0 0112 3a4 4 0 015 3.13" />
                                                </svg>
                                            </div>
                                            <div>
                                                <div class="text-xs text-black/50 dark:text-white/50 font-semibold">
                                                    Total de Indicados</div>
                                                <div class="text-2xl font-bold text-black dark:text-white">
                                                    <?php echo count($indicados); ?></div>
                                            </div>
                                        </div>
                                        <div class="flex items-center gap-3">
                                            <div class="bg-blue-100 dark:bg-blue-900/30 rounded-full p-2">
                                                <svg class="w-6 h-6 text-blue-600 dark:text-blue-400" fill="none"
                                                    stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round"
                                                        stroke-width="2"
                                                        d="M12 8c-1.657 0-3 1.343-3 3s1.343 3 3 3 3-1.343 3-3-1.343-3-3-3z" />
                                                    <path stroke-linecap="round" stroke-linejoin="round"
                                                        stroke-width="2" d="M12 19v-2m0 0a7 7 0 100-14 7 7 0 000 14z" />
                                                </svg>
                                            </div>
                                            <div>
                                                <div class="text-xs text-black/50 dark:text-white/50 font-semibold">
                                                    Bônus de Indicação</div>
                                                <div class="text-2xl font-bold text-black dark:text-white">R$
                                                    <?php echo number_format($total_bonus, 2, ',', '.'); ?></div>
                                            </div>
                                        </div>
                                        <div class="flex items-center gap-3">
                                            <div class="bg-purple-100 dark:bg-purple-900/30 rounded-full p-2">
                                                <svg class="w-6 h-6 text-purple-600 dark:text-purple-400" fill="none"
                                                    stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round"
                                                        stroke-width="2"
                                                        d="M12 8c-1.657 0-3 1.343-3 3s1.343 3 3 3 3-1.343 3-3-1.343-3-3-3z" />
                                                    <path stroke-linecap="round" stroke-linejoin="round"
                                                        stroke-width="2" d="M12 19v-2m0 0a7 7 0 100-14 7 7 0 000 14z" />
                                                </svg>
                                            </div>
                                            <div>
                                                <div class="text-xs text-black/50 dark:text-white/50 font-semibold">
                                                    Total Depositado pelos Indicados</div>
                                                <div class="text-2xl font-bold text-black dark:text-white">R$
                                                    <?php echo number_format($total_depositos_indicados, 2, ',', '.'); ?>
                                                </div>
                                            </div>
                                        </div>
                                        <div class="flex items-center gap-3">
                                            <div class="bg-orange-100 dark:bg-orange-900/30 rounded-full p-2">
                                                <svg class="w-6 h-6 text-orange-600 dark:text-orange-400" fill="none"
                                                    stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round"
                                                        stroke-width="2"
                                                        d="M12 8c-1.657 0-3 1.343-3 3s1.343 3 3 3 3-1.343 3-3-1.343-3-3-3z" />
                                                    <path stroke-linecap="round" stroke-linejoin="round"
                                                        stroke-width="2" d="M12 19v-2m0 0a7 7 0 100-14 7 7 0 000 14z" />
                                                </svg>
                                            </div>
                                            <div>
                                                <div class="text-xs text-black/50 dark:text-white/50 font-semibold">
                                                    Total Sacado pelos Indicados</div>
                                                <div class="text-2xl font-bold text-black dark:text-white">R$
                                                    <?php echo number_format($total_saques_indicados, 2, ',', '.'); ?>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="overflow-x-auto mt-6">
                                        <table class="min-w-full text-xs border-separate border-spacing-y-1">
                                            <thead>
                                                <tr class="bg-gray-100 dark:bg-white/10">
                                                    <th class="px-3 py-2 text-left">Usuário</th>
                                                    <th class="px-3 py-2 text-left">Email</th>
                                                    <th class="px-3 py-2 text-left">Data de Registro</th>
                                                    <th class="px-3 py-2 text-right">Depositado</th>
                                                    <th class="px-3 py-2 text-right">Sacado</th>
                                                    <th class="px-3 py-2 text-right">Bônus</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($indicados as $ind): ?>
                                                    <tr class="even:bg-white dark:even:bg-white/5">
                                                        <td class="px-3 py-2 font-semibold">
                                                            <?php echo htmlspecialchars($ind['usuario']); ?></td>
                                                        <td class="px-3 py-2"><?php echo htmlspecialchars($ind['email']); ?>
                                                        </td>
                                                        <td class="px-3 py-2">
                                                            <?php echo date('d/m/Y H:i', strtotime($ind['data_registro'])); ?>
                                                        </td>
                                                        <td class="px-3 py-2 text-right">R$
                                                            <?php echo number_format($ind['depositado'], 2, ',', '.'); ?>
                                                        </td>
                                                        <td class="px-3 py-2 text-right">R$
                                                            <?php echo number_format($ind['sacado'], 2, ',', '.'); ?></td>
                                                        <td class="px-3 py-2 text-right">R$
                                                            <?php echo number_format($ind['bonus'], 2, ',', '.'); ?></td>
                                                    </tr>
                                                <?php endforeach; ?>
                                                <?php if (empty($indicados)): ?>
                                                    <tr>
                                                        <td colspan="6" class="text-center text-gray-400 py-4">Nenhum
                                                            indicado encontrado para este usuário.</td>
                                                    </tr>
                                                <?php endif; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                            <div x-show="activeTab === 'depositos'">
                                <!-- Histórico de depósitos -->
                                <div class="card bg-white dark:bg-black rounded-2xl shadow p-6">
                                    <div
                                        class="card-header mb-4 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                                        <div class="flex items-center gap-2">
                                            <svg class="w-5 h-5 text-indigo-500" fill="none" stroke="currentColor"
                                                viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                                    d="M4 4h16M4 8h16M4 12h16M4 16h16" />
                                            </svg>
                                            <h3 class="card-title text-lg font-bold">Histórico de Depósitos</h3>
                                        </div>
                                        <div class="flex flex-col md:flex-row gap-2 items-center">
                                            <input type="text" placeholder="Buscar..."
                                                class="form-input w-full md:w-48 border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-3 py-2 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition" />
                                            <select
                                                class="form-input w-full md:w-36 border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-3 py-2 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition">
                                                <option value="">Todos</option>
                                                <option value="aprovado">Aprovado</option>
                                                <option value="pendente">Pendente</option>
                                            </select>
                                        </div>
                                    </div>
                                    <div class="card-body" id="tabela-depositos-area">
                                        <?php if (count($historico_depositos) > 0): ?>
                                            <div class="overflow-x-auto">
                                                <table class="min-w-full text-sm text-left">
                                                    <thead class="bg-gray-50 dark:bg-white/10">
                                                        <tr>
                                                            <th
                                                                class="px-4 py-2 font-semibold text-gray-700 dark:text-gray-200">
                                                                Valor</th>
                                                            <th
                                                                class="px-4 py-2 font-semibold text-gray-700 dark:text-gray-200">
                                                                Data/Hora</th>
                                                            <th
                                                                class="px-4 py-2 font-semibold text-gray-700 dark:text-gray-200">
                                                                Status</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        <?php foreach ($historico_depositos as $dep): ?>
                                                            <tr class="even:bg-gray-50 dark:even:bg-white/5">
                                                                <td class="px-4 py-2 flex items-center gap-2">
                                                                    <svg class="w-4 h-4 text-green-500" fill="none"
                                                                        stroke="currentColor" viewBox="0 0 24 24">
                                                                        <path stroke-linecap="round" stroke-linejoin="round"
                                                                            stroke-width="2"
                                                                            d="M12 8c-1.657 0-3 1.343-3 3s1.343 3 3 3 3-1.343 3-3-1.343-3-3-3z" />
                                                                    </svg>
                                                                    R$ <?php echo number_format($dep['valor'], 2, ',', '.'); ?>
                                                                </td>
                                                                <td class="px-4 py-2">
                                                                    <?php echo date('d/m/Y H:i', strtotime($dep['data_registro'])); ?>
                                                                </td>
                                                                <td class="px-4 py-2">
                                                                    <span
                                                                        class="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-semibold
                                                                            <?php echo $dep['status'] === 'aprovado' ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'; ?>">
                                                                        <?php echo ucfirst($dep['status']); ?>
                                                                    </span>
                                                                </td>
                                                            </tr>
                                                        <?php endforeach; ?>
                                                    </tbody>
                                                </table>
                                            </div>
                                        <?php else: ?>
                                            <div
                                                class="flex flex-col items-center justify-center py-8 text-gray-400 dark:text-gray-500">
                                                <svg class="w-10 h-10 mb-2" fill="none" stroke="currentColor"
                                                    viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                                        d="M12 8c-1.657 0-3 1.343-3 3s1.343 3 3 3 3-1.343 3-3-1.343-3-3-3z" />
                                                </svg>
                                                <span class="text-base font-medium">Nenhum depósito encontrado para este
                                                    usuário.</span>
                                            </div>
                                        <?php endif; ?>
                                        <!-- Paginação -->
                                        <div class="flex justify-end mt-4 gap-2">
                                            <button
                                                class="btn px-3 py-1 rounded bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700 transition">Anterior</button>
                                            <button
                                                class="btn px-3 py-1 rounded bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700 transition">Próxima</button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div x-show="activeTab === 'saques'">
                                <!-- Histórico de saques -->
                                <div class="card bg-white dark:bg-black rounded-2xl shadow p-6">
                                    <div class="card-header mb-4 flex items-center gap-2">
                                        <svg class="w-5 h-5 text-pink-500" fill="none" stroke="currentColor"
                                            viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                                d="M9 2a1 1 0 000 2h2a1 1 0 100-2H9z"></path>
                                            <path fill-rule="evenodd"
                                                d="M4 5a2 2 0 012-2 3 3 0 003 3h2a3 3 0 003-3 2 2 0 012 2v11a2 2 0 01-2 2H6a2 2 0 01-2-2V5zm3 4a1 1 0 000 2h.01a1 1 0 100-2H7zm3 0a1 1 0 000 2h3a1 1 0 100-2h-3zm-3 4a1 1 0 100 2h.01a1 1 0 100-2H7zm3 0a1 1 0 100 2h3a1 1 0 100-2h-3z"
                                                clip-rule="evenodd"></path>
                                        </svg>
                                        <h3 class="card-title text-lg font-bold">Histórico de Saques</h3>
                                    </div>
                                    <div class="card-body" id="tabela-saques-area">
                                        <?php if (count($historico_saques) > 0): ?>
                                            <div class="overflow-x-auto">
                                                <table class="min-w-full text-sm text-left">
                                                    <thead class="bg-gray-50 dark:bg-white/10">
                                                        <tr>
                                                            <th
                                                                class="px-4 py-2 font-semibold text-gray-700 dark:text-gray-200">
                                                                Valor</th>
                                                            <th
                                                                class="px-4 py-2 font-semibold text-gray-700 dark:text-gray-200">
                                                                Data/Hora</th>
                                                            <th
                                                                class="px-4 py-2 font-semibold text-gray-700 dark:text-gray-200">
                                                                Status</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        <?php foreach ($historico_saques as $saq): ?>
                                                            <tr class="even:bg-gray-50 dark:even:bg-white/5">
                                                                <td class="px-4 py-2">
                                                                    <?php echo number_format($saq['valor'], 2, ',', '.'); ?>
                                                                </td>
                                                                <td class="px-4 py-2">
                                                                    <?php echo date('d/m/Y H:i', strtotime($saq['data_registro'])); ?>
                                                                </td>
                                                                <td class="px-4 py-2">
                                                                    <span
                                                                        class="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-semibold
                                                                        <?php echo $saq['status'] == 1 ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : ($saq['status'] == 0 ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300' : 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300'); ?>">
                                                                        <?php echo $saq['status'] == 1 ? 'Pago' : ($saq['status'] == 0 ? 'Pendente' : 'Outro'); ?>
                                                                    </span>
                                                                </td>
                                                            </tr>
                                                        <?php endforeach; ?>
                                                    </tbody>
                                                </table>
                                            </div>
                                        <?php else: ?>
                                            <div
                                                class="flex flex-col items-center justify-center py-8 text-gray-400 dark:text-gray-500">
                                                <svg class="w-10 h-10 mb-2" fill="none" stroke="currentColor"
                                                    viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                                        d="M9 2a1 1 0 000 2h2a1 1 0 100-2H9z"></path>
                                                    <path fill-rule="evenodd"
                                                        d="M4 5a2 2 0 012-2 3 3 0 003 3h2a3 3 0 003-3 2 2 0 012 2v11a2 2 0 01-2 2H6a2 2 0 01-2-2V5zm3 4a1 1 0 000 2h.01a1 1 0 100-2H7zm3 0a1 1 0 000 2h3a1 1 0 100-2h-3zm-3 4a1 1 0 100 2h.01a1 1 0 100-2H7zm3 0a1 1 0 100 2h3a1 1 0 100-2h-3z"
                                                        clip-rule="evenodd"></path>
                                                </svg>
                                                <span class="text-base font-medium">Nenhum saque encontrado para este
                                                    usuário.</span>
                                            </div>
                                        <?php endif; ?>
                                    </div>

                                </div>
                            </div>
                            <div x-show="activeTab === 'settings'" class="block">
                                <form method="POST" action="?id=<?php echo $user_id; ?>&action=edit">
                                    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">

                                    <!-- Informações Pessoais e Status -->
                                    <div class="bg-lightwhite dark:bg-white/5 rounded-2xl p-6">
                                        <div class="card-header mb-4 flex items-center gap-2">
                                            <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor"
                                                viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                                    d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                                            </svg>
                                            <h3 class="card-title text-lg font-bold">Informações Pessoais</h3>
                                        </div>
                                        <div class="space-y-5">
                                            <div>
                                                <span
                                                    class="text-xs font-semibold text-black/60 dark:text-white/60 uppercase tracking-wider">Celular</span>
                                                <input type="text" name="celular"
                                                    value="<?php echo htmlspecialchars($usuario_data['celular']); ?>"
                                                    class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition"
                                                    readonly>
                                            </div>
                                            <div>
                                                <span
                                                    class="text-xs font-semibold text-black/60 dark:text-white/60 uppercase tracking-wider">CPF</span>
                                                <input type="text" name="cpf"
                                                    value="<?php echo htmlspecialchars($usuario_data['cpf']); ?>"
                                                    class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition"
                                                    readonly>
                                            </div>
                                            <div>
                                                <span
                                                    class="text-xs font-semibold text-black/60 dark:text-white/60 uppercase tracking-wider">Data
                                                    de Registro</span>
                                                <input type="text" name="data_registro"
                                                    value="<?php echo date('d/m/Y H:i', strtotime($usuario_data['data_registro'])); ?>"
                                                    class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition"
                                                    readonly>
                                            </div>
                                            <div>
                                                <span
                                                    class="text-xs font-semibold text-black/60 dark:text-white/60 uppercase tracking-wider">URL
                                                    Personalizada</span>
                                                <input type="text" name="url"
                                                    value="<?php echo htmlspecialchars($usuario_data['url']); ?>"
                                                    class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition font-mono"
                                                    readonly>
                                            </div>
                                            <div>
                                                <span
                                                    class="text-xs font-semibold text-black/60 dark:text-white/60 uppercase tracking-wider">Código
                                                    de Convite</span>
                                                <div
                                                    class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 p-3 rounded-lg flex items-center justify-between">
                                                    <input type="text" name="codigo_convite"
                                                        value="<?php echo htmlspecialchars($usuario_data['codigo_convite']); ?>"
                                                        class="form-input w-full border-0 bg-transparent px-0 py-0 font-mono font-bold text-blue-900 dark:text-blue-300 focus:ring-0 focus:border-0"
                                                        readonly>
                                                    <button
                                                        onclick="copyToClipboard('<?php echo htmlspecialchars($usuario_data['codigo_convite']); ?>')"
                                                        class="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-200 p-1 rounded-md hover:bg-blue-100 dark:hover:bg-blue-900/30 transition-colors">
                                                        <svg class="w-4 h-4" fill="none" stroke="currentColor"
                                                            viewBox="0 0 24 24">
                                                            <path stroke-linecap="round" stroke-linejoin="round"
                                                                stroke-width="2"
                                                                d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                                        </svg>
                                                    </button>
                                                </div>
                                            </div>
                                            <div>
                                                <span
                                                    class="text-xs font-semibold text-black/60 dark:text-white/60 uppercase tracking-wider">Alterar
                                                    Senha</span>
                                                <input type="password" name="nova_senha" placeholder="Nova senha"
                                                    class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition">
                                            </div>
                                            
                                            <div>
                                                <span
                                                    class="text-xs font-semibold text-black/60 dark:text-white/60 uppercase tracking-wider">Status de Influenciador</span>
                                                <select name="influenciador" 
                                                    class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition">
                                                    <option value="0" <?php echo ($usuario_data['influenciador'] == 0) ? 'selected' : ''; ?>>Não</option>
                                                    <option value="1" <?php echo ($usuario_data['influenciador'] == 1) ? 'selected' : ''; ?>>Sim</option>
                                                </select>
                                                <div class="flex items-center gap-2 mt-2">
                                                    <?php if ($usuario_data['influenciador'] == 1): ?>
                                                        <span
                                                            class="inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300">
                                                            <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                                                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-8.707l-3-3a1 1 0 00-1.414 0l-3 3a1 1 0 001.414 1.414L9 9.414V13a1 1 0 102 0V9.414l1.293 1.293a1 1 0 001.414-1.414z" clip-rule="evenodd" />
                                                            </svg>
                                                            Influenciador Ativo
                                                        </span>
                                                    <?php else: ?>
                                                        <span
                                                            class="inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300">
                                                            <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                                                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                            </svg>
                                                            Usuário Comum
                                                        </span>
                                                    <?php endif; ?>
                                                </div>
                                            </div>
                                            <div>
                                                <span
                                                    class="text-xs font-semibold text-black/60 dark:text-white/60 uppercase tracking-wider">Status de Afiliado</span>
                                                <select name="afiliado" 
                                                    class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition">
                                                    <option value="0" <?php echo ($usuario_data['afiliado'] == 0) ? 'selected' : ''; ?>>Não</option>
                                                    <option value="1" <?php echo ($usuario_data['afiliado'] == 1) ? 'selected' : ''; ?>>Sim</option>
                                                </select>
                                               
                                            </div>
                                            
                                        </div>
                                    </div>

                                    <!-- Configurações de Afiliados -->
                                    <div class="bg-lightwhite dark:bg-white/5 rounded-2xl p-6">
                                        <div class="card-header mb-6 flex items-center gap-3">
                                            <div class="p-2 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
                                                <svg class="w-6 h-6 text-purple-600 dark:text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                                                </svg>
                                            </div>
                                            <div>
                                                <h3 class="card-title text-lg font-bold text-purple-900 dark:text-purple-100">Configurações de Afiliados</h3>
                                                <p class="text-sm text-purple-600 dark:text-purple-400">Valores personalizados para este usuário</p>
                                            </div>
                                        </div>
                                        
                                        <div class="space-y-6">
                                            <!-- CPA Settings -->
                                            <div class="dark:bg-black/20 rounded-xl p-4 border-purple-200 dark:border-purple-800">
                                                <h4 class="font-semibold text-purple-900 dark:text-purple-100 mb-4 flex items-center gap-2">
                                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1" />
                                                    </svg>
                                                    Configurações CPA
                                                </h4>
                                                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                                                    <div>
                                                        <label class="text-xs font-semibold text-purple-700 dark:text-purple-300 uppercase tracking-wider">CPA Nível 1 (%)</label>
                                                        <div class="relative">
                                                            <input type="number" name="cpaLvl1" step="0.01" min="0" max="100"
                                                                value="<?php echo htmlspecialchars($usuario_data['cpaLvl1'] ?? ''); ?>"
                                                                placeholder="10.00"
                                                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-purple-500 focus:ring-2 focus:ring-purple-200 dark:focus:border-purple-400 dark:focus:ring-purple-900 transition text-black dark:text-white">
                                                            <div class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                                                                <span class="text-purple-500 text-sm font-medium">%</span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <div>
                                                        <label class="text-xs font-semibold text-purple-700 dark:text-purple-300 uppercase tracking-wider">CPA Nível 2 (%)</label>
                                                        <div class="relative">
                                                            <input type="number" name="cpaLvl2" step="0.01" min="0" max="100"
                                                                value="<?php echo htmlspecialchars($usuario_data['cpaLvl2'] ?? ''); ?>"
                                                                placeholder="0.00"
                                                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-purple-500 focus:ring-2 focus:ring-purple-200 dark:focus:border-purple-400 dark:focus:ring-purple-900 transition text-black dark:text-white">
                                                            <div class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                                                                <span class="text-purple-500 text-sm font-medium">%</span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <div>
                                                        <label class="text-xs font-semibold text-purple-700 dark:text-purple-300 uppercase tracking-wider">CPA Nível 3 (%)</label>
                                                        <div class="relative">
                                                            <input type="number" name="cpaLvl3" step="0.01" min="0" max="100"
                                                                value="<?php echo htmlspecialchars($usuario_data['cpaLvl3'] ?? ''); ?>"
                                                                placeholder="0.00"
                                                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-purple-500 focus:ring-2 focus:ring-purple-200 dark:focus:border-purple-400 dark:focus:ring-purple-900 transition text-black dark:text-white">
                                                            <div class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                                                                <span class="text-purple-500 text-sm font-medium">%</span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>

                                            <!-- Revenue Share Settings -->
                                            <div class="dark:bg-black/20 rounded-xl p-4 border-purple-200 dark:border-purple-800">
                                                <h4 class="font-semibold text-purple-900 dark:text-purple-100 mb-4 flex items-center gap-2">
                                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 7h6m0 10v-3m-3 3h.01M9 17h.01M9 14h.01M12 14h.01M15 11h.01M12 11h.01M9 11h.01M7 21h10a2 2 0 002-2V5a2 2 0 00-2-2H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                                                    </svg>
                                                    Configurações Revenue Share
                                                </h4>
                                                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                    <div>
                                                        <label class="text-xs font-semibold text-purple-700 dark:text-purple-300 uppercase tracking-wider">RevShare Falso (%)</label>
                                                        <div class="relative">
                                                            <input type="number" name="revShareFalso" step="0.01" min="0" max="100"
                                                                value="<?php echo htmlspecialchars($usuario_data['revShareFalso'] ?? ''); ?>"
                                                                placeholder="0.00"
                                                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-purple-500 focus:ring-2 focus:ring-purple-200 dark:focus:border-purple-400 dark:focus:ring-purple-900 transition text-black dark:text-white">
                                                            <div class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                                                                <span class="text-purple-500 text-sm font-medium">%</span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <div>
                                                        <label class="text-xs font-semibold text-purple-700 dark:text-purple-300 uppercase tracking-wider">RevShare Nível 1 (%)</label>
                                                        <div class="relative">
                                                            <input type="number" name="revShareLvl1" step="0.01" min="0" max="100"
                                                                value="<?php echo htmlspecialchars($usuario_data['revShareLvl1'] ?? ''); ?>"
                                                                placeholder="15.00"
                                                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-purple-500 focus:ring-2 focus:ring-purple-200 dark:focus:border-purple-400 dark:focus:ring-purple-900 transition text-black dark:text-white">
                                                            <div class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                                                                <span class="text-purple-500 text-sm font-medium">%</span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <div>
                                                        <label class="text-xs font-semibold text-purple-700 dark:text-purple-300 uppercase tracking-wider">RevShare Nível 2 (%)</label>
                                                        <div class="relative">
                                                            <input type="number" name="revShareLvl2" step="0.01" min="0" max="100"
                                                                value="<?php echo htmlspecialchars($usuario_data['revShareLvl2'] ?? ''); ?>"
                                                                placeholder="0.00"
                                                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-purple-500 focus:ring-2 focus:ring-purple-200 dark:focus:border-purple-400 dark:focus:ring-purple-900 transition text-black dark:text-white">
                                                            <div class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                                                                <span class="text-purple-500 text-sm font-medium">%</span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <div>
                                                        <label class="text-xs font-semibold text-purple-700 dark:text-purple-300 uppercase tracking-wider">RevShare Nível 3 (%)</label>
                                                        <div class="relative">
                                                            <input type="number" name="revShareLvl3" step="0.01" min="0" max="100"
                                                                value="<?php echo htmlspecialchars($usuario_data['revShareLvl3'] ?? ''); ?>"
                                                                placeholder="0.00"
                                                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-purple-500 focus:ring-2 focus:ring-purple-200 dark:focus:border-purple-400 dark:focus:ring-purple-900 transition text-black dark:text-white">
                                                            <div class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                                                                <span class="text-purple-500 text-sm font-medium">%</span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>

                                            <!-- Other Settings -->
                                            <div class="dark:bg-black/20 rounded-xl p-4 border-purple-200 dark:border-purple-800">
                                                <h4 class="font-semibold text-purple-900 dark:text-purple-100 mb-4 flex items-center gap-2">
                                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                                    </svg>
                                                    Outras Configurações
                                                </h4>
                                                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                                                    <div>
                                                        <label class="text-xs font-semibold text-purple-700 dark:text-purple-300 uppercase tracking-wider">Chance CPA (%)</label>
                                                        <div class="relative">
                                                            <input type="number" name="chanceCpa" step="0.01" min="0" max="100"
                                                                value="<?php echo htmlspecialchars($usuario_data['chanceCpa'] ?? ''); ?>"
                                                                placeholder="100.00"
                                                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-purple-500 focus:ring-2 focus:ring-purple-200 dark:focus:border-purple-400 dark:focus:ring-purple-900 transition text-black dark:text-white">
                                                            <div class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                                                                <span class="text-purple-500 text-sm font-medium">%</span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <div>
                                                        <label class="text-xs font-semibold text-purple-700 dark:text-purple-300 uppercase tracking-wider">Min. Depósito CPA (R$)</label>
                                                        <div class="relative">
                                                            <input type="number" name="minDepForCpa" step="0.01" min="0"
                                                                value="<?php echo htmlspecialchars($usuario_data['minDepForCpa'] ?? ''); ?>"
                                                                placeholder="10.00"
                                                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-purple-500 focus:ring-2 focus:ring-purple-200 dark:focus:border-purple-400 dark:focus:ring-purple-900 transition text-black dark:text-white">
                                                            <div class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                                                                <span class="text-purple-500 text-sm font-medium">R$</span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <div>
                                                        <label class="text-xs font-semibold text-purple-700 dark:text-purple-300 uppercase tracking-wider">Min. Resgate (R$)</label>
                                                        <div class="relative">
                                                            <input type="number" name="minResgate" step="0.01" min="0"
                                                                value="<?php echo htmlspecialchars($usuario_data['minResgate'] ?? ''); ?>"
                                                                placeholder="500.00"
                                                                class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-purple-500 focus:ring-2 focus:ring-purple-200 dark:focus:border-purple-400 dark:focus:ring-purple-900 transition text-black dark:text-white">
                                                            <div class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                                                                <span class="text-purple-500 text-sm font-medium">R$</span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>

                                            <!-- Info Box -->
                                            <div class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-xl p-4">
                                                <div class="flex items-start gap-3">
                                                    <div class="p-1 bg-blue-100 dark:bg-blue-900/30 rounded">
                                                        <svg class="w-4 h-4 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                                        </svg>
                                                    </div>
                                                    <div>
                                                        <h5 class="font-semibold text-blue-900 dark:text-blue-100 text-sm">Como Funciona</h5>
                                                        <p class="text-xs text-blue-700 dark:text-blue-300 mt-1">
                                                            Deixe os campos vazios para usar os valores globais. Preencha apenas os valores que deseja personalizar para este usuário.
                                                        </p>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                </div>
                                <div class="flex justify-end mt-6">
                                    <button type="submit" name="update_user" 
                                        class="btn bg-gradient-to-r from-blue-500 to-blue-700 text-white font-semibold rounded-lg px-6 py-3 shadow hover:from-blue-600 hover:to-blue-800 transition flex items-center gap-2">
                                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                                        </svg>
                                        Salvar Alterações
                                    </button>
                                </div>
                            </form>
                        </div>
                        <div x-show="activeTab === 'logs'" class="flex flex-col gap-7">
                                <?php
                                // Paginação
                                $page_jogadas = isset($_GET['page_jogadas']) ? max(1, intval($_GET['page_jogadas'])) : 1;
                                $per_page = 20;
                                $offset = ($page_jogadas - 1) * $per_page;
                                $total_jogadas = 0;
                                $historico_jogadas = [];
                                // Contar total
                                $stmt = $mysqli->prepare("SELECT COUNT(*) FROM historico_raspadas WHERE user_id = ?");
                                $stmt->bind_param("i", $user_id);
                                $stmt->execute();
                                $stmt->bind_result($total_jogadas);
                                $stmt->fetch();
                                $stmt->close();
                                // Buscar jogadas
                                $stmt = $mysqli->prepare("SELECT id, scratch_card_name, amount_paid, prize_amount, status, played_at FROM historico_raspadas WHERE user_id = ? ORDER BY played_at DESC LIMIT ? OFFSET ?");
                                $stmt->bind_param("iii", $user_id, $per_page, $offset);
                                $stmt->execute();
                                $res = $stmt->get_result();
                                while ($row = $res->fetch_assoc()) {
                                    $historico_jogadas[] = $row;
                                }
                                $stmt->close();
                                $total_pages = max(1, ceil($total_jogadas / $per_page));
                                ?>
                                <div class="bg-lightwhite dark:bg-white/5 rounded-2xl p-6 mb-6 grid grid-flow-row">
                                    <div class="flex flex-wrap items-center justify-between gap-3 mb-2">
                                        <h3 class="text-sm font-semibold">Histórico de Jogadas</h3>
                                    </div>
                                    <div class="table-responsive">
                                        <table class="table-hover text-xs min-w-full">
                                            <thead>
                                                <tr>
                                                    <th class="py-2">Data/Hora</th>
                                                    <th class="py-2">Raspadinha</th>
                                                    <th class="py-2">Valor Pago</th>
                                                    <th class="py-2">Prêmio</th>
                                                    <th class="py-2">Status</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php if (count($historico_jogadas) > 0): ?>
                                                    <?php foreach ($historico_jogadas as $jogada): ?>
                                                        <tr>
                                                            <td class="whitespace-nowrap py-2"><?php echo date('d/m/Y H:i', strtotime($jogada['played_at'])); ?></td>
                                                            <td class="py-2"><?php echo htmlspecialchars($jogada['scratch_card_name']); ?></td>
                                                            <td class="py-2">R$ <?php echo number_format($jogada['amount_paid'] / 100, 2, ',', '.'); ?></td>
                                                            <td class="py-2 font-semibold <?php echo $jogada['prize_amount'] > 0 ? 'text-green-600 dark:text-green-400' : 'text-black/60 dark:text-white/60'; ?>">R$ <?php echo number_format($jogada['prize_amount'] / 100, 2, ',', '.'); ?></td>
                                                            <td class="py-2">
                                                                <span class="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-semibold
                                                                    <?php
                                                                    if ($jogada['status'] === 'completed') echo 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300';
                                                                    elseif ($jogada['status'] === 'pending') echo 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300';
                                                                    else echo 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300';
                                                                    ?>">
                                                                    <?php echo ucfirst($jogada['status']); ?>
                                                                </span>
                                                            </td>
                                                        </tr>
                                                    <?php endforeach; ?>
                                                <?php else: ?>
                                                    <tr><td colspan="5" class="text-center text-gray-400 py-4">Nenhuma jogada encontrada.</td></tr>
                                                <?php endif; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                    <!-- Paginação abaixo da tabela -->
                                    <?php
                                    // Cálculo dos índices para o texto
                                    $start_result = $total_jogadas > 0 ? ($offset + 1) : 0;
                                    $end_result = min($offset + $per_page, $total_jogadas);
                                    $max_links = 3; // máximo de links de página exibidos (além de First/Last)
                                    $start_page = max(1, $page_jogadas - floor($max_links / 2));
                                    $end_page = min($total_pages, $start_page + $max_links - 1);
                                    if ($end_page - $start_page + 1 < $max_links) {
                                        $start_page = max(1, $end_page - $max_links + 1);
                                    }
                                    ?>
                                    <div class="flex flex-wrap items-center justify-center sm:justify-between gap-3 mt-4">
                                        <div class="text-sm text-black/60 dark:text-white/60 text-left">
                                            Mostrando <span class="font-semibold text-black dark:text-white"><?php echo $start_result; ?></span> a <span class="font-semibold text-black dark:text-white"><?php echo $end_result; ?></span> de <span class="font-semibold text-black dark:text-white"><?php echo $total_jogadas; ?></span> resultados
                                        </div>
                                        <ul class="inline-flex items-center space-x-1 m-auto mb-4">
                                            <li>
                                                <?php if ($page_jogadas > 1): ?>
                                                    <a href="<?php $params = $_GET; $params['page_jogadas'] = 1; echo '?' . http_build_query($params); ?>" class="flex justify-center px-3.5 py-2 rounded transition text-black/60 hover:text-white bg-black/10 hover:bg-black dark:text-white/60 dark:bg-white/10 dark:hover:bg-white dark:hover:text-black">First</a>
                                                <?php else: ?>
                                                    <span class="flex justify-center px-3.5 py-2 rounded transition text-black/30 bg-black/5 dark:text-white/30 dark:bg-white/5 cursor-not-allowed">First</span>
                                                <?php endif; ?>
                                            </li>
                                            <li>
                                                <?php if ($page_jogadas > 1): ?>
                                                    <a href="<?php $params = $_GET; $params['page_jogadas'] = $page_jogadas - 1; echo '?' . http_build_query($params); ?>" class="flex justify-center px-3.5 py-2 rounded transition text-black/60 hover:text-white bg-black/10 hover:bg-black dark:text-white/60 dark:bg-white/10 dark:hover:bg-white dark:hover:text-black">Prev</a>
                                                <?php else: ?>
                                                    <span class="flex justify-center px-3.5 py-2 rounded transition text-black/30 bg-black/5 dark:text-white/30 dark:bg-white/5 cursor-not-allowed">Prev</span>
                                                <?php endif; ?>
                                            </li>
                                            <?php for ($i = $start_page; $i <= $end_page; $i++): ?>
                                                <li>
                                                    <?php if ($i == $page_jogadas): ?>
                                                        <span class="flex justify-center px-3.5 py-2 rounded transition text-white bg-black dark:text-black dark:bg-white"><?php echo $i; ?></span>
                                                    <?php else: ?>
                                                        <a href="<?php $params = $_GET; $params['page_jogadas'] = $i; echo '?' . http_build_query($params); ?>" class="flex justify-center px-3.5 py-2 rounded transition text-black/60 hover:text-white bg-black/10 hover:bg-black dark:text-white/60 dark:bg-white/10 dark:hover:bg-white dark:hover:text-black"><?php echo $i; ?></a>
                                                    <?php endif; ?>
                                                </li>
                                            <?php endfor; ?>
                                            <li>
                                                <?php if ($page_jogadas < $total_pages): ?>
                                                    <a href="<?php $params = $_GET; $params['page_jogadas'] = $page_jogadas + 1; echo '?' . http_build_query($params); ?>" class="flex justify-center px-3.5 py-2 rounded transition text-black/60 hover:text-white bg-black/10 hover:bg-black dark:text-white/60 dark:bg-white/10 dark:hover:bg-white dark:hover:text-black">Next</a>
                                                <?php else: ?>
                                                    <span class="flex justify-center px-3.5 py-2 rounded transition text-black/30 bg-black/5 dark:text-white/30 dark:bg-white/5 cursor-not-allowed">Next</span>
                                                <?php endif; ?>
                                            </li>
                                            <li>
                                                <?php if ($page_jogadas < $total_pages): ?>
                                                    <a href="<?php $params = $_GET; $params['page_jogadas'] = $total_pages; echo '?' . http_build_query($params); ?>" class="flex justify-center px-3.5 py-2 rounded transition text-black/60 hover:text-white bg-black/10 hover:bg-black dark:text-white/60 dark:bg-white/10 dark:hover:bg-white dark:hover:text-black">Last</a>
                                                <?php else: ?>
                                                    <span class="flex justify-center px-3.5 py-2 rounded transition text-black/30 bg-black/5 dark:text-white/30 dark:bg-white/5 cursor-not-allowed">Last</span>
                                                <?php endif; ?>
                                            </li>
                                        </ul>
                                    </div>
                                </div>
                                <div class="bg-lightwhite dark:bg-white/5 rounded-2xl grid grid-flow-row p-6 mb-6">
                                    <div class="flex flex-wrap items-center justify-between gap-3 mb-2">
                                        <h3 class="font-semibold">Acessos Ao Site</h3>
                                    </div>
                                    <div class="table-responsive">
                                        <table class="text-xs min-w-full">
                                            <thead>
                                                <tr>
                                                    <th>Data/Hora</th>
                                                    <th>IP</th>
                                                    <th>Navegador/Dispositivo</th>
                                                    <th>Referência</th>
                                                    <th>Localidade</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php
                                                // Busca o IP do usuário na tabela usuarios
                                                $usuario_ip = $usuario_data['ip'] ?? null;
                                                $acessos = [];
                                                if ($usuario_ip && $mysqli->query("SHOW TABLES LIKE 'visita_site'")->num_rows) {
                                                    $stmt = $mysqli->prepare("SELECT data_cad, hora_cad, ip_visita, nav_os, refer_visita, pais, cidade, estado FROM visita_site WHERE ip_visita = ? ORDER BY data_cad DESC LIMIT 10");
                                                    $stmt->bind_param("s", $usuario_ip);
                                                    $stmt->execute();
                                                    $res = $stmt->get_result();
                                                    while ($row = $res->fetch_assoc()) {
                                                        $acessos[] = $row;
                                                    }
                                                    $stmt->close();
                                                }
                                                // Se não houver tabela ou IP, simula dados para layout
                                                if (empty($acessos)) {
                                                    $acessos = [
                                                        [
                                                            'datahora' => date('d/m/Y H:i', strtotime('-1 hour')),
                                                            'ip' => $usuario_ip ?: '189.45.123.10',
                                                            'user_agent' => 'Chrome - Windows',
                                                            'status' => 'sucesso',
                                                            'localidade' => 'São Paulo, BR'
                                                        ],
                                                        [
                                                            'datahora' => date('d/m/Y H:i', strtotime('-2 hours')),
                                                            'ip' => $usuario_ip ?: '189.45.123.10',
                                                            'user_agent' => 'Safari - iPhone',
                                                            'status' => 'erro',
                                                            'localidade' => 'Rio de Janeiro, BR'
                                                        ],
                                                        [
                                                            'datahora' => date('d/m/Y H:i', strtotime('-5 hours')),
                                                            'ip' => $usuario_ip ?: '201.22.11.55',
                                                            'user_agent' => 'Edge - Windows',
                                                            'status' => 'sucesso',
                                                            'localidade' => 'Curitiba, BR'
                                                        ],
                                                    ];
                                                }
                                                foreach ($acessos as $acesso): ?>
                                                    <tr>
                                                        <td><?php echo htmlspecialchars($acesso['data_cad'] . ' ' . $acesso['hora_cad']); ?></td>
                                                        <td><?php echo htmlspecialchars($acesso['ip_visita']); ?></td>
                                                        <td><?php echo htmlspecialchars($acesso['nav_os']); ?></td>
                                                        <td><?php echo htmlspecialchars($acesso['refer_visita']); ?></td>
                                                       
                                                        <td><?php echo htmlspecialchars($acesso['pais'] . ', ' . $acesso['estado'] . ' - ' . $acesso['cidade']); ?></td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                            <!-- Fim sistema de tabs Snow -->

                            <!-- Alert Messages -->
                            <?php if (isset($success_message)): ?>
                                <div class="alert alert-success">
                                    <svg class="w-5 h-5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                                        <path fill-rule="evenodd"
                                            d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                                            clip-rule="evenodd" />
                                    </svg>
                                    <div>
                                        <h4 class="font-medium">Sucesso!</h4>
                                        <p class="text-sm"><?php echo $success_message; ?></p>
                                    </div>
                                </div>
                            <?php endif; ?>

                            <?php if (isset($error_message)): ?>
                                <div class="alert alert-danger">
                                    <svg class="w-5 h-5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                                        <path fill-rule="evenodd"
                                            d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                                            clip-rule="evenodd" />
                                    </svg>
                                    <div>
                                        <h4 class="font-medium">Erro!</h4>
                                        <p class="text-sm"><?php echo $error_message; ?></p>
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

        <!-- Toast global -->
        <div id="toast-area"
            class="fixed bottom-10 right-10 z-[999999] flex flex-col items-end gap-2 pointer-events-auto drop-shadow-2xl">
        </div>

        <script src="/assets/js/toast.js"></script>
        <!-- Adiciona Alpine.js caso não exista -->
        <script src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
        <script>
            window.addEventListener('DOMContentLoaded', function () {
                // Função para atualizar saldo em tempo real
                function atualizarSaldoUsuario() {
                    const url = new URL(window.location.href);
                    url.searchParams.set('get_saldo', '1');
                    fetch(url.toString())
                        .then(res => res.json())
                        .then(data => {
                            if (data.saldo !== undefined) {
                                document.querySelectorAll('[data-saldo-user]').forEach(function (el) {
                                    el.textContent = 'R$ ' + Number(data.saldo).toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
                                });
                            }
                        });
                }

                // Função para atualizar tabelas de histórico
                function atualizarTabelasHistorico() {
                    const urlBase = window.location.pathname + window.location.search;
                    ['depositos', 'saques', 'indicados'].forEach(tipo => {
                        const url = new URL(window.location.origin + urlBase);
                        url.searchParams.set('get_tabela', tipo);
                        fetch(url.toString())
                            .then(res => res.text())
                            .then(html => {
                                const area = document.getElementById('tabela-' + tipo + '-area');
                                if (area) area.innerHTML = html;
                            });
                    });
                }

                // AJAX para adicionar/remover saldo
                const formAdd = document.getElementById('form-add-saldo');
                const formRemove = document.getElementById('form-remove-saldo');
                // Captura o id do usuário da URL
                const urlParams = new URLSearchParams(window.location.search);
                const userId = urlParams.get('id');
                if (formAdd) {
                    formAdd.addEventListener('submit', function (e) {
                        e.preventDefault();
                        const valor = this.add_saldo.value;
                        if (!userId) {
                            showToast('ID do usuário não encontrado!', 'error');
                            return;
                        }
                        const url = new URL(window.location.origin + window.location.pathname);
                        url.searchParams.set('id', userId);
                        fetch(url.toString(), {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                            body: `ajax_saldo=add&valor=${encodeURIComponent(valor)}`
                        })
                            .then(res => res.json())
                            .then(data => {
                                showToast(data.message, data.success ? 'success' : 'error');
                                if (data.success) {
                                    this.reset();
                                    atualizarSaldoUsuario();
                                    atualizarTabelasHistorico();
                                }
                            });
                    });
                }
                if (formRemove) {
                    formRemove.addEventListener('submit', function (e) {
                        e.preventDefault();
                        const valor = this.remove_saldo.value;
                        if (!userId) {
                            showToast('ID do usuário não encontrado!', 'error');
                            return;
                        }
                        const url = new URL(window.location.origin + window.location.pathname);
                        url.searchParams.set('id', userId);
                        fetch(url.toString(), {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                            body: `ajax_saldo=remove&valor=${encodeURIComponent(valor)}`
                        })
                            .then(res => res.json())
                            .then(data => {
                                showToast(data.message, data.success ? 'success' : 'error');
                                if (data.success) {
                                    this.reset();
                                    atualizarSaldoUsuario();
                                    atualizarTabelasHistorico();
                                }
                            });
                    });
                }
            });
        </script>
</body>

</html>