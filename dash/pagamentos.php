<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax_gateway_config'])) {
    header('Content-Type: application/json');
    session_start();
    include_once "services/database.php";
    $admin_id = $_SESSION['data_adm']['id'] ?? null;
    $mysqli->begin_transaction();
    try {
        // Salvar apenas gateways individuais
        $gateways = ['ondapay'];
        $ativos = [];
        foreach ($gateways as $gw) {
            $ativo = isset($_POST[$gw.'_ativo']) ? 1 : 0;
            $ativos[$gw] = $ativo;
        }
        
        // Garantir que apenas um gateway esteja ativo por vez
        $primeiroAtivo = null;
        foreach ($gateways as $gw) {
            if ($ativos[$gw] && $primeiroAtivo === null) {
                $primeiroAtivo = $gw;
            } else {
                $ativos[$gw] = 0;
            }
        }
        
        foreach ($gateways as $gw) {
            $url = $_POST[$gw.'_url'] ?? '';
            $client_id = $_POST[$gw.'_client_id'] ?? '';
            $client_secret = $_POST[$gw.'_client_secret'] ?? '';
            $ativo = $ativos[$gw];
            $atualizado = date('Y-m-d H:i:s');
            $sql = $mysqli->prepare("UPDATE $gw SET url=?, client_id=?, client_secret=?, atualizado=?, ativo=? WHERE id=1");
            $sql->bind_param("ssssi", $url, $client_id, $client_secret, $atualizado, $ativo);
            $sql->execute();
        }
        $mysqli->commit();
        
        // Retorna os novos valores para atualizar na tela
        $configs = [];
        foreach ($gateways as $gw) {
            $res = $mysqli->query("SELECT * FROM $gw WHERE id=1");
            $configs[$gw] = ($res && ($row = $res->fetch_assoc())) ? $row : [];
        }
        
        echo json_encode([
            'success' => true,
            'message' => 'Configurações salvas com sucesso!',
            'configs' => $configs
        ]);
        exit;
    } catch (Exception $e) {
        $mysqli->rollback();
        echo json_encode([
            'success' => false,
            'message' => 'Erro ao salvar configurações: ' . $e->getMessage()
        ]);
        exit;
    }
}
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
                <?php
                $gateways = ['ondapay'];
                $labels = [
                    'ondapay' => 'OndaPay',
                ];
                $configs = [];
                foreach ($gateways as $gw) {
                    $configs[$gw] = [
                        'url' => '',
                        'client_id' => '',
                        'client_secret' => '',
                        'atualizado' => '',
                        'ativo' => 0
                    ];
                    $res = $mysqli->query("SELECT * FROM $gw WHERE id=1");
                    if ($res && $row = $res->fetch_assoc()) {
                        $configs[$gw] = array_merge($configs[$gw], $row);
                    }
                }
                ?>
                <div class="p-4 sm:p-7 min-h-[calc(100vh-145px)]">
                    <form id="form-gateway-config" class="space-y-7">
                        <div class="grid grid-cols-1 lg:grid-cols-2 gap-7">
                        <?php foreach ($gateways as $gw): ?>
                            <div class="border border-black/10 dark:border-white/10 p-5 rounded-md">
                                <div class="mb-5 flex items-center justify-between">
                                    <div>
                                        <p class="text-sm font-semibold"><?php echo $labels[$gw]; ?></p>
                                        <h2 class="text-xs font-italic">Gateway <?php echo $labels[$gw]; ?> - preencha as credenciais abaixo.</h2>
                                    </div>
                                    <div class="togglebutton inline-block">
                                        <label class="flex items-center cursor-pointer">
                                            <div class="relative">
                                                <input type="checkbox" name="<?php echo $gw; ?>_ativo" value="1" class="sr-only" <?php if ($configs[$gw]['ativo']) echo 'checked'; ?> />
                                                <div class="block band bg-black/20 dark:bg-white/20 w-[52px] h-7 rounded-full"></div>
                                                <div class="dot absolute left-[1.5px] top-[2px] bg-white dark:bg-black w-6 h-6 rounded-full transition"></div>
                                            </div>
                                        </label>
                                    </div>
                                </div>
                                <div class="mb-3">
                                    <label class="text-xs font-semibold">URL</label>
                                    <input name="<?php echo $gw; ?>_url" class="form-input w-full border border-black/10 dark:border-white/10 bg-transparent px-3 py-2.5 rounded-lg" placeholder="URL do gateway" type="text" value="<?php echo htmlspecialchars($configs[$gw]['url']); ?>" />
                                </div>
                                <div class="mb-3">
                                    <label class="text-xs font-semibold">Client ID</label>
                                    <input name="<?php echo $gw; ?>_client_id" class="form-input w-full border border-black/10 dark:border-white/10 bg-transparent px-3 py-2.5 rounded-lg" placeholder="Client ID" type="text" value="<?php echo htmlspecialchars($configs[$gw]['client_id']); ?>" />
                                </div>
                                <div class="mb-3">
                                    <label class="text-xs font-semibold">Client Secret</label>
                                    <input name="<?php echo $gw; ?>_client_secret" class="form-input w-full border border-black/10 dark:border-white/10 bg-transparent px-3 py-2.5 rounded-lg" placeholder="Client Secret" type="text" value="<?php echo htmlspecialchars($configs[$gw]['client_secret']); ?>" />
                                </div>
                                <div class="mb-1">
                                    <label class="text-xs font-semibold">Última Atualização</label>
                                    <input class="form-input w-full border border-black/10 dark:border-white/10 bg-transparent px-3 py-2.5 rounded-lg text-xs" type="text" value="<?php echo htmlspecialchars($configs[$gw]['atualizado']); ?>" readonly />
                                </div>
                            </div>
                        <?php endforeach; ?>
                        </div>
                        <div class="flex justify-center mt-8">
                            <button type="submit"
                                class="btn inline-flex items-center px-9 py-2 text-base font-medium rounded-lg bg-lightgreen-100 dark:bg-lightblue-100 align-middle text-black dark:text-black hover:bg-lightgreen-200 dark:hover:bg-lightgreen-200 hover:text-black dark:hover:text-black">
                                <svg class="w-5 h-5 mr-2" width="32" height="32" viewBox="0 0 32 32" fill="none"
                                    xmlns="http://www.w3.org/2000/svg">
                                    <path fill-rule="evenodd" clip-rule="evenodd"
                                        d="M11.4012 27.0849C11.4012 27.0849 10.9664 26.9028 9.6139 26.8843C9.6139 26.8843 8.4575 26.8685 7.88867 26.7645C7.88867 26.7645 6.77082 26.56 6.10539 25.8946C6.10539 25.8946 5.43594 25.2252 5.22844 24.0882C5.22844 24.0882 5.12294 23.5102 5.10465 22.3366C5.10465 22.3366 5.08389 21.0046 4.91418 20.5965C4.91418 20.5965 4.74093 20.18 3.79698 19.1924C3.79698 19.1924 2.98525 18.3431 2.6547 17.8655C2.6547 17.8655 2 16.9195 2 16C2 16 2 15.0846 2.64417 14.1522C2.64417 14.1522 2.96978 13.6809 3.77243 12.8434C3.77243 12.8434 4.7293 11.8449 4.91512 11.4012C4.91512 11.4012 5.09721 10.9664 5.1157 9.6139C5.1157 9.6139 5.13151 8.4575 5.23553 7.88867C5.23553 7.88867 5.43996 6.77082 6.10539 6.10539C6.10539 6.10539 6.77484 5.43594 7.91181 5.22844C7.91181 5.22844 8.48983 5.12294 9.66342 5.10465C9.66342 5.10465 10.9954 5.08389 11.4035 4.91418C11.4035 4.91418 11.82 4.74093 12.8076 3.79698C12.8076 3.79698 13.6569 2.98525 14.1345 2.6547C14.1345 2.6547 15.0805 2 16 2C16 2 16.9154 2 17.8478 2.64417C17.8478 2.64417 18.3191 2.96978 19.1566 3.77243C19.1566 3.77243 20.1551 4.7293 20.5988 4.91512C20.5988 4.91512 21.0336 5.09721 22.3861 5.1157C22.3861 5.1157 23.5425 5.13151 24.1113 5.23553C24.1113 5.23553 25.2292 5.43996 25.8946 6.10539C25.8946 6.10539 26.5641 6.77484 26.7716 7.91181C26.7716 7.91181 26.8771 8.48985 26.8953 9.66342C26.8953 9.66342 26.9161 10.9954 27.0858 11.4035C27.0858 11.4035 27.2591 11.82 28.203 12.8076C28.203 12.8076 29.0148 13.6569 29.3453 14.1345C29.3453 14.1345 30 15.0805 30 16C30 16 30 16.9154 29.3558 17.8478C29.3558 17.8478 29.0302 18.3191 28.2276 19.1566C28.2276 19.1566 27.2707 20.1551 27.0849 20.5988C27.0849 20.5988 26.9028 21.0336 26.8843 22.3861C26.8843 22.3861 26.8685 23.5425 26.7645 24.1113C26.7645 24.1113 26.56 25.2292 25.8946 25.8946C25.8946 25.8946 25.2252 26.5641 24.0882 26.7716C24.0882 26.7716 23.5102 26.8771 22.3366 26.8953C22.3366 26.8953 21.0046 26.9161 20.5965 27.0858C20.5965 27.0858 20.18 27.2591 19.1924 28.203C19.1924 28.203 18.3431 29.0148 17.8655 29.3453C17.8655 29.3453 16.9195 30 16 30C16 30 15.0846 30 14.1522 29.3558C14.1522 29.3558 13.6809 29.0302 12.8434 28.2276C12.8434 28.2276 11.8449 27.2707 11.4012 27.0849ZM12.1738 25.2401C12.1738 25.2401 12.9603 25.5695 14.2272 26.7836C14.2272 26.7836 15.4965 28 16 28C16 28 16.5103 28 17.8105 26.7572C17.8105 26.7572 19.0676 25.5556 19.8285 25.2392C19.8285 25.2392 20.5903 24.9223 22.3054 24.8956C22.3054 24.8956 24.0931 24.8677 24.4804 24.4804C24.4804 24.4804 24.8607 24.1001 24.8845 22.3588C24.8845 22.3588 24.9083 20.6186 25.2401 19.8262C25.2401 19.8262 25.5695 19.0397 26.7836 17.7728C26.7836 17.7728 28 16.5035 28 16C28 16 28 15.4897 26.7572 14.1895C26.7572 14.1895 25.5556 12.9324 25.2392 12.1715C25.2392 12.1715 24.9223 11.4097 24.8956 9.69459C24.8956 9.69459 24.8677 7.90694 24.4804 7.51961C24.4804 7.51961 24.1001 7.13932 22.3588 7.11551C22.3588 7.11551 20.6186 7.09172 19.8262 6.75988C19.8262 6.75988 19.0397 6.43046 17.7728 5.2164C17.7728 5.2164 16.5035 4 16 4C16 4 15.4897 4 14.1895 5.24278C14.1895 5.24278 12.9324 6.44437 12.1715 6.76082C12.1715 6.76082 11.4097 7.07767 9.69459 7.10441C9.69459 7.10441 7.90694 7.13227 7.51961 7.51961C7.51961 7.51961 7.13932 7.8999 7.11551 9.64124C7.11551 9.64124 7.09172 11.3814 6.75988 12.1738C6.75988 12.1738 6.43047 12.9603 5.2164 14.2272C5.2164 14.2272 4 15.4965 4 16C4 16 4 16.5103 5.24278 17.8105C5.24278 17.8105 6.44437 19.0676 6.76082 19.8285C6.76082 19.8285 7.07767 20.5903 7.10441 22.3054C7.10441 22.3054 7.13227 24.0931 7.51961 24.4804C7.51961 24.4804 7.8999 24.8607 9.64124 24.8845C9.64124 24.8845 11.3814 24.9083 12.1738 25.2401Z"
                                        fill="currentColor"></path>
                                    <path
                                        d="M11.1909 15.777C11.0048 15.5992 10.7574 15.5 10.5 15.5C10.4998 15.5 10.4773 15.5003 10.4773 15.5003C10.2122 15.5063 9.96027 15.6174 9.77704 15.8091C9.59923 15.9952 9.5 16.2426 9.5 16.5L9.50026 16.5227C9.50627 16.7878 9.61737 17.0397 9.80911 17.223L13.4716 20.723C13.8579 21.0921 14.4662 21.0924 14.8528 20.7236L22.19 13.7238C22.3819 13.5407 22.4935 13.2887 22.4997 13.0235C22.5001 13.0075 22.5001 12.9915 22.4997 12.9755C22.4936 12.727 22.3952 12.4896 22.2236 12.3097C22.0348 12.1119 21.7734 12 21.5 12L21.4718 12.0004C21.2245 12.0074 20.9887 12.1057 20.8097 12.2764L14.1631 18.6174L11.1909 15.777Z"
                                        fill="currentColor"></path>
                                </svg>
                                <span>Salvar Alterações</span>
                            </button>
                        </div>
                    </form>
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
        document.getElementById('form-gateway-config')?.addEventListener('submit', function (e) {
            e.preventDefault();
            const form = this;
            
            // Verificar se apenas um gateway está ativo
            const checkboxes = form.querySelectorAll('input[type=checkbox][name$="_ativo"]');
            let checkedCount = 0;
            checkboxes.forEach(cb => { if (cb.checked) checkedCount++; });
            
            if (checkedCount === 0) {
                showToast('É necessário ativar pelo menos um gateway.', 'error');
                return;
            }
            
            if (checkedCount > 1) {
                showToast('Só é permitido ativar um gateway por vez.', 'error');
                return;
            }
            
            const fd = new FormData(form);
            fd.append('ajax_gateway_config', 1);
            fetch('pagamentos', { method: 'POST', body: fd })
                .then(r => r.json())
                .then(data => {
                    showToast(data.message, data.success ? 'success' : 'error');
                });
        });
        
        // Lógica para garantir que apenas um gateway esteja ativo por vez
        const gatewayChecks = document.querySelectorAll('input[type=checkbox][name$="_ativo"]');
        gatewayChecks.forEach(cb => {
            cb.addEventListener('change', function() {
                if (this.checked) {
                    // Desmarca todos os outros
                    gatewayChecks.forEach(other => { 
                        if (other !== this) other.checked = false; 
                    });
                }
            });
        });
    </script>

</body>

</html>