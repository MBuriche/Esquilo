<?php
include_once "services/database.php";
// --- CORES DO SITE ---
$resCores = $mysqli->query("SELECT cor_padrao, background_padrao FROM config WHERE id=1");
$cores = $resCores && ($rowCores = $resCores->fetch_assoc()) ? $rowCores : [
    'cor_padrao' => '#000000',
    'background_padrao' => '#ffffff'
];
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax_cores'])) {
    header('Content-Type: application/json');
    $cor_padrao = $_POST['cor_padrao'] ?? '';
    $background_padrao = $_POST['background_padrao'] ?? '';
    if (!preg_match('/^#[0-9a-fA-F]{6}$/', $cor_padrao) || !preg_match('/^#[0-9a-fA-F]{6}$/', $background_padrao)) {
        echo json_encode(['success' => false, 'message' => 'Cores inválidas!']);
        exit;
    }
    $ok = $mysqli->query("UPDATE config SET cor_padrao='$cor_padrao', background_padrao='$background_padrao' WHERE id=1");
    echo json_encode([
        'success' => $ok,
        'message' => $ok ? 'Cores salvas com sucesso!' : 'Erro ao salvar cores.'
    ]);
    exit;
}
?>
<!DOCTYPE html>
<html x-data="main" class="" :class="[$store.app.mode]">
<?php include "partes/head.php"; ?>
<body x-data="main"
    class="antialiased relative font-inter bg-white dark:bg-black text-black dark:text-white text-sm font-normal overflow-x-hidden vertical"
    :class="[ $store.app.sidebar ? 'toggle-sidebar' : '', $store.app.rightsidebar ? 'right-sidebar' : '', $store.app.menu, $store.app.layout]">
    <div x-cloak class="fixed inset-0 bg-[black]/60 z-40 lg:hidden" :class="{'hidden' : !$store.app.sidebar}"
        @click="$store.app.toggleSidebar()"></div>
    <div x-cloak class="fixed inset-0 bg-[black]/60 z-50 2xl:hidden" :class="{'hidden' : !$store.app.rightsidebar}"
        @click="$store.app.rightSidebar()"></div>
    <div class="main-container navbar-sticky flex" :class="[$store.app.navbar]">
        <nav class="sidebar fixed top-0 bottom-0 z-40 flex-none w-[212px] border-r border-black/10 dark:border-white/10 transition-all duration-300">
            <div class="bg-white dark:bg-black h-full">
                <?php include 'partes/menu-lateral.php'; ?>
            </div>
        </nav>
        <div class="main-content flex-1">
            <?php include 'partes/topbar.php'; ?>
            <div class="h-[calc(100vh-73px)] overflow-y-auto overflow-x-hidden">
                <div class="p-4 sm:p-7 min-h-[calc(100vh-145px)]">
                    <h2 class="text-lg font-semibold mb-6">Cores do Site</h2>
                    <form id="form-cores-site" class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-10">
                        <div x-data="{ cor: '<?php echo htmlspecialchars($cores['cor_padrao']); ?>' }" class="flex flex-col gap-2">
                            <label class="font-semibold text-sm">Cor Padrão</label>
                            <div class="flex items-center gap-2">
                                <input type="text" name="cor_padrao" x-model="cor" class="form-input w-full border border-black/10 dark:border-white/10 bg-transparent px-3 py-2.5 placeholder:text-black/60 dark:placeholder:text-white/60 hover:z-10 hover:border-black dark:hover:border-white focus:z-10 focus:border-black dark:focus:border-white rounded-lg" />
                                <input type="color" x-model="cor" class="w-10 h-10 border-2 border-black/10 dark:border-white/10 rounded-lg cursor-pointer bg-transparent" />
                            </div>
                        </div>
                        <div x-data="{ cor: '<?php echo htmlspecialchars($cores['background_padrao']); ?>' }" class="flex flex-col gap-2">
                            <label class="font-semibold text-sm">Cor de Fundo</label>
                            <div class="flex items-center gap-2">
                                <input type="text" name="background_padrao" x-model="cor" class="form-input w-full border border-black/10 dark:border-white/10 bg-transparent px-3 py-2.5 placeholder:text-black/60 dark:placeholder:text-white/60 hover:z-10 hover:border-black dark:hover:border-white focus:z-10 focus:border-black dark:focus:border-white rounded-lg" />
                                <input type="color" x-model="cor" class="w-10 h-10 border-2 border-black/10 dark:border-white/10 rounded-lg cursor-pointer bg-transparent" />
                            </div>
                        </div>
                        <div class="md:col-span-2 flex justify-center mt-4">
                            <button type="submit" class="btn px-6 py-2 bg-lightgreen-100 dark:bg-lightgreen-100 text-black dark:text-black hover:bg-lightgreen-200 dark:hover:bg-lightpurple-200 hover:text-black dark:hover:text-black rounded-lg font-semibold">Salvar Cores</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <?php include 'partes/notificacao.php'; ?>
    </div>
    <?php include 'partes/footer.php'; ?>
    <div id="toast-area" class="fixed bottom-10 right-10 z-[999999] flex flex-col items-end gap-2 pointer-events-auto drop-shadow-2xl"></div>
    <script src="assets/js/toast.js"></script>
    <script>
    document.getElementById('form-cores-site')?.addEventListener('submit', function(e) {
        e.preventDefault();
        const fd = new FormData(this);
        fd.append('ajax_cores', 1);
        fetch('cores.php', { method: 'POST', body: fd })
            .then(r => r.json())
            .then(data => {
                showToast(data.message, data.success ? 'success' : 'error');
            });
    });
    </script>
</body>
</html>