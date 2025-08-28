<?php
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
if (!admin_has_permission('gerenciar_usuarios')) {
    include 'partes/sem-permissao.php';
    exit;
}
// Buscar raspadinha
$id = isset($_GET['id']) ? (int) $_GET['id'] : 0;
$stmt = $mysqli->prepare("SELECT * FROM raspadinhas WHERE id = ?");
$stmt->bind_param('i', $id);
$stmt->execute();
$res = $stmt->get_result();
$raspadinha = $res ? $res->fetch_assoc() : null;
$stmt->close();
if (!$raspadinha) {
    echo '<div class="p-8 text-center text-red-600 font-bold">Raspadinha não encontrada.</div>';
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
        <nav
            class="sidebar fixed top-0 bottom-0 z-40 flex-none w-[212px] border-r border-black/10 dark:border-white/10 transition-all duration-300">
            <div class="bg-white dark:bg-black h-full">
                <?php include 'partes/menu-lateral.php'; ?>
            </div>
        </nav>
        <div class="main-content flex-1">
            <?php include 'partes/topbar.php'; ?>
            <div class="h-[calc(100vh-73px)] overflow-y-auto overflow-x-hidden">
                <div class="p-7 min-h-[calc(100vh-145px)]">
                    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-6">
                        <div>
                            <h2 class="text-2xl font-bold text-black dark:text-white mb-1">Gerenciar Prêmios</h2>
                            <div class="text-sm text-gray-500">Raspadinha: <span
                                    class="font-semibold text-black dark:text-white"><?php echo htmlspecialchars($raspadinha['name']); ?></span>
                            </div>
                        </div>
                        <a href="raspadinhas.php"
                            class="inline-flex items-center gap-2 px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-200 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 font-semibold transition"><svg
                                class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M15 19l-7-7 7-7" />
                            </svg>Voltar</a>
                    </div>
                    <div id="premios-area"></div>
                </div>
            </div>
        </div>
        <?php include 'partes/notificacao.php'; ?>
    </div>
    <?php include 'partes/footer.php'; ?>
    <div id="toast-area"
        class="fixed bottom-10 right-10 z-[999999] flex flex-col items-end gap-2 pointer-events-auto drop-shadow-2xl">
    </div>
    <script src="assets/js/toast.js"></script>
    <script>
        // Funções AJAX para listar, adicionar, editar, remover prêmios
        // Renderização dinâmica do conteúdo
        const idRaspadinha = <?php echo (int) $raspadinha['id']; ?>;
        let premiosPage = 1;
        let premiosLimit = 5;
        let removendoPremio = false;
        function renderPremiosArea() {
            document.getElementById('premios-area').innerHTML = `
<div x-data="{ modalOpen: false }" class='flex flex-col gap-6'>
    <div class="flex justify-end mb-4">
        <button type="button" @click="modalOpen = true" class="px-4 py-2 bg-lightgreen-100 dark:bg-lightgreen-100 text-black dark:text-black hover:bg-lightgreen-200 dark:hover:bg-lightpurple-200 rounded-lg font-semibold shadow transition flex items-center gap-2">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4"/></svg>
            Adicionar Prêmio
        </button>
    </div>
    <!-- Modal -->
    <div x-show="modalOpen" x-cloak x-data="{ isSubmitting: false }" class="fixed inset-0 bg-black/60 dark:bg-white/10 z-[999] flex items-center justify-center overflow-y-auto p-4 transition-all duration-300">
        <div @click.away="modalOpen = false" class="bg-white dark:bg-black relative shadow-3xl border-0 p-0 rounded-lg overflow-hidden w-full max-w-lg my-8 animate-fade-in-up">
            <div class="flex bg-white dark:bg-black border-b border-black/10 dark:border-white/10 items-center justify-between px-5 py-4">
                <h3 class="font-bold text-xl text-black dark:text-white">Adicionar Prêmio</h3>
                <button type="button" class="text-black/40 dark:text-white/40 hover:text-black dark:hover:text-white" @click="modalOpen = false">
                    <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M24.2929 6.29289L6.29289 24.2929C6.10536 24.4804 6 24.7348 6 25C6 25.2652 6.10536 25.5196 6.29289 25.7071C6.48043 25.8946 6.73478 26 7 26C7.26522 26 7.51957 25.8946 7.70711 25.7071L25.7071 7.70711C25.8946 7.51957 26 7.26522 26 7C26 6.73478 25.8946 6.48043 25.7071 6.29289C25.5196 6.10536 25.2652 6 25 6C24.7348 6 24.4804 6.10536 24.2929 6.29289Z" fill="currentcolor"></path>
                        <path d="M7.70711 6.29289C7.51957 6.10536 7.26522 6 7 6C6.73478 6 6.48043 6.10536 6.29289 6.29289C6.10536 6.48043 6 6.73478 6 7C6 7.26522 6.10536 7.51957 6.29289 7.70711L24.2929 25.7071C24.48043 25.8946 24.7348 26 25 26C25.2652 26 25.51957 25.8946 25.7071 25.7071C25.8946 25.5196 26 25.2652 26 25C26 24.7348 25.8946 24.4804 25.7071 24.2929L7.70711 6.29289Z" fill="currentcolor"></path>
                    </svg>
                </button>
            </div>
            <form @submit.prevent="if (!isSubmitting) { isSubmitting = true; adicionarPremioRaspadinha().finally(() => isSubmitting = false); }" class="space-y-5 px-6 py-6" enctype="multipart/form-data">
                <div class="space-y-2">
                    <label class="form-label font-semibold">Prêmio</label>
                    <div x-data="{
                                open: false,
                                selected: null,
                                options: [],
                                filteredOptions: [],
                                search: '',
                                placeholder: 'Selecione...',
                                currentPage: 1,
                                perPage: 2,
                                isLoading: false,
                                async fetchOptions() {
                                    if (this.isLoading || this.options.length > 0) return;
                                    this.isLoading = true;
                                    const res = await fetch('raspadinhas.php?get_all_rewards=1');
                                    this.options = await res.json();
                                    this.filteredOptions = this.options;
                                    this.isLoading = false;
                                },
                                select(option) {
                                    this.selected = option;
                                    this.open = false;
                                    $refs.rewardId.value = option.id;
                                },
                                displayText() {
                                    if (this.selected) {
                                        return this.selected.name + ' - R$ ' + (Number(this.selected.amount)/100).toFixed(2);
                                    }
                                    return this.placeholder;
                                },
                                handleDropdownScroll(e) {
                                    const el = e.currentTarget;
                                    const scrollTop = el.scrollTop;
                                    const scrollHeight = el.scrollHeight;
                                    const clientHeight = el.clientHeight;
                                    const delta = e.deltaY;
                                    if (scrollHeight <= clientHeight) return;
                                    if (scrollTop === 0 && delta < 0) {
                                        e.preventDefault();
                                        return;
                                    }
                                    if (scrollTop + clientHeight >= scrollHeight && delta > 0) {
                                        e.preventDefault();
                                        return;
                                    }
                                },
                                filterOptions() {
                                    const term = this.search.toLowerCase();
                                    this.filteredOptions = this.options.filter(opt => opt.name.toLowerCase().includes(term));
                                    this.currentPage = 1;
                                },
                                paginatedOptions() {
                                    const start = (this.currentPage - 1) * this.perPage;
                                    return this.filteredOptions.slice(start, start + this.perPage);
                                },
                                totalPages() {
                                    return Math.max(1, Math.ceil(this.filteredOptions.length / this.perPage));
                                }
                            }"
                            x-init="fetchOptions()"
                            class="relative">
                            <button type="button" @click="open = !open" @keydown.arrow-down.prevent="open = true" @keydown.enter.prevent="open = !open" class="form-input w-full border border-black/10 dark:border-white/10 bg-transparent px-3 py-2.5 text-left text-black dark:text-white placeholder:text-black/60 dark:placeholder:text-white/60 hover:z-10 hover:border-black dark:hover:border-white focus:z-10 focus:border-black dark:focus:border-white rounded-lg transition flex items-center justify-between">
                                <span x-text='displayText()' :class="{'text-black/60 dark:text-white/60': !selected}"></span>
                                <svg class="w-4 h-4 ml-2 text-black/40 dark:text-white/40" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7"/></svg>
                            </button>
                            <input type="hidden" x-ref="rewardId" id="add-reward-id" name="add-reward-id">
                            <div x-show="open" @mousedown.away="open = false" @keydown.escape.window="open = false" @wheel.stop="handleDropdownScroll($event)"
                                x-transition:enter="transition ease-out duration-100"
                                x-transition:enter-start="opacity-0 scale-95"
                                x-transition:enter-end="opacity-100 scale-100"
                                x-transition:leave="transition ease-in duration-75"
                                x-transition:leave-start="opacity-100 scale-100"
                                x-transition:leave-end="opacity-0 scale-95"
                                class="absolute left-0 mt-1 w-full bg-white dark:bg-black border border-black/10 dark:border-white/10 rounded-lg shadow-lg z-50 max-h-60 overflow-y-auto scrollbar-thin scrollbar-thumb-blue-200 dark:scrollbar-thumb-blue-900 scrollbar-track-transparent transition-all">
                                <div class="p-2 sticky top-0 bg-white dark:bg-black z-10">
                                    <input type="text" x-model="search" @input="filterOptions()" placeholder="Pesquisar..." class="form-input w-full border border-black/10 dark:border-white/10 bg-transparent px-3 py-2.5 text-black dark:text-white placeholder:text-black/60 dark:placeholder:text-white/60 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition" autocomplete="off">
                                </div>
                                <template x-for="option in paginatedOptions()" :key="option.id">
                                    <div @click="select(option); open = false" class="px-4 py-2 cursor-pointer hover:bg-blue-100 dark:hover:bg-blue-900/40 flex items-center gap-2 transition-all"
                                        :class="{'bg-blue-600 text-white dark:bg-blue-400 dark:text-black font-semibold': selected && selected.id === option.id}">
                                        <span x-text="option.name"></span>
                                        <span class="ml-auto text-xs text-gray-500 dark:text-gray-300">R$ <span x-text="(option.amount/100).toFixed(2)"></span></span>
                                    </div>
                                </template>
                                <div x-show="filteredOptions.length === 0" class="px-4 py-2 text-gray-400">Nenhum prêmio disponível</div>
                                <div class="flex items-center justify-between px-2 py-1 border-t border-black/10 dark:border-white/10 bg-white dark:bg-black sticky bottom-0 z-10">
                                    <button type="button" class="px-2 py-1 text-xs rounded hover:bg-black/10 dark:hover:bg-white/10" :disabled="currentPage === 1" @click="currentPage = Math.max(1, currentPage - 1)">Anterior</button>
                                    <span class="text-xs text-gray-500" x-text="currentPage + ' / ' + totalPages()"></span>
                                    <button type="button" class="px-2 py-1 text-xs rounded hover:bg-black/10 dark:hover:bg-white/10" :disabled="currentPage === totalPages()" @click="currentPage = Math.min(totalPages(), currentPage + 1)">Próxima</button>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="space-y-2">
                    <label class="form-label font-semibold">Probabilidade</label>
                    <input id="add-reward-prob" name="add-reward-prob" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition" placeholder="0.05" value="0.05">
                </div>
                <div class="space-y-2">
                    <label class="form-label font-semibold">Ordem</label>
                    <input id="add-reward-order" name="add-reward-order" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition" placeholder="0" type="number" value="0">
                </div>
                <div class="flex gap-2 pt-4 justify-end">
                    <button type="submit" :disabled="isSubmitting" class="px-4 py-2 bg-gray-900 dark:bg-white text-white dark:text-black rounded-lg hover:bg-gray-800 dark:hover:bg-gray-200 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 font-semibold transition disabled:opacity-60 disabled:pointer-events-none">
                        Adicionar
                    </button>
                    <button type="button" @click="modalOpen = false" class="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 font-semibold transition">
                        Cancelar
                    </button>
                </div>
                </div>
                <p class="text-xs text-gray-500">* Campos obrigatórios</p>
            </form>
        </div>
    </div>
    <div class='overflow-x-auto rounded-lg border border-black/10 dark:border-white/10 min-w-full max-w-full mt-4'>
        <table class='min-w-[700px] w-full divide-y divide-black/10 dark:divide-white/10 text-xs'>
                    <thead class='bg-gray-100 dark:bg-white/10 sticky top-0 z-10'>
                        <tr>
                            <th class='px-2 py-2 text-left whitespace-nowrap'>Imagem</th>
                            <th class='px-2 py-2 text-left whitespace-nowrap'>Nome</th>
                            <th class='px-2 py-2 text-left whitespace-nowrap'>Valor</th>
                            <th class='px-2 py-2 text-left whitespace-nowrap'>Probabilidade</th>
                            <th class='px-2 py-2 text-left whitespace-nowrap'>Ordem</th>
                            <th class='px-2 py-2 text-left whitespace-nowrap'>Status</th>
                            <th class='px-2 py-2 text-left whitespace-nowrap'>Ações</th>
                        </tr>
                    </thead>
                    <tbody id='premios-table-body' class='bg-white dark:bg-black'></tbody>
                </table>
                <div id='premios-pagination' class='mt-4'></div>
            </div>
        </div>`;
            carregarTodosPremios();
            carregarPremiosRaspadinha(idRaspadinha, premiosPage, premiosLimit);
            setTimeout(() => {
                // Botão para abrir modal
                document.getElementById('abrir-modal-adicionar-premio')?.addEventListener('click', function () {
                    const modal = document.getElementById('modal-adicionar-premio');
                    if (modal && modal.__x) modal.__x.$data.open = true;
                    // Renderizar o formulário dentro do modal
                    document.getElementById('form-adicionar-premio-modal').innerHTML = `<div class='flex flex-col gap-4'>
            <div class='flex flex-col sm:flex-row gap-4 items-end'>
                <div class='flex-1 min-w-[180px]'>
                    <label class='form-label font-semibold'>Prêmio</label>
                    <!-- select customizado aqui (copiar o bloco Alpine.js do select) -->
                </div>
                <div class='flex-1 min-w-[120px]'>
                    <label class='form-label font-semibold'>Probabilidade</label>
                    <input id="add-reward-prob" name="add-reward-prob" class="form-input w-full border border-black/10 dark:border-white/10 bg-transparent px-3 py-2.5 placeholder:text-black/60 dark:placeholder:text-white/60 hover:z-10 hover:border-black dark:hover:border-white focus:z-10 focus:border-black dark:focus:border-white rounded-lg" placeholder="0.05" type="number" value="0.05" min="0" max="1">
                </div>
                <div class='flex-1 min-w-[80px]'>
                    <label class='form-label font-semibold'>Ordem</label>
                    <input id="add-reward-order" name="add-reward-order" class="form-input w-full border border-black/10 dark:border-white/10 bg-transparent px-3 py-2.5 placeholder:text-black/60 dark:placeholder:text-white/60 hover:z-10 hover:border-black dark:hover:border-white focus:z-10 focus:border-black dark:focus:border-white rounded-lg" placeholder="0" type="number" value="0">
                </div>
            </div>
            <div class='flex justify-end'>
                <button type='button' id='add-reward-btn-modal' class='px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg font-semibold shadow transition flex items-center gap-2'><svg class='w-4 h-4' fill='none' stroke='currentColor' stroke-width='2' viewBox='0 0 24 24'><path stroke-linecap='round' stroke-linejoin='round' d='M12 4v16m8-8H4'/></svg>Adicionar</button>
            </div>
        </div>`;
                    // Adicionar event listener ao botão do modal
                    document.getElementById('add-reward-btn-modal')?.addEventListener('click', adicionarPremioRaspadinha);
                });
                document.getElementById('premios-table-body')?.addEventListener('change', function (e) {
                    const t = e.target;
                    if (t.dataset && t.dataset.id && t.dataset.field) {
                        atualizarCampoPremio(t.dataset.id, t.dataset.field, t.type === 'checkbox' ? (t.checked ? 1 : 0) : t.value);
                    }
                });
            }, 500);
        }
        function carregarTodosPremios() {
            fetch('raspadinhas.php?get_all_rewards=1')
                .then(r => r.json())
                .then(data => {
                    const sel = document.getElementById('add-reward-select');
                    sel.innerHTML = '<option value="">Selecione...</option>';
                    data.forEach(item => {
                        sel.innerHTML += `<option value='${item.id}'>${item.name} - R$ ${(item.amount / 100).toFixed(2)}</option>`;
                    });
                });
        }
        function carregarPremiosRaspadinha(scratchId, page = 1, limit = 5) {
            premiosPage = page;
            premiosLimit = limit;
            fetch(`raspadinhas.php?get_rewards_for_scratch=${scratchId}&page=${page}&limit=${limit}`)
                .then(r => r.json())
                .then(data => {
                    renderizarTabelaPremios(data);
                });
        }
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
                <td class='px-2 py-2 font-mono text-green-700 dark:text-green-400'>R$ ${(item.amount / 100).toFixed(2)}</td>
                <td class='px-2 py-2'><input name="reward-${item.id}-probability" class="form-input w-full border border-black/10 dark:border-white/10 bg-transparent px-3 py-2.5 placeholder:text-black/60 dark:placeholder:text-white/60 hover:z-10 hover:border-black dark:hover:border-white focus:z-10 focus:border-black dark:focus:border-white rounded-lg" placeholder="0.05" type="number" value="${item.probability}" min="0" max="1" data-id='${item.id}' data-field='probability'></td>
                <td class='px-2 py-2'><input name="reward-${item.id}-sort_order" class="form-input w-full border border-black/10 dark:border-white/10 bg-transparent px-3 py-2.5 placeholder:text-black/60 dark:placeholder:text-white/60 hover:z-10 hover:border-black dark:hover:border-white focus:z-10 focus:border-black dark:focus:border-white rounded-lg" placeholder="0" type="number" value="${item.sort_order}" data-id='${item.id}' data-field='sort_order'></td>
                <td class='px-2 py-2'>
                    <input type="checkbox" class="form-checkbox text-lightgreen-200 rounded-full" ${item.is_active == 1 ? 'checked' : ''} onchange="toggleAtivoPremioCheckbox(${item.id}, this)">
                </td>
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
            let html = `<div class='flex w-full justify-end pr-4 mb-2'>`;
            html += `<ul class='inline-flex items-center space-x-1'>`;
            html += `<li><button type="button" class="flex justify-center px-3.5 py-2 rounded transition text-black/60 hover:text-white bg-black/10 hover:bg-black dark:text-white/60 dark:hover:text-black dark:bg-white/10 dark:hover:bg-white ${page == 1 ? 'pointer-events-none opacity-50' : ''}" onclick='mudarPaginaPremios(1);return false;'>First</button></li>`;
            html += `<li><button type="button" class="flex justify-center px-3.5 py-2 rounded transition text-black/60 hover:text-white bg-black/10 hover:bg-black dark:text-white/60 dark:hover:text-black dark:bg-white/10 dark:hover:bg-white ${page == 1 ? 'pointer-events-none opacity-50' : ''}" onclick='mudarPaginaPremios(${page - 1});return false;'>Prev</button></li>`;
            for (let i = Math.max(1, page - 2); i <= Math.min(totalPages, page + 2); i++) {
                if (i == page) {
                    html += `<li><button type="button" class="flex justify-center px-3.5 py-2 rounded transition text-white bg-black dark:text-black dark:bg-white">${i}</button></li>`;
                } else {
                    html += `<li><button type="button" class="flex justify-center px-3.5 py-2 rounded transition text-black/60 hover:text-white bg-black/10 hover:bg-black dark:text-white/60 dark:hover:text-black dark:bg-white/10 dark:hover:bg-white" onclick='mudarPaginaPremios(${i});return false;'>${i}</button></li>`;
                }
            }
            html += `<li><button type="button" class="flex justify-center px-3.5 py-2 rounded transition text-black/60 hover:text-white bg-black/10 hover:bg-black dark:text-white/60 dark:hover:text-black dark:bg-white/10 dark:hover:bg-white ${page == totalPages ? 'pointer-events-none opacity-50' : ''}" onclick='mudarPaginaPremios(${page + 1});return false;'>Next</button></li>`;
            html += `<li><button type="button" class="flex justify-center px-3.5 py-2 rounded transition text-black/60 hover:text-white bg-black/10 hover:bg-black dark:text-white/60 dark:hover:text-black dark:bg-white/10 dark:hover:bg-white ${page == totalPages ? 'pointer-events-none opacity-50' : ''}" onclick='mudarPaginaPremios(${totalPages});return false;'>Last</button></li>`;
            html += `</ul></div>`;
            pag.innerHTML = html;
        }
        function mudarPaginaPremios(p) {
            carregarPremiosRaspadinha(idRaspadinha, p, premiosLimit);
        }
        // Substituir a função adicionarPremioRaspadinha para proteger contra null e mostrar toast amigável
        async function adicionarPremioRaspadinha() {
            const rewardInput = document.getElementById('add-reward-id');
            if (!rewardInput || !rewardInput.value) {
                showToast('Selecione um prêmio antes de adicionar.', 'error');
                return;
            }
            const rewardId = rewardInput.value;
            const prob = document.getElementById('add-reward-prob').value;
            const order = document.getElementById('add-reward-order').value;
            if (!rewardId || !prob) return showToast('Selecione o prêmio e a probabilidade', 'error');
            const fd = new FormData();
            fd.append('ajax_scratch_reward', 1);
            fd.append('acao', 'adicionar');
            fd.append('scratch_card_id', idRaspadinha);
            fd.append('reward_id', rewardId);
            fd.append('probability', prob);
            fd.append('sort_order', order);
            try {
                const r = await fetch('raspadinhas.php', { method: 'POST', body: fd });
                const text = await r.text();
                let data;
                try {
                    data = JSON.parse(text);
                } catch (e) {
                    showToast('Erro inesperado: ' + text.slice(0, 200), 'error');
                    throw e;
                }
                showToast(data.message, data.success ? 'success' : 'error');
                if (data.success) carregarPremiosRaspadinha(idRaspadinha);
            } finally {
                // handled by .finally in form
            }
        }
        function atualizarCampoPremio(id, campo, valor) {
            const fd = new FormData();
            fd.append('ajax_scratch_reward', 1);
            fd.append('acao', 'editar');
            fd.append('id', id);
            fd.append('campo', campo);
            fd.append('valor', valor);
            fetch('raspadinhas.php', { method: 'POST', body: fd })
                .then(r => r.json())
                .then(data => {
                    showToast(data.message, data.success ? 'success' : 'error');
                });
        }
        function removerPremioRaspadinha(id) {
            if (removendoPremio) return;
            removendoPremio = true;
            if (!confirm('Tem certeza que deseja remover este prêmio?')) { removendoPremio = false; return; }
            const fd = new FormData();
            fd.append('ajax_scratch_reward', 1);
            fd.append('acao', 'remover');
            fd.append('id', id);
            fetch('raspadinhas.php', { method: 'POST', body: fd })
                .then(r => r.json())
                .then(data => {
                    showToast(data.message, data.success ? 'success' : 'error');
                    if (data.success) carregarPremiosRaspadinha(idRaspadinha);
                })
                .finally(() => { removendoPremio = false; });
        }
        // Checkbox AJAX para ativar/desativar prêmio
        function toggleAtivoPremioCheckbox(id, input) {
            const novo = input.checked ? 1 : 0;
            const fd = new FormData();
            fd.append('ajax_scratch_reward', 1);
            fd.append('acao', 'editar');
            fd.append('id', id);
            fd.append('campo', 'is_active');
            fd.append('valor', novo);
            fetch('raspadinhas.php', { method: 'POST', body: fd })
                .then(r => r.json())
                .then(data => {
                    showToast(data.message, data.success ? 'success' : 'error');
                    if (!data.success) {
                        input.checked = !novo;
                    }
                });
        }
        // Inicialização
        document.addEventListener('DOMContentLoaded', function () {
            const premiosArea = document.getElementById('premios-area');
            if (premiosArea) renderPremiosArea();
        });
    </script>
</body>

</html>