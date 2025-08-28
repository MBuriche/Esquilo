<?php
// --- BACKEND: Upload, Remoção e Atualização dos campos de imagem ---
include_once "services/database.php";

function getConfigImages($mysqli)
{
    $res = $mysqli->query("SELECT logo, favicon, btn_deposit, btn_play, btn_receive, gamebg, ui_share, ui_social, ui_support FROM config WHERE id=1");
    if ($res && ($row = $res->fetch_assoc())) {
        return $row;
    }
    return [
        'logo' => '',
        'favicon' => '',
        'btn_deposit' => '',
        'btn_play' => '',
        'btn_receive' => '',
        'gamebg' => '',
        'ui_share' => '',
        'ui_social' => '',
        'ui_support' => ''
    ];
}

function deleteImageFile($path)
{
    if ($path && file_exists(__DIR__ . '/../' . $path)) {
        @unlink(__DIR__ . '/../' . $path);
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax_imagem'])) {
    header('Content-Type: application/json');
    session_start();
    $campo = $_POST['campo'] ?? '';
    $acao = $_POST['acao'] ?? '';
    $permitidos = ['logo', 'favicon', 'btn_deposit', 'btn_play', 'btn_receive', 'gamebg', 'ui_share', 'ui_social', 'ui_support'];
    if (!in_array($campo, $permitidos)) {
        echo json_encode(['success' => false, 'message' => 'Campo inválido!']);
        exit;
    }
    // Remover imagem ou link
    if ($acao === 'remover') {
        $res = $mysqli->query("SELECT `$campo` FROM config WHERE id=1");
        $img = '';
        if ($res && ($row = $res->fetch_assoc())) {
            $img = $row[$campo];
        }
        // Só remove arquivo se for caminho local
        if ($img && !preg_match('/^https?:\/\//', $img))
            deleteImageFile($img);
        $mysqli->query("UPDATE config SET `$campo`=NULL WHERE id=1");
        echo json_encode(['success' => true, 'message' => 'Imagem removida com sucesso!', 'url' => '']);
        exit;
    }
    // Upload de imagem
    if ($acao === 'upload' && isset($_FILES['imagem'])) {
        $file = $_FILES['imagem'];
        if ($file['error'] !== 0) {
            echo json_encode(['success' => false, 'message' => 'Erro no upload!']);
            exit;
        }
        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($ext, ['jpg', 'jpeg', 'png', 'webp', 'svg', 'ico', 'gif'])) { // Aceita gif
            echo json_encode(['success' => false, 'message' => 'Formato não permitido!']);
            exit;
        }
        
        // Definir nome específico para logo e favicon
        if ($campo === 'logo') {
            $nome = 'logo.png';
            $dest = 'storage/' . $nome;
        } elseif ($campo === 'favicon') {
            $nome = 'favicon.png';
            $dest = 'storage/' . $nome;
        } elseif ($campo === 'btn_deposit') {
            $nome = 'btn_deposit.png';
            $dest = 'storage/' . $nome;
        } elseif ($campo === 'btn_play') {
            $nome = 'btn_play.png';
            $dest = 'storage/' . $nome;
        } elseif ($campo === 'btn_receive') {
            $nome = 'btn_receive.png';
            $dest = 'storage/' . $nome;
        } elseif ($campo === 'gamebg') {
            $nome = 'gamebg.png';
            $dest = 'storage/' . $nome;
        } elseif ($campo === 'ui_share') {
            $nome = 'ui_share.png';
            $dest = 'storage/' . $nome;
        } elseif ($campo === 'ui_social') {
            $nome = 'ui_social.png';
            $dest = 'storage/' . $nome;
        } elseif ($campo === 'ui_support') {
            $nome = 'ui_support.png';
            $dest = 'storage/' . $nome;
        } else {
            $nome = uniqid($campo . '_') . '.' . $ext;
            $dest = 'tmp/imagens/' . $nome;
        }
        
        // Criar diretório se não existir
        if (in_array($campo, ['logo', 'favicon', 'btn_deposit', 'btn_play', 'btn_receive', 'gamebg', 'ui_share', 'ui_social', 'ui_support'])) {
            if (!is_dir(__DIR__ . '/../storage/')) {
                mkdir(__DIR__ . '/../storage/', 0777, true);
            }
        } else {
            if (!is_dir(__DIR__ . '/../tmp/imagens/')) {
                mkdir(__DIR__ . '/../tmp/imagens/', 0777, true);
            }
        }
        
        if (!move_uploaded_file($file['tmp_name'], __DIR__ . '/../' . $dest)) {
            echo json_encode(['success' => false, 'message' => 'Falha ao salvar imagem!']);
            exit;
        }
        
        // Remove imagem antiga se for arquivo local
        $res = $mysqli->query("SELECT `$campo` FROM config WHERE id=1");
        $img = '';
        if ($res && ($row = $res->fetch_assoc())) {
            $img = $row[$campo];
        }
        if ($img && !preg_match('/^https?:\/\//', $img))
            deleteImageFile($img);
        $mysqli->query("UPDATE config SET `$campo`='$dest' WHERE id=1");
        echo json_encode(['success' => true, 'message' => 'Imagem atualizada com sucesso!', 'url' => $dest]);
        exit;
    }
    // Salvar link
    if ($acao === 'link' && isset($_POST['link'])) {
        $link = trim($_POST['link']);
        if (!filter_var($link, FILTER_VALIDATE_URL)) {
            echo json_encode(['success' => false, 'message' => 'Link inválido!']);
            exit;
        }
        // Remove imagem antiga se for arquivo local
        $res = $mysqli->query("SELECT `$campo` FROM config WHERE id=1");
        $img = '';
        if ($res && ($row = $res->fetch_assoc())) {
            $img = $row[$campo];
        }
        if ($img && !preg_match('/^https?:\/\//', $img))
            deleteImageFile($img);
        $mysqli->query("UPDATE config SET `$campo`='$link' WHERE id=1");
        echo json_encode(['success' => true, 'message' => 'Link salvo com sucesso!', 'url' => $link]);
        exit;
    }
    echo json_encode(['success' => false, 'message' => 'Ação inválida!']);
    exit;
}

// --- FRONTEND ---
$imagens = getConfigImages($mysqli);
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
            <!-- Modal de confirmação de exclusão -->
            <div x-data="{ open: false, campo: null }" x-show="open" x-cloak
                @abrir-modal-remover.window="open = true; campo = $event.detail.campo"
                class="fixed inset-0 bg-black/60 dark:bg-white/10 z-[999] flex items-center justify-center overflow-y-auto p-4 transition-all duration-300">
                <div @click.away="open = false"
                    class="bg-white dark:bg-black relative shadow-3xl border-0 p-0 rounded-lg overflow-hidden w-full max-w-lg my-8 animate-fade-in-up">
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
                            <p>Tem certeza que deseja remover esta imagem? Esta ação não pode ser desfeita.</p>
                        </div>
                        <div class="flex justify-end items-center mt-8 gap-4">
                            <button type="button" class="btn !bg-gray-500 !text-white"
                                @click="open = false">Cancelar</button>
                            <button type="button" class="btn !bg-red-500 !text-white"
                                @click="open = false; window.removerImagem(campo);">Remover</button>
                        </div>
                    </div>
                </div>
            </div>
            <div class="h-[calc(100vh-73px)] overflow-y-auto overflow-x-hidden">
                <div class="p-4 sm:p-7 min-h-[calc(100vh-145px)]">
                    <h2 class="text-lg font-semibold mb-6">Imagens do Sistema</h2>
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                        <?php
                        $labels = [
                            'logo' => 'Logo Principal',
                            'favicon' => 'Favicon',
                            'btn_deposit' => 'Botão de Depósito',
                            'btn_play' => 'Botão de Jogar',
                            'btn_receive' => 'Botão de Recolher Prêmio',
                            'gamebg' => 'Imagem de Fundo do Jogo',
                            'ui_share' => 'Indique e Ganhe',
                            'ui_social' => 'Botão Social',
                            'ui_support' => 'Suporte',
                        ];
                        foreach ($labels as $campo => $label):
                            $url = $imagens[$campo] ?? '';
                            $is_link = $url && preg_match('/^https?:\/\//', $url);
                            $preview_url = $url ? ($is_link ? $url : ('../' . $url)) : '';
                            ?>
                            <div
                                class="border border-black/10 dark:border-white/10 p-5 rounded-md flex flex-col justify-between h-full items-center">
                                <span class="font-semibold mb-2"><?php echo $label; ?></span>
                                <div class="w-full flex flex-col items-center">
                                    <div
                                        class="w-28 h-32 sm:w-32 sm:h-36 mb-3 flex items-center justify-center bg-black/5 dark:bg-white/5 rounded overflow-hidden relative group">
                                        <img id="img-preview-<?php echo $campo; ?>" src="<?php echo $preview_url; ?>"
                                            alt="<?php echo $label; ?>" class="w-full h-full object-contain mx-auto"
                                            style="<?php echo $preview_url ? '' : 'display:none;'; ?>">
                                        <div id="img-placeholder-<?php echo $campo; ?>"
                                            class="absolute inset-0 flex items-center justify-center text-black/40 dark:text-white/40 text-xs"
                                            style="<?php echo $preview_url ? 'display:none;' : ''; ?>">Nenhuma imagem</div>
                                    </div>
                                </div>
                                <form class="w-full flex flex-col grow justify-end items-center gap-2"
                                    enctype="multipart/form-data" onsubmit="return false;">
                                    <div class="w-full flex flex-col gap-2">
                                        <label
                                            class="w-full h-16 flex items-center justify-center cursor-pointer border-2 border-dashed border-black/20 dark:border-white/20 rounded-lg p-2 hover:bg-black/5 dark:hover:bg-white/5 transition"
                                            ondragover="event.preventDefault();"
                                            ondrop="uploadImage(event, '<?php echo $campo; ?>');">
                                            <input type="file" accept="image/*" class="hidden"
                                                onchange="uploadImage(event, '<?php echo $campo; ?>');">
                                            <span class="text-xs text-black/60 dark:text-white/60">Arraste ou clique para
                                                enviar</span>
                                        </label>
                                        <div class="w-full h-16 flex flex-row items-center gap-2">
                                            <input type="text" id="input-link-<?php echo $campo; ?>"
                                                class="form-input w-full border border-black/10 dark:border-white/10 bg-transparent px-3 py-2.5 placeholder:text-black/60 dark:placeholder:text-white/60 hover:z-10 hover:border-black dark:hover:border-white focus:z-10 focus:border-black dark:focus:border-white rounded-lg"
                                                placeholder="Ou cole um link de imagem"
                                                value="<?php echo $is_link ? htmlspecialchars($url) : ''; ?>">
                                            <button type="button" onclick="salvarLink('<?php echo $campo; ?>')"
                                                class="btn px-2 bg-lightgreen-100 dark:bg-lightgreen-100 text-black dark:text-black hover:bg-lightgreen-200 dark:hover:bg-lightpurple-200 hover:text-black dark:hover:text-black">
                                                <svg class="w-4 h-4" width="32" height="32" viewBox="0 0 32 32" fill="none"
                                                    xmlns="http://www.w3.org/2000/svg">
                                                    <path fill-rule="evenodd" clip-rule="evenodd"
                                                        d="M11.4012 27.0849C11.4012 27.0849 10.9664 26.9028 9.6139 26.8843C9.6139 26.8843 8.4575 26.8685 7.88867 26.7645C7.88867 26.7645 6.77082 26.56 6.10539 25.8946C6.10539 25.8946 5.43594 25.2252 5.22844 24.0882C5.22844 24.0882 5.12294 23.5102 5.10465 22.3366C5.10465 22.3366 5.08389 21.0046 4.91418 20.5965C4.91418 20.5965 4.74093 20.18 3.79698 19.1924C3.79698 19.1924 2.98525 18.3431 2.6547 17.8655C2.6547 17.8655 2 16.9195 2 16C2 16 2 15.0846 2.64417 14.1522C2.64417 14.1522 2.96978 13.6809 3.77243 12.8434C3.77243 12.8434 4.7293 11.8449 4.91512 11.4012C4.91512 11.4012 5.09721 10.9664 5.1157 9.6139C5.1157 9.6139 5.13151 8.4575 5.23553 7.88867C5.23553 7.88867 5.43996 6.77082 6.10539 6.10539C6.10539 6.10539 6.77484 5.43594 7.91181 5.22844C7.91181 5.22844 8.48983 5.12294 9.66342 5.10465C9.66342 5.10465 10.9954 5.08389 11.4035 4.91418C11.4035 4.91418 11.82 4.74093 12.8076 3.79698C12.8076 3.79698 13.6569 2.98525 14.1345 2.6547C14.1345 2.6547 15.0805 2 16 2C16 2 16.9154 2 17.8478 2.64417C17.8478 2.64417 18.3191 2.96978 19.1566 3.77243C19.1566 3.77243 20.1551 4.7293 20.5988 4.91512C20.5988 4.91512 21.0336 5.09721 22.3861 5.1157C22.3861 5.1157 23.5425 5.13151 24.1113 5.23553C24.1113 5.23553 25.2292 5.43996 25.8946 6.10539C25.8946 6.10539 26.5641 6.77484 26.7716 7.91181C26.7716 7.91181 26.8771 8.48985 26.8953 9.66342C26.8953 9.66342 26.9161 10.9954 27.0858 11.4035C27.0858 11.4035 27.2591 11.82 28.203 12.8076C28.203 12.8076 29.0148 13.6569 29.3453 14.1345C29.3453 14.1345 30 15.0805 30 16C30 16 30 16.9154 29.3558 17.8478C29.3558 17.8478 29.0302 18.3191 28.2276 19.1566C28.2276 19.1566 27.2707 20.1551 27.0849 20.5988C27.0849 20.5988 26.9028 21.0336 26.8843 22.3861C26.8843 22.3861 26.8685 23.5425 26.7645 24.1113C26.7645 24.1113 26.56 25.2292 25.8946 25.8946C25.8946 25.8946 25.2252 26.5641 24.0882 26.7716C24.0882 26.7716 23.5102 26.8771 22.3366 26.8953C22.3366 26.8953 21.0046 26.9161 20.5965 27.0858C20.5965 27.0858 20.18 27.2591 19.1924 28.203C19.1924 28.203 18.3431 29.0148 17.8655 29.3453C17.8655 29.3453 16.9195 30 16 30C16 30 15.0846 30 14.1522 29.3558C14.1522 29.3558 13.6809 29.0302 12.8434 28.2276C12.8434 28.2276 11.8449 27.2707 11.4012 27.0849ZM12.1738 25.2401C12.1738 25.2401 12.9603 25.5695 14.2272 26.7836C14.2272 26.7836 15.4965 28 16 28C16 28 16.5103 28 17.8105 26.7572C17.8105 26.7572 19.0676 25.5556 19.8285 25.2392C19.8285 25.2392 20.5903 24.9223 22.3054 24.8956C22.3054 24.8956 24.0931 24.8677 24.4804 24.4804C24.4804 24.4804 24.8607 24.1001 24.8845 22.3588C24.8845 22.3588 24.9083 20.6186 25.2401 19.8262C25.2401 19.8262 25.5695 19.0397 26.7836 17.7728C26.7836 17.7728 28 16.5035 28 16C28 16 28 15.4897 26.7572 14.1895C26.7572 14.1895 25.5556 12.9324 25.2392 12.1715C25.2392 12.1715 24.9223 11.4097 24.8956 9.69459C24.8956 9.69459 24.8677 7.90694 24.4804 7.51961C24.4804 7.51961 24.1001 7.13932 22.3588 7.11551C22.3588 7.11551 20.6186 7.09172 19.8262 6.75988C19.8262 6.75988 19.0397 6.43046 17.7728 5.2164C17.7728 5.2164 16.5035 4 16 4C16 4 15.4897 4 14.1895 5.24278C14.1895 5.24278 12.9324 6.44437 12.1715 6.76082C12.1715 6.76082 11.4097 7.07767 9.69459 7.10441C9.69459 7.10441 7.90694 7.13227 7.51961 7.51961C7.51961 7.51961 7.13932 7.8999 7.11551 9.64124C7.11551 9.64124 7.09172 11.3814 6.75988 12.1738C6.75988 12.1738 6.43047 12.9603 5.2164 14.2272C5.2164 14.2272 4 15.4965 4 16C4 16 4 16.5103 5.24278 17.8105C5.24278 17.8105 6.44437 19.0676 6.76082 19.8285C6.76082 19.8285 7.07767 20.5903 7.10441 22.3054C7.10441 22.3054 7.13227 24.0931 7.51961 24.4804C7.51961 24.4804 7.8999 24.8607 9.64124 24.8845C9.64124 24.8845 11.3814 24.9083 12.1738 25.2401Z"
                                                        fill="currentColor"></path>
                                                    <path
                                                        d="M11.1909 15.777C11.0048 15.5992 10.7574 15.5 10.5 15.5C10.4998 15.5 10.4773 15.5003 10.4773 15.5003C10.2122 15.5063 9.96027 15.6174 9.77704 15.8091C9.59923 15.9952 9.5 16.2426 9.5 16.5L9.50026 16.5227C9.50627 16.7878 9.61737 17.0397 9.80911 17.223L13.4716 20.723C13.8579 21.0921 14.4662 21.0924 14.8528 20.7236L22.19 13.7238C22.3819 13.5407 22.4935 13.2887 22.4997 13.0235C22.5001 13.0075 22.5001 12.9915 22.4997 12.9755C22.4936 12.727 22.3952 12.4896 22.2236 12.3097C22.0348 12.1119 21.7734 12 21.5 12L21.4718 12.0004C21.2245 12.0074 20.9887 12.1057 20.8097 12.2764L14.1631 18.6174L11.1909 15.777Z"
                                                        fill="currentColor"></path>
                                                </svg>
                                            </button>
                                        </div>
                                    </div>
                                    <button type="button" onclick="abrirModalRemoverImagem('<?php echo $campo; ?>')"
                                        class="btn inline-flex items-center bg-lightred dark:bg-lightred align-middle text-black dark:text-black hover:bg-red-600 dark:hover:bg-red-600 hover:text-black dark:hover:text-black mt-2"
                                        <?php if (!$url)
                                            echo 'disabled style="opacity:.5;cursor:not-allowed"'; ?>>
                                        <svg class="w-4 h-4 mr-1" width="32" height="32" viewBox="0 0 32 32" fill="none"
                                            xmlns="http://www.w3.org/2000/svg">
                                            <path fill-rule="evenodd" clip-rule="evenodd"
                                                d="M16 3C16 3 18.6442 3 21.0605 4.02201C21.0605 4.02201 23.3936 5.00884 25.1924 6.80761C25.1924 6.80761 26.9912 8.60638 27.978 10.9395C27.978 10.9395 29 13.3558 29 16C29 16 29 18.6442 27.978 21.0605C27.978 21.0605 26.9912 23.3936 25.1924 25.1924C25.1924 25.1924 23.3936 26.9912 21.0605 27.978C21.0605 27.978 18.6442 29 16 29C16 29 13.3558 29 10.9395 27.978C10.9395 27.978 8.60638 26.9912 6.80761 25.1924C6.80761 25.1924 5.00884 23.3936 4.02202 21.0605C4.02202 21.0605 3 18.6442 3 16C3 16 3 13.3558 4.02202 10.9395C4.02202 10.9395 5.00885 8.60638 6.80761 6.80761C6.80761 6.80761 8.60638 5.00884 10.9395 4.02201C10.9395 4.02201 13.3558 3 16 3ZM16 5C16 5 13.7614 5 11.7186 5.86402C11.7186 5.86402 9.74476 6.69889 8.22183 8.22182C8.22183 8.22182 6.6989 9.74476 5.86402 11.7186C5.86402 11.7186 5 13.7614 5 16C5 16 5 18.2386 5.86402 20.2814C5.86402 20.2814 6.69889 22.2552 8.22183 23.7782C8.22183 23.7782 9.74476 25.3011 11.7186 26.136C11.7186 26.136 13.7614 27 16 27C16 27 18.2386 27 20.2814 26.136C20.2814 26.136 22.2552 25.3011 23.7782 23.7782C23.7782 23.7782 25.3011 22.2552 26.136 20.2814C26.136 20.2814 27 18.2386 27 16C27 16 27 13.7614 26.136 11.7186C26.136 11.7186 25.3011 9.74476 23.7782 8.22183C23.7782 8.22183 22.2552 6.69889 20.2814 5.86402C20.2814 5.86402 18.2386 5 16 5Z"
                                                fill="currentColor"></path>
                                            <path
                                                d="M6.80546 8.21968L23.7803 25.1946C23.9679 25.3821 24.2222 25.4874 24.4874 25.4874C24.7527 25.4875 25.007 25.3821 25.1946 25.1946C25.3821 25.007 25.4875 24.7527 25.4875 24.4874C25.4874 24.2222 25.3821 23.9679 25.1946 23.7803L8.21968 6.80546C8.03202 6.61781 7.77767 6.51245 7.51245 6.51245C7.24723 6.51245 6.99288 6.61781 6.80534 6.80534C6.61781 6.99288 6.51245 7.24723 6.51245 7.51245C6.51245 7.77767 6.61781 8.03202 6.80546 8.21968Z"
                                                fill="currentColor"></path>
                                        </svg>
                                        <span class="text-xs">Remover</span>
                                    </button>
                                </form>
                            </div>
                        <?php endforeach; ?>
                    </div>
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
        function uploadImage(e, campo) {
            e.preventDefault();
            let file;
            if (e.type === 'drop') {
                file = e.dataTransfer.files[0];
            } else {
                file = e.target.files[0];
            }
            if (!file) return;
            const fd = new FormData();
            fd.append('ajax_imagem', 1);
            fd.append('acao', 'upload');
            fd.append('campo', campo);
            fd.append('imagem', file);
            fetch('imagens.php', { method: 'POST', body: fd })
                .then(r => r.json())
                .then(data => {
                    showToast(data.message, data.success ? 'success' : 'error');
                    if (data.success) {
                        const img = document.getElementById('img-preview-' + campo);
                        const placeholder = document.getElementById('img-placeholder-' + campo);
                        img.src = '../' + data.url;
                        img.style.display = '';
                        placeholder.style.display = 'none';
                    }
                });
        }
        let removendo = false;
        function removerImagem(campo) {
            if (removendo) return;
            removendo = true;
            const fd = new FormData();
            fd.append('ajax_imagem', 1);
            fd.append('acao', 'remover');
            fd.append('campo', campo);
            fetch('imagens.php', { method: 'POST', body: fd })
                .then(r => r.json())
                .then(data => {
                    showToast(data.message, data.success ? 'success' : 'error');
                    if (data.success) {
                        const img = document.getElementById('img-preview-' + campo);
                        const placeholder = document.getElementById('img-placeholder-' + campo);
                        img.src = '';
                        img.style.display = 'none';
                        placeholder.style.display = '';
                    }
                })
                .finally(() => { removendo = false; });
        }
        function salvarLink(campo) {
            const input = document.getElementById('input-link-' + campo);
            const link = input.value.trim();
            if (!link) {
                showToast('Informe um link!', 'error');
                return;
            }
            const fd = new FormData();
            fd.append('ajax_imagem', 1);
            fd.append('acao', 'link');
            fd.append('campo', campo);
            fd.append('link', link);
            fetch('imagens.php', { method: 'POST', body: fd })
                .then(r => r.json())
                .then(data => {
                    showToast(data.message, data.success ? 'success' : 'error');
                    if (data.success) {
                        const img = document.getElementById('img-preview-' + campo);
                        const placeholder = document.getElementById('img-placeholder-' + campo);
                        img.src = link;
                        img.style.display = '';
                        placeholder.style.display = 'none';
                    }
                });
        }
        function abrirModalRemoverImagem(campo) {
            window.dispatchEvent(new CustomEvent('abrir-modal-remover', { detail: { campo } }));
        }
    </script>
</body>

</html>