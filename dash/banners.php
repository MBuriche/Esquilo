<?php
include_once "services/database.php";

// Função para buscar todos os banners
function getBanners($mysqli) {
    $res = $mysqli->query("SELECT * FROM banner ORDER BY id DESC");
    $banners = [];
    while ($row = $res->fetch_assoc()) {
        $banners[] = $row;
    }
    return $banners;
}

// Função para deletar arquivo de imagem
function deleteImageFile($path) {
    if ($path && file_exists(__DIR__ . '/../' . $path)) {
        @unlink(__DIR__ . '/../' . $path);
    }
}

// AJAX: Adicionar, editar, remover banner
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax_banner'])) {
    header('Content-Type: application/json');
    $acao = $_POST['acao'] ?? '';
    $id = intval($_POST['id'] ?? 0);
    // Remover banner
    if ($acao === 'remover' && $id) {
        $res = $mysqli->query("SELECT img FROM banner WHERE id=$id");
        $img = ($res && $row = $res->fetch_assoc()) ? $row['img'] : '';
        if ($img && !preg_match('/^https?:\/\//', $img)) deleteImageFile($img);
        $mysqli->query("DELETE FROM banner WHERE id=$id");
        echo json_encode(['success' => true, 'message' => 'Banner removido com sucesso!']);
        exit;
    }
    // Editar banner
    if ($acao === 'editar' && $id) {
        $titulo = trim($_POST['titulo'] ?? '');
        $link = trim($_POST['link'] ?? '');
        $status = intval($_POST['status'] ?? 1);
        $mysqli->query("UPDATE banner SET titulo='$titulo', link='$link', status=$status WHERE id=$id");
        echo json_encode(['success' => true, 'message' => 'Banner atualizado!']);
        exit;
    }
    // Trocar imagem
    if ($acao === 'imagem' && $id && isset($_FILES['imagem'])) {
        $file = $_FILES['imagem'];
        if ($file['error'] !== 0) {
            echo json_encode(['success' => false, 'message' => 'Erro no upload!']);
            exit;
        }
        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($ext, ['jpg', 'jpeg', 'png', 'webp', 'svg', 'ico', 'gif'])) {
            echo json_encode(['success' => false, 'message' => 'Formato não permitido!']);
            exit;
        }
        $nome = uniqid('banner_') . '.' . $ext;
        $dest = 'tmp/imagens/' . $nome;
        if (!is_dir(__DIR__ . '/../tmp/imagens/')) {
            mkdir(__DIR__ . '/../tmp/imagens/', 0777, true);
        }
        if (!move_uploaded_file($file['tmp_name'], __DIR__ . '/../' . $dest)) {
            echo json_encode(['success' => false, 'message' => 'Falha ao salvar imagem!']);
            exit;
        }
        // Remove imagem antiga se for arquivo local
        $res = $mysqli->query("SELECT img FROM banner WHERE id=$id");
        $img = ($res && $row = $res->fetch_assoc()) ? $row['img'] : '';
        if ($img && !preg_match('/^https?:\/\//', $img)) deleteImageFile($img);
        $mysqli->query("UPDATE banner SET img='$dest' WHERE id=$id");
        echo json_encode(['success' => true, 'message' => 'Imagem atualizada!', 'url' => $dest]);
        exit;
    }
    // Trocar imagem por link
    if ($acao === 'imagem_link' && $id && isset($_POST['link'])) {
        $linkimg = trim($_POST['link']);
        if (!filter_var($linkimg, FILTER_VALIDATE_URL)) {
            echo json_encode(['success' => false, 'message' => 'Link inválido!']);
            exit;
        }
        // Remove imagem antiga se for arquivo local
        $res = $mysqli->query("SELECT img FROM banner WHERE id=$id");
        $img = ($res && $row = $res->fetch_assoc()) ? $row['img'] : '';
        if ($img && !preg_match('/^https?:\/\//', $img)) deleteImageFile($img);
        $mysqli->query("UPDATE banner SET img='$linkimg' WHERE id=$id");
        echo json_encode(['success' => true, 'message' => 'Imagem atualizada!', 'url' => $linkimg]);
        exit;
    }
    // Adicionar novo banner
    if ($acao === 'adicionar') {
        $titulo = trim($_POST['titulo'] ?? '');
        $link = trim($_POST['link'] ?? '');
        $status = intval($_POST['status'] ?? 1);
        $img = '';
        if (isset($_FILES['imagem'])) {
            $file = $_FILES['imagem'];
            if ($file['error'] === 0) {
                $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
                if (in_array($ext, ['jpg', 'jpeg', 'png', 'webp', 'svg', 'ico', 'gif'])) {
                    $nome = uniqid('banner_') . '.' . $ext;
                    $dest = 'tmp/imagens/' . $nome;
                    if (!is_dir(__DIR__ . '/../tmp/imagens/')) {
                        mkdir(__DIR__ . '/../tmp/imagens/', 0777, true);
                    }
                    if (move_uploaded_file($file['tmp_name'], __DIR__ . '/../' . $dest)) {
                        $img = $dest;
                    }
                }
            }
        } else if (isset($_POST['imagem_link']) && filter_var($_POST['imagem_link'], FILTER_VALIDATE_URL)) {
            $img = trim($_POST['imagem_link']);
        }
        if (!$img) {
            echo json_encode(['success' => false, 'message' => 'Imagem obrigatória!']);
            exit;
        }
        $mysqli->query("INSERT INTO banner (titulo, img, link, status) VALUES ('$titulo', '$img', '$link', $status)");
        echo json_encode(['success' => true, 'message' => 'Banner adicionado!']);
        exit;
    }
    echo json_encode(['success' => false, 'message' => 'Ação inválida!']);
    exit;
}

$banners = getBanners($mysqli);
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
                <div class="p-4 sm:p-7 min-h-[calc(100vh-145px)]" x-data="{ showModal: false }">
                    <h2 class="text-lg font-semibold mb-6">Banners do Sistema</h2>
                    <div class="mb-8 flex justify-end">
                        <button type="button" class="btn px-6 py-2 bg-lightgreen-100 dark:bg-lightgreen-100 text-black dark:text-black hover:bg-lightgreen-200 dark:hover:bg-lightpurple-200 rounded-lg font-semibold" @click="showModal = true">
                            Adicionar Banner
                        </button>
                    </div>
                    <!-- Modal para adicionar banner -->
                    <div x-show="showModal" x-cloak class="fixed inset-0 bg-black/60 dark:bg-white/10 z-[999] flex items-center justify-center overflow-y-auto p-4 transition-all duration-300">
                        <div @click.away="showModal = false" class="bg-white dark:bg-black relative shadow-3xl border-0 p-0 rounded-lg overflow-hidden w-full max-w-lg my-8 animate-fade-in-up">
                            <div class="flex bg-white dark:bg-black border-b border-black/10 dark:border-white/10 items-center justify-between px-5 py-4">
                                <h3 class="font-bold text-xl text-black dark:text-white">Adicionar Novo Banner</h3>
                                <button type="button" class="text-black/40 dark:text-white/40 hover:text-black dark:hover:text-white" @click="showModal = false">
                                    <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                                        <path d="M24.2929 6.29289L6.29289 24.2929C6.10536 24.4804 6 24.7348 6 25C6 25.2652 6.10536 25.5196 6.29289 25.7071C6.48043 25.8946 6.73478 26 7 26C7.26522 26 7.51957 25.8946 7.70711 25.7071L25.7071 7.70711C25.8946 7.51957 26 7.26522 26 7C26 6.73478 25.8946 6.48043 25.7071 6.29289C25.5196 6.10536 25.2652 6 25 6C24.7348 6 24.4804 6.10536 24.2929 6.29289Z" fill="currentcolor"></path>
                                        <path d="M7.70711 6.29289C7.51957 6.10536 7.26522 6 7 6C6.73478 6 6.48043 6.10536 6.29289 6.29289C6.10536 6.48043 6 6.73478 6 7C6 7.26522 6.10536 7.51957 6.29289 7.70711L24.2929 25.7071C24.48043 25.8946 24.7348 26 25 26C25.2652 26 25.51957 25.8946 25.7071 25.7071C25.8946 25.5196 26 25.2652 26 25C26 24.7348 25.8946 24.4804 25.7071 24.2929L7.70711 6.29289Z" fill="currentcolor"></path>
                                    </svg>
                                </button>
                            </div>
                            <form id="form-add-banner" class="space-y-5 px-6 py-6" enctype="multipart/form-data" onsubmit="return false;">
                                <div class="space-y-2">
                                    <label class="form-label font-semibold">Título *</label>
                                    <input type="text" name="titulo" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition" required>
                                </div>
                                <div class="space-y-2">
                                    <label class="form-label font-semibold">Link de Ação</label>
                                    <input type="text" name="link" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition" placeholder="https://...">
                                </div>
                                <div class="space-y-2">
                                    <label class="form-label font-semibold">Imagem *</label>
                                    <label class="w-full h-16 flex items-center justify-center cursor-pointer border-2 border-dashed border-black/20 dark:border-white/20 rounded-lg p-2 hover:bg-black/5 dark:hover:bg-white/5 transition" ondragover="event.preventDefault();" ondrop="handleBannerDrop(event)">
                                        <input type="file" name="imagem" accept="image/*" class="hidden" onchange="uploadBannerImageModal(event)">
                                        <span class="text-xs text-black/60 dark:text-white/60">Arraste ou clique para enviar</span>
                                    </label>
                                    <div id="modal-banner-preview" class="w-full flex justify-center my-2" style="display:none;">
                                        <img id="modal-banner-img" src="" alt="Preview" class="w-32 h-32 object-contain rounded shadow" />
                                    </div>
                                    <span class="text-xs text-black/40 dark:text-white/40">ou cole um link abaixo</span>
                                    <input type="text" name="imagem_link" id="modal-banner-link" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg mt-1" placeholder="https://..." oninput="previewBannerLink(this.value)">
                                </div>
                                <div class="space-y-2">
                                    <label class="form-label font-semibold">Status</label>
                                    <select name="status" class="form-input w-full border border-black/10 dark:border-white/10 bg-gray-50 dark:bg-white/10 px-4 py-3 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 dark:focus:border-blue-400 dark:focus:ring-blue-900 transition">
                                        <option value="1">Ativo</option>
                                        <option value="0">Inativo</option>
                                    </select>
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
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                        <?php foreach ($banners as $banner):
                            $is_link = $banner['img'] && preg_match('/^https?:\/\//', $banner['img']);
                            $preview_url = $banner['img'] ? ($is_link ? $banner['img'] : ('../' . $banner['img'])) : '';
                        ?>
                        <div class="border border-black/10 dark:border-white/10 p-5 rounded-md flex flex-col justify-between h-full items-center">
                            <span class="font-semibold mb-2"><?php echo htmlspecialchars($banner['titulo']); ?></span>
                            <div class="w-full flex flex-col items-center">
                                <div class="w-28 h-32 sm:w-32 sm:h-36 mb-3 flex items-center justify-center bg-black/5 dark:bg-white/5 rounded overflow-hidden relative group">
                                    <img id="img-preview-<?php echo $banner['id']; ?>" src="<?php echo $preview_url; ?>" alt="Banner" class="w-full h-full object-contain mx-auto" style="<?php echo $preview_url ? '' : 'display:none;'; ?>">
                                    <div id="img-placeholder-<?php echo $banner['id']; ?>" class="absolute inset-0 flex items-center justify-center text-black/40 dark:text-white/40 text-xs" style="<?php echo $preview_url ? 'display:none;' : ''; ?>">Nenhuma imagem</div>
                                </div>
                            </div>
                            <form class="w-full flex flex-col grow justify-end items-center gap-2" enctype="multipart/form-data" onsubmit="return false;">
                                <div class="w-full flex flex-col gap-2">
                                    <label class="w-full h-16 flex items-center justify-center cursor-pointer border-2 border-dashed border-black/20 dark:border-white/20 rounded-lg p-2 hover:bg-black/5 dark:hover:bg-white/5 transition" ondragover="event.preventDefault();" ondrop="uploadBannerImage(event, <?php echo $banner['id']; ?>);">
                                        <input type="file" accept="image/*" class="hidden" onchange="uploadBannerImage(event, <?php echo $banner['id']; ?>);">
                                        <span class="text-xs text-black/60 dark:text-white/60">Arraste ou clique para trocar imagem</span>
                                    </label>
                                    <div class="w-full h-16 flex flex-row items-center gap-2">
                                        <input type="text" id="input-link-img-<?php echo $banner['id']; ?>" class="form-input w-full border border-black/10 dark:border-white/10 bg-transparent px-3 py-2.5 rounded-lg" placeholder="Ou cole um link de imagem" value="<?php echo $is_link ? htmlspecialchars($banner['img']) : ''; ?>">
                                        <button type="button" onclick="salvarBannerImgLink(<?php echo $banner['id']; ?>)" class="btn px-2 bg-lightgreen-100 dark:bg-lightgreen-100 text-black dark:text-black hover:bg-lightgreen-200 dark:hover:bg-lightpurple-200 rounded-lg">
                                            <svg class="w-4 h-4" width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                                                <path fill-rule="evenodd" clip-rule="evenodd" d="M11.4012 27.0849C11.4012 27.0849 10.9664 26.9028 9.6139 26.8843C9.6139 26.8843 8.4575 26.8685 7.88867 26.7645C7.88867 26.7645 6.77082 26.56 6.10539 25.8946C6.10539 25.8946 5.43594 25.2252 5.22844 24.0882C5.22844 24.0882 5.12294 23.5102 5.10465 22.3366C5.10465 22.3366 5.08389 21.0046 4.91418 20.5965C4.91418 20.5965 4.74093 20.18 3.79698 19.1924C3.79698 19.1924 2.98525 18.3431 2.6547 17.8655C2.6547 17.8655 2 16.9195 2 16C2 16 2 15.0846 2.64417 14.1522C2.64417 14.1522 2.96978 13.6809 3.77243 12.8434C3.77243 12.8434 4.7293 11.8449 4.91512 11.4012C4.91512 11.4012 5.09721 10.9664 5.1157 9.6139C5.1157 9.6139 5.13151 8.4575 5.23553 7.88867C5.23553 7.88867 5.43996 6.77082 6.10539 6.10539C6.10539 6.10539 6.77484 5.43594 7.91181 5.22844C7.91181 5.22844 8.48983 5.12294 9.66342 5.10465C9.66342 5.10465 10.9954 5.08389 11.4035 4.91418C11.4035 4.91418 11.82 4.74093 12.8076 3.79698C12.8076 3.79698 13.6569 2.98525 14.1345 2.6547C14.1345 2.6547 15.0805 2 16 2C16 2 16.9154 2 17.8478 2.64417C17.8478 2.64417 18.3191 2.96978 19.1566 3.77243C19.1566 3.77243 20.1551 4.7293 20.5988 4.91512C20.5988 4.91512 21.0336 5.09721 22.3861 5.1157C22.3861 5.1157 23.5425 5.13151 24.1113 5.23553C24.1113 5.23553 25.2292 5.43996 25.8946 6.10539C25.8946 6.10539 26.5641 6.77484 26.7716 7.91181C26.7716 7.91181 26.8771 8.48985 26.8953 9.66342C26.8953 9.66342 26.9161 10.9954 27.0858 11.4035C27.0858 11.4035 27.2591 11.82 28.203 12.8076C28.203 12.8076 29.0148 13.6569 29.3453 14.1345C29.3453 14.1345 30 15.0805 30 16C30 16 30 16.9154 29.3558 17.8478C29.3558 17.8478 29.0302 18.3191 28.2276 19.1566C28.2276 19.1566 27.2707 20.1551 27.0849 20.5988C27.0849 20.5988 26.9028 21.0336 26.8843 22.3861C26.8843 22.3861 26.8685 23.5425 26.7645 24.1113C26.7645 24.1113 26.56 25.2292 25.8946 25.8946C25.8946 25.8946 25.2252 26.5641 24.0882 26.7716C24.0882 26.7716 23.5102 26.8771 22.3366 26.8953C22.3366 26.8953 21.0046 26.9161 20.5965 27.0858C20.5965 27.0858 20.18 27.2591 19.1924 28.203C19.1924 28.203 18.3431 29.0148 17.8655 29.3453C17.8655 29.3453 16.9195 30 16 30C16 30 15.0846 30 14.1522 29.3558C14.1522 29.3558 13.6809 29.0302 12.8434 28.2276C12.8434 28.2276 11.8449 27.2707 11.4012 27.0849ZM12.1738 25.2401C12.1738 25.2401 12.9603 25.5695 14.2272 26.7836C14.2272 26.7836 15.4965 28 16 28C16 28 16.5103 28 17.8105 26.7572C17.8105 26.7572 19.0676 25.5556 19.8285 25.2392C19.8285 25.2392 20.5903 24.9223 22.3054 24.8956C22.3054 24.8956 24.0931 24.8677 24.4804 24.4804C24.4804 24.4804 24.8607 24.1001 24.8845 22.3588C24.8845 22.3588 24.9083 20.6186 25.2401 19.8262C25.2401 19.8262 25.5695 19.0397 26.7836 17.7728C26.7836 17.7728 28 16.5035 28 16C28 16 28 15.4897 26.7572 14.1895C26.7572 14.1895 25.5556 12.9324 25.2392 12.1715C25.2392 12.1715 24.9223 11.4097 24.8956 9.69459C24.8956 9.69459 24.8677 7.90694 24.4804 7.51961C24.4804 7.51961 24.1001 7.13932 22.3588 7.11551C22.3588 7.11551 20.6186 7.09172 19.8262 6.75988C19.8262 6.75988 19.0397 6.43046 17.7728 5.2164C17.7728 5.2164 16.5035 4 16 4C16 4 15.4897 4 14.1895 5.24278C14.1895 5.24278 12.9324 6.44437 12.1715 6.76082C12.1715 6.76082 11.4097 7.07767 9.69459 7.10441C9.69459 7.10441 7.90694 7.13227 7.51961 7.51961C7.51961 7.51961 7.13932 7.8999 7.11551 9.64124C7.11551 9.64124 7.09172 11.3814 6.75988 12.1738C6.75988 12.1738 6.43047 12.9603 5.2164 14.2272C5.2164 14.2272 4 15.4965 4 16C4 16 4 16.5103 5.24278 17.8105C5.24278 17.8105 6.44437 19.0676 6.76082 19.8285C6.76082 19.8285 7.07767 20.5903 7.10441 22.3054C7.10441 22.3054 7.13227 24.0931 7.51961 24.4804C7.51961 24.4804 7.8999 24.8607 9.64124 24.8845C9.64124 24.8845 11.3814 24.9083 12.1738 25.2401Z" fill="currentColor"></path>
                                                <path d="M11.1909 15.777C11.0048 15.5992 10.7574 15.5 10.5 15.5C10.4998 15.5 10.4773 15.5003 10.4773 15.5003C10.2122 15.5063 9.96027 15.6174 9.77704 15.8091C9.59923 15.9952 9.5 16.2426 9.5 16.5L9.50026 16.5227C9.50627 16.7878 9.61737 17.0397 9.80911 17.223L13.4716 20.723C13.8579 21.0921 14.4662 21.0924 14.8528 20.7236L22.19 13.7238C22.3819 13.5407 22.4935 13.2887 22.4997 13.0235C22.5001 13.0075 22.5001 12.9915 22.4997 12.9755C22.4936 12.727 22.3952 12.4896 22.2236 12.3097C22.0348 12.1119 21.7734 12 21.5 12L21.4718 12.0004C21.2245 12.0074 20.9887 12.1057 20.8097 12.2764L14.1631 18.6174L11.1909 15.777Z" fill="currentColor"></path>
                                            </svg>
                                        </button>
                                    </div>
                                </div>
                                <button type="button" class="btn inline-flex items-center bg-lightred dark:bg-lightred align-middle text-black dark:text-black hover:bg-red-600 dark:hover:bg-red-600 hover:text-black dark:hover:text-black mt-2" onclick="abrirModalRemoverBanner(<?php echo $banner['id']; ?>)">
                                    <svg class="w-4 h-4 mr-1" width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                                        <path fill-rule="evenodd" clip-rule="evenodd" d="M16 3C16 3 18.6442 3 21.0605 4.02201C21.0605 4.02201 23.3936 5.00884 25.1924 6.80761C25.1924 6.80761 26.9912 8.60638 27.978 10.9395C27.978 10.9395 29 13.3558 29 16C29 16 29 18.6442 27.978 21.0605C27.978 21.0605 26.9912 23.3936 25.1924 25.1924C25.1924 25.1924 23.3936 26.9912 21.0605 27.978C21.0605 27.978 18.6442 29 16 29C16 29 13.3558 29 10.9395 27.978C10.9395 27.978 8.60638 26.9912 6.80761 25.1924C6.80761 25.1924 5.00884 23.3936 4.02202 21.0605C4.02202 21.0605 3 18.6442 3 16C3 16 3 13.3558 4.02202 10.9395C4.02202 10.9395 5.00885 8.60638 6.80761 6.80761C6.80761 6.80761 8.60638 5.00884 10.9395 4.02201C10.9395 4.02201 13.3558 3 16 3ZM16 5C16 5 13.7614 5 11.7186 5.86402C11.7186 5.86402 9.74476 6.69889 8.22183 8.22182C8.22183 8.22182 6.6989 9.74476 5.86402 11.7186C5.86402 11.7186 5 13.7614 5 16C5 16 5 18.2386 5.86402 20.2814C5.86402 20.2814 6.69889 22.2552 8.22183 23.7782C8.22183 23.7782 9.74476 25.3011 11.7186 26.136C11.7186 26.136 13.7614 27 16 27C16 27 18.2386 27 20.2814 26.136C20.2814 26.136 22.2552 25.3011 23.7782 23.7782C23.7782 23.7782 25.3011 22.2552 26.136 20.2814C26.136 20.2814 27 18.2386 27 16C27 16 27 13.7614 26.136 11.7186C26.136 11.7186 25.3011 9.74476 23.7782 8.22183C23.7782 8.22183 22.2552 6.69889 20.2814 5.86402C20.2814 5.86402 18.2386 5 16 5Z" fill="currentColor"></path>
                                        <path d="M6.80546 8.21968L23.7803 25.1946C23.9679 25.3821 24.2222 25.4874 24.4874 25.4874C24.7527 25.4875 25.007 25.3821 25.1946 25.1946C25.3821 25.007 25.4875 24.7527 25.4875 24.4874C25.4874 24.2222 25.3821 23.9679 25.1946 23.7803L8.21968 6.80546C8.03202 6.61781 7.77767 6.51245 7.51245 6.51245C7.24723 6.51245 6.99288 6.61781 6.80534 6.80534C6.61781 6.99288 6.51245 7.24723 6.51245 7.51245C6.51245 7.77767 6.61781 8.03202 6.80546 8.21968Z" fill="currentColor"></path>
                                    </svg>
                                    <span class="text-xs">Remover</span>
                                </button>
                            </form>
                            <form class="w-full flex flex-col gap-2 mt-2" onsubmit="return false;">
                                <input type="text" name="titulo" class="form-input w-full border border-black/10 dark:border-white/10 bg-transparent px-3 py-2.5 rounded-lg" value="<?php echo htmlspecialchars($banner['titulo']); ?>" placeholder="Título">
                                <input type="text" name="link" class="form-input w-full border border-black/10 dark:border-white/10 bg-transparent px-3 py-2.5 rounded-lg" value="<?php echo htmlspecialchars($banner['link'] ?? ''); ?>" placeholder="Link de ação">
                                <select name="status" class="form-input w-full border border-black/10 dark:border-white/10 bg-transparent px-3 py-2.5 rounded-lg">
                                    <option value="1" <?php if ($banner['status'] == 1) echo 'selected'; ?>>Ativo</option>
                                    <option value="0" <?php if ($banner['status'] == 0) echo 'selected'; ?>>Inativo</option>
                                </select>
                                <button type="button" onclick="salvarBannerEdicao(<?php echo $banner['id']; ?>, this.form)" class="btn px-4 py-2 bg-lightgreen-100 dark:bg-lightgreen-100 text-black dark:text-black hover:bg-lightgreen-200 dark:hover:bg-lightpurple-200 rounded-lg font-semibold">Salvar</button>
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
    <!-- Modal de confirmação de exclusão de imagem do banner -->
    <div x-data="{ open: false, id: null }" x-show="open" x-cloak
        @abrir-modal-remover-banner.window="open = true; id = $event.detail.id"
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
                    <p>Tem certeza que deseja remover este banner? Esta ação não pode ser desfeita.</p>
                </div>
                <div class="flex justify-end items-center mt-8 gap-4">
                    <button type="button" class="btn !bg-gray-500 !text-white"
                        @click="open = false">Cancelar</button>
                    <button type="button" class="btn !bg-red-500 !text-white"
                        @click="open = false; window.removerBanner(id);">Remover</button>
                </div>
            </div>
        </div>
    </div>
    <script src="assets/js/toast.js"></script>
    <script>
    let removendoBanner = false;
    function removerBanner(id) {
        if (removendoBanner) return;
        removendoBanner = true;
        const fd = new FormData();
        fd.append('ajax_banner', 1);
        fd.append('acao', 'remover');
        fd.append('id', id);
        fetch('banners.php', { method: 'POST', body: fd })
            .then(r => r.json())
            .then(data => {
                showToast(data.message, data.success ? 'success' : 'error');
                if (data.success) {
                    // Opcional: recarregar a página ou remover o banner do DOM
                    location.reload();
                }
            })
            .finally(() => { removendoBanner = false; });
    }
    function abrirModalRemoverBanner(id) {
        window.dispatchEvent(new CustomEvent('abrir-modal-remover-banner', { detail: { id } }));
    }
    // Adicionar banner
    document.getElementById('form-add-banner')?.addEventListener('submit', function(e) {
        e.preventDefault();
        const fd = new FormData(this);
        fd.append('ajax_banner', 1);
        fd.append('acao', 'adicionar');
        fetch('banners.php', { method: 'POST', body: fd })
            .then(r => r.json())
            .then(data => {
                showToast(data.message, data.success ? 'success' : 'error');
                if (data.success) location.reload();
            });
    });
    // Remover banner
    // (Remover a função abaixo que usa confirm, pois o modal já faz a confirmação)
    // function removerBanner(id) {
    //     if (!confirm('Tem certeza que deseja remover este banner?')) return;
    //     const fd = new FormData();
    //     fd.append('ajax_banner', 1);
    //     fd.append('acao', 'remover');
    //     fd.append('id', id);
    //     fetch('banners.php', { method: 'POST', body: fd })
    //         .then(r => r.json())
    //         .then(data => {
    //             showToast(data.message, data.success ? 'success' : 'error');
    //             if (data.success) location.reload();
    //         });
    // }
    // Editar banner
    function salvarBannerEdicao(id, form) {
        const fd = new FormData();
        fd.append('ajax_banner', 1);
        fd.append('acao', 'editar');
        fd.append('id', id);
        fd.append('titulo', form.titulo.value);
        fd.append('link', form.link.value);
        fd.append('status', form.status.value);
        fetch('banners.php', { method: 'POST', body: fd })
            .then(r => r.json())
            .then(data => {
                showToast(data.message, data.success ? 'success' : 'error');
            });
    }
    // Trocar imagem
    function uploadBannerImage(e, id) {
        e.preventDefault();
        let file;
        if (e.type === 'drop') {
            file = e.dataTransfer.files[0];
        } else {
            file = e.target.files[0];
        }
        if (!file) return;
        const fd = new FormData();
        fd.append('ajax_banner', 1);
        fd.append('acao', 'imagem');
        fd.append('id', id);
        fd.append('imagem', file);
        fetch('banners.php', { method: 'POST', body: fd })
            .then(r => r.json())
            .then(data => {
                showToast(data.message, data.success ? 'success' : 'error');
                if (data.success && data.url) {
                    document.getElementById('img-preview-' + id).src = '../' + data.url;
                    document.getElementById('img-preview-' + id).style.display = '';
                    document.getElementById('img-placeholder-' + id).style.display = 'none';
                }
            });
    }
    // Trocar imagem por link
    function salvarBannerImgLink(id) {
        const input = document.getElementById('input-link-img-' + id);
        const link = input.value.trim();
        if (!link) {
            showToast('Informe um link!', 'error');
            return;
        }
        const fd = new FormData();
        fd.append('ajax_banner', 1);
        fd.append('acao', 'imagem_link');
        fd.append('id', id);
        fd.append('link', link);
        fetch('banners.php', { method: 'POST', body: fd })
            .then(r => r.json())
            .then(data => {
                showToast(data.message, data.success ? 'success' : 'error');
                if (data.success && data.url) {
                    document.getElementById('img-preview-' + id).src = link;
                    document.getElementById('img-preview-' + id).style.display = '';
                    document.getElementById('img-placeholder-' + id).style.display = 'none';
                }
            });
    }
    function uploadBannerImageModal(e) {
        const input = e.target;
        if (input.files && input.files[0]) {
            showToast('Arquivo selecionado: ' + input.files[0].name, 'info');
            const reader = new FileReader();
            reader.onload = function(ev) {
                document.getElementById('modal-banner-img').src = ev.target.result;
                document.getElementById('modal-banner-preview').style.display = '';
            };
            reader.readAsDataURL(input.files[0]);
        }
    }
    function handleBannerDrop(e) {
        e.preventDefault();
        e.stopPropagation();
        const files = e.dataTransfer.files;
        if (files && files[0]) {
            const input = e.currentTarget.querySelector('input[type=file]');
            const dt = new DataTransfer();
            dt.items.add(files[0]);
            input.files = dt.files;
            showToast('Arquivo selecionado: ' + files[0].name, 'info');
            const reader = new FileReader();
            reader.onload = function(ev) {
                document.getElementById('modal-banner-img').src = ev.target.result;
                document.getElementById('modal-banner-preview').style.display = '';
            };
            reader.readAsDataURL(files[0]);
        }
    }
    function previewBannerLink(val) {
        if (val && /^https?:\/\//.test(val)) {
            document.getElementById('modal-banner-img').src = val;
            document.getElementById('modal-banner-preview').style.display = '';
        } else {
            document.getElementById('modal-banner-preview').style.display = 'none';
        }
    }
    </script>
</body>
</html>