<?php
// admin-usuarios.php
ini_set('display_errors', 0);
error_reporting(E_ALL);
?>
<!DOCTYPE html>
<html x-data="main" class="" :class="[$store.app.mode]">
<?php include "head.php"; ?>

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
        <nav
            class="sidebar fixed top-0 bottom-0 z-40 flex-none w-[212px] border-r border-black/10 dark:border-white/10 transition-all duration-300">
            <div class="bg-white dark:bg-black h-full">
                <?php include 'menu-lateral.php'; ?>
            </div>
        </nav>
        <!-- End sidebar -->
        <!-- Start Content Area -->
        <div class="main-content flex-1">
            <!-- Start Topbar -->
            <?php include 'topbar.php'; ?>
            <!-- End Topbar -->
            <div class="min-h-[calc(100vh-134px)] py-4 px-4 sm:px-12 flex justify-center items-center">
                <div class="text-center sm:flex-none">
                    <h2 class="text-5xl font-semibold mb-2">403 - Acesso Negado</h2>
                    <p class="text-black/40 dark:text-white/40 mb-10">Você não tem permissão para acessar esta página.</p>
                    <img src="assets/images/image404.svg" class="mb-11 mx-auto dark:hidden" alt="images">
                    <img src="assets/images/image404-dark.svg" class="mb-11 mx-auto hidden dark:block" alt="images">

                    <a class="max-w-[149px] py-1 px-2 inline-block bg-black/5 dark:bg-white/5 w-full rounded-lg text-black/40 dark:text-white/40 border border-black/5 dark:border-white/5 hover:bg-transparent dark:hover:bg-transparent hover:text-black dark:hover:text-white transition-all duration-300"
                        href="index">
                        Voltar para a página inicial
                    </a>
                </div>
            </div>
            <!-- Notificações -->
            <?php include 'notificacao.php'; ?>
        </div>
        <!-- End Content Area -->
    </div>
    <?php include 'footer.php'; ?>
</body>

</html>