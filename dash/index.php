<!DOCTYPE html>
<html x-data="main" class="" :class="[$store.app.mode]">

<?php include_once './partes/head.php'; ?>
<?php include_once './partes/head-js.php'; ?>

<?php
// Carregando dados do dashboard uma única vez para otimização
$saldo_usuarios_data = saldo_usuarios_info();
$depositos_data = depositos_info();
$saques_data = saques_info();
$pix_data = pix_gerados();
$usuarios_resumo_dashboard = usuarios_resumo_dashboard();
$dados_grafico = dados_grafico_depositos_saques();
$trafego_dados = trafego_por_fonte();
$estatisticas_trafego = estatisticas_trafego_site();

// Buscar saldo do caixa de premiações
$caixaValor = 0.00;
$resCaixa = $mysqli->query("SELECT valor_atual FROM caixa_premiacoes_status WHERE id=1");
if ($resCaixa && $rowCaixa = $resCaixa->fetch_assoc()) {
    $caixaValor = floatval($rowCaixa['valor_atual']);
}
// Buscar total já liberado em prêmios
$totalPremios = 0.00;
$resPremios = $mysqli->query("SELECT SUM(prize_amount) as total FROM historico_raspadas WHERE prize_amount > 0 AND status='completed'");
if ($resPremios && $rowPremios = $resPremios->fetch_assoc()) {
    $totalPremios = floatval($rowPremios['total']) / 100; // prize_amount está em centavos
}
function formatarReais($valor) {
    return 'R$' . number_format($valor, 2, ',', '.');
}
?>

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

                <!-- Start Menu -->
                <?php include_once 'partes/menu-lateral.php'; ?>
                <!-- End Menu -->

            </div>
        </nav>
        <!-- End sidebar -->

        <!-- Start Content Area -->
        <div class="main-content flex-1">
            <!-- Start Topbar -->
            <?php include_once 'partes/topbar.php'; ?>
            <!-- End Topbar -->

            <!-- Start Content -->
            <div class="h-[calc(100vh-73px)] overflow-y-auto overflow-x-hidden">
                <div x-data="sales" class="p-4 sm:p-7 min-h-[calc(100vh-145px)]">
                    <div class="relative mb-4 w-32">
                        <select class="form-select font-semibold text-sm px-2 dark:bg-black dark:text-white"
                            id="seletorPeriodo">
                            <option class="px-2" value="week">7 dias</option>
                            <option class="px-2" value="month">30 dias</option>
                            <option class="px-2" value="weeks">4 semanas</option>
                        </select>
                    </div>
                    <div class="flex flex-col gap-7">
                        <div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-7">

                            <div class="bg-lightblue-100 rounded-2xl p-6">
                                <p class="text-sm font-semibold text-black mb-2">Usuarios Cadastrados</p>
                                <div class="flex items-center justify-between">
                                    <h2 class="text-2xl leading-9 font-semibold text-black">
                                        <?= $_SESSION['2fa_verified'] == true ? qtd_usuarios() : "Token não informado." ?>
                                    </h2>
                                    <div class="flex items-center gap-1">
                                        <p class="text-xs leading-[18px] text-black">+11.01%</p>
                                        <svg width="16" height="16" viewBox="0 0 16 16" fill="none"
                                            xmlns="http://www.w3.org/2000/svg">
                                            <path fill-rule="evenodd" clip-rule="evenodd"
                                                d="M8.45488 5.60777L14 4L12.6198 9.6061L10.898 7.9532L8.12069 10.8463C8.02641 10.9445 7.89615 11 7.76 11C7.62385 11 7.49359 10.9445 7.39931 10.8463L5.36 8.72199L2.36069 11.8463C2.16946 12.0455 1.85294 12.0519 1.65373 11.8607C1.45453 11.6695 1.44807 11.3529 1.63931 11.1537L4.99931 7.65373C5.09359 7.55552 5.22385 7.5 5.36 7.5C5.49615 7.5 5.62641 7.55552 5.72069 7.65373L7.76 9.77801L10.1766 7.26067L8.45488 5.60777Z"
                                                fill="#1C1C1C" />
                                        </svg>
                                    </div>
                                </div>
                                <p class="text-m text-black/60 mt-2"><?php echo qtd_usuarios_depositantes(); ?>
                                    Depositaram</p>
                            </div>

                            <div class="bg-lightpurple-100 rounded-2xl p-6">
                                <p class="text-sm font-semibold text-black mb-2">Saldo Dos Jogadores</p>
                                <div class="flex items-center justify-between">
                                    <h2 class="text-2xl leading-9 font-semibold text-black">
                                        R$<?php echo number_format($saldo_usuarios_data['total_saldo'], 2, ',', '.') ?>
                                    </h2>
                                    <div class="flex items-center gap-1">
                                        <p class="text-xs leading-[18px] text-black">+9.15%</p>
                                        <svg width="16" height="16" viewBox="0 0 16 16" fill="none"
                                            xmlns="http://www.w3.org/2000/svg">
                                            <path fill-rule="evenodd" clip-rule="evenodd"
                                                d="M8.45488 5.60777L14 4L12.6198 9.6061L10.898 7.9532L8.12069 10.8463C8.02641 10.9445 7.89615 11 7.76 11C7.62385 11 7.49359 10.9445 7.39931 10.8463L5.36 8.72199L2.36069 11.8463C2.16946 12.0455 1.85294 12.0519 1.65373 11.8607C1.45453 11.6695 1.44807 11.3529 1.63931 11.1537L4.99931 7.65373C5.09359 7.55552 5.22385 7.5 5.36 7.5C5.49615 7.5 5.62641 7.55552 5.72069 7.65373L7.76 9.77801L10.1766 7.26067L8.45488 5.60777Z"
                                                fill="#1C1C1C" />
                                        </svg>
                                    </div>
                                </div>
                                <p class="text-m text-black/60 mt-2">
                                    <?php echo $saldo_usuarios_data['usuarios_com_saldo'] . ' Jogadores com saldo'; ?>
                                </p>
                            </div>

                            <div class="bg-lightblue-100 rounded-2xl p-6">
                                <p class="text-sm font-semibold text-black mb-2">Caixa De Premiaçao</p>
                                <div class="flex items-center justify-between">
                                    <h2 class="text-2xl leading-9 font-semibold text-black"><?php echo formatarReais($caixaValor); ?></h2>
                                    <div class="flex items-center gap-1">
                                        <p class="text-xs leading-[18px] text-black">&nbsp;</p>
                                        <svg width="16" height="16" class="rotate-180" viewBox="0 0 16 16" fill="none"
                                            xmlns="http://www.w3.org/2000/svg">
                                            <path fill-rule="evenodd" clip-rule="evenodd"
                                                d="M8.45488 5.60777L14 4L12.6198 9.6061L10.898 7.9532L8.12069 10.8463C8.02641 10.9445 7.89615 11 7.76 11C7.62385 11 7.49359 10.9445 7.39931 10.8463L5.36 8.72199L2.36069 11.8463C2.16946 12.0455 1.85294 12.0519 1.65373 11.8607C1.45453 11.6695 1.44807 11.3529 1.63931 11.1537L4.99931 7.65373C5.09359 7.55552 5.22385 7.5 5.36 7.5C5.49615 7.5 5.62641 7.55552 5.72069 7.65373L7.76 9.77801L10.1766 7.26067L8.45488 5.60777Z"
                                                fill="#1C1C1C" />
                                        </svg>
                                    </div>
                                </div>
                                <p class="text-m text-black/60 mt-2">Saldo disponivel para premiação</p>
                            </div>

                            <div class="bg-lightpurple-100 rounded-2xl p-6">
                                <p class="text-sm font-semibold text-black mb-2">Prêmios</p>
                                <div class="flex items-center justify-between">
                                    <h2 class="text-2xl leading-9 font-semibold text-black"><?php echo formatarReais($totalPremios); ?></h2>
                                    <div class="flex items-center gap-1">
                                        <p class="text-xs leading-[18px] text-black">&nbsp;</p>
                                        <svg width="16" height="16" class="rotate-180" viewBox="0 0 16 16" fill="none"
                                            xmlns="http://www.w3.org/2000/svg">
                                            <path fill-rule="evenodd" clip-rule="evenodd"
                                                d="M8.45488 5.60777L14 4L12.6198 9.6061L10.898 7.9532L8.12069 10.8463C8.02641 10.9445 7.89615 11 7.76 11C7.62385 11 7.49359 10.9445 7.39931 10.8463L5.36 8.72199L2.36069 11.8463C2.16946 12.0455 1.85294 12.0519 1.65373 11.8607C1.45453 11.6695 1.44807 11.3529 1.63931 11.1537L4.99931 7.65373C5.09359 7.55552 5.22385 7.5 5.36 7.5C5.49615 7.5 5.62641 7.55552 5.72069 7.65373L7.76 9.77801L10.1766 7.26067L8.45488 5.60777Z"
                                                fill="#1C1C1C" />
                                        </svg>
                                    </div>
                                </div>
                                <p class="text-m text-black/60 mt-2">Total liberado em prêmios</p>
                            </div>

                            <div class="bg-lightblue-100 rounded-2xl p-6">
                                <p class="text-sm font-semibold text-black mb-2">Depósitos Recebidos Hoje</p>
                                <div class="flex items-center justify-between">
                                    <h2 class="text-2xl leading-9 font-semibold text-black">
                                        R$<?php echo number_format($depositos_data['total_depositos_hoje'], 2, ',', '.') ?>
                                    </h2>
                                    <div class="flex items-center gap-1">
                                        <p class="text-xs leading-[18px] text-black">-1.48%</p>
                                        <svg width="16" height="16" class="rotate-180" viewBox="0 0 16 16" fill="none"
                                            xmlns="http://www.w3.org/2000/svg">
                                            <path fill-rule="evenodd" clip-rule="evenodd"
                                                d="M8.45488 5.60777L14 4L12.6198 9.6061L10.898 7.9532L8.12069 10.8463C8.02641 10.9445 7.89615 11 7.76 11C7.62385 11 7.49359 10.9445 7.39931 10.8463L5.36 8.72199L2.36069 11.8463C2.16946 12.0455 1.85294 12.0519 1.65373 11.8607C1.45453 11.6695 1.44807 11.3529 1.63931 11.1537L4.99931 7.65373C5.09359 7.55552 5.22385 7.5 5.36 7.5C5.49615 7.5 5.62641 7.55552 5.72069 7.65373L7.76 9.77801L10.1766 7.26067L8.45488 5.60777Z"
                                                fill="#1C1C1C" />
                                        </svg>
                                    </div>
                                </div>
                                <p class="text-m text-black/60 mt-2">
                                    <?php echo $depositos_data['qtd_depositos_hoje'] ?>
                                    Pagamentos recebidos
                                </p>
                            </div>

                            <div class="bg-lightpurple-100 rounded-2xl p-6">
                                <p class="text-sm font-semibold text-black mb-2">Saques Realizados Hoje</p>
                                <div class="flex items-center justify-between">
                                    <h2 class="text-2xl leading-9 font-semibold text-black">
                                        R$<?php echo number_format($saques_data['total_saques_hoje'], 2, ',', '.') ?>
                                    </h2>
                                    <div class="flex items-center gap-1">
                                        <p class="text-xs leading-[18px] text-black">-1.48%</p>
                                        <svg width="16" height="16" class="rotate-180" viewBox="0 0 16 16" fill="none"
                                            xmlns="http://www.w3.org/2000/svg">
                                            <path fill-rule="evenodd" clip-rule="evenodd"
                                                d="M8.45488 5.60777L14 4L12.6198 9.6061L10.898 7.9532L8.12069 10.8463C8.02641 10.9445 7.89615 11 7.76 11C7.62385 11 7.49359 10.9445 7.39931 10.8463L5.36 8.72199L2.36069 11.8463C2.16946 12.0455 1.85294 12.0519 1.65373 11.8607C1.45453 11.6695 1.44807 11.3529 1.63931 11.1537L4.99931 7.65373C5.09359 7.55552 5.22385 7.5 5.36 7.5C5.49615 7.5 5.62641 7.55552 5.72069 7.65373L7.76 9.77801L10.1766 7.26067L8.45488 5.60777Z"
                                                fill="#1C1C1C" />
                                        </svg>
                                    </div>
                                </div>
                                <p class="text-m text-black/60 mt-2">
                                    <?php echo $saques_data['qtd_saques_hoje'] ?>
                                    Pagamentos realizados
                                </p>
                            </div>

                            <div class="bg-lightblue-100 rounded-2xl p-6">
                                <p class="text-sm font-semibold text-black mb-2">Pix Gerados Hoje</p>
                                <div class="flex items-center justify-between">
                                    <h2 class="text-2xl leading-9 font-semibold text-black">
                                        <?php echo $pix_data['qtd_pix_hoje'] ?>
                                    </h2>
                                    <div class="flex items-center gap-1">
                                        <p class="text-xs leading-[18px] text-black">-1.48%</p>
                                        <svg width="16" height="16" class="rotate-180" viewBox="0 0 16 16" fill="none"
                                            xmlns="http://www.w3.org/2000/svg">
                                            <path fill-rule="evenodd" clip-rule="evenodd"
                                                d="M8.45488 5.60777L14 4L12.6198 9.6061L10.898 7.9532L8.12069 10.8463C8.02641 10.9445 7.89615 11 7.76 11C7.62385 11 7.49359 10.9445 7.39931 10.8463L5.36 8.72199L2.36069 11.8463C2.16946 12.0455 1.85294 12.0519 1.65373 11.8607C1.45453 11.6695 1.44807 11.3529 1.63931 11.1537L4.99931 7.65373C5.09359 7.55552 5.22385 7.5 5.36 7.5C5.49615 7.5 5.62641 7.55552 5.72069 7.65373L7.76 9.77801L10.1766 7.26067L8.45488 5.60777Z"
                                                fill="#1C1C1C" />
                                        </svg>
                                    </div>
                                </div>
                                <p class="text-m text-black/60 mt-2">
                                    <?php echo $pix_data['porcentagem_pagos_hoje'] ?>%
                                    Pagos
                                </p>
                            </div>

                            <div class="bg-lightpurple-100 rounded-2xl p-6">
                                <p class="text-sm font-semibold text-black mb-2">Usuarios Cadastrados Hoje</p>
                                <div class="flex items-center justify-between">
                                    <h2 class="text-2xl leading-9 font-semibold text-black">
                                        <?php echo qtd_usuarios_diarios(); ?>
                                    </h2>
                                    <div class="flex items-center gap-1">
                                        <p class="text-xs leading-[18px] text-black">-1.48%</p>
                                        <svg width="16" height="16" class="rotate-180" viewBox="0 0 16 16" fill="none"
                                            xmlns="http://www.w3.org/2000/svg">
                                            <path fill-rule="evenodd" clip-rule="evenodd"
                                                d="M8.45488 5.60777L14 4L12.6198 9.6061L10.898 7.9532L8.12069 10.8463C8.02641 10.9445 7.89615 11 7.76 11C7.62385 11 7.49359 10.9445 7.39931 10.8463L5.36 8.72199L2.36069 11.8463C2.16946 12.0455 1.85294 12.0519 1.65373 11.8607C1.45453 11.6695 1.44807 11.3529 1.63931 11.1537L4.99931 7.65373C5.09359 7.55552 5.22385 7.5 5.36 7.5C5.49615 7.5 5.62641 7.55552 5.72069 7.65373L7.76 9.77801L10.1766 7.26067L8.45488 5.60777Z"
                                                fill="#1C1C1C" />
                                        </svg>
                                    </div>
                                </div>
                                <p class="text-m text-black/60 mt-2">
                                    <?php echo $usuarios_resumo_dashboard['depositantes_hoje']; ?>
                                    Depositaram
                                    (<?php echo $usuarios_resumo_dashboard['porcentagem_depositantes_hoje']; ?>%)
                                </p>
                            </div>

                            <div class="bg-lightblue-100 rounded-2xl p-6">
                                <p class="text-sm font-semibold text-black mb-2">Depósitos Realizados</p>
                                <div class="flex items-center justify-between">
                                    <h2 class="text-2xl leading-9 font-semibold text-black">
                                        R$<?php echo number_format($depositos_data['total_depositos'], 2, ',', '.') ?>
                                    </h2>
                                    <div class="flex items-center gap-1">
                                        <p class="text-xs leading-[18px] text-black">-1.48%</p>
                                        <svg width="16" height="16" class="rotate-180" viewBox="0 0 16 16" fill="none"
                                            xmlns="http://www.w3.org/2000/svg">
                                            <path fill-rule="evenodd" clip-rule="evenodd"
                                                d="M8.45488 5.60777L14 4L12.6198 9.6061L10.898 7.9532L8.12069 10.8463C8.02641 10.9445 7.89615 11 7.76 11C7.62385 11 7.49359 10.9445 7.39931 10.8463L5.36 8.72199L2.36069 11.8463C2.16946 12.0455 1.85294 12.0519 1.65373 11.8607C1.45453 11.6695 1.44807 11.3529 1.63931 11.1537L4.99931 7.65373C5.09359 7.55552 5.22385 7.5 5.36 7.5C5.49615 7.5 5.62641 7.55552 5.72069 7.65373L7.76 9.77801L10.1766 7.26067L8.45488 5.60777Z"
                                                fill="#1C1C1C" />
                                        </svg>
                                    </div>
                                </div>
                                <p class="text-m text-black/60 mt-2">
                                    <?php echo $depositos_data['qtd_depositos_total'] ?>
                                    Depósitos recebidos
                                </p>
                            </div>

                            <div class="bg-lightpurple-100 rounded-2xl p-6">
                                <p class="text-sm font-semibold text-black mb-2">Saques Realizados</p>
                                <div class="flex items-center justify-between">
                                    <h2 class="text-2xl leading-9 font-semibold text-black">
                                        R$<?php echo number_format($saques_data['total_saques'], 2, ',', '.') ?>
                                    </h2>
                                    <div class="flex items-center gap-1">
                                        <p class="text-xs leading-[18px] text-black">-1.48%</p>
                                        <svg width="16" height="16" class="rotate-180" viewBox="0 0 16 16" fill="none"
                                            xmlns="http://www.w3.org/2000/svg">
                                            <path fill-rule="evenodd" clip-rule="evenodd"
                                                d="M8.45488 5.60777L14 4L12.6198 9.6061L10.898 7.9532L8.12069 10.8463C8.02641 10.9445 7.89615 11 7.76 11C7.62385 11 7.49359 10.9445 7.39931 10.8463L5.36 8.72199L2.36069 11.8463C2.16946 12.0455 1.85294 12.0519 1.65373 11.8607C1.45453 11.6695 1.44807 11.3529 1.63931 11.1537L4.99931 7.65373C5.09359 7.55552 5.22385 7.5 5.36 7.5C5.49615 7.5 5.62641 7.55552 5.72069 7.65373L7.76 9.77801L10.1766 7.26067L8.45488 5.60777Z"
                                                fill="#1C1C1C" />
                                        </svg>
                                    </div>
                                </div>
                                <p class="text-m text-black/60 mt-2">
                                    <?php echo $saques_data['qtd_saques_total'] ?>
                                    Saques aprovados
                                </p>
                            </div>

                            <div class="bg-lightblue-100 rounded-2xl p-6">
                                <p class="text-sm font-semibold text-black mb-2">Pix Gerados</p>
                                <div class="flex items-center justify-between">
                                    <h2 class="text-2xl leading-9 font-semibold text-black">
                                        <?php echo $pix_data['qtd_pix_total'] ?>
                                    </h2>
                                    <div class="flex items-center gap-1">
                                        <p class="text-xs leading-[18px] text-black">-1.48%</p>
                                        <svg width="16" height="16" class="rotate-180" viewBox="0 0 16 16" fill="none"
                                            xmlns="http://www.w3.org/2000/svg">
                                            <path fill-rule="evenodd" clip-rule="evenodd"
                                                d="M8.45488 5.60777L14 4L12.6198 9.6061L10.898 7.9532L8.12069 10.8463C8.02641 10.9445 7.89615 11 7.76 11C7.62385 11 7.49359 10.9445 7.39931 10.8463L5.36 8.72199L2.36069 11.8463C2.16946 12.0455 1.85294 12.0519 1.65373 11.8607C1.45453 11.6695 1.44807 11.3529 1.63931 11.1537L4.99931 7.65373C5.09359 7.55552 5.22385 7.5 5.36 7.5C5.49615 7.5 5.62641 7.55552 5.72069 7.65373L7.76 9.77801L10.1766 7.26067L8.45488 5.60777Z"
                                                fill="#1C1C1C" />
                                        </svg>
                                    </div>
                                </div>
                                <p class="text-m text-black/60 mt-2">
                                    <?php echo $pix_data['porcentagem_pagos_total'] ?>%
                                    Conversão total
                                </p>
                            </div>

                            <div class="bg-lightpurple-100 rounded-2xl p-6">
                                <p class="text-sm font-semibold text-black mb-2">Lucro Total</p>
                                <div class="flex items-center justify-between">
                                    <h2 class="text-2xl leading-9 font-semibold text-black">
                                        R$<?php echo number_format(saldo_cassino(), 2, ',', '.') ?>
                                    </h2>
                                    <div class="flex items-center gap-1">
                                        <p class="text-xs leading-[18px] text-black">-1.48%</p>
                                        <svg width="16" height="16" class="rotate-180" viewBox="0 0 16 16" fill="none"
                                            xmlns="http://www.w3.org/2000/svg">
                                            <path fill-rule="evenodd" clip-rule="evenodd"
                                                d="M8.45488 5.60777L14 4L12.6198 9.6061L10.898 7.9532L8.12069 10.8463C8.02641 10.9445 7.89615 11 7.76 11C7.62385 11 7.49359 10.9445 7.39931 10.8463L5.36 8.72199L2.36069 11.8463C2.16946 12.0455 1.85294 12.0519 1.65373 11.8607C1.45453 11.6695 1.44807 11.3529 1.63931 11.1537L4.99931 7.65373C5.09359 7.55552 5.22385 7.5 5.36 7.5C5.49615 7.5 5.62641 7.55552 5.72069 7.65373L7.76 9.77801L10.1766 7.26067L8.45488 5.60777Z"
                                                fill="#1C1C1C" />
                                        </svg>
                                    </div>
                                </div>
                                <p class="text-m text-black/60 mt-2">
                                    Valor do lucro total
                                </p>
                            </div>
                        </div>

                        <div class="grid grid-cols-1 md:grid-cols-4 gap-7">
                            <div class="md:col-span-3 bg-lightwhite dark:bg-white/5 p-6 rounded-2xl">
                                <div class="flex justify-between gap-3 items-start md:items-center mb-4">
                                    <div class="flex flex-col md:flex-row items-center gap-4">
                                        <ul id="tabs" class="inline-flex gap-1 text-sm font-normal">
                                            <li class="px-1.5 py-1 text-black dark:text-white font-semibold"><a
                                                    href="javaScript:;">Depósitos e Saques (7 dias)</a></li>
                                        </ul>
                                        <p class="hidden md:block">|</p>
                                        <div class="flex gap-4 items-center flex-none">
                                            <div class="flex items-center">
                                                <svg width="16" height="16" viewBox="0 0 16 16" fill="none"
                                                    xmlns="http://www.w3.org/2000/svg">
                                                    <path
                                                        d="M11 8C11 9.65685 9.65685 11 8 11C6.34315 11 5 9.65685 5 8C5 6.34315 6.34315 5 8 5C9.65685 5 11 6.34315 11 8Z"
                                                        fill="#10B981" />
                                                </svg>
                                                <p class="text-xs">Depósitos</p>
                                            </div>
                                            <div class="flex items-center">
                                                <svg width="16" height="16" viewBox="0 0 16 16" fill="none"
                                                    xmlns="http://www.w3.org/2000/svg">
                                                    <path
                                                        d="M11 8C11 9.65685 9.65685 11 8 11C6.34315 11 5 9.65685 5 8C5 6.34315 6.34315 5 8 5C9.65685 5 11 6.34315 11 8Z"
                                                        fill="#EF4444" />
                                                </svg>
                                                <p class="text-xs">Saques</p>
                                            </div>
                                            <div class="flex items-center">
                                                <svg width="16" height="16" viewBox="0 0 16 16" fill="none"
                                                    xmlns="http://www.w3.org/2000/svg">
                                                    <path
                                                        d="M11 8C11 9.65685 9.65685 11 8 11C6.34315 11 5 9.65685 5 8C5 6.34315 6.34315 5 8 5C9.65685 5 11 6.34315 11 8Z"
                                                        fill="#3B82F6" />
                                                </svg>
                                                <p class="text-xs">Lucro</p>
                                            </div>
                                        </div>
                                    </div>
                                    <div x-data="{ dropdown: false}" class="dropdown ml-auto">
                                        <a href="javaScript:;" class="text-black dark:text-white"
                                            @click="dropdown = !dropdown" @keydown.escape="dropdown = false">
                                            <svg width="28" height="28" viewBox="0 0 28 28" fill="none"
                                                xmlns="http://www.w3.org/2000/svg">
                                                <path
                                                    d="M9 12.75C9.69036 12.75 10.25 13.3096 10.25 14C10.25 14.6904 9.69036 15.25 9 15.25C8.30964 15.25 7.75 14.6904 7.75 14C7.75 13.3096 8.30964 12.75 9 12.75Z"
                                                    fill="currentColor" />
                                                <path
                                                    d="M14 12.75C14.6904 12.75 15.25 13.3096 15.25 14C15.25 14.6904 14.6904 15.25 14 15.25C13.3096 15.25 12.75 14.6904 12.75 14C12.75 13.3096 13.3096 12.75 14 12.75Z"
                                                    fill="currentColor" />
                                                <path
                                                    d="M20.25 14C20.25 13.3096 19.6904 12.75 19 12.75C18.3096 12.75 17.75 13.3096 17.75 14C17.75 14.6904 18.3096 15.25 19 15.25C19.6904 15.25 20.25 14.6904 20.25 14Z"
                                                    fill="currentColor" />
                                            </svg>
                                        </a>
                                        <ul x-show="dropdown" @click.away="dropdown = false" x-transition
                                            x-transition.duration.300ms class="right-0 whitespace-nowrap">
                                            <li><a href="javascript:;">Weekly</a></li>
                                            <li><a href="javascript:;">Monthly</a></li>
                                            <li><a href="javascript:;">Yearly</a></li>
                                        </ul>
                                    </div>
                                </div>
                                <div id="depositosSaquesChart" class="text-black dark:text-white"
                                    style="height: 350px;">
                                    <div id="loadingChart" class="flex items-center justify-center h-full"
                                        style="display: none;">
                                        <div class="flex items-center space-x-2">
                                            <div class="w-4 h-4 bg-blue-500 rounded-full animate-pulse"></div>
                                            <div class="w-4 h-4 bg-green-500 rounded-full animate-pulse"
                                                style="animation-delay: 0.2s;"></div>
                                            <div class="w-4 h-4 bg-red-500 rounded-full animate-pulse"
                                                style="animation-delay: 0.4s;"></div>
                                            <span class="text-sm text-gray-600 ml-2">Carregando dados...</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="bg-lightwhite dark:bg-white/5 p-6 rounded-2xl">
                                <h2 class="text-sm font-semibold text-black dark:text-white mb-4">Tráfego do Site
                                    <span class="text-xs text-gray-500 ml-2">(últimos 7 dias)</span>
                                </h2>
                                <div class="flex flex-col gap-[18px]">
                                    <?php
                                    $cores_fontes = [
                                        'Google' => 'bg-blue-500',
                                        'Instagram' => 'bg-pink-500',
                                        'Facebook' => 'bg-blue-600',
                                        'YouTube' => 'bg-red-500',
                                        'Twitter' => 'bg-sky-500',
                                        'Direto' => 'bg-gray-500'
                                    ];
                                    foreach ($trafego_dados as $fonte => $dados):
                                        $cor = isset($cores_fontes[$fonte]) ? $cores_fontes[$fonte] : 'bg-gray-400';
                                        ?>
                                        <div class="flex gap-4 items-center group">
                                            <div class="w-16 flex-none flex items-center gap-2">
                                                <div class="w-2 h-2 rounded-full <?php echo $cor; ?>"></div>
                                                <p class="text-xs font-medium truncate"><?php echo $fonte; ?></p>
                                            </div>
                                            <div class="flex-1 flex items-center gap-2">
                                                <div
                                                    class="flex-1 h-[8px] relative bg-black/10 dark:bg-white/10 rounded-full overflow-hidden">
                                                    <div class="h-full <?php echo $cor; ?> rounded-full transition-all duration-300 hover:opacity-80"
                                                        style="width: <?php echo max($dados['porcentagem'], 2); ?>%;">
                                                    </div>
                                                </div>
                                                <span
                                                    class="text-xs text-gray-600 dark:text-gray-400 min-w-[45px] text-right font-semibold">
                                                    <?php echo $dados['porcentagem']; ?>%
                                                </span>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                                <div class="mt-4 pt-3 border-gray-200 dark:border-gray-700">
                                    <div
                                        class="flex justify-between items-center text-xs">
                                        
                                        <p class="text-xs font-medium truncate">Total de visitas (7 dias)</p>
                                        <span
                                            class="text-xs font-medium truncate"><?php echo number_format($estatisticas_trafego['visitas_7_dias']); ?></span>
                                    </div>
                                    <div
                                        class="flex justify-between items-center text-xs mt-1">
                                         <p class="text-xs font-medium truncate">Hoje</p>
                                        <span
                                            class="text-xs font-medium truncate <?php echo $estatisticas_trafego['crescimento_diario'] >= 0; ?>">
                                            <?php echo number_format($estatisticas_trafego['visitas_hoje']); ?>
                                            <?php if ($estatisticas_trafego['crescimento_diario'] != 0): ?>
                                                (<?php echo $estatisticas_trafego['crescimento_diario'] > 0 ? '+' : ''; ?><?php echo $estatisticas_trafego['crescimento_diario']; ?>%)
                                            <?php endif; ?>
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                      
                    </div>
                </div>
                <!-- Start Footer -->
                <footer
                    class="p-7 bg-white dark:bg-black flex flex-wrap items-center justify-center sm:justify-between gap-3">
                    <p class="text-xs text-black/40 dark:text-white/40">&copy; 2023 Snow</p>
                    <ul class="flex items-center text-black/40 dark:text-white/40 text-xs">
                        <li><a href="javascirpt:;"
                                class="px-2 py-1 hover:text-black dark:hover:text-white transition-all duration-300">About</a>
                        </li>
                        <li><a href="javascirpt:;"
                                class="px-2 py-1 hover:text-black dark:hover:text-white transition-all duration-300">Support</a>
                        </li>
                        <li><a href="javascirpt:;"
                                class="px-2 py-1 hover:text-black dark:hover:text-white transition-all duration-300">Contact
                                Us</a></li>
                    </ul>
                </footer>
                <!-- End Footer -->
            </div>
            <!-- End Content -->
        </div>
        <!-- End Content Area -->
        <?php include './partes/notificacao.php'; ?>
    </div>
    <!-- End Main Content -->
    <?php include './partes/footer.php'; ?>

    <script>
        // Dados do gráfico vindos do PHP
        const dadosGrafico7Dias = <?php echo json_encode($dados_grafico); ?>;
        let chartInstance = null;

        // Função para preparar dados para o ApexCharts
        function prepararDadosGrafico(dados) {
            return {
                labels: dados.map(item => item.data),
                depositos: dados.map(item => parseFloat(item.depositos)),
                saques: dados.map(item => parseFloat(item.saques)),
                lucros: dados.map(item => parseFloat(item.lucro))
            };
        }

        // Função para criar configuração do gráfico
        function criarConfigGrafico(dadosPreparados, titulo = 'Últimos 7 dias') {
            return {
                series: [
                    {
                        name: 'Depósitos',
                        data: dadosPreparados.depositos,
                        color: '#10B981'
                    },
                    {
                        name: 'Saques',
                        data: dadosPreparados.saques,
                        color: '#EF4444'
                    },
                    {
                        name: 'Lucro',
                        data: dadosPreparados.lucros,
                        color: '#3B82F6'
                    }
                ],
                chart: {
                    type: 'line',
                    height: 350,
                    toolbar: {
                        show: false
                    },
                    background: 'transparent',
                    animations: {
                        enabled: true,
                        easing: 'easeinout',
                        speed: 800
                    },
                    zoom: {
                        enabled: false
                    }
                },
                dataLabels: {
                    enabled: false
                },
                markers: {
                    size: 6,
                    strokeColors: '#fff',
                    strokeWidth: 2,
                    hover: {
                        size: 8,
                        sizeOffset: 2
                    }
                },
                stroke: {
                    curve: 'smooth',
                    width: 3,
                    lineCap: 'round'
                },
                xaxis: {
                    categories: dadosPreparados.labels,
                    labels: {
                        style: {
                            colors: '#64748B',
                            fontSize: '12px'
                        }
                    },
                    axisBorder: {
                        show: false
                    },
                    axisTicks: {
                        show: false
                    }
                },
                yaxis: {
                    labels: {
                        style: {
                            colors: '#64748B',
                            fontSize: '12px'
                        },
                        formatter: function (val) {
                            return 'R$ ' + val.toLocaleString('pt-BR', {
                                minimumFractionDigits: 2,
                                maximumFractionDigits: 2
                            });
                        }
                    }
                },
                fill: {
                    opacity: 1,
                    type: 'gradient',
                    gradient: {
                        shade: 'light',
                        type: 'vertical',
                        shadeIntensity: 0.25,
                        gradientToColors: undefined,
                        inverseColors: true,
                        opacityFrom: 0.8,
                        opacityTo: 0.1,
                        stops: [0, 100]
                    }
                },
                tooltip: {
                    theme: 'light',
                    y: {
                        formatter: function (val) {
                            return 'R$ ' + val.toLocaleString('pt-BR', {
                                minimumFractionDigits: 2,
                                maximumFractionDigits: 2
                            });
                        }
                    }
                },
                legend: {
                    position: 'top',
                    horizontalAlign: 'left',
                    fontSize: '12px',
                    markers: {
                        width: 8,
                        height: 8,
                        radius: 2
                    },
                    itemMargin: {
                        horizontal: 15
                    }
                },
                grid: {
                    show: true,
                    borderColor: '#E2E8F0',
                    strokeDashArray: 3,
                    xaxis: {
                        lines: {
                            show: false
                        }
                    },
                    yaxis: {
                        lines: {
                            show: true
                        }
                    }
                },
                responsive: [
                    {
                        breakpoint: 768,
                        options: {
                            chart: {
                                height: 280
                            },
                            markers: {
                                size: 4
                            },
                            legend: {
                                position: 'bottom'
                            }
                        }
                    },
                    {
                        breakpoint: 480,
                        options: {
                            chart: {
                                height: 250
                            },
                            markers: {
                                size: 3
                            },
                            stroke: {
                                width: 2
                            },
                            xaxis: {
                                labels: {
                                    rotate: -45
                                }
                            }
                        }
                    }
                ]
            };
        }

        // Função para mostrar/esconder loading
        function mostrarLoading(mostrar) {
            const loading = document.getElementById('loadingChart');
            if (loading) {
                loading.style.display = mostrar ? 'flex' : 'none';
            }
        }

        // Função para carregar dados via AJAX
        function carregarDados(periodo) {
            mostrarLoading(true);
            return new Promise((resolve, reject) => {
                const xhr = new XMLHttpRequest();
                xhr.open('POST', 'ajax/dados-grafico.php', true);
                xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                xhr.onreadystatechange = function () {
                    if (xhr.readyState === 4) {
                        mostrarLoading(false);
                        if (xhr.status === 200) {
                            try {
                                const dados = JSON.parse(xhr.responseText);
                                resolve(dados);
                            } catch (e) {
                                reject(e);
                            }
                        } else {
                            reject(new Error('Erro na requisição'));
                        }
                    }
                };
                xhr.send('periodo=' + periodo);
            });
        }

        // Função para atualizar gráfico
        function atualizarGrafico(periodo) {
            if (periodo === '7dias') {
                const dadosPreparados = prepararDadosGrafico(dadosGrafico7Dias);
                const config = criarConfigGrafico(dadosPreparados, 'Últimos 7 dias');

                if (chartInstance) {
                    chartInstance.updateOptions(config);
                } else {
                    chartInstance = new ApexCharts(document.querySelector("#depositosSaquesChart"), config);
                    chartInstance.render();
                }
            } else {
                // Para outros períodos, fazer requisição AJAX
                carregarDados(periodo).then(dados => {
                    const dadosPreparados = prepararDadosGrafico(dados);
                    let titulo = '';

                    switch (periodo) {
                        case '30dias':
                            titulo = 'Últimos 30 dias';
                            break;
                        case 'semanal':
                            titulo = 'Últimas 4 semanas';
                            break;
                        default:
                            titulo = 'Período selecionado';
                    }

                    const config = criarConfigGrafico(dadosPreparados, titulo);

                    if (chartInstance) {
                        chartInstance.updateOptions(config);
                    }
                }).catch(error => {
                    console.error('Erro ao carregar dados:', error);
                });
            }
        }

        // Renderizar o gráfico inicial
        document.addEventListener('DOMContentLoaded', function () {
            atualizarGrafico('7dias');

            // Adicionar eventos aos botões de período
            const selectPeriodo = document.querySelector('#seletorPeriodo');
            if (selectPeriodo) {
                selectPeriodo.addEventListener('change', function () {
                    const periodo = this.value;
                    let periodoAPI = '';

                    switch (periodo) {
                        case 'week':
                            periodoAPI = '7dias';
                            break;
                        case 'month':
                            periodoAPI = '30dias';
                            break;
                        case 'weeks':
                            periodoAPI = 'semanal';
                            break;
                        default:
                            periodoAPI = '7dias';
                    }

                    atualizarGrafico(periodoAPI);
                });
            }
        });
    </script>
</body>

</html>