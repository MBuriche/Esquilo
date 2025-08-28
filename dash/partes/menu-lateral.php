<!-- Start Logo -->
<div class="flex p-4">
    <a class='main-logo flex-1 w-full' href='/'>
        <p class="text-2x font-bold"></p>
    </a>
</div>
<!-- End Logo -->

<!-- Start Menu -->
<ul class="relative h-[calc(100vh-58px)] flex flex-col gap-1 overflow-y-auto overflow-x-hidden p-4 py-0"
    x-data="{ activeMenu: 'dashboard' }">
    <li class="menu nav-item">
        <a href="javaScript:;" class="nav-link group text-black dark:text-white"
            :class="{'active' : activeMenu === 'dashboard'}"
            @click="activeMenu === 'dashboard' ? activeMenu = null : activeMenu = 'dashboard'">
            <div class="text-black/50 dark:text-white/20 w-4 h-4 flex items-center justify-center"
                :class="{'!rotate-90' : activeMenu === 'dashboard'}">
                <svg width="6" height="10" viewBox="0 0 6 10" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path fill-rule="evenodd" clip-rule="evenodd"
                        d="M0.659675 9.35355C0.446775 9.15829 0.446775 8.84171 0.659675 8.64645L4.25 5.35355C4.4629 5.15829 4.4629 4.84171 4.25 4.64645L0.659675 1.35355C0.446776 1.15829 0.446776 0.841709 0.659675 0.646446C0.872575 0.451184 1.21775 0.451185 1.43065 0.646446L5.02098 3.93934C5.65967 4.52513 5.65968 5.47487 5.02098 6.06066L1.43065 9.35355C1.21775 9.54882 0.872574 9.54882 0.659675 9.35355Z"
                        fill="currentcolor" />
                </svg>
            </div>
            <div class="flex items-center">
                <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none"
                    xmlns="http://www.w3.org/2000/svg">
                    <path
                        d="M4.20007 18.2C4.06372 17.4747 3.9967 16.738 4.00012 16C3.99854 13.5182 4.76721 11.0972 6.2002 9.07092C7.63318 7.04456 9.65967 5.51306 12.0001 4.6875V13.6875L4.20007 18.2Z"
                        fill="black" fill-opacity="0.1" />
                    <path
                        d="M17 16V4C17 3.44772 16.5523 3 16 3C15.4477 3 15 3.44772 15 4V16C15 16.5523 15.4477 17 16 17C16.5523 17 17 16.5523 17 16Z"
                        fill="currentcolor" />
                    <path
                        d="M5.11288 21.1336L5.11213 21.1341C4.88247 21.2667 4.71492 21.4852 4.64633 21.7414C4.62374 21.8257 4.6123 21.9127 4.6123 22C4.6123 22.0106 4.61247 22.0212 4.61281 22.0317C4.61804 22.1965 4.66392 22.3574 4.74638 22.5002C4.92504 22.8095 5.25511 23 5.6123 23C5.62784 23 5.64337 22.9996 5.65889 22.9989C5.81854 22.9915 5.97408 22.9459 6.11248 22.8659L6.11323 22.8655L26.8875 10.8659C27.1968 10.6873 27.3873 10.3572 27.3873 10C27.3873 9.98447 27.3869 9.96894 27.3862 9.95342C27.3788 9.79377 27.3332 9.63822 27.2532 9.49983C27.1206 9.27017 26.9021 9.10261 26.6459 9.03402C26.5616 9.01144 26.4746 9 26.3873 9C26.3767 9 26.3662 9.00017 26.3556 9.0005C26.1908 9.00573 26.0299 9.05162 25.8871 9.13407L5.11288 21.1336Z"
                        fill="currentcolor" />
                    <path fill-rule="evenodd" clip-rule="evenodd"
                        d="M12.5009 14.5531L4.70089 19.0656C4.47132 19.1984 4.1984 19.2346 3.94216 19.1662C3.68592 19.0977 3.46735 18.9303 3.33454 18.7008C3.27789 18.6028 3.23827 18.496 3.21736 18.3849C3.21736 18.3849 2.99459 17.2005 3.00013 15.9954C3.00013 15.9954 2.99749 11.8678 5.38375 8.4935C5.38375 8.4935 7.77001 5.11918 11.6675 3.74445C11.9176 3.65622 12.1925 3.67097 12.4318 3.78545C12.671 3.89992 12.855 4.10475 12.9432 4.35486C12.9809 4.46172 13.0001 4.5742 13.0001 4.6875V13.6875C13.0001 14.0445 12.8099 14.3743 12.5009 14.5531ZM5.01273 16.5746L11.0001 13.1107V6.19572C11.0001 6.19572 8.61014 7.39503 7.01668 9.64828C7.01668 9.64828 4.9979 12.503 5.00011 16.0046C5.00011 16.0046 4.9988 16.2903 5.01273 16.5746Z"
                        fill="currentcolor" />
                    <path
                        d="M10.5588 25.5608C8.00169 24.1059 6.51229 21.5688 6.51229 21.5688C6.37802 21.34 6.1584 21.174 5.90173 21.1072C5.8195 21.0858 5.73487 21.075 5.64991 21.075C5.63698 21.075 5.62406 21.0753 5.61115 21.0758C5.44642 21.0821 5.28582 21.1292 5.14365 21.2126C4.83778 21.3922 4.6499 21.7203 4.6499 22.075L4.64991 22.0779C4.65042 22.2549 4.6979 22.4286 4.78752 22.5813C6.54772 25.5797 9.56976 27.2991 9.56976 27.2991C12.5918 29.0186 16.0687 28.9998 16.0687 28.9998C19.5456 28.981 22.5489 27.2291 22.5489 27.2291C25.5522 25.4772 27.2799 22.4599 27.2799 22.4599C29.0077 19.4426 28.9985 15.9657 28.9985 15.9657C28.9893 12.4887 27.2457 9.48061 27.2457 9.48061C25.502 6.47249 22.4895 4.73644 22.4895 4.73644C19.477 3.00039 16 3 16 3C15.9389 3 15.878 3.00558 15.8181 3.01667C15.344 3.10435 15 3.51778 14.9999 3.99989C14.9999 4.01594 15.0003 4.03196 15.0011 4.04792C15.013 4.29624 15.1169 4.53122 15.2927 4.70702C15.4802 4.89458 15.7346 4.99997 15.9998 5H16.0002C18.942 5.00045 21.4909 6.4693 21.4909 6.4693C24.0399 7.93826 25.5153 10.4836 25.5153 10.4836C26.9907 13.0289 26.9985 15.9709 26.9985 15.9709C27.0063 18.913 25.5443 21.4661 25.5443 21.4661C24.0824 24.0191 21.5411 25.5016 21.5411 25.5016C18.9999 26.984 16.0579 26.9998 16.0579 26.9998C13.1159 27.0157 10.5588 25.5608 10.5588 25.5608Z"
                        fill="currentcolor" />
                </svg>
                <span class="pl-1">Painel De Controle</span>
            </div>
        </a>
        <ul x-cloak x-show="activeMenu === 'dashboard'" x-collapse
            class="sub-menu flex flex-col gap-1 text-black dark:text-white/80">
            <li>
                <a class='active' href='index'>Relatórios</a>
            </li>

        </ul>
    </li>
    <h2 class="pl-3 my-2 text-black/60 dark:text-white/40 text-sm">
        <span>Gestão do sistema</span>
    </h2>
    <li class="menu nav-item">
        <a href="javaScript:;" class="nav-link group active text-black dark:text-white"
            :class="{'active' : activeMenu === 'apps'}"
            @click="activeMenu === 'apps' ? activeMenu = null : activeMenu = 'apps'">
            <div class="text-black/50 dark:text-white/20 w-4 h-4 flex items-center justify-center"
                :class="{'!rotate-90' : activeMenu === 'apps'}">
                <svg width="6" height="10" viewBox="0 0 6 10" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path fill-rule="evenodd" clip-rule="evenodd"
                        d="M0.659675 9.35355C0.446775 9.15829 0.446775 8.84171 0.659675 8.64645L4.25 5.35355C4.4629 5.15829 4.4629 4.84171 4.25 4.64645L0.659675 1.35355C0.446776 1.15829 0.446776 0.841709 0.659675 0.646446C0.872575 0.451184 1.21775 0.451185 1.43065 0.646446L5.02098 3.93934C5.65967 4.52513 5.65968 5.47487 5.02098 6.06066L1.43065 9.35355C1.21775 9.54882 0.872574 9.54882 0.659675 9.35355Z"
                        fill="currentcolor" />
                </svg>
            </div>
            <div class="flex items-center">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor"
                    viewBox="0 0 256 256">
                    <path
                        d="M152,120H136V56h8a32,32,0,0,1,32,32,8,8,0,0,0,16,0,48.05,48.05,0,0,0-48-48h-8V24a8,8,0,0,0-16,0V40h-8a48,48,0,0,0,0,96h8v64H104a32,32,0,0,1-32-32,8,8,0,0,0-16,0,48.05,48.05,0,0,0,48,48h16v16a8,8,0,0,0,16,0V216h16a48,48,0,0,0,0-96Zm-40,0a32,32,0,0,1,0-64h8v64Zm40,80H136V136h16a32,32,0,0,1,0,64Z">
                    </path>
                </svg>
                <span class="pl-1">Controle Da Casa</span>
            </div>
        </a>
        <ul x-cloak x-show="activeMenu === 'apps'" x-collapse
            class="sub-menu flex flex-col gap-1 text-black dark:text-white/80">
            <li><a href='caixa-premiacoes'>Caixa</a></li>
            <li><a href='valores'>Valores</a></li>
        </ul>
    </li>
    <li class="menu nav-item">
        <a href="javaScript:;" class="nav-link group active text-black dark:text-white"
            :class="{'active' : activeMenu === 'components'}"
            @click="activeMenu === 'components' ? activeMenu = null : activeMenu = 'components'">
            <div class="text-black/50 dark:text-white/20 w-4 h-4 flex items-center justify-center"
                :class="{'!rotate-90' : activeMenu === 'components'}">
                <svg width="6" height="10" viewBox="0 0 6 10" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path fill-rule="evenodd" clip-rule="evenodd"
                        d="M0.659675 9.35355C0.446775 9.15829 0.446775 8.84171 0.659675 8.64645L4.25 5.35355C4.4629 5.15829 4.4629 4.84171 4.25 4.64645L0.659675 1.35355C0.446776 1.15829 0.446776 0.841709 0.659675 0.646446C0.872575 0.451184 1.21775 0.451185 1.43065 0.646446L5.02098 3.93934C5.65967 4.52513 5.65968 5.47487 5.02098 6.06066L1.43065 9.35355C1.21775 9.54882 0.872574 9.54882 0.659675 9.35355Z"
                        fill="currentcolor" />
                </svg>
            </div>
            <div class="flex items-center">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor"
                    viewBox="0 0 256 256">
                    <path
                        d="M128,80a48,48,0,1,0,48,48A48.05,48.05,0,0,0,128,80Zm0,80a32,32,0,1,1,32-32A32,32,0,0,1,128,160Zm88-29.84q.06-2.16,0-4.32l14.92-18.64a8,8,0,0,0,1.48-7.06,107.21,107.21,0,0,0-10.88-26.25,8,8,0,0,0-6-3.93l-23.72-2.64q-1.48-1.56-3-3L186,40.54a8,8,0,0,0-3.94-6,107.71,107.71,0,0,0-26.25-10.87,8,8,0,0,0-7.06,1.49L130.16,40Q128,40,125.84,40L107.2,25.11a8,8,0,0,0-7.06-1.48A107.6,107.6,0,0,0,73.89,34.51a8,8,0,0,0-3.93,6L67.32,64.27q-1.56,1.49-3,3L40.54,70a8,8,0,0,0-6,3.94,107.71,107.71,0,0,0-10.87,26.25,8,8,0,0,0,1.49,7.06L40,125.84Q40,128,40,130.16L25.11,148.8a8,8,0,0,0-1.48,7.06,107.21,107.21,0,0,0,10.88,26.25,8,8,0,0,0,6,3.93l23.72,2.64q1.49,1.56,3,3L70,215.46a8,8,0,0,0,3.94,6,107.71,107.71,0,0,0,26.25,10.87,8,8,0,0,0,7.06-1.49L125.84,216q2.16.06,4.32,0l18.64,14.92a8,8,0,0,0,7.06,1.48,107.21,107.21,0,0,0,26.25-10.88,8,8,0,0,0,3.93-6l2.64-23.72q1.56-1.48,3-3L215.46,186a8,8,0,0,0,6-3.94,107.71,107.71,0,0,0,10.87-26.25,8,8,0,0,0-1.49-7.06Zm-16.1-6.5a73.93,73.93,0,0,1,0,8.68,8,8,0,0,0,1.74,5.48l14.19,17.73a91.57,91.57,0,0,1-6.23,15L187,173.11a8,8,0,0,0-5.1,2.64,74.11,74.11,0,0,1-6.14,6.14,8,8,0,0,0-2.64,5.1l-2.51,22.58a91.32,91.32,0,0,1-15,6.23l-17.74-14.19a8,8,0,0,0-5-1.75h-.48a73.93,73.93,0,0,1-8.68,0,8,8,0,0,0-5.48,1.74L100.45,215.8a91.57,91.57,0,0,1-15-6.23L82.89,187a8,8,0,0,0-2.64-5.1,74.11,74.11,0,0,1-6.14-6.14,8,8,0,0,0-5.1-2.64L46.43,170.6a91.32,91.32,0,0,1-6.23-15l14.19-17.74a8,8,0,0,0,1.74-5.48,73.93,73.93,0,0,1,0-8.68,8,8,0,0,0-1.74-5.48L40.2,100.45a91.57,91.57,0,0,1,6.23-15L69,82.89a8,8,0,0,0,5.1-2.64,74.11,74.11,0,0,1,6.14-6.14A8,8,0,0,0,82.89,69L85.4,46.43a91.32,91.32,0,0,1,15-6.23l17.74,14.19a8,8,0,0,0,5.48,1.74,73.93,73.93,0,0,1,8.68,0,8,8,0,0,0,5.48-1.74L155.55,40.2a91.57,91.57,0,0,1,15,6.23L173.11,69a8,8,0,0,0,2.64,5.1,74.11,74.11,0,0,1,6.14,6.14,8,8,0,0,0,5.1,2.64l22.58,2.51a91.32,91.32,0,0,1,6.23,15l-14.19,17.74A8,8,0,0,0,199.87,123.66Z">
                    </path>
                </svg>
                <span class="pl-1">Configurações</span>
            </div>
        </a>
        <ul x-cloak x-show="activeMenu === 'components'" x-collapse
            class="sub-menu flex flex-col gap-1 text-black dark:text-white/80">
            <li>
                <a href='sistema'>Sistema</a>
            </li>
            <li>
                <a href='afiliados'>Afiliados</a>
            </li>
            <li>
                <a href='pagamentos'>Pagamentos</a>
            </li>
        </ul>
    </li>

    <li class="menu nav-item">
        <a href="javaScript:;" class="nav-link group text-black dark:text-white"
            :class="{'active' : activeMenu === 'personalizacao'}"
            @click="activeMenu === 'personalizacao' ? activeMenu = null : activeMenu = 'personalizacao'">
            <div class="text-black/50 dark:text-white/20 w-4 h-4 flex items-center justify-center"
                :class="{'!rotate-90' : activeMenu === 'personalizacao'}">
                <svg width="6" height="10" viewBox="0 0 6 10" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path fill-rule="evenodd" clip-rule="evenodd"
                        d="M0.659675 9.35355C0.446775 9.15829 0.446775 8.84171 0.659675 8.64645L4.25 5.35355C4.4629 5.15829 4.4629 4.84171 4.25 4.64645L0.659675 1.35355C0.446776 1.15829 0.446776 0.841709 0.659675 0.646446C0.872575 0.451184 1.21775 0.451185 1.43065 0.646446L5.02098 3.93934C5.65967 4.52513 5.65968 5.47487 5.02098 6.06066L1.43065 9.35355C1.21775 9.54882 0.872574 9.54882 0.659675 9.35355Z"
                        fill="currentcolor" />
                </svg>
            </div>
            <div class="flex items-center">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor"
                    viewBox="0 0 256 256">
                    <path
                        d="M200.77,53.89A103.27,103.27,0,0,0,128,24h-1.07A104,104,0,0,0,24,128c0,43,26.58,79.06,69.36,94.17A32,32,0,0,0,136,192a16,16,0,0,1,16-16h46.21a31.81,31.81,0,0,0,31.2-24.88,104.43,104.43,0,0,0,2.59-24A103.28,103.28,0,0,0,200.77,53.89Zm13,93.71A15.89,15.89,0,0,1,198.21,160H152a32,32,0,0,0-32,32,16,16,0,0,1-21.31,15.07C62.49,194.3,40,164,40,128a88,88,0,0,1,87.09-88h.9a88.35,88.35,0,0,1,88,87.25A88.86,88.86,0,0,1,213.81,147.6ZM140,76a12,12,0,1,1-12-12A12,12,0,0,1,140,76ZM96,100A12,12,0,1,1,84,88,12,12,0,0,1,96,100Zm0,56a12,12,0,1,1-12-12A12,12,0,0,1,96,156Zm88-56a12,12,0,1,1-12-12A12,12,0,0,1,184,100Z">
                    </path>
                </svg>

                <span class="pl-1">Personalização</span>
            </div>
        </a>
        <ul x-cloak x-show="activeMenu === 'personalizacao'" x-collapse
            class="sub-menu flex flex-col gap-1 text-black dark:text-white/80">
            <li>
                <a href='imagens'>Imagens</a>
            </li>
            
            
        </ul>
    </li>
    <h2 class="pl-3 my-2 text-black/40 dark:text-white/40 text-sm">
        <span><?php echo $dataconfig['nome_site']; ?></span>
    </h2>
   <!-- <li class="menu nav-item">
        <a :class="{'active': activeMenu === 'table'}" class="nav-link group" href="raspadinhas">
            <div class="flex pl-5 items-center">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor"
                    viewBox="0 0 256 256">
                    <path
                        d="M227.19,104.48A16,16,0,0,0,240,88.81V64a16,16,0,0,0-16-16H32A16,16,0,0,0,16,64V88.81a16,16,0,0,0,12.81,15.67,24,24,0,0,1,0,47A16,16,0,0,0,16,167.19V192a16,16,0,0,0,16,16H224a16,16,0,0,0,16-16V167.19a16,16,0,0,0-12.81-15.67,24,24,0,0,1,0-47ZM32,167.2a40,40,0,0,0,0-78.39V64H88V192H32Zm192,0V192H104V64H224V88.8a40,40,0,0,0,0,78.39Z">
                    </path>
                </svg>
                <span class="pl-1 text-black dark:text-white">Raspadinhas</span>
            </div>
        </a>
    </li> -->


    <li class="menu nav-item">
        <a :class="{'active': activeMenu === 'historico-raspadinhas'}" class="nav-link group" href="historico-raspadinhas">
            <div class="flex pl-5 items-center">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor"
                    viewBox="0 0 256 256">
                    <path
                        d="M232,136.66A104.12,104.12,0,1,1,119.34,24,8,8,0,0,1,120.66,40,88.12,88.12,0,1,0,216,135.34,8,8,0,0,1,232,136.66ZM120,72v56a8,8,0,0,0,8,8h56a8,8,0,0,0,0-16H136V72a8,8,0,0,0-16,0Zm40-24a12,12,0,1,0-12-12A12,12,0,0,0,160,48Zm36,24a12,12,0,1,0-12-12A12,12,0,0,0,196,72Zm24,36a12,12,0,1,0-12-12A12,12,0,0,0,220,108Z">
                    </path>
                </svg>
                <span class="pl-1 text-black dark:text-white">Histórico</span>
            </div>
        </a>
    </li>
    <!-- <li class="menu nav-item">
        <a href="javaScript:;" class="nav-link group" :class="{'active' : activeMenu === 'forms'}"
            @click="activeMenu === 'forms' ? activeMenu = null : activeMenu = 'forms'">
            <div class="text-black/50 dark:text-white/20 w-4 h-4 flex items-center justify-center"
                :class="{'!rotate-90' : activeMenu === 'forms'}">
                <svg width="6" height="10" viewBox="0 0 6 10" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path fill-rule="evenodd" clip-rule="evenodd"
                        d="M0.659675 9.35355C0.446775 9.15829 0.446775 8.84171 0.659675 8.64645L4.25 5.35355C4.4629 5.15829 4.4629 4.84171 4.25 4.64645L0.659675 1.35355C0.446776 1.15829 0.446776 0.841709 0.659675 0.646446C0.872575 0.451184 1.21775 0.451185 1.43065 0.646446L5.02098 3.93934C5.65967 4.52513 5.65968 5.47487 5.02098 6.06066L1.43065 9.35355C1.21775 9.54882 0.872574 9.54882 0.659675 9.35355Z"
                        fill="currentcolor" />
                </svg>
            </div>
            <div class="flex items-center">
                <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none"
                    xmlns="http://www.w3.org/2000/svg">
                    <path
                        d="M20 5C20.6492 5.86548 21 6.91809 21 8V9H11V8C11 6.91809 11.3508 5.86548 12 5H7C6.73486 5 6.48047 5.10535 6.29297 5.29285C6.10547 5.48047 6 5.73474 6 6V27C6 27.2653 6.10547 27.5195 6.29297 27.7072C6.48047 27.8947 6.73486 28 7 28H25C25.2651 28 25.5195 27.8947 25.707 27.7072C25.8945 27.5195 26 27.2653 26 27V6C26 5.73474 25.8945 5.48047 25.707 5.29285C25.5195 5.10535 25.2651 5 25 5H20Z"
                        fill="black" fill-opacity="0.1" />
                    <path
                        d="M12 20H20C20.5523 20 21 19.5523 21 19C21 18.4477 20.5523 18 20 18H12C11.4477 18 11 18.4477 11 19C11 19.5523 11.4477 20 12 20Z"
                        fill="currentcolor" />
                    <path
                        d="M12 16H20C20.5523 16 21 15.5523 21 15C21 14.4477 20.5523 14 20 14H12C11.4477 14 11 14.4477 11 15C11 15.5523 11.4477 16 12 16Z"
                        fill="currentcolor" />
                    <path
                        d="M7 6H12C12.5523 6 13 5.55228 13 5C13 4.44772 12.5523 4 12 4H7C6.17157 4 5.58579 4.58579 5.58579 4.58579C5 5.17157 5 6 5 6V27C5 27.8284 5.58579 28.4142 5.58579 28.4142C6.17157 29 7 29 7 29H25C25.8284 29 26.4142 28.4142 26.4142 28.4142C27 27.8284 27 27 27 27V6C27 5.17157 26.4142 4.58579 26.4142 4.58579C25.8284 4 25 4 25 4H20C19.4477 4 19 4.44772 19 5C19 5.55228 19.4477 6 20 6H25V27H7V6Z"
                        fill="currentcolor" />
                    <path fill-rule="evenodd" clip-rule="evenodd"
                        d="M11 10C10.4477 10 10 9.55228 10 9V8C10 8 10 5.51472 11.7574 3.75736C11.7574 3.75736 13.5147 2 16 2C16 2 18.4853 2 20.2426 3.75736C20.2426 3.75736 22 5.51472 22 8V9C22 9.55228 21.5523 10 21 10H11ZM18.8284 5.17157C18.8284 5.17157 20 6.34315 20 8H12C12 8 12 6.34315 13.1716 5.17157C13.1716 5.17157 14.3431 4 16 4C16 4 17.6569 4 18.8284 5.17157Z"
                        fill="currentcolor" />
                </svg>
                <span class="pl-1 text-black dark:text-white">Histórico</span>
            </div>
        </a>
        <ul x-cloak x-show="activeMenu === 'forms'" x-collapse
            class="sub-menu flex flex-col gap-1 text-black dark:text-white/80">
            <li>
                <a href='/forms-basic'>Basic</a>
            </li>
            <li>
                <a href='/input-group'>Input Group</a>
            </li>
            <li>
                <a href='/validation'>Validation</a>
            </li>
            <li>
                <a href='/checkbox'>Checkbox </a>
            </li>
            <li>
                <a href='/radio'>Radio</a>
            </li>
            <li>
                <a href='/switches'>Switches</a>
            </li>
        </ul>
    </li> -->
    <h2 class="pl-3 my-2 text-black/40 dark:text-white/40 text-sm">
        <span>Financeiro</span>
    </h2>
    <li class="menu nav-item">
        <a href="javaScript:;" class="nav-link group" :class="{'active' : activeMenu === 'pages'}"
            @click="activeMenu === 'pages' ? activeMenu = null : activeMenu = 'pages'">
            <div class="text-black/50 dark:text-white/20 w-4 h-4 flex items-center justify-center"
                :class="{'!rotate-90' : activeMenu === 'pages'}">
                <svg width="6" height="10" viewBox="0 0 6 10" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path fill-rule="evenodd" clip-rule="evenodd"
                        d="M0.659675 9.35355C0.446775 9.15829 0.446775 8.84171 0.659675 8.64645L4.25 5.35355C4.4629 5.15829 4.4629 4.84171 4.25 4.64645L0.659675 1.35355C0.446776 1.15829 0.446776 0.841709 0.659675 0.646446C0.872575 0.451184 1.21775 0.451185 1.43065 0.646446L5.02098 3.93934C5.65967 4.52513 5.65968 5.47487 5.02098 6.06066L1.43065 9.35355C1.21775 9.54882 0.872574 9.54882 0.659675 9.35355Z"
                        fill="currentcolor" />
                </svg>
            </div>
            <div class="flex items-center">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor"
                    viewBox="0 0 256 256">
                    <path
                        d="M213.66,82.34l-56-56A8,8,0,0,0,152,24H56A16,16,0,0,0,40,40V216a16,16,0,0,0,16,16H200a16,16,0,0,0,16-16V88A8,8,0,0,0,213.66,82.34ZM160,51.31,188.69,80H160ZM200,216H56V40h88V88a8,8,0,0,0,8,8h48V216Zm-42.34-61.66a8,8,0,0,1,0,11.32l-24,24a8,8,0,0,1-11.32,0l-24-24a8,8,0,0,1,11.32-11.32L120,164.69V120a8,8,0,0,1,16,0v44.69l10.34-10.35A8,8,0,0,1,157.66,154.34Z">
                    </path>
                </svg>
                <span class="pl-1 text-black dark:text-white">Depósitos</span>
            </div>
        </a>
        <ul x-cloak x-show="activeMenu === 'pages'" x-collapse
            class="sub-menu flex flex-col gap-1 text-black dark:text-white/80">
            <li><a href='depositos'>Todos Depósitos</a></li>
        </ul>
    </li>
    <li class="menu nav-item">
        <a href="javaScript:;" class="nav-link group" :class="{'active' : activeMenu === 'authentication'}"
            @click="activeMenu === 'authentication' ? activeMenu = null : activeMenu = 'authentication'">
            <div class="text-black/50 dark:text-white/20 w-4 h-4 flex items-center justify-center"
                :class="{'!rotate-90' : activeMenu === 'authentication'}">
                <svg width="6" height="10" viewBox="0 0 6 10" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path fill-rule="evenodd" clip-rule="evenodd"
                        d="M0.659675 9.35355C0.446775 9.15829 0.446775 8.84171 0.659675 8.64645L4.25 5.35355C4.4629 5.15829 4.4629 4.84171 4.25 4.64645L0.659675 1.35355C0.446776 1.15829 0.446776 0.841709 0.659675 0.646446C0.872575 0.451184 1.21775 0.451185 1.43065 0.646446L5.02098 3.93934C5.65967 4.52513 5.65968 5.47487 5.02098 6.06066L1.43065 9.35355C1.21775 9.54882 0.872574 9.54882 0.659675 9.35355Z"
                        fill="currentcolor" />
                </svg>
            </div>
            <div class="flex items-center">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor"
                    viewBox="0 0 256 256">
                    <path
                        d="M213.66,82.34l-56-56A8,8,0,0,0,152,24H56A16,16,0,0,0,40,40V216a16,16,0,0,0,16,16H200a16,16,0,0,0,16-16V88A8,8,0,0,0,213.66,82.34ZM160,51.31,188.69,80H160ZM200,216H56V40h88V88a8,8,0,0,0,8,8h48V216Zm-42.34-77.66a8,8,0,0,1-11.32,11.32L136,139.31V184a8,8,0,0,1-16,0V139.31l-10.34,10.35a8,8,0,0,1-11.32-11.32l24-24a8,8,0,0,1,11.32,0Z">
                    </path>
                </svg>
                <span class="pl-1 text-black dark:text-white">Saques</span>
            </div>
        </a>
        <ul x-cloak x-show="activeMenu === 'authentication'" x-collapse
            class="sub-menu flex flex-col gap-1 text-black dark:text-white/80">
            <li><a href='saques'>Todos Saques</a></li>
        </ul>
    </li>

    <h2 class="pl-3 my-2 text-black/40 dark:text-white/40 text-sm">
        <span>Gestão De Jogadores</span>
    </h2>
    <li class="menu nav-item">
        <a href="javaScript:;" class="nav-link group" :class="{'active' : activeMenu === 'users'}"
            @click="activeMenu === 'users' ? activeMenu = null : activeMenu = 'users'">
            <div class="text-black/50 dark:text-white/20 w-4 h-4 flex items-center justify-center"
                :class="{'!rotate-90' : activeMenu === 'users'}">
                <svg width="6" height="10" viewBox="0 0 6 10" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path fill-rule="evenodd" clip-rule="evenodd"
                        d="M0.659675 9.35355C0.446775 9.15829 0.446775 8.84171 0.659675 8.64645L4.25 5.35355C4.4629 5.15829 4.4629 4.84171 4.25 4.64645L0.659675 1.35355C0.446776 1.15829 0.446776 0.841709 0.659675 0.646446C0.872575 0.451184 1.21775 0.451185 1.43065 0.646446L5.02098 3.93934C5.65967 4.52513 5.65968 5.47487 5.02098 6.06066L1.43065 9.35355C1.21775 9.54882 0.872574 9.54882 0.659675 9.35355Z"
                        fill="currentcolor" />
                </svg>
            </div>
            <div class="flex items-center">
                <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none"
                    xmlns="http://www.w3.org/2000/svg">
                    <path
                        d="M17.5 13.5C17.5 17.0898 14.5898 20 11 20C7.41016 20 4.5 17.0898 4.5 13.5C4.5 9.91016 7.41016 7 11 7C14.5898 7 17.5 9.91016 17.5 13.5Z"
                        fill="black" fill-opacity="0.1" />
                    <path fill-rule="evenodd" clip-rule="evenodd"
                        d="M11 6C11 6 14.1066 6 16.3033 8.1967C16.3033 8.1967 18.5 10.3934 18.5 13.5C18.5 13.5 18.5 16.6066 16.3033 18.8033C16.3033 18.8033 14.1066 21 11 21C11 21 7.8934 21 5.6967 18.8033C5.6967 18.8033 3.5 16.6066 3.5 13.5C3.5 13.5 3.5 10.3934 5.6967 8.1967C5.6967 8.1967 7.8934 6 11 6ZM11 8C11 8 8.72182 8 7.11091 9.61091C7.11091 9.61091 5.5 11.2218 5.5 13.5C5.5 13.5 5.5 15.7782 7.11091 17.3891C7.11091 17.3891 8.72182 19 11 19C11 19 13.2782 19 14.8891 17.3891C14.8891 17.3891 16.5 15.7782 16.5 13.5C16.5 13.5 16.5 11.2218 14.8891 9.61091C14.8891 9.61091 13.2782 8 11 8Z"
                        fill="currentcolor" />
                    <path
                        d="M25.0764 17.3891C23.4655 19 21.1873 19 21.1873 19C20.635 19 20.1873 19.4477 20.1873 20C20.1873 20.5523 20.635 21 21.1873 21C24.2939 21 26.4906 18.8033 26.4906 18.8033C28.6873 16.6066 28.6873 13.5 28.6873 13.5C28.6873 10.3934 26.4906 8.1967 26.4906 8.1967C24.2939 6 21.1873 6 21.1873 6C20.156 6.00314 19.1636 6.27221 19.1636 6.27221L19.163 6.27237C18.7273 6.39055 18.4248 6.78603 18.4248 7.2375L18.4249 7.24778C18.4257 7.33274 18.4374 7.41725 18.4597 7.49926C18.5778 7.93499 18.9733 8.2375 19.4248 8.2375L19.4351 8.23745C19.52 8.23657 19.6046 8.22488 19.6866 8.20263L19.6868 8.20256C20.4253 8.00232 21.1873 8 21.1873 8C23.4655 8 25.0764 9.61091 25.0764 9.61091C26.6873 11.2218 26.6873 13.5 26.6873 13.5C26.6873 15.7782 25.0764 17.3891 25.0764 17.3891Z"
                        fill="currentcolor" />
                    <path
                        d="M15.61 22.1255C17.7775 23.2515 19.1818 25.2499 19.1818 25.2499C19.3691 25.5164 19.6743 25.675 20 25.675C20.0112 25.675 20.0224 25.6748 20.0335 25.6744C20.2278 25.6679 20.4159 25.6049 20.575 25.4931C20.792 25.3406 20.9395 25.1082 20.9851 24.8469C20.995 24.7901 21 24.7326 21 24.675L20.9998 24.6534C20.9955 24.455 20.9323 24.2623 20.8182 24.1C19.133 21.7019 16.532 20.3507 16.532 20.3507C13.931 18.9995 11 18.9995 11 18.9995C8.06899 18.9995 5.46801 20.3507 5.46801 20.3507C2.86717 21.7018 1.182 24.0997 1.182 24.0997L1.18182 24.1C1.06349 24.2684 1 24.4692 1 24.675C1 24.6981 1.0008 24.7212 1.00241 24.7443C1.02329 25.0448 1.17855 25.3199 1.42504 25.4931C1.59342 25.6115 1.7942 25.675 2 25.675L2.00299 25.675C2.05964 25.6748 2.11618 25.6698 2.17198 25.6601C2.43325 25.6144 2.66569 25.4669 2.81818 25.2499C4.22252 23.2515 6.39001 22.1255 6.39001 22.1255C8.55749 20.9995 11 20.9995 11 20.9995C13.4425 20.9995 15.61 22.1255 15.61 22.1255Z"
                        fill="currentcolor" />
                    <path
                        d="M29.3685 25.2488L29.369 25.2495C29.5562 25.5162 29.8616 25.675 30.1875 25.675C30.1985 25.675 30.2095 25.6748 30.2205 25.6745C30.4147 25.668 30.6029 25.6052 30.762 25.4935C31.0287 25.3063 31.1875 25.0009 31.1875 24.675C31.1875 24.664 31.1873 24.653 31.187 24.642C31.1805 24.4478 31.1177 24.2596 31.006 24.1005C31.0053 24.0995 31.0047 24.0986 31.0047 24.0986C29.3207 21.7004 26.7201 20.3496 26.7201 20.3496C24.1188 18.9983 21.1875 19 21.1875 19L21.1869 19C20.9217 19.0002 20.6674 19.1057 20.48 19.2933C20.2927 19.4808 20.1875 19.735 20.1875 20L20.1875 20.0006C20.1878 20.5527 20.6355 21 21.1875 21H21.1881C23.6306 20.9985 25.7982 22.1244 25.7982 22.1244C27.9653 23.2501 29.3685 25.2488 29.3685 25.2488Z"
                        fill="currentcolor" />
                </svg>

                <span class="pl-1 text-black dark:text-white">Usuários</span>
            </div>
        </a>
        <ul x-cloak x-show="activeMenu === 'users'" x-collapse
            class="sub-menu flex flex-col gap-1 text-black dark:text-white/80">
            <li><a href='usuarios'>Jogadores</a></li>
            <li><a href='listagem-afiliados'>Afiliados</a></li>
        </ul>
    </li>
    <h2 class="pl-3 my-2 text-black/40 dark:text-white/40 text-sm">
        <span>Gestão de Webhooks</span>
    </h2>
    <li class="menu nav-item">
        <a href="webhooks" class="nav-link group"
            :class="{'active' : activeMenu === 'docs'}">
            <div class="flex pl-5 items-center">
                <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none"
                    xmlns="http://www.w3.org/2000/svg">
                    <path fill-rule="evenodd" clip-rule="evenodd"
                        d="M4 6C4 6 4 5.17157 4.58579 4.58579C4.58579 4.58579 5.17157 4 6 4H26C26 4 26.8284 4 27.4142 4.58579C27.4142 4.58579 28 5.17157 28 6V26C28 26 28 26.8284 27.4142 27.4142C27.4142 27.4142 26.8284 28 26 28H6C6 28 5.17157 28 4.58579 27.4142C4.58579 27.4142 4 26.8284 4 26V6ZM6 6V26H26V6H6Z"
                        fill="currentcolor" />
                    <path
                        d="M22.4142 21H27C27.5523 21 28 20.5523 28 20C28 19.4477 27.5523 19 27 19H22.4125C22.0201 18.9986 21.6539 19.149 21.6539 19.149C21.2878 19.2994 21.0071 19.5787 21.0071 19.5787L18.5858 22L13.4142 22L10.9946 19.5804C10.7122 19.2994 10.3461 19.149 10.3461 19.149C9.97986 18.9986 9.58399 19 9.58399 19L5 19C4.44772 19 4 19.4477 4 20C4 20.5523 4.44772 21 5 21L9.58578 21L12.0071 23.4214C12.2878 23.7006 12.6539 23.851 12.6539 23.851C13.0201 24.0014 13.4125 24 13.4125 24L18.584 24C18.9799 24.0014 19.3461 23.851 19.3461 23.851C19.7122 23.7006 19.9946 23.4196 19.9946 23.4196L22.4142 21Z"
                        fill="currentcolor" />
                </svg>
                <span class="pl-1 text-black dark:text-white">Webhooks</span>
            </div>
        </a>
    </li>
</ul>
<!-- End Menu -->