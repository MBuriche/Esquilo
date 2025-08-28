<!DOCTYPE html>
<html x-data="main" class="" :class="[$store.app.mode]">

<?php include_once './partes/head-login.php'; ?>
<?php include_once './partes/head-js.php'; ?>

<body
    class="antialiased relative font-inter bg-lightwhite dark:bg-black text-black dark:text-white text-sm font-normal overflow-x-hidden">
    <!-- Start Header -->
    <header>
        <nav class="bg-lightwhite dark:bg-black px-4 lg:px-7 py-4">
            <div class="flex flex-wrap justify-between items-center">
                
                <div class="flex items-center lg:order-2">
                    <div class="mr-2">
                        <a href="javascript:;" class="text-black dark:text-white" x-cloak
                            x-show="$store.app.mode === 'light'" @click="$store.app.toggleMode('dark')">
                            <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none"
                                xmlns="http://www.w3.org/2000/svg">
                                <path
                                    d="M27.0876 19.0752C25.1243 19.6257 23.0498 19.6438 21.0771 19.1274C19.1045 18.6111 17.3049 17.5789 15.863 16.1372C14.4214 14.6953 13.3892 12.8958 12.8728 10.9231C12.3564 8.95044 12.3745 6.87598 12.925 4.9126C10.9895 5.45142 9.22876 6.48779 7.81836 7.91895C6.40796 9.34985 5.39697 11.1255 4.88647 13.0688C4.37573 15.012 4.38306 17.0552 4.90796 18.9946C5.43262 20.9343 6.4563 22.7024 7.87695 24.1233C9.29785 25.5439 11.0659 26.5676 13.0056 27.0923C14.9451 27.6172 16.9883 27.6245 18.9314 27.1138C20.8748 26.6033 22.6504 25.5923 24.0813 24.1819C25.5125 22.7715 26.5488 21.0107 27.0876 19.0752Z"
                                    fill="currentColor" fill-opacity="0.1" />
                                <path fill-rule="evenodd" clip-rule="evenodd"
                                    d="M28.051 19.3438L28.0506 19.3454C28.0506 19.3454 27.1566 22.5551 24.7835 24.8941C24.7835 24.8941 22.4095 27.2339 19.1858 28.081C19.1858 28.081 15.962 28.9282 12.7445 28.0577C12.7445 28.0577 9.52702 27.1872 7.1701 24.8303C7.1701 24.8303 4.81318 22.4734 3.94271 19.2559C3.94271 19.2559 3.07225 16.0383 3.91937 12.8146C3.91937 12.8146 4.76649 9.59087 7.10626 7.21693C7.10626 7.21693 9.44603 4.84299 12.6572 3.94922C12.9127 3.8781 13.1859 3.9114 13.4169 4.04178C13.6479 4.17217 13.8176 4.38895 13.8887 4.64446C13.9377 4.82052 13.9375 5.00664 13.8882 5.1826C13.8882 5.1826 13.1206 7.91975 13.8404 10.6698C13.8404 10.6698 14.5603 13.4199 16.5704 15.43C16.5704 15.43 18.5805 17.4401 21.3306 18.16C21.3306 18.16 24.0806 18.8798 26.8178 18.1122C26.9882 18.0644 27.1683 18.0628 27.3396 18.1073L27.3559 18.1117C27.6928 18.2055 27.9562 18.4684 28.0507 18.8051C28.0984 18.9755 28.1001 19.1556 28.0556 19.3269L28.051 19.3438ZM23.3795 23.4697C23.3795 23.4697 24.7551 22.114 25.539 20.4099C25.539 20.4099 23.1856 20.7129 20.8241 20.0948C20.8241 20.0948 17.5496 19.2377 15.1562 16.8442C15.1562 16.8442 12.7627 14.4508 11.9056 11.1763C11.9056 11.1763 11.2875 8.81482 11.5905 6.46138C11.5905 6.46138 9.88644 7.24531 8.53069 8.62085C8.53069 8.62085 6.56528 10.615 5.8537 13.3229C5.8537 13.3229 5.14212 16.0308 5.87331 18.7336C5.87331 18.7336 6.6045 21.4363 8.58431 23.4161C8.58431 23.4161 10.5641 25.3959 13.2668 26.1271C13.2668 26.1271 15.9695 26.8583 18.6775 26.1467C18.6775 26.1467 21.3854 25.4351 23.3795 23.4697Z"
                                    fill="currentColor" />
                            </svg>
                        </a>
                        <a href="javascript:;" class="text-black dark:text-white" x-cloak
                            x-show="$store.app.mode === 'dark'" @click="$store.app.toggleMode('light')">
                            <svg class="w-5 h-5" width="32" height="32" viewBox="0 0 32 32" fill="none"
                                xmlns="http://www.w3.org/2000/svg">
                                <path
                                    d="M23.5 16C23.5 20.1421 20.1421 23.5 16 23.5C11.8579 23.5 8.5 20.1421 8.5 16C8.5 11.8579 11.8579 8.5 16 8.5C20.1421 8.5 23.5 11.8579 23.5 16Z"
                                    fill="currentColor" fill-opacity="0.1" />
                                <path fill-rule="evenodd" clip-rule="evenodd"
                                    d="M16 7.5C16 7.5 17.7287 7.5 19.3089 8.16838C19.3089 8.16838 20.8345 8.81364 22.0104 9.98959C22.0104 9.98959 23.1864 11.1655 23.8316 12.6911C23.8316 12.6911 24.5 14.2713 24.5 16C24.5 16 24.5 17.7287 23.8316 19.3089C23.8316 19.3089 23.1864 20.8345 22.0104 22.0104C22.0104 22.0104 20.8345 23.1864 19.3089 23.8316C19.3089 23.8316 17.7287 24.5 16 24.5C16 24.5 14.2713 24.5 12.6911 23.8316C12.6911 23.8316 11.1655 23.1864 9.98959 22.0104C9.98959 22.0104 8.81364 20.8345 8.16838 19.3089C8.16838 19.3089 7.5 17.7287 7.5 16C7.5 16 7.5 14.2713 8.16838 12.6911C8.16838 12.6911 8.81364 11.1655 9.98959 9.98959C9.98959 9.98959 11.1655 8.81364 12.6911 8.16838C12.6911 8.16838 14.2713 7.5 16 7.5ZM16 9.5C16 9.5 13.3076 9.5 11.4038 11.4038C11.4038 11.4038 9.5 13.3076 9.5 16C9.5 16 9.5 18.6924 11.4038 20.5962C11.4038 20.5962 13.3076 22.5 16 22.5C16 22.5 18.6924 22.5 20.5962 20.5962C20.5962 20.5962 22.5 18.6924 22.5 16C22.5 16 22.5 13.3076 20.5962 11.4038C20.5962 11.4038 18.6924 9.5 16 9.5Z"
                                    fill="currentColor" />
                                <path
                                    d="M17 4.5V2C17 1.44772 16.5523 1 16 1C15.4477 1 15 1.44772 15 2V4.5C15 5.05228 15.4477 5.5 16 5.5C16.5523 5.5 17 5.05228 17 4.5Z"
                                    fill="currentColor" />
                                <path
                                    d="M6.80672 5.39299C6.61918 5.20545 6.36483 5.1001 6.09961 5.1001C5.83439 5.1001 5.58004 5.20545 5.3925 5.39299C5.20497 5.58053 5.09961 5.83488 5.09961 6.1001C5.09961 6.36531 5.20497 6.61967 5.3925 6.8072L7.155 8.5697C7.34254 8.75724 7.59689 8.8626 7.86211 8.8626C8.12733 8.8626 8.38168 8.75724 8.56922 8.5697C8.75675 8.38217 8.86211 8.12781 8.86211 7.8626C8.86211 7.59738 8.75675 7.34303 8.56922 7.15549L6.80672 5.39299Z"
                                    fill="currentColor" />
                                <path
                                    d="M4.5 15H2C1.44772 15 1 15.4477 1 16C1 16.5523 1.44772 17 2 17H4.5C5.05228 17 5.5 16.5523 5.5 16C5.5 15.4477 5.05228 15 4.5 15Z"
                                    fill="currentColor" />
                                <path
                                    d="M5.3925 25.1928C5.20497 25.3804 5.09961 25.6347 5.09961 25.9C5.09961 25.9172 5.10006 25.9345 5.10095 25.9517C5.11375 26.1987 5.21762 26.4322 5.3925 26.6071C5.58004 26.7946 5.83439 26.9 6.09961 26.9C6.36483 26.9 6.61918 26.7946 6.80672 26.6071L8.56922 24.8446C8.75675 24.657 8.86211 24.4027 8.86211 24.1375C8.86211 23.8722 8.75675 23.6179 8.56922 23.4303C8.38168 23.2428 8.12733 23.1375 7.86211 23.1375C7.84485 23.1375 7.8276 23.1379 7.81037 23.1388C7.56338 23.1516 7.32989 23.2555 7.155 23.4303L5.3925 25.1928Z"
                                    fill="currentColor" />
                                <path
                                    d="M15 27.5V30C15 30.5523 15.4477 31 16 31C16.5523 31 17 30.5523 17 30V27.5C17 26.9477 16.5523 26.5 16 26.5C15.4477 26.5 15 26.9477 15 27.5Z"
                                    fill="currentColor" />
                                <path
                                    d="M23.4307 24.8447L25.1931 26.6071C25.3806 26.7946 25.635 26.9 25.9002 26.9C26.1654 26.9 26.4198 26.7946 26.6073 26.6071C26.7948 26.4195 26.9002 26.1652 26.9002 25.9C26.9002 25.6347 26.7948 25.3804 26.6073 25.1928L24.8449 23.4305C24.6573 23.2428 24.4029 23.1375 24.1377 23.1375C23.8725 23.1375 23.6181 23.2428 23.4306 23.4303C23.2431 23.6179 23.1377 23.8722 23.1377 24.1375C23.1377 24.4027 23.2431 24.657 23.4307 24.8447Z"
                                    fill="currentColor" />
                                <path
                                    d="M27.5 17H30C30.5523 17 31 16.5523 31 16C31 15.4477 30.5523 15 30 15H27.5C26.9477 15 26.5 15.4477 26.5 16C26.5 16.5523 26.9477 17 27.5 17Z"
                                    fill="currentColor" />
                                <path
                                    d="M26.6073 6.8072C26.7948 6.61967 26.9002 6.36531 26.9002 6.1001C26.9002 5.83488 26.7948 5.58053 26.6073 5.39299C26.4198 5.20545 26.1654 5.1001 25.9002 5.1001C25.635 5.1001 25.3806 5.20545 25.1931 5.39299L23.4307 7.15537C23.2431 7.34303 23.1377 7.59738 23.1377 7.8626C23.1377 8.12781 23.2431 8.38217 23.4306 8.56971C23.6181 8.75724 23.8725 8.8626 24.1377 8.8626C24.4029 8.8626 24.6573 8.75724 24.8448 8.5697L26.6073 6.8072Z"
                                    fill="currentColor" />
                            </svg>
                        </a>
                    </div>
                </div>
            </div>
        </nav>
    </header>
    <!-- End Header -->
    <!-- Start Content -->
    <div class="min-h-[calc(100vh-134px)] py-4 px-4 sm:px-12 flex justify-center items-center">
        <div
            class="max-w-[680px] flex-none w-full bg-white dark:bg-white/5 p-4 sm:p-10 lg:px-[146px] lg:py-[107px] rounded-2xl loginform">
            <h1 class="text-2xl font-semibold mb-2 text-center">🛡️Acessar Painel</h1>
            <p class="text-center text-black/40 dark:text-white/40 mb-7">Administrativo da:
                <?php echo isset($dataconfig['nome']) ? htmlspecialchars($dataconfig['nome']) : 'Nome não definido'; ?>
            </p>

            <div class="flex items-center mb-7">
                <div class="w-full h-[2px] bg-black/10 dark:bg-white/10"></div>
                <div class="text-black/40 dark:text-white/40 px-5 whitespace-nowrap">Digite suas credenciais abaixo
                </div>
                <div class="w-full h-[2px] bg-black/10 dark:bg-white/10"></div>
            </div>
            <form id="form-acessar" method="post" class="mb-4">
                <div id="response" style="display: none;"
                    class="mb-4 p-3 rounded-lg bg-white dark:bg-white/5 border border-black/10 dark:border-white/10 text-center text-sm">
                </div>
                <div class="mb-4">
                    <input type="text" placeholder="Email" id="email" name="email" class="form-input" />
                </div>
                <div class="mb-2">
                    <input type="password" placeholder="Senha" id="senha" name="senha" class="form-input" />
                </div>
                <div class="mb-7 text-right">
                    <a class='text-lightpurple-300' href='/forgot-password'>Esqueceu a Senha?</a>
                </div>
                <?php $csrf->echoInputField(); ?>
                <button type="submit"
                    class="py-2 px-4 bg-black dark:bg-lightpurple-200 w-full rounded-lg text-white dark:text-black text-lg font-semibold border border-black dark:border-lightpurple-200 hover:bg-transparent dark:hover:bg-transparent hover:text-black dark:hover:text-white transition-all duration-300">
                    Acessar
                </button>
            </form>
            
        </div>
    </div>
    <!-- End Content -->
     
    <!-- Start Footer -->
    <footer class="p-7 flex items-center justify-center">
        <p class="text-xs text-black/40 dark:text-white/40">&copy; 2025</p>
    </footer>
    <!-- End Footer -->

    <?php include './partes/footer.php'; ?>
</body>

<script>
    $(document).ready(function () {
        $('#form-acessar').submit(function (event) {
            event.preventDefault();
            let formData = $(this).serialize();
            $.ajax({
                url: 'ajax/form-acessar.php',
                type: 'POST',
                data: formData,
                success: function (response) {
                    $('#response').html(response).show();
                    setTimeout(function () {
                        $('#response').hide();
                    }, 9000);
                },
            });
        });
    });
</script>

</html>