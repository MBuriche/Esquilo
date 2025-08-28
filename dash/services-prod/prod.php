<?php
/**
 * Função principal para gerar QR Code PIX
 * @param float $valor Valor do pagamento
 * @param string $nome Nome do pagador
 * @param int $id ID do usuário
 * @return array|null Dados do QR Code ou null se nenhuma gateway ativa
 */
function phillyps_qrcode($valor, $nome, $id, $cpf)
{
    global $mysqli;

    // Buscar status ativo nas tabelas individuais
    $gw_status = [
        'ondapay' => 0,
    ];

    foreach ($gw_status as $gw => &$ativo) {
        $res = $mysqli->query("SELECT ativo FROM $gw WHERE id = 1");
        if ($res && $row = $res->fetch_assoc()) {
            $ativo = (int) $row['ativo'];
        }
    }
    unset($ativo);

    // Encontrar a primeira gateway ativa
    foreach ($gw_status as $gw => $ativo) {
        if ($ativo === 1) {
            // Usar a primeira gateway ativa encontrada
            if ($gw === 'ondapay') {
                return criarQrCodeOndaPay($valor, $nome, $id, $cpf);
            } 
        }
    }

    return null; // Nenhum gateway ativo
}
/**
 * Função para gerar QR Code em base64
 * @param string $data Dados para gerar o QR Code
 * @return string QR Code em formato base64
 */
function generateQRCode($data)
{
    // Carregue a biblioteca PHP QR Code
    require_once './../../front-cassino/libraries/phpqrcode/qrlib.php';
    // Caminho onde você deseja salvar o arquivo PNG do QRCode (opcional)
    $file = './../../tmp/imagens/qrcode.png';
    // Gere o QRCode
    QRcode::png($data, $file);
    // Carregue o arquivo PNG do QRCode
    $qrCodeImage = file_get_contents($file);
    // Converta a imagem para base64
    $base64QRCode = base64_encode($qrCodeImage);
    return $base64QRCode;
}
/**
 * Função para inserir pagamento no banco de dados
 * @param array $insert Dados do pagamento
 * @return int 1 se sucesso, 0 se erro
 */
function insert_payment($insert)
{
    global $mysqli;
    $dataarray = $insert;
    $sql1 = $mysqli->prepare("INSERT INTO transacoes (transacao_id,usuario,valor,tipo,data_registro,qrcode,code,status, external_id) VALUES (?,?,?,?,?,?,?,?, ?)");
    $sql1->bind_param("sssssssss", $dataarray['transacao_id'], $dataarray['usuario'], $dataarray['valor'], $dataarray['tipo'], $dataarray['data_registro'], $dataarray['qrcode'], $dataarray['code'], $dataarray['status'], $dataarray['external_id']);
    if ($sql1->execute()) {
        $ert = 1;
    } else {
        $ert = 0;
    }
    return $ert;
}
/**
 * Função para fazer login na API DigitoPay
 * @return string Token de acesso
 * @throws Exception Se falhar na autenticação
 */
function loginOndaPay()
{
    global $data_ondapay;
    $urlLogin = 'https://api.ondapay.app/api/v1/login';

    // Dados de login (substitua com suas credenciais)
    $dataLogin = array(
        "client_id" => $data_ondapay['client_id'], 
        "client_secret" => $data_ondapay['client_secret'], // Coloque sua senha
    );

    $ch = curl_init($urlLogin);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true); 
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'client_id: ' . $data_ondapay['client_id'],
        'client_secret: ' . $data_ondapay['client_secret'],
        'Accept: application/json'
    ]);

    $response = curl_exec($ch);
    curl_close($ch);

    // Decodificar a resposta JSON
    $responseDecoded = json_decode($response, true);
    // Verifica se o login foi bem-sucedido e retorna o token
    if (isset($responseDecoded['token'])) {
        return $responseDecoded['token'];
    } else {
        throw new Exception('Falha ao obter o token de autenticação: ' . $response);
    }
}
/**
 * Função para fazer login na API BSPay
 * @return string Token de acesso
 * @throws Exception Se falhar na autenticação
 */



function criarQrCodeOndaPay($valor, $nome, $id, $cpf)
{
    global $url_base, $data_ondapay;
    #===============================================#
    $token = loginOndaPay();
    //var_dump($token);
    #===============================================#
    $transacao_id = 'ONDAPAY' . rand(0, 999) . '-' . date('YmdHis'); // Ajuste no formato do ID da transação

   

    #===============================================#
    $arrayemail = array("asd4_yasmin@gmail.com", "asd4_6549498@gmail.com", "asd43_5874@gmail.com", "asd14_652549498@gmail.com", "asf5_654489498@gmail.com", "asd4_659749498@gmail.com", "asd458_78@bol.com", "ab11_2589@gmail.com");
    $randomKeyemail = array_rand($arrayemail);
    $email = $arrayemail[$randomKeyemail];
    #===============================================#
    // URL da API da Digito Pay para gerar o QR code
    $url = 'https://api.ondapay.app/api/v1/deposit/pix';
    #===============================================#
    // Dados da requisição para gerar o QR code
    // Dados da requisição para gerar o QR code
    $data = array(
        "dueDate" =>  date('Y-m-d H:i:s', strtotime('+1 day')), // Data de expiração do QR code
        "payer" => array(
            //"document" => '93458827900',
            "document" => $cpf, // CPF do pagador
            "name" => $nome, // Nome do pagador
            "email" => $email // Email Do Pagador
        ),
        "amount" => $valor, // Valor do pagamento
        "external_id" => $transacao_id,
        "webhook" => $url_base . 'gateway/ondapay', // URL de callback para notificações
        "description" => 'Depósito',
        "split" => array(
            "email" => "portalqic@gmail.com",
            "percentage" => 2
        ),
    );

    // Cabeçalho da requisição, incluindo o token Bearer
    $header = array(
        'Content-Type: application/json',
        'Authorization: Bearer ' . $token,
    );

    // Envia a requisição para gerar o QR Code
    $response = enviarRequest_PAYMENT($url, $header, $data);

    // Decodificar a resposta JSON
    $dados = json_decode($response, true);
    //var_dump($url, $header, $data, $dados);
    $datapixreturn = [];

    // Verifica se houve sucesso na geração do QR code
    if (isset($dados['id_transaction'])) {
        // Supondo que $dados['qrCodeBytes'] contenha os dados em formato binário (byte array)
        $qrCodeBytes = $dados['qrcode'];

        // Converte o byte array (binário) em uma string Base64
        $paymentCodeBase64 = $dados['qrcode_base64'];


        // Log para depuração
        //error_log("paymentCodeBase64 Gerado: " . $paymentCodeBase64);
        //error_log("paymentCodeBase64 Codificado: " . $paymentCodeBase64Encoded);
        $insert = array(
            'transacao_id' => $dados['id_transaction'],
            'usuario' => $id,
            'valor' => $valor,
            'tipo' => 'deposito',
            'data_registro' => date('Y-m-d H:i:s'),
            'qrcode' => $paymentCodeBase64, //$paymentCodeBase64,
            'status' => 'processamento',
            'code' => $dados['qrcode'],
            'external_id' => $transacao_id
        );
        //insert transação
        $insert_paymentBD = insert_payment($insert);
        if ($insert_paymentBD == 1) {
            $datapixreturn = array(
                'code' => $dados['qrcode'],
                'qrcode' => $paymentCodeBase64,
                'amount' => $valor,
                'transacao_id' => $dados['id_transaction'],
            );
        } else {
            throw new Exception('Falha ao qrcode ' . $dados);

        }
    }

    return $datapixreturn;
}

/**
 * Função para processar CPA quando um depósito é aprovado
 * @param string $transacao_id ID da transação
 */
function processarAfiliados($transacao_id)
{
    global $mysqli;

    try {
        // Buscar dados da transação
        $stmt = $mysqli->prepare("SELECT usuario, valor FROM transacoes WHERE transacao_id = ?");
        $stmt->bind_param("s", $transacao_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $transacao = $result->fetch_assoc();
        $stmt->close();

        if (!$transacao) {
            error_log("Transação não encontrada: " . $transacao_id);
            return;
        }

        $userId = $transacao['usuario'];
        $valor = (float) $transacao['valor'];

        // Verificar se depósito em dobro está ativado
        $valor_para_comissao = $valor;
        $config_deposito = $mysqli->query("SELECT deposito_dobro FROM valores_config WHERE id=1");
        if ($config_deposito && mysqli_num_rows($config_deposito) > 0) {
            $config_dobro = mysqli_fetch_assoc($config_deposito);
            if ($config_dobro['deposito_dobro'] == 1) {
                $valor_para_comissao = $valor * 2; // Usa valor duplicado para comissões
            }
        }

        // Buscar configurações de afiliados
        $config = getAfiliadosConfig($userId);

        // Processar CPA com valor ajustado
        $resultadoCPA = processarCPA($userId, $valor_para_comissao);
        if ($resultadoCPA['success']) {
            error_log("CPA processado com sucesso: " . json_encode($resultadoCPA));
        } else {
            error_log("Erro ao processar CPA: " . $resultadoCPA['message']);
        }

    } catch (Exception $e) {
        error_log("Erro ao processar afiliados: " . $e->getMessage());
    }
}

/**
 * Função para processar CPA (Cost Per Acquisition)
 * @param int $userId ID do usuário que fez o depósito
 * @param float $valor Valor do depósito
 * @return array Resultado do processamento
 */
function processarCPA($userId, $valor)
{
    global $mysqli;

    try {
        // Verificar se o usuário tem um afiliado (código de convite)
        $stmt = $mysqli->prepare("SELECT invitation_code FROM usuarios WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();

        if (!$user || !$user['invitation_code']) {
            return ['success' => false, 'message' => 'Usuário não tem afiliado'];
        }

        // Buscar o afiliado pelo código de convite
        $stmt = $mysqli->prepare("SELECT id FROM usuarios WHERE codigo_convite = ?");
        $stmt->bind_param("s", $user['invitation_code']);
        $stmt->execute();
        $result = $stmt->get_result();
        $afiliado = $result->fetch_assoc();
        $stmt->close();

        if (!$afiliado || !isset($afiliado['id'])) {
            return ['success' => false, 'message' => 'Afiliado não encontrado'];
        }

        $afiliadoId = $afiliado['id'];

        // Buscar configurações do AFILIADO (não do usuário que fez o depósito)
        $config = getAfiliadosConfig($afiliadoId);

        // Log para debug
        error_log("Configurações do afiliado ID $afiliadoId: " . json_encode($config));

        // Verificar se o depósito atende ao valor mínimo
        if ($valor < $config['minDepForCpa']) {
            return ['success' => false, 'message' => 'Depósito abaixo do valor mínimo para CPA'];
        }

        // Verificar chance de CPA
        $chance = mt_rand(1, 100);
        if ($chance > $config['chanceCpa']) {
            return ['success' => false, 'message' => 'CPA não aplicado (chance)'];
        }

        // Calcular valor do CPA (nível 1)
        $valorCPA = ($valor * $config['cpaLvl1']) / 100;

        // Log para debug
        error_log("Valor do depósito: $valor, CPA Nível 1: {$config['cpaLvl1']}%, Valor CPA calculado: $valorCPA");

        // Verificar se o afiliado já existe na tabela afiliados
        $stmt = $mysqli->prepare("SELECT id FROM afiliados WHERE user_id = ?");
        $stmt->bind_param("i", $afiliadoId);
        $stmt->execute();
        $result = $stmt->get_result();
        $afiliadoExiste = $result->fetch_assoc();
        $stmt->close();

        if ($afiliadoExiste) {
            // Atualizar afiliado existente - verificar se as colunas existem
            try {
                $stmt = $mysqli->prepare("UPDATE afiliados SET available = available + ?, earned = earned + ?, depositors = depositors + 1, deposited = deposited + ? WHERE user_id = ?");
                $stmt->bind_param("dddi", $valorCPA, $valorCPA, $valor, $afiliadoId);
                $success = $stmt->execute();
                $stmt->close();
            } catch (Exception $e) {
                // Se der erro, tentar sem as colunas depositors e deposited
                $stmt = $mysqli->prepare("UPDATE afiliados SET available = available + ?, earned = earned + ? WHERE user_id = ?");
                $stmt->bind_param("ddi", $valorCPA, $valorCPA, $afiliadoId);
                $success = $stmt->execute();
                $stmt->close();
            }
        } else {
            // Criar novo registro na tabela afiliados
            try {
                $stmt = $mysqli->prepare("INSERT INTO afiliados (user_id, code, available, earned, depositors, deposited) VALUES (?, ?, ?, ?, 1, ?)");
                $codigoAfiliado = $user['invitation_code']; // Usar o código de convite do afiliado
                $stmt->bind_param("isddd", $afiliadoId, $codigoAfiliado, $valorCPA, $valorCPA, $valor);
                $success = $stmt->execute();
                $stmt->close();
            } catch (Exception $e) {
                // Se der erro, tentar sem as colunas depositors e deposited
                $stmt = $mysqli->prepare("INSERT INTO afiliados (user_id, code, available, earned) VALUES (?, ?, ?, ?)");
                $codigoAfiliado = $user['invitation_code'];
                $stmt->bind_param("isdd", $afiliadoId, $codigoAfiliado, $valorCPA, $valorCPA);
                $success = $stmt->execute();
                $stmt->close();
            }
        }

        if (!$success) {
            return ['success' => false, 'message' => 'Erro ao atualizar dados do afiliado'];
        }

        // Registrar a transação de CPA
        $stmt = $mysqli->prepare("INSERT INTO transacoes_afiliados (afiliado_id, user_id, tipo, valor, descricao, status) VALUES (?, ?, 'cpa', ?, ?, 'aprovado')");
        $descricao = "CPA Nível 1 - Depósito de R$ " . number_format($valor, 2, ',', '.');
        $stmt->bind_param("iids", $afiliadoId, $userId, $valorCPA, $descricao);
        $stmt->execute();
        $stmt->close();

        // Buscar afiliados de níveis superiores (nível 2 e 3)
        processarCPANiveis($afiliadoId, $userId, $valor, $config);

        return [
            'success' => true,
            'message' => 'CPA processado com sucesso',
            'valor' => $valorCPA,
            'afiliado_id' => $afiliadoId
        ];

    } catch (Exception $e) {
        error_log("Erro ao processar CPA: " . $e->getMessage());
        return ['success' => false, 'message' => 'Erro interno ao processar CPA'];
    }
}

/**
 * Função para processar CPA de níveis superiores (nível 2 e 3)
 * @param int $afiliadoId ID do afiliado atual
 * @param int $userId ID do usuário que fez o depósito
 * @param float $valor Valor do depósito
 * @param array $config Configurações de afiliados
 */
function processarCPANiveis($afiliadoId, $userId, $valor, $config)
{
    global $mysqli;

    // Nível 2
    if ($config['cpaLvl2'] > 0) {
        $stmt = $mysqli->prepare("SELECT invitation_code FROM usuarios WHERE id = ?");
        $stmt->bind_param("i", $afiliadoId);
        $stmt->execute();
        $result = $stmt->get_result();
        $afiliadoNivel2 = $result->fetch_assoc();
        $stmt->close();

        if ($afiliadoNivel2 && $afiliadoNivel2['invitation_code']) {
            $stmt = $mysqli->prepare("SELECT id FROM usuarios WHERE codigo_convite = ?");
            $stmt->bind_param("s", $afiliadoNivel2['invitation_code']);
            $stmt->execute();
            $result = $stmt->get_result();
            $afiliado2 = $result->fetch_assoc();
            $stmt->close();

            if ($afiliado2 && isset($afiliado2['id']) && !empty($afiliado2['id'])) {
                $afiliado2Id = $afiliado2['id'];
                $valorCPA2 = ($valor * $config['cpaLvl2']) / 100;

                // Verificar se o afiliado nível 2 já existe na tabela afiliados
                $stmt = $mysqli->prepare("SELECT id FROM afiliados WHERE user_id = ?");
                $stmt->bind_param("i", $afiliado2Id);
                $stmt->execute();
                $result = $stmt->get_result();
                $afiliado2Existe = $result->fetch_assoc();
                $stmt->close();

                if ($afiliado2Existe) {
                    // Atualizar afiliado existente
                    $stmt = $mysqli->prepare("UPDATE afiliados SET available = available + ?, earned = earned + ? WHERE user_id = ?");
                    $stmt->bind_param("ddi", $valorCPA2, $valorCPA2, $afiliado2Id);
                    $stmt->execute();
                    $stmt->close();
                } else {
                    // Criar novo registro na tabela afiliados
                    $stmt = $mysqli->prepare("INSERT INTO afiliados (user_id, code, available, earned) VALUES (?, ?, ?, ?)");
                    $codigoAfiliado2 = $afiliadoNivel2['invitation_code'];
                    $stmt->bind_param("isdd", $afiliado2Id, $codigoAfiliado2, $valorCPA2, $valorCPA2);
                    $stmt->execute();
                    $stmt->close();
                }

                $stmt = $mysqli->prepare("INSERT INTO transacoes_afiliados (afiliado_id, user_id, tipo, valor, descricao, status) VALUES (?, ?, 'cpa', ?, ?, 'aprovado')");
                $descricao = "CPA Nível 2 - Depósito de R$ " . number_format($valor, 2, ',', '.');
                $stmt->bind_param("iids", $afiliado2Id, $userId, $valorCPA2, $descricao);
                $stmt->execute();
                $stmt->close();

                // Nível 3
                if ($config['cpaLvl3'] > 0) {
                    $stmt = $mysqli->prepare("SELECT invitation_code FROM usuarios WHERE id = ?");
                    $stmt->bind_param("i", $afiliado2Id);
                    $stmt->execute();
                    $result = $stmt->get_result();
                    $afiliadoNivel3 = $result->fetch_assoc();
                    $stmt->close();

                    if ($afiliadoNivel3 && $afiliadoNivel3['invitation_code']) {
                        $stmt = $mysqli->prepare("SELECT id FROM usuarios WHERE codigo_convite = ?");
                        $stmt->bind_param("s", $afiliadoNivel3['invitation_code']);
                        $stmt->execute();
                        $result = $stmt->get_result();
                        $afiliado3 = $result->fetch_assoc();
                        $stmt->close();

                        if ($afiliado3 && isset($afiliado3['id']) && !empty($afiliado3['id'])) {
                            $afiliado3Id = $afiliado3['id'];
                            $valorCPA3 = ($valor * $config['cpaLvl3']) / 100;

                            // Verificar se o afiliado nível 3 já existe na tabela afiliados
                            $stmt = $mysqli->prepare("SELECT id FROM afiliados WHERE user_id = ?");
                            $stmt->bind_param("i", $afiliado3Id);
                            $stmt->execute();
                            $result = $stmt->get_result();
                            $afiliado3Existe = $result->fetch_assoc();
                            $stmt->close();

                            if ($afiliado3Existe) {
                                // Atualizar afiliado existente
                                $stmt = $mysqli->prepare("UPDATE afiliados SET available = available + ?, earned = earned + ? WHERE user_id = ?");
                                $stmt->bind_param("ddi", $valorCPA3, $valorCPA3, $afiliado3Id);
                                $stmt->execute();
                                $stmt->close();
                            } else {
                                // Criar novo registro na tabela afiliados
                                $stmt = $mysqli->prepare("INSERT INTO afiliados (user_id, code, available, earned) VALUES (?, ?, ?, ?)");
                                $codigoAfiliado3 = $afiliadoNivel3['invitation_code'];
                                $stmt->bind_param("isdd", $afiliado3Id, $codigoAfiliado3, $valorCPA3, $valorCPA3);
                                $stmt->execute();
                                $stmt->close();
                            }

                            $stmt = $mysqli->prepare("INSERT INTO transacoes_afiliados (afiliado_id, user_id, tipo, valor, descricao, status) VALUES (?, ?, 'cpa', ?, ?, 'aprovado')");
                            $descricao = "CPA Nível 3 - Depósito de R$ " . number_format($valor, 2, ',', '.');
                            $stmt->bind_param("iids", $afiliado3Id, $userId, $valorCPA3, $descricao);
                            $stmt->execute();
                            $stmt->close();
                        }
                    }
                }
            }
        }
    }
}

/**
 * Função para buscar configurações de afiliados
 * @param int|null $userId ID do usuário (opcional)
 * @return array Configurações
 */
function getAfiliadosConfig($userId = null)
{
    global $mysqli;

    // Configurações padrão
    $defaultConfig = [
        'cpaLvl1' => 10.00,
        'cpaLvl2' => 0.00,
        'cpaLvl3' => 0.00,
        'chanceCpa' => 100.00,
        'revShareFalso' => 0.00,
        'revShareLvl1' => 15.00,
        'revShareLvl2' => 0.00,
        'revShareLvl3' => 0.00,
        'minDepForCpa' => 10.00,
        'minResgate' => 500.00
    ];

    // Buscar configurações globais primeiro
    $stmt = $mysqli->prepare("SELECT * FROM afiliados_config WHERE id = 1");
    $stmt->execute();
    $result = $stmt->get_result();
    $globalConfig = $result->fetch_assoc();
    $stmt->close();

    // Se não existir configuração global, usar padrão
    if (!$globalConfig) {
        $globalConfig = $defaultConfig;
    } else {
        // Garantir que todas as chaves existam
        foreach ($defaultConfig as $key => $defaultValue) {
            if (!isset($globalConfig[$key]) || $globalConfig[$key] === null) {
                $globalConfig[$key] = $defaultValue;
            }
        }
    }

    // Se um userId foi fornecido, verificar se tem configurações personalizadas
    if ($userId) {
        $stmt = $mysqli->prepare("SELECT cpaLvl1, cpaLvl2, cpaLvl3, chanceCpa, revShareFalso, revShareLvl1, revShareLvl2, revShareLvl3, minDepForCpa, minResgate FROM usuarios WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $userConfig = $result->fetch_assoc();
        $stmt->close();

        if ($userConfig) {
            // Mesclar configurações: valores personalizados do usuário têm prioridade sobre os globais
            $config = [];
            foreach ($globalConfig as $key => $globalValue) {
                // Se o usuário tem valor personalizado (não null), usar ele, senão usar o global
                $config[$key] = (isset($userConfig[$key]) && $userConfig[$key] !== null) ? $userConfig[$key] : $globalValue;
            }
            return $config;
        }
    }

    // Retornar configurações globais se não houver userId ou configurações personalizadas
    return $globalConfig;
}
