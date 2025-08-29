// ⚠️ ATENÇÃO:Precisamos validar isso aqui ⚠️
<?php
início_da_sessão ();
include_once "../config.php" ;
 
include_once ( '../' . DASH. '/services/database.php' );
include_once ( '../' . DASH. '/services/funcao.php' );
include_once ( '../' . DASH. '/services/crud.php' );
include_once ( '../' . DASH. '/services-prod/prod.php' );

global $mysqli ;
 

// Decodifica o JSON recebido
$payload = json_decode ( file_get_contents ( "php://input" ), verdadeiro );
se ( $payload === nulo && json_last_error () !== JSON_ERROR_NONE) {
    http_response_code ( 400 );
    echo json_encode ([ 'erro' => 'json inválido' ]);
 
    saída ;
}

// Suporta carga com campos dentro de "data" ou na raiz
$dados = $payload [ 'dados' ] ?? $payload ;
$transactionId = PHP_SEGURO ( $dados [ 'id_da_transação' ] ?? $dados [ 'id' ] ?? $dados [ 'txid' ] ?? '' );
$identificador     = PHP_SEGURO ( $data [ 'identificador' ] ?? $data [ 'referência' ] ?? '' );
$status         = strtoupper ( PHP_SECURE ( $data [ 'status' ] ?? '' ));

se ( vazio ( $ transactionId ) || vazio ( $ status )) {
    http_response_code ( 400 );
    echo json_encode ([ 'erro' => 'dados ausentes' ]);
 
    saída ;
}

function busca_valor_ipn ( $transacao_id )
 
{
    global $mysqli ;
 
    $qry = "SELECT usuário, valor FROM transações WHERE transacao_id='" . $transacao_id . "'" ;
    $res = mysqli_query ( $mysqli , $qry );
    se ( mysqli_num_rows ( $res ) > 0 ) {
        $dados = mysqli_fetch_assoc ( $res );
        $retornaUSER = get_user_by_id($data['usuario']);

        // Verificar se depósito em dobro está ativado
        $valor_final = $data['valor'];
        $config_query = "SELECT deposito_dobro FROM valores_config WHERE id=1" ;
        $config_res = mysqli_query ( $mysqli , $config_query );
        se ( $config_res && mysqli_num_rows ( $config_res ) > 0 ) {
            $config = mysqli_fetch_assoc ( $config_res );
            se ( $config [ 'deposito_dobro' ] == 1 ) {
                $valor_final = $data['valor'] * 2;
            }
        }

        $retorna_insert_saldo_suit_pay = enviarSaldo($retornaUSER['mobile'], $valor_final);
        retornar $retorna_insert_saldo_suit_pay ;
 
    }
    retornar falso ;
 
}

função get_user_by_id ( $user_id )
 
{
    global $mysqli ;
 
    $qry = "SELECT email FROM usuários ONDE id = ?" ;
    $stmt = $mysqli -> preparar ( $qry );
    $stmt -> bind_param ( "s" , $user_id );
    $stmt -> executar ();
    $stmt -> bind_result ( $móvel );
    $stmt -> buscar ();
    $stmt -> fechar ();
    retornar [ 'móvel' => $móvel ];
}

função att_paymentpix ( $transacao_id )
 
{
    global $mysqli ;
 
    $sql = $mysqli -> prepare ( "ATUALIZAR transações SET status='1' ONDE transacao_id=?" );
    $sql -> bind_param ( "s" , $transacao_id );
    se ( $sql -> executar ()) {
        $buscar = busca_valor_ipn($transacao_id);
        se ( $pesquisar ) {
            $rf = 1 ;
            // Processar CPA e RevShare
            processarAfiliados($transacao_id);
        } outro {
            $rf = 0 ;
        }
    } outro {
        $rf = 0 ;
    }
    retornar $rf ;
 
}

$settledStatuses = [ 'PAGO' , 'LIQUIDADO' , 'LIQUIDAÇÃO' , 'PAGO_SAÍDA' , 'CONCLUÍDO' ];

se ( in_array ( $ status , $settledStatuses , verdadeiro )) {
    $atualizado = att_paymentpix ( $transactionId );
    se ( $atualizado ) {
        http_response_code ( 200 );
        echo json_encode ([ 'status' => 'processado' ]);
 
    } outro {
        http_response_code ( 500 );
        eco json_encode ([ 'status' => 'erro' ]);
 
    }
} outro {
    http_response_code ( 202 );
    echo json_encode ([ 'status' => 'ignorado' ]);
 
}
?>