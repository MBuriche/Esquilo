<?php
	function checa_login_adm(){
		global $painel_adm_acessar;
	//FUNÇÃO CHECA LOGIN
		if(!isset($_SESSION['token_adm_encrypted']) && !isset($_SESSION["crsf_token_adm"]) && !isset($_SESSION["anti_crsf_token_adm"])){
			header('Location: '.$painel_adm_acessar.''); //Redireciona para pagina de login
		exit();
		}
	}
	if(isset($_SESSION['token_adm_encrypted']) && isset($_SESSION["crsf_token_adm"]) && isset($_SESSION["anti_crsf_token_adm"])){
		$view_id_user_decrypted = CRIPT_AES('decrypt', $_SESSION["token_adm_encrypted"]);
		$query = "SELECT * FROM admin_users WHERE id = '$view_id_user_decrypted' AND status=1";
		$result = mysqli_query($mysqli , $query) or die (mysqli_error($mysqli));
		if (mysqli_num_rows($result) > 0) {
			$row = mysqli_fetch_assoc($result);
			$_SESSION['data_adm'] = $row;
		}
	}
// Função para checar permissão do admin logado
function admin_has_permission($perm) {
    if (!isset($_SESSION['admin_id'])) return false;
    if (!isset($_SESSION['admin_perms'])) return false;
    return in_array($perm, $_SESSION['admin_perms']);
}
// Carregar permissões do admin logado na sessão (se ainda não carregado)
if (isset($_SESSION['admin_id']) && !isset($_SESSION['admin_perms'])) {
    global $mysqli;
    $perms = [];
    $stmt = $mysqli->prepare('SELECT permission FROM admin_permissions WHERE admin_id = ?');
    $stmt->bind_param('i', $_SESSION['admin_id']);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($row = $res->fetch_assoc()) $perms[] = $row['permission'];
    $stmt->close();
    $_SESSION['admin_perms'] = $perms;
}