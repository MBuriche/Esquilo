// ⚠️ ATENÇÃO:Precisamos validar isso aqui ⚠️
<?php
if (getenv('APP_ENV') !== 'production') {
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);
} else {
    ini_set('display_errors', 0);
    ini_set('display_startup_errors', 0);
    error_reporting(0);
}

session_start();
include_once("config.php");
include_once(DASH . "/services/database.php");
include_once(DASH . "/services/funcao.php");
include_once(DASH . "/services/crud.php");
include_once(DASH . "/services/CSRF_Protect.php");
include_once(DASH . "/services/pega-ip.php");
include_once(DASH . "/services/ip-crawler.php");


$csrf = new CSRF_Protect();

// Base application URL
$appUrl = getenv('APP_URL') ?: 'https://weizhen.games';
$appDomain = parse_url($appUrl, PHP_URL_HOST);

// Verificar se o usuário está logado
$isAuthenticated = false;
$userData = null;

if (isset($_SESSION['user_id']) && !empty($_SESSION['user_id'])) {
    $isAuthenticated = true;
    
    // Buscar dados do usuário logado
    $userId = $_SESSION['user_id'];
    $stmt = $mysqli->prepare("SELECT id, email, usuario, celular, saldo, cpf, data_registro, codigo_convite FROM usuarios WHERE id = ?");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result && $row = $result->fetch_assoc()) {
        // Buscar estatísticas do usuário
        $total_bet = "0.00";
        $total_win = "0.00";
        $cpa_receive = "0.00";
        $revshare_receive = "0.00";
        $chest_open = 0;
        $chest_level = 0;
        $give_chest = 0;
        $pendent_comission = "0.00";
        $by_user_id = null;
        $rollover = "100000.00";
        $cpa_lv1 = "0.00";
        $cpa_lv2 = "0.00";
        $cpa_lv3 = "0.00";
        $revshare_lv1 = "0.00";
        $revshare_lv2 = "0.00";
        $revshare_lv3 = "0.00";
        $demo_account = 0;
        
        // Buscar total de apostas (game_history)
        $stmtBet = $mysqli->prepare("SELECT COALESCE(SUM(amount), 0) FROM game_history WHERE user_id = ?");
        $stmtBet->bind_param("i", $userId);
        $stmtBet->execute();
        $stmtBet->bind_result($total_bet_decimal);
        $stmtBet->fetch();
        $total_bet = number_format($total_bet_decimal, 2, '.', '');
        $stmtBet->close();
        
        // Buscar total de vitórias (game_history)
        $stmtWin = $mysqli->prepare("SELECT COALESCE(SUM(prize_amount), 0) FROM game_history WHERE user_id = ? AND prize_amount > 0");
        $stmtWin->bind_param("i", $userId);
        $stmtWin->execute();
        $stmtWin->bind_result($total_win_decimal);
        $stmtWin->fetch();
        $total_win = number_format($total_win_decimal, 2, '.', '');
        $stmtWin->close();
        
        // Buscar dados de afiliação se for afiliado
        if (!empty($row['codigo_convite'])) {
            $stmtAff = $mysqli->prepare("SELECT earned, available FROM afiliados WHERE user_id = ?");
            if ($stmtAff) {
                $stmtAff->bind_param("i", $userId);
                $stmtAff->execute();
                $stmtAff->bind_result($earned, $available);
                $stmtAff->fetch();
                $stmtAff->close();
                
                $cpa_receive = number_format($earned, 2, '.', '');
                $revshare_receive = number_format($available, 2, '.', '');
                $pendent_comission = number_format($earned - $available, 2, '.', '');
            }
        }
        
        // Formatar dados
        $balance = number_format($row['saldo'], 2, '.', '');
        $created_at = $row['data_registro'] ? date('Y-m-d\TH:i:s.000000\Z', strtotime($row['data_registro'])) : date('Y-m-d\TH:i:s.000000\Z');
        $updated_at = $created_at;
        
        $userData = [
            "id" => (int) $row['id'],
            "name" => $row['usuario'],
            "email" => $row['email'],
            "phone" => $row['celular'],
            "email_verified_at" => null,
            "role" => "user",
            "total_bet" => $total_bet,
            "pix_document" => $row['cpf'],
            "total_win" => $total_win,
            "cpa_receive" => $cpa_receive,
            "revshare_receive" => $revshare_receive,
            "chest_open" => $chest_open,
            "chest_level" => $chest_level,
            "give_chest" => $give_chest,
            "pendent_comission" => $pendent_comission,
            "by_user_id" => $by_user_id,
            "balance" => $balance,
            "rollover" => $rollover,
            "cpa_lv1" => $cpa_lv1,
            "cpa_lv2" => $cpa_lv2,
            "cpa_lv3" => $cpa_lv3,
            "revshare_lv1" => $revshare_lv1,
            "revshare_lv2" => $revshare_lv2,
            "revshare_lv3" => $revshare_lv3,
            "created_at" => $created_at,
            "updated_at" => $updated_at,
            "demo_account" => $demo_account
        ];
    }
    $stmt->close();
}
#==================================================================#
if (isset($_GET['utm_ads']) && !empty($_GET['utm_ads'])) {
  $ads_tipo = PHP_SEGURO($_GET['utm_ads']);
} else {
  $ads_tipo = NULL;
}
#==================================================================#
$url_atual = (isset($_SERVER['HTTPS']) ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
#==================================================================#
//INSERT DE VISITAS NAS LPS
$data_hoje = date("Y-m-d");
$hora_hoje = date("H:i:s");
if (isset($_SERVER['HTTP_REFERER'])) {
  $ref = $_SERVER['HTTP_REFERER'];
} else {
  $ref = $url_atual;
}
#==================================================================#
$data_us = ip_F($ip);
#==================================================================#
if ($browser != "Unknown Browser" and $os != "Unknown OS Platform" and $data_us['pais'] == "Brazil") {
  $id_user_ret = "1";
  $sql0 = $mysqli->prepare("SELECT ip_visita FROM visita_site WHERE data_cad=? AND ip_visita=?");
  $sql0->bind_param("ss", $data_hoje, $ip);
  $sql0->execute();
  $sql0->store_result();
  if ($sql0->num_rows) { //JÁ EXISTE CAD 
  } else {
    $sql = $mysqli->prepare("INSERT INTO visita_site (nav_os,mac_os,ip_visita,refer_visita,data_cad,hora_cad,id_user,pais,cidade,estado,ads_tipo) VALUES (?,?,?,?,?,?,?,?,?,?,?)");
    $sql->bind_param("sssssssssss", $browser, $os, $ip, $ref, $data_hoje, $hora_hoje, $id_user_ret, $data_us['pais'], $data_us['cidade'], $data_us['regiao'], $ads_tipo);
    $sql->execute();
  }
}
#===============================================================================#  

?>
<!DOCTYPE html>
<html lang="pt-BR">

<head>
  <meta charset="utf-8">
  <script>
   window.APP_URL = window.location.origin;
  </script>
  <meta name="viewport"
    content="width=device-width, initial-scale=1, shrink-to-fit=no, maximum-scale=1, viewport-fit=cover">

  <title>QIC Business</title>
  <base href="/" />

  <!-- Fonts -->
  <link rel="preconnect" href="https://fonts.bunny.net">
  <link href="https://fonts.bunny.net/css?family=figtree:400,500,600&display=swap" rel="stylesheet" />

<!-- Inércia + Rotas -->
  <script nonce="<?php echo htmlspecialchars($scriptNonce, ENT_QUOTES, 'UTF-8'); ?>" type="text/javascript">const Ziggy = { "url": "https:\/\/weizhen.games", "porta": nulo, "padrões": {}, "rotas": { "debugbar.openhandler": { "uri": "_debugbar\/abrir", "métodos": ["OBTER", "CABEÇA"] }, "debugbar.clockwork": { "uri": "_debugbar\/clockwork\/{id}", "métodos": ["OBTER", "CABEÇA"], "parâmetros": ["id"] }, "debugbar.assets.css": { "uri": "_debugbar\/assets\/folhas de estilo", "métodos": ["OBTER", "CABEÇA"] }, "debugbar.assets.js": { "uri": "_debugbar\/assets\/javascript", "métodos": ["GET", "HEAD"] }, "debugbar.cache.delete": { "uri": "_debugbar\/cache\/{chave}\/{tags?}", "métodos": ["DELETE"], "parâmetros": ["chave", "tags"] }, "debugbar.queries.explain": { "uri": "_debugbar\/queries\/explain", "métodos": ["POST"] }, "horizon.stats.index": { "uri": "horizon\/api\/stats", "métodos": ["GET", "HEAD"] }, "horizon.workload.index": { "uri": "horizon\/api\/carga de trabalho", "métodos": ["GET", "HEAD"] }, "horizon.masters.index": { "uri": "horizon\/api\/masters", "métodos": ["GET", "HEAD"] }, "horizon.monitoring.index": { "uri": "horizon\/api\/monitoring", "métodos": ["GET", "HEAD"] }, "horizon.monitoring.store": { "uri": "horizon\/api\/monitoring", "métodos": ["POST"] }, "horizon.monitoring-tag.paginate": { "uri": "horizon\/api\/monitoring\/{tag}", "métodos": ["GET", "HEAD"]", "parâmetros": ["tag"] }, "horizon.monitoring-tag.destroy": { "uri": "horizon\/api\/monitoring\/{tag}", "métodos": ["EXCLUIR"], "ondes": { "tag": ".*" }, "parâmetros": ["tag"] }, "horizon.jobs-metrics.index": { "uri": "horizon\/api\/metrics\/jobs", "métodos": ["OBTER", "CABEÇA"] }, "horizon.jobs-metrics.show": { "uri": "horizon\/api\/metrics\/jobs\/{id}", "métodos": ["OBTER", "CABEÇA"], "parâmetros": ["id"] }, "horizon.queues-metrics.index": { "uri": "horizon\/api\/metrics\/queues", "métodos": ["OBTER", "CABEÇA"] }, "horizon.queues-metrics.show": { "uri":"horizon\/api\/metrics\/queues\/{id}", "métodos": ["GET", "HEAD"], "parâmetros": ["id"] }, "horizon.jobs-batches.index": { "uri": "horizon\/api\/batches", "métodos": ["GET", "HEAD"] }, "horizon.jobs-batches.show": { "uri": "horizon\/api\/batches\/{id}", "métodos": ["GET", "HEAD"], "parâmetros": ["id"] }, "horizon.jobs-batches.retry": { "uri": "horizon\/api\/batches\/retry\/{id}", "métodos": ["POST"], "parâmetros": ["id"] }, "horizon.pending-jobs.index": { "uri": "horizon\/api\/jobs\/pendentes", "métodos": ["GET", "HEAD"] }, "horizon.completed-jobs.index": { "uri": "horizon\/api\/jobs\/concluídos", "métodos": ["GET", "HEAD"] }, "horizon.silenced-jobs.index": { "uri": "horizon\/api\/jobs\/silenciados", "métodos": ["GET", "HEAD"] }, "horizon.failed-jobs.index": { "uri": "horizon\/api\/jobs\/falhados", "métodos": ["GET", "HEAD"] }, "horizon.failed-jobs.show": { "uri": "horizon\/api\/jobs\/failed\/{id}", "métodos": ["GET", "HEAD"], "parâmetros": ["id"] }, "horizon.retry-jobs.show": { "uri": "horizon\/api\/jobs\/retry\/{id}", "métodos": ["POST"], "parâmetros": ["id"] }, "horizon.jobs.show": { "uri": "horizon\/api\/jobs\/{id}", "métodos": ["GET", "HEAD"], "parâmetros": ["id"] }, "horizon.index": { "uri": "horizon\/{view?}", "métodos": ["GET", "HEAD"], "wheres": { "view": "(.*)" }, "parâmetros": ["visualizar"] }, "sanctum.csrf-cookie": { "uri": "sanctum\/csrf-cookie", "métodos": ["OBTER", "CABEÇA"] }, "stancl.tenancy.asset": { "uri": "tenancy\/ativos\/{caminho?}", "métodos": ["OBTER", "CABEÇA"], "ondes": { "caminho": "(.*)" }, "parâmetros": ["caminho"] }, "painel": { "uri": "painel", "métodos": ["OBTER", "CABEÇA"], "domínio": "vc.psn.wine" }, "profile.edit": { "uri": "perfil", "métodos": ["OBTER", "CABEÇA"], "domínio": "vc.psn.wine" }, "profile.update": { "uri": "perfil", "métodos":["PATCH"], "domínio": "vc.psn.wine" }, "profile.destroy": { "uri": "perfil", "métodos": ["EXCLUIR"], "domínio": "vc.psn.wine" }, "tenants.create": { "uri": "inquilinos\/criar", "métodos": ["OBTER", "CABEÇA"], "domínio": "vc.psn.wine" }, "tenants.store": { "uri": "inquilinos", "métodos": ["POST"], "domínio": "vc.psn.wine" }, "tenants.update": { "uri": "inquilinos\/{id}", "métodos": ["COLOCAR"], "domínio": "vc.psn.wine", "parâmetros": ["id"] }, "tenants.destroy": { "uri": "tenants\/{id}", "métodos": ["EXCLUIR"], "domínio": "vc.psn.wine", "parâmetros": ["id"] }, "tenants.migrateAll": { "uri": "tenants\/migrate-all", "métodos": ["POST"], "domínio": "vc.psn.wine" }, "login": { "uri": "login", "métodos": ["GET", "HEAD"], "domínio": "vc.psn.wine" }, "password.request": { "uri": "esqueci a senha", "métodos": ["GET", "HEAD"], "domínio": "vc.psn.wine" }, "password.email": { "uri": "esqueci a senha", "métodos": ["POST"], "domínio": "vc.psn.wine" }, "password.reset": { "uri": "redefinir-senha\/{token}", "métodos": ["GET", "HEAD"], "domínio": "vc.psn.wine", "parâmetros": ["token"] }, "password.store": { "uri": "redefinir-senha", "métodos": ["POST"], "domínio": "vc.psn.wine" }, "verification.notice": { "uri": "verificar-email", "métodos": ["GET", "HEAD"], "domínio": "vc.psn.wine" }, "verification.verify": { "uri": "verificar-email\/{id}\/{hash}", "métodos": ["GET", "HEAD"], "domínio": "vc.psn.wine", "parâmetros": ["id", "hash"] }, "verification.send": { "uri": "email\/verification-notification", "métodos": ["POST"], "domínio": "vc.psn.wine" }, "password.confirm": { "uri": "confirm-password", "métodos": ["GET", "HEAD"], "domínio": "vc.psn.wine" }, "password.update": { "uri": "password", "métodos": ["PUT"], "domínio": "vc.psn.wine" }, "logout": { "uri": "logout", "métodos": ["POST"], "domínio": "vc.psn.wine" }, "storage.local": { "uri": "caminho\/{storage}", "métodos": ["GET", "HEAD"], "wheres": { "caminho": ".*" }, "parâmetros": ["caminho"] }, "tenant.game.launch": { "uri": "\/", "métodos": ["GET", "HEAD"] }, "tenant.admin.weizhen-manager": { "uri": "admin\/weizhen-manager", "métodos": ["GET", "HEAD"] }, "tenant.admin.users.index": { "uri": "admin\/users", "métodos": ["GET", "HEAD"] }, "tenant.admin.users.update": { "uri": "admin\/users\/{usuário}", "métodos": ["PUT"], "parâmetros": ["usuário"], "ligações": { "usuário": "id" } }, "tenant.admin.users.reset-password": { "uri": "admin\/users\/{usuário}\/reset-password", "métodos": ["POST"], "parâmetros": ["usuário"], "ligações": { "usuário": "id" } }, "tenant.admin.users.details": { "uri": "admin\/users\/{usuário}\/detalhes", "métodos": ["GET", "HEAD"], "parâmetros": ["usuário"], "ligações": { "usuário": "id" } }, "tenant.admin.users.referrals": { "uri": "admin\/users\/{usuário}\/referências", "métodos": ["GET", "HEAD"], "parâmetros": ["usuário"], "vinculações": { "usuário": "id" } }, "tenant.admin.deposits.index": { "uri": "admin\/depósitos", "métodos": ["GET", "HEAD"] }, "tenant.admin.deposits.update": { "uri": "admin\/depósitos\/{transação}", "métodos": ["PUT"], "parâmetros": ["transação"], "vinculações": { "transação": "id" } }, "tenant.admin.withdrawals.index": { "uri": "admin\/retiradas", "métodos": ["GET", "HEAD"] }, "tenant.admin.withdrawals.update": { "uri": "admin\/withdrawals\/{transaction}", "métodos": ["PUT"], "parâmetros": ["transação"], "vinculações": { "transação": "id" } }, "tenant.admin.settings.index": { "uri": "admin\/settings", "métodos": ["GET", "HEAD"] }, "tenant.admin.settings.update": { "uri": "admin\/settings", "métodos": ["PUT"] }, "tenant.admin.settings.unlockDeveloper": { "uri": "admin\/settings\/unlock-developer", "métodos": ["POST"] }, "tenant.admin.tenant.admin.online-users": { "uri": "admin\/online-users", "métodos": ["GET", "HEAD"] }, "tenant.admin.jackpot.index": { "uri": "admin\/jackpot", "métodos": ["GET", "HEAD"] }, "tenant.admin.jackpot.update": { "uri": "admin\/jackpot", "métodos": ["PUT"] }, "tenant.register": { "uri": "register", "métodos": ["GET", "HEAD"] }, "weizhen-manager": { "uri": "weizhen-manager", "métodos": ["OBTER", "CABEÇA"] }, "login-to-manager.store": { "uri": "login-to-manager", "métodos": ["POST"] }, "login-to-game.store": { "uri": "login-to-game", "métodos": ["POST"] }, "tenant.game.history": { "uri": "histórico-do-jogo", "métodos": ["OBTER", "CABEÇA"] }, "tenant.profile.changePassword": { "uri": "alterar-senha", "métodos": ["COLOCAR"] }, "tenant.withdrawal.data": { "uri": "dados-de-saque", "métodos": ["OBTER", "CABEÇA"] }, "tenant.withdrawal.store": { "uri": "saque", "métodos": ["POST"] }, "tenant.withdrawal.updatePix": { "uri": "update-pix-document", "métodos": ["POST"] }, "tenant.deposit.data": { "uri": "deposit-data", "métodos": ["GET", "HEAD"] }, "tenant.deposit.store": { "uri": "deposit", "métodos": ["POST"] }, "tenant.deposit.checkStatus": { "uri": "check-payment-status", "métodos": ["POST"] }, "tenant.user.data": { "uri": "user-data", "métodos": ["GET", "HEAD"] }, "tenant.agent.panel.data": { "uri": "agent-panel-data", "métodos": ["GET", "HEAD"] }, "tenant.agent.collect": { "uri": "agent-collect-commission", "métodos": ["POST"] }, "tenant.user.refresh": { "uri": "api\/user\/refresh", "métodos": ["GET", "HEAD"] }, "game.start": { "uri": "game\/start", "métodos": ["POST"] }, "game.openChest": { "uri": "game\/open-chest", "métodos": ["POST"] }, "game.cashOut":{ "uri": "jogo\/saque", "métodos": ["POST"] }, "tenant.referral.link": { "uri": "link de referência", "métodos": ["GET", "HEAD"] }, "tenant.logout": { "uri": "logout", "métodos": ["POST"] }, "tenant.user.heartbeat": { "uri": "api\/usuário\/batimento cardíaco", "métodos": ["POST"] }, "tenant.horsepay.callback": { "uri": "pagamento\/retorno\/horsepay", "métodos": ["POST"] }, "tenant.api.logout": { "uri": "api\/logout", "métodos": ["POST"] } } }; !function(t, r) { "objeto" == tipo de exportações && "indefinido" != tipo de módulo ? module.exports = r() : "função" == tipo de define && define.amd ? define(r) : (t || self).route = r() }(this, function () { function t(t, r) { for (var n = 0; n < r.length; n++) { var e = r[n]; e.enumerable = e.enumerable || !1, e.configurable = !0, "value" in e && (e.writable = !0), Object.defineProperty(t, u(e.key), e) } } function r(r, n, e) { return n && t(r.prototype, n), e && t(r, e), Object.defineProperty(r, "prototype", { writable: !1 }), r } function n() { return n = Object.assign ? Object.assign.bind() : function (t) { for (var r = 1; r < arguments.length; r++) { var n = argumentos[r]; para (var e em n) ({}).hasOwnProperty.call(n, e) && (t[e] = n[e]) } retornar t }, n.aplicar(nulo, argumentos) } função e(t) { retornar e = Objeto.setPrototypeOf ? Objeto.getPrototypeOf.bind() : função (t) { retornar t.__proto__ || Objeto.getPrototypeOf(t) }, e(t) } função o() { tentar { var t = !Boolean.prototype.valueOf.call(Reflect.construct(Boolean, [], função () { })) } pegar (t) { } retornar (o = função () { retornar !!t })() } função i(t, r) { retornar i = Objeto.setPrototypeOf ? Object.setPrototypeOf.bind() : function (t, r) { return t.__proto__ = r, t }, i(t, r) } function u(t) { var r = function (t) { if ("object" != typeof t || !t) return t; var r = t[Symbol.toPrimitive]; if (void 0 !== r) { var n = r.call(t, "string"); if ("object" != typeof n) return n; throw new TypeError("@@toPrimitive deve retornar um valor primitivo.") } return String(t) }(t); return "symbol" == typeof r ? r : r + "" } function f(t) { var r = "function" == typeof Map ? new Map : void 0; return f = function (t) { if (null === t || !function (t) { try { return -1 !== Function.toString.call(t).indexOf("[código nativo]") } catch (r) { return "function" == typeof t } }(t)) return t; if ("function" != typeof t) throw new TypeError("A superexpressão deve ser nula ou uma função"); if (void 0 !== r) { if (r.has(t)) return r.get(t); r.set(t, n) } function n() { return function (t,r, n) { if (o()) return Reflect.construct.apply(null, argumentos); var e = [null]; e.push.apply(e, r); var u = new (t.bind.apply(t, e)); retornar n && i(u, n.prototype), u }(t, argumentos, e(this).constructor) } retornar n.prototype = Objeto.create(t.prototype, { construtor: { valor: n, enumerável: !1, gravável: !0, configurável: !0 } }), i(n, t) }, f(t) } var a = String.prototype.replace, c = /%20/g, l = "RFC3986", s = { padrão: l, formatadores: { RFC1738: função (t) { retornar a.call(t, c, "+") }, RFC3986: função (t) { retornar String(t) } }, RFC1738: "RFC1738", RFC3986: l }, v = Objeto.prototype.hasOwnProperty, p = Array.isArray, y = function () { para (var t = [], r = 0; r < 256; ++r)t.push("%" + ((r < 16 ? "0" : "") + r.toString(16)).toUpperCase()); return t }(), d = function (t, r) { para (var n = r && r.plainObjects ? Object.create(null) : {}, e = 0; e < t.length; ++e)void 0 !== t[e] && (n[e] = t[e]); retornar n }, b = { arrayToObject: d, atribuir: função (t, r) { retornar Object.keys(r).reduce(função (t, n) { retornar t[n] = r[n], t }, t) }, combinar: função (t, r) { retornar [].concat(t, r) }, compactar: ​​função (t) { para (var r = [{ obj: { o: t }, prop: "o" }], n = [], e = 0; e < r.length; ++e)para (var o = r[e], i = o.obj[o.prop], u = Object.keys(i), f = 0; f < u.length; ++f) { var a = u[f], c = i[a]; "objeto" == tipo de c && nulo !== c && -1 === n.indexOf(c) && (r.push({ obj: i, prop: a }), n.push(c)) } return function (t) { for (; t.length > 1;) { var r = t.pop(), n = r.obj[r.prop]; if (p(n)) { for (var e = [], o = 0; o < n.length; ++o)void 0 !== n[o] && e.push(n[o]); r.obj[r.prop] = e } } }(r), t }, decodificar: função (t, r, n) { var e = t.replace(/\+/g, " "); se ("iso-8859-1" === n) retornar e. substituir(/%[0-9a-f]{2}/gi, unescape); tentar { retornar decodeURIComponent(e) } pegar (t) { retornar e } }, codificar: função (t, r, n, e, o) { se (0 === t. comprimento) retornar t; var i = t; se ("símbolo" == tipo de t ? i = Símbolo. protótipo. toString. chamar(t) : "string" != tipo de t && (i = String(t)), "iso-8859-1" === n) retornar escape(i). substituir(/%u[0-9a-f]{4}/gi, função (t) { retornar "%26%23" + parseInt(t. fatia(2), 16) + "%3B" }); para (var u = "", f = 0; f < i.length; ++f) { var a = i.charCodeAt(f); 45 === a || 46 === a || 95 === a || 126 === a || a >= 48 && a <= 57 || a >= 65 && a <= 90 || a >= 97 && a <= 122 || o === s.RFC1738 && (40 === a || 41 === a) ? u += i.charAt(f) : a < 128 ? u += y[a] : a < 2048 ? u += y[192 | a >> 6] + y[128 | 63 & a] : a < 55296 || a >= 57344 ? u += y[224 | a >> 12] + y[128 | a >> 6 e 63] + y[128 | 63 e a] : (a = 65536 + ((1023 e a) << 10 | 1023 e i.charCodeAt(f += 1)),u += y[240 | a >> 18] + y[128 | a >> 12 e 63] + y[128 | a >> 6 e 63] + y[128 | 63 e a]) } return u }, isBuffer: função (t) { return !(!t || "objeto" != tipo de t || !(t.construtor && t.construtor.isBuffer && t.construtor.isBuffer(t))) }, isRegExp: função (t) { return "[objeto RegExp]" === Object.prototype.toString.call(t) }, maybeMap: função (t, r) { if (p(t)) { for (var n = [], e = 0; e < t.length; e += 1)n.push(r(t[e])); retornar n } retornar r(t) }, mesclar: função t(r, n, e) { se (!n) retornar r; se ("objeto" != tipo de n) { se (p(r)) r.push(n); senão { se (!r || "objeto" != tipo de r) retornar [r, n]; (e && (e.plainObjects || e.allowPrototypes) || !v.call(Object.prototype, n)) && (r[n] = !0) } retornar r } se (!r || "objeto" != tipo de r) retornar [r].concat(n); var o = r; retornar p(r) && !p(n) && (o = d(r, e)), p(r) && p(n) ? (n.forEach(function(n, o) { if (v.call(r, o)) { var i = r[o]; i && "object" == typeof i && n && "object" == typeof n ? r[o] = t(i, n, e) : r.push(n) } else r[o] = n }), r) : Object.keys(n).reduce(function(r, o) { var i = n[o]; return r[o] = v.call(r, o) ? t(r[o], i, e) : i, r }, o) } }, h = Object.prototype.hasOwnProperty, g = { brackets: function(t) { return t + "[]" }, comma: "comma", indices: function(t, r) { return t + "[" + r + "]" }, repeat: function (t) { return t } }, m = Array.isArray, j = String.prototype.split, w = Array.prototype.push, O = function (t, r) { w.apply(t, m(r) ? r : [r]) }, E = Date.prototype.toISOString, R = s.default, S = { addQueryPrefix: !1, allowDots: !1, charset: "utf-8", charsetSentinel: !1, delimiter: "&", encode: !0, encoder: b.encode, encodeValuesOnly: !1, format: R, formatador: s.formatters[R], índices: !1, serializeDate: function (t) { return E.call(t) }, skipNulls: !1, strictNullHandling: !1 }, k = function t(r, n, e, o, i, u, f, a, c, l, s, v, p, y) { var d, h = r; if ("function" == typeof f ? h = f(n, h) : h instanceof Date ? h = l(h) : "comma" === e && m(h) && (h = b.maybeMap(h, function (t) { return t instanceof Date ? l(t) : t })), null === h) { if (o) return u && !p ? u(n, S.encoder, y, "key", s) : n; h = "" } if ("string" == tipo de (d = h) || "número" == tipo de d || "booleano" == tipo de d || "símbolo" == tipo de d || "bigint" == tipo de d || b.isBuffer(h)) { if (u) { var g = p ? n : u(n, S.encoder, y, "chave", s); if ("vírgula" === e && p) { for (var w = j.call(String(h), ","), E = "", R = 0; R < w.length; ++R)E += (0 === R ? "" : ",") + v(u(w[R], S.encoder, y, "valor", s)); return [v(g) + "=" + E] } return [v(g) + "=" + v(u(h, S.codificador, y, "valor", s))] } retornar [v(n) + "=" + v(String(h))] } var k, T = []; se (void 0 === h) retornar T; se ("vírgula" === e && m(h)) k = [{ valor: h.length > 0 ? h.join(",") || nulo : nulo 0 }]; senão se (m(f)) k = f; senão { var $ = Object.keys(h); k = a ? $.sort(a) : $ } para (var x = 0; x < k.length; ++x) { var N = k[x], C = "objeto" == tipo de N && nulo 0 !== N.valor ? N.valor : h[N]; se (!i || nulo !== C) { var A = m(h) ? "função" == tipo de e ? e(n, N) : n : n + (c ? "." + N : "[" + N + "]"); O(T, t(C, A, e, o, i, u, f, a, c, l, s, v, p, y)) } } return T }, T = Object.prototype.hasOwnProperty, $ = Array.isArray, x = { allowDots: !1, allowPrototypes: !1, arrayLimit: 20, conjunto de caracteres: "utf-8", charsetSentinel: !1, vírgula: !1, decodificador: b.decode, delimitador: "&", profundidade: 5, ignoreQueryPrefix: !1, interpretNumericEntities: !1, parameterLimit: 1e3, parseArrays: !0, plainObjects: !1, strictNullHandling: !1 }, N = function (t) { return t.replace(/&#(\d+);/g, function (t, r) { retornar String.fromCharCode(parseInt(r, 10)) }) }, C = function (t, r) { retornar t && "string" == typeof t && r.comma && t.indexOf(",") > -1 ? t.split(",") : t }, A = function (t, r, n, e) { if (t) { var o = n.allowDots ? t.replace(/\.([^.[]+)/g, "[$1]") : t, i = /(\[[^[\]]*])/g, u = n.depth > 0 && /(\[[^[\]]*])/.exec(o), f = u ? o.slice(0, u.index) : o, a = []; se (f) { se (!n.plainObjects && T.call(Object.prototype, f) && !n.allowPrototypes) retornar; a.push(f) } para (var c = 0; n.depth > 0 && nulo !== (u = i.exec(o)) && c < n.depth;) { se (c += 1, !n.plainObjects && T.call(Object.prototype, u[1].slice(1, -1)) && !n.allowPrototypes) retornar; a.push(u[1]) } return u && a.push("[" + o.slice(u.index) + "]"), function (t, r, n, e) { for (var o = e ? r : C(r, n), i = t.length - 1; i >= 0; --i) { var u, f = t[i]; if ("[]" === f && n.parseArrays) u = [].concat(o); else { u = n.plainObjects ? Object.create(null) : {}; var a = "[" === f.charAt(0) && "]" === f.charAt(f.length - 1) ? f.slice(1, -1) : f, c = parseInt(a, 10); n.parseArrays || "" !== a ? !isNaN(c) && f !== a && String(c) === a && c >= 0 && n.parseArrays && c <= n.arrayLimit ? (u = [])[c] = o : "__proto__" !== a && (u[a] = o) : u = { 0: o } } o = u } return o }(a, r, n, e) } }, D = function (t, r) { var n = function (t) { if (!t) return x; if (null != t.decoder && "function" != typeof t.decoder) throw new TypeError("O decodificador tem que ser uma função."); se (void 0 !== t.charset && "utf-8" !== t.charset && "iso-8859-1" !== t.charset) throw new TypeError("A opção charset deve ser utf-8, iso-8859-1 ou undefined"); return { allowDots: void 0 === t.allowDots ? x.allowDots : !!t.allowDots, allowPrototypes: "boolean" == typeof t.allowPrototypes ? t.allowPrototypes : x.allowPrototypes, arrayLimit: "number" == typeof t.arrayLimit ? t.arrayLimit : x.arrayLimit, charset: void 0 === t.charset ? x.charset : t.charset, charsetSentinel: "boolean" == typeof t.charsetSentinel ? t.charsetSentinel : x.charsetSentinel, vírgula: "booleano" == tipo de t.vírgula ? t.vírgula : x.vírgula, decodificador: "função" == tipo de t.codificador ? t.codificador : x.codificador, delimitador: "string" == tipo de t.delimitador || b.isRegExp(t.delimitador) ? t.delimitador : x.delimitador, profundidade: "número" == tipo de t.profundidade || !1 === t.profundidade ? +t.profundidade : x.profundidade, ignoreQueryPrefix: !0 === t.ignoreQueryPrefix, interpretNumericEntities: "booleano" == tipo de t.interpretNumericEntities ? t.interpretNumericEntities: x.interpretNumericEntities, parameterLimit: "número" == tipo de t.parameterLimit? t.parameterLimit: x.parameterLimit, parseArrays: !1 !== t.parseArrays, plainObjects: "booleano" == tipo de t.plainObjects? t.plainObjects: x.plainObjects, strictNullHandling: "booleano" == tipo de t.strictNullHandling? t.strictNullHandling: x.strictNullHandling} }(r); se ("" === t || nulo == t) retornar n.plainObjects? Objeto.criar(nulo): {}; para (var e = "string" == typeof t ? function (t, r) { var n, e = {}, o = (r.ignoreQueryPrefix ? t.replace(/^\?/, "") : t).split(r.delimiter, Infinity === r.parameterLimit ? void 0 : r.parameterLimit), i = -1, u = r.charset; se (r.charsetSentinel) para (n = 0; n < o.length; ++n)0 === o[n].indexOf("utf8=") && ("utf8=%E2%9C%93" === o[n] ? u = "utf-8" : "utf8=%26%2310003%3B" === o[n] && (u = "iso-8859-1"), i = n, n = o.length); para (n = 0; n < o.length; ++n)se (n !== i) { var f, a, c = o[n], l = c.indexOf("]="), s = -1 === l ? c.indexOf("=") : l + 1; -1 === s ? (f = r.decoder(c, x.decoder, u, "chave"), a = r.strictNullHandling ? nulo : "") : (f = r.decoder(c.slice(0, s), x.decoder, u, "chave"), a = b.maybeMap(C(c.slice(s + 1), r), função (t) { return r.decoder(t, x.decoder, u, "valor") })), a && r.interpretNumericEntities && "iso-8859-1" === u && (a = N(a)), c.indexOf("[]=") > -1 && (a = $(a) ​​? [a] : a), e[f] = T.call(e, f) ? b.combine(e[f], a) : a } return e }(t, n) : t, o = n.plainObjects ? Object.create(null) : {}, i = Object.keys(e), u = 0; u < i.length; ++u) { var f = i[u], a = A(f, e[f], n, "string" == typeof t); o = b.merge(o, a, n) } return b.compact(o) }, P =/*#__PURE__*/function () { function t(t, r, n) { var e, o; this.nome = t, this.definição = r, this.ligações = nulo != (e = r.bindings) ? e : {}, this.wheres = nulo != (o = r.wheres) ? o : {}, this.config = n } var n = t.prototype; retornar n.matchesUrl = função (t) { var r, n = isto; se (!this.definition.methods.includes("GET")) retornar !1; var e = this.template.replace(/[.*+$()[\]]/g, "\\$&").replace(/(\/?){([^}?]*)(\??)}/g, function (t, r, e, o) { var i, u = "(?<" + e + ">" + ((null == (i = n.wheres[e]) ? void 0 : i.replace(/(^\^)|(\$$)/g, "")) || "[^/?]+") + ")"; return o ? "(" + r + u + ")?" : "" + r + u }).replace(/^\w+:\/\//, ""), o = t.replace(/^\w+:\/\//, "").split("?"), i = o[0], u = o[1], f = nulo != (r = new RegExp("^" + e + "/?$").exec(i)) ? r : new RegExp("^" + e + "/?$").exec(decodeURI(i)); if (f) { for (var a in f.groups) f.groups[a] = "string" == typeof f.groups[a] ? decodeURIComponent(f.groups[a]) : f.groups[a]; return { params: f.groups, query: D(u) } } return !1 }, n.compile = function (t) { var r = this; return this.parameterSegments.length ? this.template.replace(/{([^}?]+)(\??)}/g, function (n, e, o) { var i, u; if (!o && [null, void 0].includes(t[e])) throw new Error("Erro do Ziggy: o parâmetro '" + e + "' é necessário para a rota '" + r.name + "'."); if (r.wheres[e] && !new RegExp("^" + (o ? "(" + r.wheres[e] + ")?" : r.wheres[e]) + "$").test(null != (u = t[e]) ? u : "")) throw new Error("Erro do Ziggy: o parâmetro '" + t[e] + "' não corresponde ao formato necessário '" + r.wheres[e] + "' para a rota '" + r.name + "'."); retornar encodeURI(null != (i = t[e]) ? i : "").replace(/%7C/g, "|").replace(/%25/g, "%").replace(/\$/g, "%24") }).replace(this.config.absolute ? /(\.[^/]+?)(\/\/)/ : /(^)(\/\/)/, "$1/").replace(/\/+$/, "") : this.template }, r(t, [{ chave: "template", obter: function () { var t = (this.origin + "/" + this.definition.uri).replace(/\/+$/, ""); retornar "" === t ? "/" : t } }, { chave: "origin", obter: function () { retornar this.config.absolute ? this.definition.domain ? "" + this.config.url.match(/^\w+:\/\//)[0] + this.definition.domain + (this.config.port ? ":" + this.config.port : "") : this.config.url : "" } }, { chave: "parameterSegments", obter: função () { var t, r; retornar nulo != (t = nulo == (r = this.template.match(/{[^}?]+\??}/g)) ? vazio 0 : r.map(função (t) { retornar { nome: t.replace(/{|\??}/g, ""), obrigatório: !/\?}$/.test(t) } })) ? t : [] } }]) }(), F =/*#__PURE__*/função (t) { função e(r, e, o, i) { var u; se (void 0 === o && (o = !0), (u = t.call(this) || this).t = null != i ? i : "indefinido" != typeof Ziggy ? Ziggy : null == globalThis ? void 0 : globalThis.Ziggy, ut = n({}, ut, { absolute: o }), r) { if (!utroutes[r]) throw new Error("Erro do Ziggy: a rota '" + r + "' não está na lista de rotas."); ui = new P(r, utroutes[r], ut), uu = ul(e) } return u } var o, u; u = t, (o = e).prototype = Object.create(u.prototype), o.prototype.constructor = o, i(o, u); var f = e.prototype; retornar f.toString = function () { var t = this, r = Object.keys(this.u).filter(function (r) { retornar !tiparameterSegments.some(function (t) { retornar t.name === r }) }).filter(function (t) { retornar "_query" !== t }).reduce(function (r, e) { var o; retornar n({}, r, ((o = {})[e] = tu[e], o)) }, {}); retornar this.i.compile(this.u) + function (t, r) { var n, e = t, o = function (t) { se (!t) retornar S; se (nulo != t.encoder && "função" != typeof t.encoder) lançar novo TypeError("O codificador deve ser uma função."); var r = t.charset || S.charset; if (void 0 !== t.charset && "utf-8" !== t.charset && "iso-8859-1" !== t.charset) throw new TypeError("A opção charset deve ser utf-8, iso-8859-1 ou indefinida"); var n = s.default; if (void 0 !== t.format) { if (!h.call(s.formatters, t.format)) throw new TypeError("Opção de formato desconhecida fornecida."); n = t.format } var e = s.formatters[n], o = S.filter; return ("function" == typeof t.filter || m(t.filter)) && (o = t.filter), { addQueryPrefix: "boolean" == typeof t.addQueryPrefix ? t.addQueryPrefix : S.addQueryPrefix, allowDots: void 0 === t.allowDots ? S.allowDots : !!t.allowDots, conjunto de caracteres: r, charsetSentinel: "booleano" == tipo de t.charsetSentinel ? t.charsetSentinel : S.charsetSentinel, delimitador: void 0 === t.delimitador ? S.delimitador : t.delimitador, codificação: "booleano" == tipo de t.codificação ? t.codificação : S.codificação, codificador: "função" == tipo de t.codificador ? t.codificador : S.codificador, encodeValuesOnly: "booleano" == tipo de t.codificaçãoValuesOnly ? t.encodeValuesOnly : S.encodeValuesOnly, filtro: o, formato: n, formatador: e, serializeDate: "função" == tipo de t.serializeDate ? t.serializeDate : S.serializeDate, skipNulls: "booleano" == tipo de t.skipNulls ? t.skipNulls : S.skipNulls, ordenar: "função" == tipo de t.sort ? t.sort : nulo, strictNullHandling: "booleano" == tipo de t.strictNullHandling ? t.strictNullHandling : S.strictNullHandling } }(r); "função" == tipo de o.filter ? e = (0, o.filter)("", e) : m(o.filter) && (n = o.filter); var i = []; if ("objeto" != typeof e || null === e) return ""; var u = g[r && r.arrayFormat em g ? r.arrayFormat : r && "índices" em r ? r.indices ? "índices" : "repeat" : "índices"]; n || (n = Object.keys(e)), o.classificar && n.sort(o.sort); for (var f = 0; f < n.comprimento; ++f) { var a = n[f]; o.skipNulls && null === e[a] || o. !0 === o.addQueryPrefix ? "?" : ""; retornar o.charsetSentinel && (l += "iso-8859-1" === o.charset ? "utf8=%26%2310003%3B&" : "utf8=%E2%9C%93&"), c.length > 0 ? l + c : "" }(n({}, r, this.u._query), { addQueryPrefix: !0, arrayFormat: "índices", encodeValuesOnly: !0, skipNulls: !0, codificador: função (t, r) { retornar "booleano" == tipo de t ? Número(t) : r(t) } }) }, fv = função (t) { var r = isto; t ? this.t.absolute && t.startsWith("/") && (t = this.p().host + t) : t = this.h(); var e = {}, o = Object.entries(this.t.routes).find(function (n) { return e = new P(n[0], n[1], rt).matchesUrl(t) }) || [void 0, void 0]; return n({ name: o[0] }, e, { route: o[1] }) }, fh = function () { var t = this.p(), r = t.pathname, n = t.search; retornar (this.t.absolute ? t.host + r : r.replace(this.t.url.replace(/^\w*:\/\/[^/]+/, ""), "").replace(/^\/+/, "/")) + n }, f.current = function (t, r) { var e = this.v(), o = e.name, i = e.params, u = e.query, f = e.route; se (!t) retornar o; var a = new RegExp("^" + t.replace(/\./g, "\\.").replace(/\*/g, ".*") + "$").test(o); se ([null, void 0].includes(r) || !a) retornar a; var c = new P(o, f, this.t); r = this.l(r, c); var l = n({}, i, u); se (Objeto. valores (r). cada (função (t) { retornar! t}) &&! Objeto. valores (l). alguns (função (t) { retornar vazio 0! == t})) retornar! 0; var s = função (t, r) { retornar Objeto. entradas (t). cada (função (t) { var n = t [0], e = t [1]; retornar Matriz. é array (e) && Matriz. é array (r [n]) ? e. cada (função (t) { retornar r [n]. inclui (t) }) : "objeto" == tipo de e && "objeto" == tipo de r [n] && nulo! == e && nulo! == r [n] ? s (e, r [n]) : r [n] == e }) }; retornar s(r, l) }, fp = function () { var t, r, n, e, o, i, u = "indefinido" != tipo de janela ? janela.localização : {}, f = u.host, a = u.caminho, c = u.pesquisa; retornar { host: nulo != (t = nulo == (r = este.localização.t) ? nulo 0 : r.host) ? t : nulo 0 === f ? "" : f, caminho: nulo != (n = nulo == (e = este.localização.t) ? nulo 0 : e.caminho) ? n : nulo 0 === a ? "" : a, pesquisa: nulo != (o = nulo == (i = este.localização.t) ? nulo 0 : i.pesquisa) ? o : nulo 0 === c ? "" : c } }, f.has = function (t) { return this.t.routes.hasOwnProperty(t) }, fl = function (t, r) { var e = this; void 0 === t && (t = {}), void 0 === r && (r = this.i), null != t || (t = {}), t = ["string", "número"].inclui(tipo de t) ? [t] : t; var o = r.parameterSegments.filter(função (t) { return !etdefaults[t.nome] }); se (Matriz.éArray(t)) t = t.reduzir(função (t, r, e) { var i, u; retornar n({}, t, o[e] ? ((i = {})[o[e].nome] = r, i) : "objeto" == tipo de r ? r : ((u = {})[r] = "", u)) }, {}); senão se (1 === o.length && !t[o[0].nome] && (t.temPropriedadePrópria(Objeto.valores(r.bindings)[0]) || t.temPropriedadePrópria("id"))) { var i; (i = {})[o[0].nome] = t, t = i } retornar n({}, isto.m(r), isto.j(t, r)) }, fm = função (t) { var r = isto; retornar t.parameterSegments.filter(função (t) { retornar rtdefaults[t.nome] }).reduce(função (t, e, o) { var i, u = e.nome; retornar n({}, t, ((i = {})[u] = rtdefaults[u], i)) }, {}) }, fj = função (t, r) { var e = r.bindings, o = r.parameterSegments; retornar Object.entries(t).reduce(function(t, r) { var i, u, f = r[0], a = r[1]; se (!a || "objeto" != typeof a || Array.isArray(a) || !o.some(function(t) { retornar t.nome === f })) retornar n({}, t, ((u = {})[f] = a, u)); se (!a.hasOwnProperty(e[f])) { se (!a.hasOwnProperty("id")) lançar novo erro("Erro Ziggy: o objeto passado como parâmetro '" + f + "' não possui a chave de vinculação do modelo de rota '" + e[f] + "'."); e[f] = "id" } retornar n({}, t, ((i = {})[f] = a[e[f]], i)) }, {}) }, f.valueOf = function () { return this.toString() }, r(e, [{ key: "params", get: function () { var t = this.v(); return n({}, t.params, t.query) } }, { key: "routeParams", get: function () { return this.v().params } }, { key: "queryParams", get: function () { return this.v().query } }]) }(/*#__PURE__*/f(String)); return function (t, r, n, e) { var o = new F(t, r, n, e); return t ? o.toString() : o } });objeto passado como parâmetro '" + f + "' está faltando chave de vinculação do modelo de rota '" + e[f] + "'."); e[f] = "id" } return n({}, t, ((i = {})[f] = a[e[f]], i)) }, {}) }, f.valueOf = function () { return this.toString() }, r(e, [{ key: "params", get: function () { var t = this.v(); return n({}, t.params, t.query) } }, { key: "routeParams", get: function () { return this.v().params } }, { key: "queryParams", get: function () { return this.v().query } }]) }(/*#__PURE__*/f(String)); return function (t, r, n, e) { var o = novo F(t, r, n, e); retornar t ? o.toString() : o } });objeto passado como parâmetro '" + f + "' está faltando chave de vinculação do modelo de rota '" + e[f] + "'."); e[f] = "id" } return n({}, t, ((i = {})[f] = a[e[f]], i)) }, {}) }, f.valueOf = function () { return this.toString() }, r(e, [{ key: "params", get: function () { var t = this.v(); return n({}, t.params, t.query) } }, { key: "routeParams", get: function () { return this.v().params } }, { key: "queryParams", get: function () { return this.v().query } }]) }(/*#__PURE__*/f(String)); return function (t, r, n, e) { var o = novo F(t, r, n, e); retornar t ? o.toString() : o } });
  </script>
  
  <link rel="stylesheet" href="/build/assets/app-B3dtaGch.css">

  <script type="module" src="/build/assets/app-ISxEiS1S.js"></script>
</head>

<body class="font-sans antialiased">
  <div id="app"
    data-page='<?php 
    $pageData = [
        "component" => "Tenant/Game/Launch",
        "props" => [
            "errors" => [],
            "auth" => [
                "user" => $userData
            ],
            "flash" => [
                "success" => null,
                "error" => null
            ],
            "user" => $userData,
            "isAuthenticated" => $isAuthenticated,
            "settings" => [
                "ui_social_link" => "https://w.app/6py0fm",
                "ui_support_link" => "https://w.app/6py0fm",
                "hide_phone_login" => "2"
            ]
        ],
        "url" => "/",
        "version" => "6b1ee3f6b70b55bacbf68ad9d92748f9",
        "clearHistory" => false,
        "encryptHistory" => false
    ];
    echo json_encode($pageData, JSON_HEX_APOS | JSON_HEX_QUOT);
    ?>'>
  </div>
</body>

</html>