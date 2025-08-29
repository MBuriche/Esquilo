<?php
// Fallbacks seguros
$UA = $UA ?? ($_SERVER['HTTP_USER_AGENT'] ?? '');

// IP real (Cloudflare > X-Forwarded-For > REMOTE_ADDR)
$CLIENT_IP = (function () {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) && filter_var($_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP)) {
        return $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        foreach (array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])) as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '';
})();

$ip = $ip ?? $CLIENT_IP;

// Heurísticas simples (preenche se não existir)
if (!isset($browser) || $browser === '') {
    $ua = strtolower($UA);
    $browser =
        (str_contains($ua,'edg') ? 'Edge' :
        (str_contains($ua,'opr') || str_contains($ua,'opera') ? 'Opera' :
        (str_contains($ua,'firefox') ? 'Firefox' :
        (str_contains($ua,'chrome') && !str_contains($ua,'edg') ? 'Chrome' :
        (str_contains($ua,'safari') && !str_contains($ua,'chrome') ? 'Safari' :
        (str_contains($ua,'curl') ? 'curl' : 'Desconhecido'))))));
}
if (!isset($os) || $os === '') {
    $ua = strtolower($UA);
    $os =
        (str_contains($ua,'windows') ? 'Windows' :
        (str_contains($ua,'macintosh') || str_contains($ua,'mac os') ? 'macOS' :
        (str_contains($ua,'android') ? 'Android' :
        (str_contains($ua,'iphone') || str_contains($ua,'ipad') ? 'iOS' :
        (str_contains($ua,'linux') ? 'Linux' : 'Desconhecido')))));
}

// Debug: se acessar o arquivo direto, mostra JSON
if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'] ?? '')) {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'ip'      => $ip,
        'ua'      => $UA,
        'browser' => $browser ?? '',
        'os'      => $os ?? '',
    ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}
