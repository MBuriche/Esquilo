<?php
/**
 * Configurações para o backend persistente utilizado pelo rate limiter.
 *
 * - redis_url: URL de conexão com o servidor Redis.
 *              Exemplo: redis://localhost:6379
 */
define('CACHE_CONFIG', [
    'redis_url' => getenv('REDIS_URL') ?: 'redis://127.0.0.1:6379',
]);