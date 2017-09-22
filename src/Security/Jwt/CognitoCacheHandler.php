<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security\Jwt;

use Gdbots\Bundle\IamBundle\Security\Jwt\Helpers\CacheHandler;
use Psr\Cache\CacheItemPoolInterface;

class CognitoCacheHandler implements CacheHandler
{
    /** @var CacheItemPoolInterface */
    protected $cache;

    /** @var string */
    protected $namespace;

    /**
     * @param CacheItemPoolInterface $cache
     * @param string                 $namespace
     */
    public function __construct(CacheItemPoolInterface $cache, string $namespace = 'cognito.jwks.')
    {
        $this->cache = $cache;
        $this->namespace = $namespace;
    }

    /**
     * {@inheritdoc}
     */
    public function get($key)
    {
        return $this->cache->getItem($this->getCacheKey($key))->get();
    }

    /**
     * {@inheritdoc}
     */
    public function set($key, $value)
    {
        $item = $this->cache->getItem($this->getCacheKey($key));
        $item->expiresAfter(null)->expiresAt(null);
        $this->cache->saveDeferred($item->set($value));
    }

    /**
     * {@inheritdoc}
     */
    public function delete($key)
    {
        $this->cache->deleteItem($this->getCacheKey($key));
    }

    /**
     * @param string $key
     *
     * @return string
     */
    protected function getCacheKey(string $key): string
    {
        $key = md5($key);
        return "{$this->namespace}.{$key}";
    }
}
