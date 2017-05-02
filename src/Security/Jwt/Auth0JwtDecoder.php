<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security\Jwt;

use Auth0\SDK\Helpers\Cache\CacheHandler;
use Auth0\SDK\JWTVerifier;

class Auth0JwtDecoder
{
    /** @var JWTVerifier */
    protected $verifier;

    /**
     * @param CacheHandler $cache
     * @param string       $apiIdentifier
     * @param string       $issuer
     */
    public function __construct(CacheHandler $cache, string $apiIdentifier, string $issuer)
    {
        $this->verifier = new JWTVerifier([
            'cache'           => $cache,
            'supported_algs'  => ['RS256'],
            'valid_audiences' => [$apiIdentifier],
            'authorized_iss'  => [$issuer],
        ]);
    }

    /**
     * @param string $jwt
     *
     * @return \stdClass
     *
     * @throws \Exception
     */
    public function decode(string $jwt): \stdClass
    {
        return $this->verifier->verifyAndDecode($jwt);
    }
}
