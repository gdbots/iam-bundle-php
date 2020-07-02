<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Auth0\SDK\Helpers\Cache\CacheHandler;
use Auth0\SDK\JWTVerifier;

final class Auth0JwtDecoder implements JwtDecoder
{
    /** @var JWTVerifier */
    private $verifier;

    /**
     * @param CacheHandler $cache
     * @param string       $apiIdentifier
     * @param string       $authorizedIssuer
     * @param string       $signingKey Required for enriching jwt access token with ctx_user_ref in rules/hoooks.
     */
    public function __construct(
        CacheHandler $cache,
        string $apiIdentifier,
        string $authorizedIssuer,
        string $signingKey
    ) {
        $this->verifier = new JWTVerifier([
            'cache'                 => $cache,
            'supported_algs'        => ['RS256', 'HS256'],
            'valid_audiences'       => [$apiIdentifier],
            'authorized_iss'        => [$authorizedIssuer],
            'client_secret'         => $signingKey,
            'secret_base64_encoded' => false,
        ]);
    }

    /**
     * @param string $jwt
     *
     * @return \stdClass
     *
     * @throws \Throwable
     */
    public function decode(string $jwt): \stdClass
    {
        $result = $this->verifier->verifyAndDecode($jwt);
        $result->is_jwt = true;
        return $result;
    }
}
