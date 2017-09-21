<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security\Jwt;

use Auth0\SDK\Helpers\Cache\CacheHandler;
use Auth0\SDK\JWTVerifier;

class CognitoJwtDecoder
{
    /** @var JWTVerifier */
    protected $verifier;

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
     * @throws \Exception
     */
    public function decode(string $jwt): \stdClass
    {
        $result = $this->verifier->verifyAndDecode($jwt);
        $result->is_jwt = true;
        return $result;
    }
}
