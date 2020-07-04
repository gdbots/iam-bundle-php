<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Auth0\SDK\Exception\InvalidTokenException;
use Auth0\SDK\Helpers\JWKFetcher;
use Auth0\SDK\Helpers\Tokens\AsymmetricVerifier;
use Auth0\SDK\Helpers\Tokens\IdTokenVerifier;
use Auth0\SDK\Helpers\Tokens\SymmetricVerifier;
use Auth0\SDK\Helpers\Tokens\TokenVerifier;
use Gdbots\Schemas\Pbjx\Enum\Code;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Cache\Psr16Cache;

class Auth0JwtDecoder implements JwtDecoder
{
    protected JWKFetcher $jwkFetcher;
    protected string $audience;
    protected string $issuer;

    /**
     * Signing keys used for verifying an HS256 jwt
     * which is only used in an Auth0 rule that enriches
     * the final token, which is signed using RS256.
     *
     * @var string[]
     */
    protected array $keys;

    public function __construct(CacheItemPoolInterface $cache, string $audience, string $issuer, array $keys)
    {
        $this->jwkFetcher = new JWKFetcher(new Psr16Cache($cache));
        $this->audience = $audience;
        $this->issuer = $issuer;
        $this->keys = array_unique($keys);
    }

    public function decode(string $jwt): array
    {
        $header = json_decode(base64_decode(explode('.', $jwt, 2)[0]), true) ?: [];
        $alg = $header['alg'] ?? 'unknown';

        switch ($alg) {
            case 'RS256':
                return $this->decodeRS256($jwt);

            case 'HS256':
                return $this->decodeHS256($jwt);

            default:
                throw new InvalidTokenException(sprintf('Unsupported alg [%s] provided.', $alg));
        }
    }

    protected function decodeRS256(string $jwt): array
    {
        $jwks = $this->jwkFetcher->getKeys($this->issuer . '.well-known/jwks.json');
        $signatureVerifier = new AsymmetricVerifier($jwks);
        $tokenVerifier = new IdTokenVerifier($this->issuer, $this->audience, $signatureVerifier);
        return $tokenVerifier->verify($jwt);
    }

    protected function decodeHS256(string $jwt): array
    {
        $exception = null;
        foreach ($this->keys as $key) {
            try {
                $signatureVerifier = new SymmetricVerifier($key);
                $tokenVerifier = new TokenVerifier($this->issuer, $this->audience, $signatureVerifier);
                return $tokenVerifier->verify($jwt);
            } catch (\Throwable $e) {
                $message = str_replace($key, '***', $e->getMessage());
                $exception = new InvalidTokenException($message, Code::UNAUTHENTICATED, $e);
            }
        }

        throw $exception ?: new InvalidTokenException('Unable to verify token.');
    }
}
