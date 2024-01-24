<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Auth0\SDK\Auth0;
use Auth0\SDK\Configuration\SdkConfiguration;
use Auth0\SDK\Exception\InvalidTokenException;
use Auth0\SDK\Token;
use Gdbots\Schemas\Pbjx\Enum\Code;
use Psr\Cache\CacheItemPoolInterface;

class Auth0JwtDecoder implements JwtDecoder
{
    /**
     * Signing keys used for verifying an HS256 jwt
     * which is only used in an Auth0 rule that enriches
     * the final token, which is signed using RS256.
     *
     * @var string[]
     */
    protected array $keys;

    protected Auth0 $auth0;

    public function __construct(CacheItemPoolInterface $cache, string $audience, string $domain, array $keys)
    {
        $this->auth0 = new Auth0([
            'strategy' => SdkConfiguration::STRATEGY_API,
            'audience' => [$audience],
            'domain'   => $domain,
        ]);

        $this->auth0->configuration()->setTokenCache($cache);
        $this->keys = array_unique($keys);
    }

    public function decode(string $jwt): array
    {
        $header = json_decode(base64_decode(explode('.', $jwt, 2)[0]), true) ?: [];
        $alg = $header['alg'] ?? 'unknown';

        switch ($alg) {
            case Token::ALGO_RS256:
                $this->auth0->configuration()->setTokenAlgorithm(Token::ALGO_RS256);
                break;

            case Token::ALGO_HS256:
                $this->auth0->configuration()->setTokenAlgorithm(Token::ALGO_HS256);
                break;

            default:
                throw new InvalidTokenException('Invalid token algorithm.');
        }

        $exception = null;
        foreach ($this->keys as $key) {
            $this->auth0->configuration()->setClientSecret($key);
            try {
                $token = $this->auth0->decode(token: $jwt, tokenType: \Auth0\SDK\Token::TYPE_ACCESS_TOKEN);
                return $token->toArray();
            } catch (\Throwable $e) {
                $message = str_replace($key, '***', $e->getMessage());
                $exception = new InvalidTokenException($message, Code::UNAUTHENTICATED->value, $e);
            }
        }

        throw $exception ?: new InvalidTokenException('Unable to verify token.');
    }
}
