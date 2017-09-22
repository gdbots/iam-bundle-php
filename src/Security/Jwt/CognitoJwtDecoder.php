<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security\Jwt;

use Auth0\SDK\Helpers\Cache\CacheHandler;
use Auth0\SDK\JWTVerifier;
use DateTime;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use Jose\Factory\JWKFactory;
use Jose\Loader;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class CognitoJwtDecoder
{
    /** @var JWTVerifier */
    protected $verifier;

    /** @var string */
    protected $authorizedIssuer;

    /** @var string */
    protected $clientId;

    /** @var string */
    protected $poolId;

    /**
     * When checking nbf, iat or expiration times,
     * we want to provide some extra leeway time to
     * account for clock skew.
     */
    public static $leeway = 0;

    /**
     * Allow the current timestamp to be specified.
     * Useful for fixing a value within unit testing.
     *
     * Will default to PHP time() value if null.
     */
    public static $timestamp = null;

    /**
     * @param CacheHandler $cache
     * @param string       $apiIdentifier
     * @param string       $authorizedIssuer
     * @param string       $clientId
     * @param string       $poolId
     */
    public function __construct(
        CacheHandler $cache,
        string $apiIdentifier,
        string $authorizedIssuer,
        string $clientId,
        string $poolId
    )
    {
        $this->authorizedIssuer = $authorizedIssuer;
        $this->clientId = $clientId;
        $this->poolId = $poolId;
        $this->verifier = new JWTVerifier([
            'cache' => $cache,
            'supported_algs' => ['RS256', 'HS256'],
            'valid_audiences' => [$apiIdentifier],
            'authorized_iss' => [$authorizedIssuer],
            'client_secret' => 'sosecret',
            'secret_base64_encoded' => false,
        ]);
    }

    /**
     * Decode a string with URL-safe Base64.
     *
     * @param string $input A Base64 encoded string
     *
     * @return string A decoded string
     */
    public static function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
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
        $tks = explode('.', $jwt);

        $encodedPayload = $tks[1];
        $payload = json_decode($this->urlsafeB64Decode($encodedPayload));

        if (
            $payload->iss !== $this->authorizedIssuer
            || $payload->client_id !== $this->clientId
            || $payload->token_use !== "access"
        ) {
            throw new AuthenticationException('Invalid token.');
        }

        $timestamp = is_null(static::$timestamp) ? time() : static::$timestamp;

        // Check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't
        // correctly used the nbf claim).
        if (isset($payload->iat) && $payload->iat > ($timestamp + static::$leeway)) {
            throw new AuthenticationException(
                'Cannot handle token prior to ' . date(DateTime::ISO8601, $payload->iat)
            );
        }

        // Check if this token has expired.
        if (isset($payload->exp) && ($timestamp - static::$leeway) >= $payload->exp) {
            throw new AuthenticationException('Expired token');
        }

        $client = new Client([
            'base_uri' => $this->authorizedIssuer
        ]);

        try {
            $response = $client->request('GET', $this->poolId . '/.well-known/jwks.json');
        } catch (RequestException $e) {
            throw $e;
        }

        $jwkSet = JWKFactory::createFromValues(json_decode($response->getBody()->getContents(), true));

        $loader = new Loader();

        try {
            $loader->loadAndVerifySignatureUsingKeySet(
                $jwt,
                $jwkSet,
                ['RS256'],
                $signature_index
            );
        } catch(\Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }

        // if we got this far without an exception, then the jwt is valid and trusted

        //throw new AuthenticationException(json_encode($payload));
        return $payload;
    }
}
