<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security\Jwt;

use Gdbots\Common\Util\ClassUtils;
use Gdbots\Schemas\Pbjx\Enum\Code;
use Gdbots\Schemas\Pbjx\Enum\HttpCode;
use Gdbots\Schemas\Pbjx\EnvelopeV1;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\InvalidArgumentException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\SimplePreAuthenticatorInterface;

class Auth0JwtAuthenticator implements SimplePreAuthenticatorInterface, AuthenticationFailureHandlerInterface
{
    /** @var Auth0JwtDecoder */
    protected $decoder;

    /**
     * @param Auth0JwtDecoder $decoder
     */
    public function __construct(Auth0JwtDecoder $decoder)
    {
        $this->decoder = $decoder;
    }

    /**
     * {@inheritdoc}
     */
    public function createToken(Request $request, $providerKey)
    {
        $header = $request->headers->get('Authorization');

        if (null === $header) {
            return new PreAuthenticatedToken('anon.', null, $providerKey);
        }

        $jwt = str_replace('Bearer ', '', $header);

        try {
            $token = $this->decoder->decode($jwt);
        } catch (\Exception $e) {
            throw new BadCredentialsException('Invalid token.');
        }

        return new PreAuthenticatedToken('anon.', $token, $providerKey);
    }

    /**
     * {@inheritdoc}
     */
    public function authenticateToken(TokenInterface $token, UserProviderInterface $userProvider, $providerKey)
    {
        if (!$userProvider instanceof JwtUserProvider) {
            throw new InvalidArgumentException('$userProvider must implement Gdbots\Bundle\IamBundle\Security\Jwt\JwtUserProvider');
        }

        if (null === $token->getCredentials()) {
            $user = $userProvider->getAnonymousUser();
        } else {
            try {
                $user = $userProvider->loadUserByJwt($token->getCredentials());
            } catch (\Exception $e) {
                throw new AuthenticationException($e->getMessage());
            }
        }

        return new PreAuthenticatedToken($user, $token, $providerKey, $user->getRoles());
    }

    /**
     * {@inheritdoc}
     */
    public function supportsToken(TokenInterface $token, $providerKey)
    {
        return $token instanceof PreAuthenticatedToken && $token->getProviderKey() === $providerKey;
    }

    /**
     * {@inheritdoc}
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $envelope = EnvelopeV1::create()
            ->set('ok', false)
            ->set('code', Code::PERMISSION_DENIED)
            ->set('http_code', HttpCode::HTTP_FORBIDDEN())
            ->set('error_name', ClassUtils::getShortName($exception))
            ->set('error_message', $exception->getMessage());

        return new JsonResponse($envelope->toArray(), HttpCode::HTTP_FORBIDDEN, [
            'Content-Type'       => 'application/json',
            'ETag'               => $envelope->get('etag'),
            'x-pbjx-envelope-id' => (string)$envelope->get('envelope_id'),
        ]);
    }
}
