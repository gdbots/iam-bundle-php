<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security\Jwt;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;
use Symfony\Component\Security\Core\Exception\InvalidArgumentException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\Authentication\SimplePreAuthenticatorInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;

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
        } catch (\UnexpectedValueException $ex) {
            throw new BadCredentialsException('Invalid token');
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
            $user = $userProvider->loadUserByJwt($token->getCredentials());
            if (!$user) {
                throw new AuthenticationException('Invalid JWT.');
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
        return new Response("Authentication Failed: {$exception->getMessage()}", 403);
    }
}
