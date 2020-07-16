<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Gdbots\Pbj\Util\ClassUtil;
use Gdbots\Schemas\Pbjx\Enum\Code;
use Gdbots\Schemas\Pbjx\Enum\HttpCode;
use Gdbots\Schemas\Pbjx\EnvelopeV1;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

class JwtAuthenticator extends AbstractGuardAuthenticator
{
    protected JwtDecoder $decoder;

    public function __construct(JwtDecoder $decoder)
    {
        $this->decoder = $decoder;
    }

    public function supports(Request $request)
    {
        return $request->headers->has('Authorization');
    }

    public function getCredentials(Request $request)
    {
        return $request->headers->get('Authorization');
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        if (null === $credentials) {
            // The token header was empty, authentication fails with HTTP Status
            // Code 401 "Unauthorized"
            return null;
        }

        if (!$userProvider instanceof JwtUserProvider) {
            return null;
        }

        try {
            $jwt = str_ireplace('bearer ', '', $credentials);
            $payload = $this->decoder->decode($jwt);
        } catch (\Throwable $e) {
            throw new BadCredentialsException($e->getMessage(), Code::UNAUTHENTICATED, $e);
        }

        return $userProvider->loadUserByJwt($payload);
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        return true;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $code = $exception->getCode() > 0 ? $exception->getCode() : Code::UNAUTHENTICATED;
        $envelope = EnvelopeV1::create()
            ->set('ok', false)
            ->set('code', $code)
            ->set('http_code', HttpCode::HTTP_UNAUTHORIZED())
            ->set('error_name', ClassUtil::getShortName($exception))
            ->set('error_message', $exception->getMessage());

        return new JsonResponse($envelope->toArray(), HttpCode::HTTP_UNAUTHORIZED, [
            'Content-Type'       => 'application/json',
            'ETag'               => $envelope->get('etag'),
            'x-pbjx-envelope-id' => (string)$envelope->get('envelope_id'),
        ]);
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        $exception = $authException ?: new AuthenticationException('Authentication Required');
        return $this->onAuthenticationFailure($request, $exception);
    }

    public function supportsRememberMe()
    {
        return false;
    }
}
