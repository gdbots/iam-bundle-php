<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Gdbots\Pbj\Util\ClassUtil;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Schemas\Pbjx\Enum\Code;
use Gdbots\Schemas\Pbjx\Enum\HttpCode;
use Gdbots\Schemas\Pbjx\EnvelopeV1;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

class JwtAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    protected JwtDecoder $decoder;
    protected JwtUserProvider $userProvider;

    public function __construct(JwtDecoder $decoder, JwtUserProvider $userProvider)
    {
        $this->decoder = $decoder;
        $this->userProvider = $userProvider;
    }

    public function start(Request $request, AuthenticationException $authException = null): Response
    {
        $exception = $authException ?: new AuthenticationException('Authentication Required');
        return $this->onAuthenticationFailure($request, $exception);
    }

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('Authorization');
    }

    public function authenticate(Request $request): Passport
    {
        $credentials = $request->headers->get('Authorization');
        return new SelfValidatingPassport(new UserBadge($credentials, function ($credentials) {
            try {
                $jwt = str_ireplace('bearer ', '', $credentials);
                $payload = $this->decoder->decode($jwt);
            } catch (\Throwable $e) {
                throw new BadCredentialsException($e->getMessage(), Code::UNAUTHENTICATED->value, $e);
            }

            return $this->userProvider->loadUserByJwt($payload);
        }));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $code = $exception->getCode() > 0 ? $exception->getCode() : Code::UNAUTHENTICATED->value;
        $envelope = EnvelopeV1::create()
            ->set('ok', false)
            ->set('code', $code)
            ->set('http_code', HttpCode::HTTP_UNAUTHORIZED)
            ->set('error_name', ClassUtil::getShortName($exception))
            ->set('error_message', $exception->getMessage());

        return new JsonResponse($envelope->toArray(), $envelope->fget('http_code'), [
            'Content-Type'       => 'application/json',
            'ETag'               => $envelope->fget('etag'),
            'x-pbjx-envelope-id' => $envelope->fget('envelope_id'),
        ]);
    }
}
