<?php
declare(strict_types = 1);

namespace Gdbots\Bundle\IamBundle\Security\OAuth;

use Gdbots\Bundle\IamBundle\Security\User;
use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Schemas\Iam\Mixin\GetUserRequest\GetUserRequest;
use Gdbots\Schemas\Iam\Mixin\GetUserRequest\GetUserRequestV1Mixin;
use Gdbots\Schemas\Iam\Mixin\User\UserV1Mixin;
use Gdbots\Schemas\Ncr\NodeRef;
use HWI\Bundle\OAuthBundle\OAuth\Response\UserResponseInterface;
use HWI\Bundle\OAuthBundle\Security\Core\User\OAuthAwareUserProviderInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

final class Auth0UserProvider implements UserProviderInterface, OAuthAwareUserProviderInterface
{
    /** @var Pbjx */
    private $pbjx;

    /** @var RequestStack */
    private $requestStack;

    /**
     * @param Pbjx         $pbjx
     * @param RequestStack $requestStack
     */
    public function __construct(Pbjx $pbjx, RequestStack $requestStack)
    {
        $this->pbjx = $pbjx;
        $this->requestStack = $requestStack;
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByUsername($username)
    {
        return $this->loadByIdOrEmail($username);
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByOAuthUserResponse(UserResponseInterface $response)
    {
        $auth0 = $response->getResponse();

        if (!isset($auth0['user_id']) || !isset($auth0['email']) || !isset($auth0['email_verified'])) {
            throw new UsernameNotFoundException('You are not authorized to access this application (1).');
        }

        if (true !== (bool)$auth0['email_verified']) {
            throw new UsernameNotFoundException('You are not authorized to access this application (2).');
        }

        return $this->loadByIdOrEmail($auth0['email'], true);
    }

    /**
     * {@inheritdoc}
     */
    public function refreshUser(UserInterface $user)
    {
        if (!$this->supportsClass(get_class($user))) {
            throw new UnsupportedUserException(sprintf('Unsupported user class "%s"', get_class($user)));
        }

        return $this->loadUserByUsername($user->getUsername());
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass($class)
    {
        return $class === User::class;
    }

    /**
     * @param string $idOrEmail
     * @param bool   $byEmail
     *
     * @return User
     *
     * @throws UsernameNotFoundException
     */
    protected function loadByIdOrEmail(string $idOrEmail, bool $byEmail = false): User
    {
        $symfonyRequest = $this->requestStack->getCurrentRequest();
        $symfonyRequest->attributes->set('_authenticating_user', true);

        $getUserSchema = MessageResolver::findOneUsingMixin(GetUserRequestV1Mixin::create(), 'iam', 'request');
        $userSchema = MessageResolver::findOneUsingMixin(UserV1Mixin::create(), 'iam', 'node');
        $qname = $userSchema->getQName();

        if ($byEmail) {
            $field = 'email';
        } else {
            $field = 'node_ref';
            $idOrEmail = new NodeRef($qname, $idOrEmail);
        }

        try {
            /** @var GetUserRequest $request */
            $request = $getUserSchema->createMessage()
                // when authorizing from auth0 flow, do a consistent read
                ->set('consistent_read', $byEmail)
                ->set('qname', $qname->toString())
                ->set($field, $idOrEmail);
            $response = $this->pbjx->request($request);

            return new User($response->get('node'));
        } catch (\Exception $e) {
            throw new UsernameNotFoundException('You are not authorized to access this application (3).',
                $e->getCode(),
                $e
            );
        } finally {
            $symfonyRequest->attributes->remove('_authenticating_user');
        }
    }
}
