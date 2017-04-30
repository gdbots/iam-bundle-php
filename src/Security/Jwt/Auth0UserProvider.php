<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security\Jwt;

use Gdbots\Bundle\IamBundle\Security\AnonymousUser;
use Gdbots\Bundle\IamBundle\Security\User;
use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Schemas\Iam\Mixin\GetUserRequest\GetUserRequest;
use Gdbots\Schemas\Iam\Mixin\GetUserRequest\GetUserRequestV1Mixin;
use Gdbots\Schemas\Iam\Mixin\User\UserV1Mixin;
use Gdbots\Schemas\Ncr\NodeRef;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;

class Auth0UserProvider implements JwtUserProvider
{
    /** @var Pbjx */
    protected $pbjx;

    /** @var RequestStack */
    protected $requestStack;

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
        throw new UsernameNotFoundException('Method not implemented');
    }

    /**
     * {@inheritdoc}
     */
    public function getAnonymousUser(): UserInterface
    {
        return new AnonymousUser();
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByJwt(\stdClass $jwt): UserInterface
    {
        return $this->loadByIdOrEmail('8cfcbd93-4a5d-418f-b73c-c7c394ec9e6a');
    }

    /**
     * {@inheritdoc}
     */
    public function refreshUser(UserInterface $user)
    {
        throw new UnsupportedUserException(sprintf('Unsupported user class "%s"', get_class($user)));
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
