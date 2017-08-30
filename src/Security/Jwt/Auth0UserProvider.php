<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security\Jwt;

use Gdbots\Bundle\IamBundle\Security\AnonymousUser;
use Gdbots\Bundle\IamBundle\Security\User;
use Gdbots\Pbj\MessageRef;
use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Schemas\Iam\Mixin\GetUserRequest\GetUserRequest;
use Gdbots\Schemas\Iam\Mixin\GetUserRequest\GetUserRequestV1Mixin;
use Gdbots\Schemas\Iam\Mixin\User\UserV1Mixin;
use Gdbots\Schemas\Ncr\NodeRef;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Exception\DisabledException;
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
        $userRefProperty = ($jwt->aud ?: '') . 'ctx_user_ref';
        $ctxUserRef = $jwt->$userRefProperty ?? null;

        if (!empty($ctxUserRef)) {
            return $this->loadByNodeRef(NodeRef::fromMessageRef(MessageRef::fromString($ctxUserRef)));
        }

        if (isset($jwt->email) && filter_var($jwt->email, FILTER_VALIDATE_EMAIL)) {
            return $this->loadByEmail($jwt->email);
        }

        return $this->getAnonymousUser();
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
     * @param NodeRef $nodeRef
     *
     * @return User
     *
     * @throws UsernameNotFoundException
     */
    protected function loadByNodeRef(NodeRef $nodeRef): User
    {
        $symfonyRequest = $this->requestStack->getCurrentRequest();
        $symfonyRequest->attributes->set('iam_bypass_permissions', true);

        $getUserSchema = MessageResolver::findOneUsingMixin(GetUserRequestV1Mixin::create(), 'iam', 'request');

        try {
            /** @var GetUserRequest $request */
            $request = $getUserSchema->createMessage()->set('node_ref', $nodeRef);
            $response = $this->pbjx->request($request);

            $user = new User($response->get('node'));
            if (!$user->isEnabled()) {
                throw new DisabledException('Your account is disabled.');
            }

            return $user;
        } catch (DisabledException $de) {
            throw $de;
        } catch (\Exception $e) {
            throw new UsernameNotFoundException('You are not authorized to access this application.', $e->getCode(), $e);
        } finally {
            $symfonyRequest->attributes->remove('iam_bypass_permissions');
        }
    }

    /**
     * @param string $email
     *
     * @return User
     *
     * @throws UsernameNotFoundException
     */
    protected function loadByEmail(string $email): User
    {
        $symfonyRequest = $this->requestStack->getCurrentRequest();
        $symfonyRequest->attributes->set('iam_bypass_permissions', true);

        $getUserSchema = MessageResolver::findOneUsingMixin(GetUserRequestV1Mixin::create(), 'iam', 'request');
        $userSchema = MessageResolver::findOneUsingMixin(UserV1Mixin::create(), 'iam', 'node');
        $qname = $userSchema->getQName();

        try {
            /** @var GetUserRequest $request */
            $request = $getUserSchema->createMessage()
                ->set('qname', $qname->toString())
                ->set('email', $email);
            $response = $this->pbjx->request($request);

            $user = new User($response->get('node'));
            if (!$user->isEnabled()) {
                throw new DisabledException('Your account is disabled.');
            }

            return $user;
        } catch (DisabledException $de) {
            throw $de;
        } catch (\Exception $e) {
            throw new UsernameNotFoundException('You are not authorized to access this application.', $e->getCode(), $e);
        } finally {
            $symfonyRequest->attributes->remove('iam_bypass_permissions');
        }
    }
}
