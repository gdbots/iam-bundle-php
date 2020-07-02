<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbj\SchemaCurie;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Schemas\Iam\Mixin\User\UserV1Mixin;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Exception\DisabledException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;

final class Auth0JwtUserProvider implements JwtUserProvider
{
    private Pbjx $pbjx;
    private RequestStack $requestStack;
    private string $apiIdentifier;

    /**
     * @param Pbjx         $pbjx
     * @param RequestStack $requestStack
     * @param string       $apiIdentifier
     */
    public function __construct(Pbjx $pbjx, RequestStack $requestStack, string $apiIdentifier)
    {
        $this->pbjx = $pbjx;
        $this->requestStack = $requestStack;
        $this->apiIdentifier = $apiIdentifier;
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
        $userRefProperty = "{$this->apiIdentifier}ctx_user_ref";
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
    private function loadByNodeRef(NodeRef $nodeRef): User
    {
        $symfonyRequest = $this->requestStack->getCurrentRequest();
        $symfonyRequest->attributes->set('iam_bypass_permissions', true);
        $userCurie = UserV1Mixin::findOne()->getCurie();

        try {
            /** @var Request $request */
            if ($nodeRef->getQName()->toString() === $userCurie->getQName()->toString()) {
                $request = GetUserRequestV1Mixin::findOne()->createMessage();
            } else {
                /** @var Request $class */
                $class = MessageResolver::resolveCurie(SchemaCurie::fromString(
                    "{$userCurie->getVendor()}:{$userCurie->getPackage()}:request:get-app-request"
                ));
                $request = $class::create();
            }

            $request->set('node_ref', $nodeRef);
            $response = $this->pbjx->request($request);

            $user = new User($response->get('node'));
            if (!$user->isEnabled()) {
                throw new DisabledException("Your {$nodeRef->getLabel()} account is disabled.");
            }

            return $user;
        } catch (DisabledException $de) {
            throw $de;
        } catch (\Throwable $e) {
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
    private function loadByEmail(string $email): User
    {
        $symfonyRequest = $this->requestStack->getCurrentRequest();
        $symfonyRequest->attributes->set('iam_bypass_permissions', true);

        try {
            /** @var GetUserRequest $request */
            $request = GetUserRequestV1Mixin::findOne()->createMessage()
                ->set('qname', UserV1Mixin::findOne()->getQName()->toString())
                ->set('email', $email);
            $response = $this->pbjx->request($request);

            $user = new User($response->get('node'));
            if (!$user->isEnabled()) {
                throw new DisabledException('Your account is disabled.');
            }

            return $user;
        } catch (DisabledException $de) {
            throw $de;
        } catch (\Throwable $e) {
            throw new UsernameNotFoundException('You are not authorized to access this application.', $e->getCode(), $e);
        } finally {
            $symfonyRequest->attributes->remove('iam_bypass_permissions');
        }
    }
}
