<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbj\SchemaCurie;
use Gdbots\Pbj\WellKnown\MessageRef;
use Gdbots\Pbj\WellKnown\NodeRef;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Schemas\Iam\Request\GetUserRequestV1;
use Gdbots\Schemas\Ncr\Request\GetNodeRequestV1;
use Symfony\Component\Security\Core\Exception\DisabledException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class JwtUserProvider implements UserProviderInterface
{
    protected Pbjx $pbjx;
    protected string $audience;

    public function __construct(Pbjx $pbjx, string $audience)
    {
        $this->pbjx = $pbjx;
        $this->audience = $audience;
    }

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        throw new UserNotFoundException('Method not implemented');
    }

    public function loadUserByUsername(string $username): UserInterface
    {
        throw new UserNotFoundException('Method not implemented');
    }

    public function getAnonymousUser(): UserInterface
    {
        return new AnonymousUser();
    }

    public function loadUserByJwt(array $payload): UserInterface
    {
        $ctxUserRef = $payload["{$this->audience}ctx_user_ref"] ?? null;
        $ctxTenantId = $payload["{$this->audience}ctx_tenant_id"] ?? null;

        if (!empty($ctxUserRef)) {
            $nodeRef = NodeRef::fromMessageRef(MessageRef::fromString($ctxUserRef));
            return $this->loadByNodeRef($nodeRef, $ctxTenantId);
        }

        if (isset($payload['email']) && filter_var($payload['email'], FILTER_VALIDATE_EMAIL)) {
            return $this->loadByEmail($payload['email'], $ctxTenantId);
        }

        return $this->getAnonymousUser();
    }

    public function refreshUser(UserInterface $user)
    {
        throw new UnsupportedUserException(sprintf('Unsupported user class "%s"', get_class($user)));
    }

    public function supportsClass(string $class): bool
    {
        return $class === User::class;
    }

    protected function loadByNodeRef(NodeRef $nodeRef, ?string $tenantId = null): User
    {
        try {
            $request = GetNodeRequestV1::create()
                ->set('node_ref', $nodeRef)
                ->set('ctx_tenant_id', $tenantId);
            $request->set('ctx_causator_ref', $request->generateMessageRef());
            $response = $this->pbjx->request($request);
            $user = new User($response->get('node'));
            if (!$user->isEnabled()) {
                throw new DisabledException("Your {$nodeRef->getLabel()} account is disabled.");
            }

            return $user;
        } catch (DisabledException $de) {
            throw $de;
        } catch (\Throwable $e) {
            throw new UserNotFoundException('You are not authorized to access this application (1).', $e->getCode(), $e);
        }
    }

    protected function loadByEmail(string $email, ?string $tenantId = null): User
    {
        try {
            $userCurie = SchemaCurie::fromString(
                MessageResolver::findOneUsingMixin('gdbots:iam:mixin:user:v1', false)
            );

            $request = GetUserRequestV1::create()
                ->set('ctx_tenant_id', $tenantId)
                ->set('qname', $userCurie->getQName()->toString())
                ->set('email', $email);
            $request->set('ctx_causator_ref', $request->generateMessageRef());
            $response = $this->pbjx->request($request);
            $user = new User($response->get('node'));
            if (!$user->isEnabled()) {
                throw new DisabledException('Your account is disabled.');
            }

            return $user;
        } catch (DisabledException $de) {
            throw $de;
        } catch (\Throwable $e) {
            throw new UserNotFoundException('You are not authorized to access this application (2).', $e->getCode(), $e);
        }
    }
}
