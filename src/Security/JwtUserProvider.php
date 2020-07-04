<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbj\SchemaCurie;
use Gdbots\Pbj\WellKnown\MessageRef;
use Gdbots\Pbj\WellKnown\NodeRef;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Schemas\Iam\Mixin\User\UserV1Mixin;
use Gdbots\Schemas\Iam\Request\GetUserRequestV1;
use Gdbots\Schemas\Ncr\Request\GetNodeRequestV1;
use Gdbots\Schemas\Ncr\Request\GetNodeResponseV1;
use Symfony\Component\Security\Core\Exception\DisabledException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
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

    public function loadUserByUsername(string $username)
    {
        throw new UsernameNotFoundException('Method not implemented');
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

    public function supportsClass(string $class)
    {
        return $class === User::class;
    }

    protected function loadByNodeRef(NodeRef $nodeRef, ?string $tenantId = null): User
    {
        try {
            $request = GetNodeRequestV1::create()
                ->set(GetNodeRequestV1::NODE_REF_FIELD, $nodeRef)
                ->set(GetNodeRequestV1::CTX_TENANT_ID_FIELD, $tenantId);
            $request->set(GetNodeRequestV1::CTX_CAUSATOR_REF_FIELD, $request->generateMessageRef());
            $response = $this->pbjx->request($request);
            $user = new User($response->get(GetNodeResponseV1::NODE_FIELD));
            if (!$user->isEnabled()) {
                throw new DisabledException("Your {$nodeRef->getLabel()} account is disabled.");
            }

            return $user;
        } catch (DisabledException $de) {
            throw $de;
        } catch (\Throwable $e) {
            throw new UsernameNotFoundException('You are not authorized to access this application (1).', $e->getCode(), $e);
        }
    }

    protected function loadByEmail(string $email, ?string $tenantId = null): User
    {
        try {
            $userCurie = SchemaCurie::fromString(
                MessageResolver::findOneUsingMixin(UserV1Mixin::SCHEMA_CURIE_MAJOR, false)
            );

            $request = GetUserRequestV1::create()
                ->set(GetUserRequestV1::CTX_TENANT_ID_FIELD, $tenantId)
                ->set(GetUserRequestV1::QNAME_FIELD, $userCurie->getQName()->toString())
                ->set(GetUserRequestV1::EMAIL_FIELD, $email);
            $request->set(GetUserRequestV1::CTX_CAUSATOR_REF_FIELD, $request->generateMessageRef());
            $response = $this->pbjx->request($request);
            $user = new User($response->get(GetNodeResponseV1::NODE_FIELD));
            if (!$user->isEnabled()) {
                throw new DisabledException('Your account is disabled.');
            }

            return $user;
        } catch (DisabledException $de) {
            throw $de;
        } catch (\Throwable $e) {
            throw new UsernameNotFoundException('You are not authorized to access this application (2).', $e->getCode(), $e);
        }
    }
}
