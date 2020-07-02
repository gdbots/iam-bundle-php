<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Controller;

use Gdbots\Bundle\IamBundle\Security\User;
use Gdbots\Pbj\Message;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Schemas\Iam\Mixin\Role\Role;
use Gdbots\Schemas\Iam\Mixin\User\UserV1Mixin;
use Gdbots\Schemas\Ncr\Mixin\GetNodeBatchRequest\GetNodeBatchRequest;
use Gdbots\Schemas\Ncr\Mixin\Node\Node;
use Gdbots\Schemas\Ncr\Mixin\Node\NodeV1Mixin;
use Gdbots\Schemas\Ncr\Request\GetNodeBatchRequestV1;
use Gdbots\Schemas\Pbjx\Enum\Code;
use Gdbots\Schemas\Pbjx\Enum\HttpCode;
use Gdbots\Schemas\Pbjx\EnvelopeV1;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;

class Auth0Controller extends AbstractController
{
    protected Pbjx $pbjx;

    public function __construct(Pbjx $pbjx)
    {
        $this->pbjx = $pbjx;
    }

    public function meAction(Request $request): Message
    {
        $user = $this->getUser();
        $envelope = EnvelopeV1::create();

        if (!$user instanceof User) {
            return $envelope
                ->set(EnvelopeV1::CODE_FIELD, Code::UNAUTHENTICATED)
                ->set(EnvelopeV1::HTTP_CODE_FIELD, HttpCode::HTTP_UNAUTHORIZED())
                ->set(EnvelopeV1::ERROR_NAME_FIELD, 'AccessDenied');
        }

        $node = $user->getNode();
        if ($user->isEnabled() && $node->has(UserV1Mixin::ROLES_FIELD)) {
            foreach ($this->getUsersRoles($request, $node) as $nodeRef => $role) {
                $envelope->addToMap(EnvelopeV1::DEREFS_FIELD, $nodeRef, $role);
            }
        }

        return $envelope
            ->set(EnvelopeV1::ETAG_FIELD, $node->get(NodeV1Mixin::ETAG_FIELD))
            ->set('message_ref', $node->generateMessageRef())
            ->set('message', $node);
    }

    /**
     * @param Request $symfonyRequest
     * @param Node    $node
     *
     * @return Role[]
     */
    protected function getUsersRoles(Request $symfonyRequest, Node $node): array
    {
        try {
            $request = $this->createGetRoleBatchRequest($symfonyRequest, $node)
                ->addToSet('node_refs', $node->get('roles', []));
            return $this->pbjx->request($request)->get('nodes', []);
        } catch (\Throwable $e) {
            return [];
        }
    }

    /**
     * @param Request $symfonyRequest
     * @param Node    $node
     *
     * @return GetNodeBatchRequest
     */
    protected function createGetRoleBatchRequest(Request $symfonyRequest, Node $node): GetNodeBatchRequest
    {
        // override if you need to customize the request (e.g. multi-tenant apps)
        return GetNodeBatchRequestV1::create();
    }
}
