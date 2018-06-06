<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Controller;

use Gdbots\Bundle\IamBundle\Security\User;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Schemas\Iam\Mixin\Role\Role;
use Gdbots\Schemas\Ncr\Mixin\GetNodeBatchRequest\GetNodeBatchRequest;
use Gdbots\Schemas\Ncr\Mixin\Node\Node;
use Gdbots\Schemas\Ncr\Request\GetNodeBatchRequestV1;
use Gdbots\Schemas\Pbjx\Enum\Code;
use Gdbots\Schemas\Pbjx\Enum\HttpCode;
use Gdbots\Schemas\Pbjx\Envelope;
use Gdbots\Schemas\Pbjx\EnvelopeV1;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;

class Auth0Controller extends Controller
{
    /** @var Pbjx */
    protected $pbjx;

    /**
     * @param Pbjx $pbjx
     */
    public function __construct(Pbjx $pbjx)
    {
        $this->pbjx = $pbjx;
    }

    /**
     * @param Request $request
     *
     * @return Envelope
     */
    public function meAction(Request $request): Envelope
    {
        $user = $this->getUser();
        $envelope = EnvelopeV1::create();

        if (!$user instanceof User) {
            return $envelope
                ->set('code', Code::UNAUTHENTICATED)
                ->set('http_code', HttpCode::HTTP_UNAUTHORIZED())
                ->set('error_name', 'AccessDenied');
        }

        $node = $user->getUserNode();
        if ($user->isEnabled() && $node->has('roles')) {
            foreach ($this->getUsersRoles($request, $node) as $nodeRef => $role) {
                $envelope->addToMap('derefs', $nodeRef, $role);
            }
        }

        return $envelope
            ->set('etag', $node->get('etag'))
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
