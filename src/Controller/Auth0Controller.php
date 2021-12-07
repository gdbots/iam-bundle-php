<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Controller;

use Gdbots\Bundle\IamBundle\Security\User;
use Gdbots\Pbj\Message;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Schemas\Ncr\Request\GetNodeBatchRequestV1;
use Gdbots\Schemas\Pbjx\Enum\Code;
use Gdbots\Schemas\Pbjx\Enum\HttpCode;
use Gdbots\Schemas\Pbjx\EnvelopeV1;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class Auth0Controller extends AbstractController
{
    protected Pbjx $pbjx;
    protected TokenStorageInterface $tokenStorage;

    public function __construct(Pbjx $pbjx, TokenStorageInterface $tokenStorage)
    {
        $this->pbjx = $pbjx;
        $this->tokenStorage = $tokenStorage;
    }

    public function meAction(Request $request): Message
    {
        $user = $this->getUser();
        $envelope = EnvelopeV1::create();

        if (!$user instanceof User) {
            return $envelope
                ->set('ok', false)
                ->set('code', Code::UNAUTHENTICATED)
                ->set('http_code', HttpCode::HTTP_UNAUTHORIZED())
                ->set('error_name', 'AuthenticationRequired');
        }

        $node = $user->getNode();
        if ($user->isEnabled() && $node->has('roles')) {
            foreach ($this->getUsersRoles($node) as $nodeRef => $role) {
                $envelope->addToMap('derefs', $nodeRef, $role);
            }
        }

        return $envelope
            ->set('etag', $node->get('etag'))
            ->set('message_ref', $node->generateMessageRef())
            ->set('message', $node);
    }

    protected function getUser(): ?UserInterface
    {
        if (null === $token = $this->tokenStorage->getToken()) {
            return null;
        }

        return $token->getUser();
    }

    /**
     * @param Message $node
     *
     * @return Message[]
     */
    protected function getUsersRoles(Message $node): array
    {
        try {
            $request = GetNodeBatchRequestV1::create()
                ->addToSet('node_refs', $node->get('roles', []));
            $request->set('ctx_causator_ref', $request->generateMessageRef());
            return $this->pbjx->request($request)->get('nodes', []);
        } catch (\Throwable $e) {
            return [];
        }
    }
}
