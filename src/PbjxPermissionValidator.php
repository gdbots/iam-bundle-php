<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle;

use Gdbots\Bundle\PbjxBundle\Validator\PermissionValidatorTrait;
use Gdbots\Pbj\Message;
use Gdbots\Pbj\WellKnown\NodeRef;
use Gdbots\Pbjx\DependencyInjection\PbjxValidator;
use Gdbots\Pbjx\Event\PbjxEvent;
use Gdbots\Pbjx\EventSubscriber;
use Gdbots\Schemas\Ncr\Mixin\CreateNode\CreateNodeV1Mixin;
use Gdbots\Schemas\Ncr\Mixin\DeleteNode\DeleteNodeV1Mixin;
use Gdbots\Schemas\Ncr\Mixin\ExpireNode\ExpireNodeV1Mixin;
use Gdbots\Schemas\Ncr\Mixin\GetNodeBatchRequest\GetNodeBatchRequestV1Mixin;
use Gdbots\Schemas\Ncr\Mixin\GetNodeRequest\GetNodeRequestV1Mixin;
use Gdbots\Schemas\Ncr\Mixin\LockNode\LockNodeV1Mixin;
use Gdbots\Schemas\Ncr\Mixin\MarkNodeAsDraft\MarkNodeAsDraftV1Mixin;
use Gdbots\Schemas\Ncr\Mixin\MarkNodeAsPending\MarkNodeAsPendingV1Mixin;
use Gdbots\Schemas\Ncr\Mixin\PatchNode\PatchNodeV1Mixin;
use Gdbots\Schemas\Ncr\Mixin\PatchNodes\PatchNodesV1Mixin;
use Gdbots\Schemas\Ncr\Mixin\PublishNode\PublishNodeV1Mixin;
use Gdbots\Schemas\Ncr\Mixin\RenameNode\RenameNodeV1Mixin;
use Gdbots\Schemas\Ncr\Mixin\UnlockNode\UnlockNodeV1Mixin;
use Gdbots\Schemas\Ncr\Mixin\UnpublishNode\UnpublishNodeV1Mixin;
use Gdbots\Schemas\Ncr\Mixin\UpdateNode\UpdateNodeV1Mixin;
use Gdbots\Schemas\Ncr\Request\GetNodeHistoryRequestV1;
use Gdbots\Schemas\Pbjx\Mixin\Event\EventV1Mixin;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;

class PbjxPermissionValidator implements EventSubscriber, PbjxValidator
{
    protected const MIXINS_TO_ACTION = [
        CreateNodeV1Mixin::SCHEMA_CURIE          => 'create',
        DeleteNodeV1Mixin::SCHEMA_CURIE          => 'delete',
        ExpireNodeV1Mixin::SCHEMA_CURIE          => 'expire',
        GetNodeRequestV1Mixin::SCHEMA_CURIE      => 'get',
        GetNodeBatchRequestV1Mixin::SCHEMA_CURIE => 'get',
        LockNodeV1Mixin::SCHEMA_CURIE            => 'lock',
        MarkNodeAsDraftV1Mixin::SCHEMA_CURIE     => 'mark-as-draft',
        MarkNodeAsPendingV1Mixin::SCHEMA_CURIE   => 'mark-as-pending',
        PatchNodeV1Mixin::SCHEMA_CURIE           => 'patch',
        PatchNodesV1Mixin::SCHEMA_CURIE          => 'patch',
        PublishNodeV1Mixin::SCHEMA_CURIE         => 'publish',
        RenameNodeV1Mixin::SCHEMA_CURIE          => 'rename',
        UnlockNodeV1Mixin::SCHEMA_CURIE          => 'unlock',
        UnpublishNodeV1Mixin::SCHEMA_CURIE       => 'unpublish',
        UpdateNodeV1Mixin::SCHEMA_CURIE          => 'update',
    ];

    use PermissionValidatorTrait;

    protected AuthorizationCheckerInterface $checker;

    public function __construct(RequestStack $requestStack, AuthorizationCheckerInterface $checker)
    {
        $this->requestStack = $requestStack;
        $this->checker = $checker;
    }

    protected function checkPermission(PbjxEvent $pbjxEvent, Message $message, Request $request): void
    {
        $schema = $message::schema();
        $permission = $schema->getCurie()->toString();
        if ($schema->hasMixin(EventV1Mixin::SCHEMA_CURIE) || !$this->checker->isGranted($permission, $message)) {
            throw new AccessDeniedHttpException("You do not have [{$permission}] permission.");
        }

        if ($schema->hasMixin(GetNodeBatchRequestV1Mixin::SCHEMA_CURIE)) {
            $this->checkGetNodeBatchRequest($pbjxEvent, $message, $request);
            return;
        }

        $this->checkNodeRefs($pbjxEvent, $message, $request);
    }

    protected function checkGetNodeBatchRequest(PbjxEvent $pbjxEvent, Message $message, Request $request): void
    {
        /** @var NodeRef[] $nodeRefs */
        $nodeRefs = $message->get(GetNodeBatchRequestV1Mixin::NODE_REFS_FIELD, []);
        $checked = [];
        $remove = [];

        foreach ($nodeRefs as $nodeRef) {
            $permission = "{$nodeRef->getQName()}:get";
            if (!isset($checked[$permission])) {
                $checked[$permission] = $this->checker->isGranted($permission, $message);
            }

            if (!$checked[$permission]) {
                $remove[] = $nodeRef;
            }
        }

        if (empty($remove)) {
            return;
        }

        $message->removeFromSet(GetNodeBatchRequestV1Mixin::NODE_REFS_FIELD, $remove);
    }

    protected function checkNodeRefs(PbjxEvent $pbjxEvent, Message $message, Request $request): void
    {
        $nodeRefs = $this->extractNodeRefs($message);
        if (empty($nodeRefs)) {
            return;
        }

        $schema = $message::schema();
        $id = $message::schema()->getId();
        $action = null;

        if ('gdbots' === $id->getVendor() && 'ncr' === $id->getPackage() && 'command' === $id->getCategory()) {
            $action = str_replace('-node', '', $id->getMessage());
        } elseif ($id->getCurie()->toString() === GetNodeHistoryRequestV1::SCHEMA_CURIE) {
            $action = 'get';
        } else {
            foreach (static::MIXINS_TO_ACTION as $mixin => $a) {
                if ($schema->hasMixin($mixin)) {
                    $action = $a;
                    break;
                }
            }
        }

        if (null === $action) {
            return;
        }

        foreach ($nodeRefs as $nodeRef) {
            $permission = "{$nodeRef->getQName()}:{$action}";
            if (!$this->checker->isGranted($permission, $message)) {
                throw new AccessDeniedHttpException("You do not have [{$permission}] permission.");
            }
        }
    }

    /**
     * @param Message $message
     *
     * @return NodeRef[]
     */
    protected function extractNodeRefs(Message $message): array
    {
        $refs = $message->get('node_refs', []);

        if ($message->has('node_ref')) {
            $refs[] = $message->get('node_ref');
        }

        if ($message->has('node')) {
            $refs[] = NodeRef::fromNode($message->get('node'));
        }

        return $refs;
    }
}
