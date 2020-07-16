<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle;

use Gdbots\Bundle\PbjxBundle\Validator\PermissionValidatorTrait;
use Gdbots\Pbj\Message;
use Gdbots\Pbj\WellKnown\NodeRef;
use Gdbots\Pbjx\DependencyInjection\PbjxValidator;
use Gdbots\Pbjx\Event\PbjxEvent;
use Gdbots\Pbjx\EventSubscriber;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;

class PbjxPermissionValidator implements EventSubscriber, PbjxValidator
{
    protected const MIXINS_TO_ACTION = [
        'gdbots:ncr:mixin:create-node'            => 'create',
        'gdbots:ncr:mixin:delete-node'            => 'delete',
        'gdbots:ncr:mixin:expire-node'            => 'expire',
        'gdbots:ncr:mixin:get-node-request'       => 'get',
        'gdbots:ncr:mixin:get-node-batch-request' => 'get',
        'gdbots:ncr:mixin:lock-node'              => 'lock',
        'gdbots:ncr:mixin:mark-node-as-draft'     => 'mark-as-draft',
        'gdbots:ncr:mixin:mark-node-as-pending'   => 'mark-as-pending',
        'gdbots:ncr:mixin:patch-node'             => 'patch',
        'gdbots:ncr:mixin:patch-nodes'            => 'patch',
        'gdbots:ncr:mixin:publish-node'           => 'publish',
        'gdbots:ncr:mixin:rename-node'            => 'rename',
        'gdbots:ncr:mixin:unlock-node'            => 'unlock',
        'gdbots:ncr:mixin:unpublish-node'         => 'unpublish',
        'gdbots:ncr:mixin:update-node'            => 'update',
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
        if ($schema->hasMixin('gdbots:pbjx:mixin:event') || !$this->checker->isGranted($permission, $message)) {
            throw new AccessDeniedHttpException("You do not have [{$permission}] permission.");
        }

        if ($schema->hasMixin('gdbots:ncr:mixin:get-node-batch-request')) {
            $this->checkGetNodeBatchRequest($pbjxEvent, $message, $request);
            return;
        }

        $this->checkNodeRefs($pbjxEvent, $message, $request);
    }

    protected function checkGetNodeBatchRequest(PbjxEvent $pbjxEvent, Message $message, Request $request): void
    {
        /** @var NodeRef[] $nodeRefs */
        $nodeRefs = $message->get('node_refs', []);
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

        $message->removeFromSet('node_refs', $remove);
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
        } elseif ($id->getCurie()->toString() === 'gdbots:ncr:request:get-node-history-request') {
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
