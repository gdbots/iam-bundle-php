<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Validator;

use Gdbots\Bundle\PbjxBundle\Validator\PermissionValidatorTrait;
use Gdbots\Pbj\Message;
use Gdbots\Pbjx\DependencyInjection\PbjxValidator;
use Gdbots\Pbjx\Event\PbjxEvent;
use Gdbots\Pbjx\EventSubscriber;
use Gdbots\Schemas\Ncr\Request\GetNodeBatchRequest;
use Gdbots\Schemas\Pbjx\Mixin\Event\Event;
use Gdbots\Schemas\Pbjx\Request\EchoRequest;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;

final class PbjxPermissionValidator implements EventSubscriber, PbjxValidator
{
    use PermissionValidatorTrait;

    /** @var AuthorizationCheckerInterface */
    private $authorizationChecker;

    /**
     * @param RequestStack                  $requestStack
     * @param AuthorizationCheckerInterface $authorizationChecker
     */
    public function __construct(RequestStack $requestStack, AuthorizationCheckerInterface $authorizationChecker)
    {
        $this->requestStack = $requestStack;
        $this->authorizationChecker = $authorizationChecker;
    }

    /**
     * @param PbjxEvent $pbjxEvent
     * @param Message   $message
     * @param Request   $request
     *
     * @throws \Exception
     */
    protected function checkPermission(PbjxEvent $pbjxEvent, Message $message, Request $request): void
    {
        if ('app_healthcheck_show' === $request->attributes->get('_route') || $message instanceof EchoRequest) {
            return;
        }

        if ('pbjx' !== $request->attributes->get('_route')) {
            if ($message instanceof GetNodeBatchRequest) {
                /*
                 * the NcrLazyLoader sends this request to populate NcrCache.
                 * If not called directly it's fine to allow.
                 */
                return;
            }
        }

        if ($request->attributes->getBoolean('iam_bypass_permissions')) {
            // when attempting to load the user for authentication, we can't do a permission check.
            $request->attributes->remove('iam_bypass_permissions');
            return;
        }

        if ($message instanceof Event || !$this->authorizationChecker->isGranted($message::schema()->getCurie()->toString(), $message)) {
            throw new AccessDeniedHttpException('You do not have permission to perform that operation.');
        }
    }
}
