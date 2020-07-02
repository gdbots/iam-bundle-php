<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle;

use Gdbots\Bundle\PbjxBundle\Validator\PermissionValidatorTrait;
use Gdbots\Pbj\Message;
use Gdbots\Pbjx\DependencyInjection\PbjxValidator;
use Gdbots\Pbjx\Event\PbjxEvent;
use Gdbots\Pbjx\EventSubscriber;
use Gdbots\Schemas\Pbjx\Mixin\Event\EventV1Mixin;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;

final class PbjxPermissionValidator implements EventSubscriber, PbjxValidator
{
    use PermissionValidatorTrait;

    private AuthorizationCheckerInterface $authorizationChecker;

    public function __construct(RequestStack $requestStack, AuthorizationCheckerInterface $authorizationChecker)
    {
        $this->requestStack = $requestStack;
        $this->authorizationChecker = $authorizationChecker;
    }

    protected function checkPermission(PbjxEvent $pbjxEvent, Message $message, Request $request): void
    {
        if ($request->attributes->getBoolean('iam_bypass_permissions')) {
            // when attempting to load the user for authentication, we can't do a permission check.
            $request->attributes->remove('iam_bypass_permissions');
            return;
        }

        $schema = $message::schema();

        if ($schema->hasMixin(EventV1Mixin::SCHEMA_CURIE)
            || !$this->authorizationChecker->isGranted($schema->getCurie()->toString(), $message)
        ) {
            throw new AccessDeniedHttpException('You do not have permission to perform that operation.');
        }
    }
}
