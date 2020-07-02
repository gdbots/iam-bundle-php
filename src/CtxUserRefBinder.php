<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle;

use Gdbots\Bundle\IamBundle\Security\User;
use Gdbots\Pbjx\DependencyInjection\PbjxBinder;
use Gdbots\Pbjx\Event\PbjxEvent;
use Gdbots\Pbjx\EventSubscriber;
use Gdbots\Schemas\Pbjx\Mixin\Command\CommandV1Mixin;
use Gdbots\Schemas\Pbjx\Mixin\Event\EventV1Mixin;
use Gdbots\Schemas\Pbjx\Mixin\Request\RequestV1Mixin;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

final class CtxUserRefBinder implements EventSubscriber, PbjxBinder
{
    private TokenStorageInterface $tokenStorage;

    public static function getSubscribedEvents()
    {
        return [
            CommandV1Mixin::SCHEMA_CURIE . '.bind' => ['bind', 20000],
            EventV1Mixin::SCHEMA_CURIE . '.bind'   => ['bind', 20000],
            RequestV1Mixin::SCHEMA_CURIE . '.bind' => ['bind', 20000],
        ];
    }

    public function __construct(TokenStorageInterface $tokenStorage)
    {
        $this->tokenStorage = $tokenStorage;
    }

    public function bind(PbjxEvent $pbjxEvent): void
    {
        $message = $pbjxEvent->getMessage();
        if ($message->has(CommandV1Mixin::CTX_USER_REF_FIELD)) {
            return;
        }

        if (null === $token = $this->tokenStorage->getToken()) {
            return;
        }

        $user = $token->getUser();
        if (!$user instanceof User) {
            return;
        }

        $message->set(CommandV1Mixin::CTX_USER_REF_FIELD, $user->getMessageRef());
    }
}
