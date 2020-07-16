<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle;

use Gdbots\Bundle\IamBundle\Security\User;
use Gdbots\Pbjx\DependencyInjection\PbjxBinder;
use Gdbots\Pbjx\Event\PbjxEvent;
use Gdbots\Pbjx\EventSubscriber;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

final class CtxUserRefBinder implements EventSubscriber, PbjxBinder
{
    private TokenStorageInterface $tokenStorage;

    public static function getSubscribedEvents()
    {
        return [
            'gdbots:pbjx:mixin:command.bind' => ['bind', 20000],
            'gdbots:pbjx:mixin:event.bind'   => ['bind', 20000],
            'gdbots:pbjx:mixin:request.bind' => ['bind', 20000],
        ];
    }

    public function __construct(TokenStorageInterface $tokenStorage)
    {
        $this->tokenStorage = $tokenStorage;
    }

    public function bind(PbjxEvent $pbjxEvent): void
    {
        $message = $pbjxEvent->getMessage();
        if ($message->has('ctx_user_ref')) {
            return;
        }

        if (null === $token = $this->tokenStorage->getToken()) {
            return;
        }

        $user = $token->getUser();
        if (!$user instanceof User) {
            return;
        }

        $message->set('ctx_user_ref', $user->getMessageRef());
    }
}
