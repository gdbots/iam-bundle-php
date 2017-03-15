<?php
declare(strict_types = 1);

namespace Gdbots\Bundle\IamBundle\Binder;

use Gdbots\Bundle\IamBundle\Security\User;
use Gdbots\Pbjx\Event\PbjxEvent;
use Gdbots\Pbjx\EventSubscriber;
use Gdbots\Schemas\Pbjx\Mixin\Command\Command;
use Gdbots\Schemas\Pbjx\Mixin\Event\Event;
use Gdbots\Schemas\Pbjx\Mixin\Request\Request as PbjxRequest;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

final class CtxUserRefBinder implements EventSubscriber
{
    /** @var TokenStorageInterface */
    private $tokenStorage;

    /**
     * @param TokenStorageInterface $tokenStorage
     */
    public function __construct(TokenStorageInterface $tokenStorage)
    {
        $this->tokenStorage = $tokenStorage;
    }

    /**
     * @param PbjxEvent $pbjxEvent
     */
    public function bind(PbjxEvent $pbjxEvent): void
    {
        $message = $pbjxEvent->getMessage();
        if (!$message instanceof Command && !$message instanceof Event && !$message instanceof PbjxRequest) {
            return;
        }

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

        $message->set('ctx_user_ref', $user->getUserRef());
    }

    /**
     * @return array
     */
    public static function getSubscribedEvents()
    {
        return [
            'gdbots_pbjx.message.bind' => 'bind',
        ];
    }
}
