<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Symfony\Component\Security\Core\User\UserInterface;

class AnonymousUser implements UserInterface
{
    public function getRoles(): array
    {
        return ['IS_AUTHENTICATED_ANONYMOUSLY'];
    }

    public function eraseCredentials(): void
    {
    }

    public function getUserIdentifier(): string
    {
        return 'anon';
    }
}
