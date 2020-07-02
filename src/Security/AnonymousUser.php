<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Symfony\Component\Security\Core\User\UserInterface;

class AnonymousUser implements UserInterface
{
    public function getRoles()
    {
        return ['IS_AUTHENTICATED_ANONYMOUSLY'];
    }

    public function getPassword()
    {
        return null;
    }

    public function getSalt()
    {
        return null;
    }

    public function getUsername()
    {
        return null;
    }

    public function eraseCredentials()
    {
    }
}
