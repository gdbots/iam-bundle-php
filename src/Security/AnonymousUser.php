<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Symfony\Component\Security\Core\User\UserInterface;

class AnonymousUser implements UserInterface
{
    /**
     * {@inheritdoc}
     */
    public function getRoles()
    {
        return ['IS_AUTHENTICATED_ANONYMOUSLY'];
    }

    /**
     * {@inheritdoc}
     */
    public function getPassword()
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function getSalt()
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function getUsername()
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function eraseCredentials()
    {
    }
}
