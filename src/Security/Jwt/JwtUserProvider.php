<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security\Jwt;

use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

interface JwtUserProvider extends UserProviderInterface
{
    /**
     * Loads the user for the given decoded JWT.
     *
     * @param \stdClass $jwt The decoded Json Web Token
     *
     * @return UserInterface
     *
     * @throws AuthenticationException
     */
    public function loadUserByJwt(\stdClass $jwt): UserInterface;

    /**
     * Returns an AnonymousUser
     *
     * @return UserInterface
     *
     * @throws AuthenticationException
     */
    public function getAnonymousUser(): UserInterface;
}
