<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

interface JwtDecoder
{
    /**
     * Decodes and verifies the JWT and returns the payload
     * portion of the decoded JWT.
     *
     * @param string $jwt
     *
     * @return array
     */
    public function decode(string $jwt): array;
}
