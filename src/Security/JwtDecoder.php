<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

interface JwtDecoder
{
    /**
     * @param string $jwt
     *
     * @return \stdClass
     *
     * @throws \Throwable
     */
    public function decode(string $jwt): \stdClass;
}
