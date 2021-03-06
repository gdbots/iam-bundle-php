<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;

final class GdbotsIamBundle extends Bundle
{
    public function getPath(): string
    {
        return \dirname(__DIR__);
    }
}
