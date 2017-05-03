<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class Auth0Controller extends Controller
{
    /**
     * @param Request $request
     *
     * @return Response
     */
    public function meAction(Request $request): Response
    {
        $token = $this->getUser();
    }
}
