<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Controller;

use Gdbots\Bundle\IamBundle\Security\User;
use Gdbots\Schemas\Pbjx\Enum\Code;
use Gdbots\Schemas\Pbjx\Enum\HttpCode;
use Gdbots\Schemas\Pbjx\Envelope;
use Gdbots\Schemas\Pbjx\EnvelopeV1;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;

class Auth0Controller extends Controller
{
    /**
     * @return Envelope
     */
    public function meAction(): Envelope
    {
        $user = $this->getUser();
        $envelope = EnvelopeV1::create();

        if (!$user instanceof User) {
            return $envelope
                ->set('code', Code::UNAUTHENTICATED)
                ->set('http_code', HttpCode::HTTP_UNAUTHORIZED())
                ->set('error_name', 'AccessDenied');
        }

        $userNode = $user->getUserNode();

        return $envelope
            ->set('etag', $userNode->get('etag'))
            ->set('message_ref', $userNode->generateMessageRef())
            ->set('message', $userNode);
    }
}
