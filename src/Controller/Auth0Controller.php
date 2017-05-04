<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Controller;

use Gdbots\Bundle\IamBundle\Security\AnonymousUser;
use Gdbots\Bundle\IamBundle\Security\User;
use Gdbots\Bundle\PbjxBundle\Controller\PbjxAwareControllerTrait;
use Gdbots\Schemas\Pbjx\Enum\Code;
use Gdbots\Schemas\Pbjx\Enum\HttpCode;
use Gdbots\Schemas\Pbjx\Envelope;
use Gdbots\Schemas\Pbjx\EnvelopeV1;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class Auth0Controller extends Controller
{
    use PbjxAwareControllerTrait;

    /**
     * @param Request $request
     *
     * @return Envelope
     */
    public function meAction(Request $request): Envelope
    {
        // wip
        $token = $this->getToken();
        $user = $token->getUser();
        $envelope = EnvelopeV1::create();

        if ($user instanceof User) {
            return $envelope
                ->set('message_ref', $user->getUserNode()->generateMessageRef())
                ->set('message', $user->getUserNode());
        }

        if (!$token instanceof \stdClass || !isset($token->is_jwt)) {
            $request->attributes->set('pbjx_redact_error_message', false);
            return $envelope
                ->set('code', Code::UNAUTHENTICATED)
                ->set('http_code', HttpCode::HTTP_UNAUTHORIZED())
                ->set('error_name', 'AccessDenied')
                ->set('error_message', 'Invalid JWT.');
        }

        return $envelope;

        //return JsonResponse::create($user->getUserNode()->toArray());
    }

    /**
     * Gets the token from the Security Token Storage.
     *
     * @return TokenInterface
     */
    protected function getToken(): ?TokenInterface
    {
        if (!$this->container->has('security.token_storage')) {
            throw new \LogicException('The SecurityBundle is not registered in your application.');
        }

        return $this->container->get('security.token_storage')->getToken();
    }
}
