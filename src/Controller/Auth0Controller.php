<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Controller;

use Gdbots\Bundle\IamBundle\Security\User;
use Gdbots\Ncr\Ncr;
use Gdbots\Schemas\Iam\Mixin\Role\Role;
use Gdbots\Schemas\Iam\Mixin\User\User as UserNode;
use Gdbots\Schemas\Pbjx\Enum\Code;
use Gdbots\Schemas\Pbjx\Enum\HttpCode;
use Gdbots\Schemas\Pbjx\Envelope;
use Gdbots\Schemas\Pbjx\EnvelopeV1;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;

class Auth0Controller extends Controller
{
    /** @var Ncr */
    protected $ncr;

    /**
     * @param Ncr $ncr
     */
    public function __construct(Ncr $ncr)
    {
        $this->ncr = $ncr;
    }

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
        if ($user->isEnabled()
            && $userNode->get('is_staff')
            && $userNode->has('roles')
        ) {
            foreach ($this->getUsersRoles($userNode) as $nodeRef => $role) {
                $envelope->addToMap('derefs', $nodeRef, $role);
            }
        }

        return $envelope
            ->set('etag', $userNode->get('etag'))
            ->set('message_ref', $userNode->generateMessageRef())
            ->set('message', $userNode);
    }

    /**
     * @param UserNode $user
     *
     * @return Role[]
     */
    protected function getUsersRoles(UserNode $user): array
    {
        try {
            return $this->ncr->getNodes($user->get('roles'));
        } catch (\Throwable $e) {
            return [];
        }
    }
}
