<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Gdbots\Iam\Policy;
use Gdbots\Pbj\SchemaCurie;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Schemas\Iam\Mixin\GetRoleBatchRequest\GetRoleBatchRequest;
use Gdbots\Schemas\Iam\Mixin\GetRoleBatchRequest\GetRoleBatchRequestV1Mixin;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

final class PbjxPermissionVoter extends Voter
{
    /** @var Pbjx */
    private $pbjx;

    /** @var RequestStack */
    private $requestStack;

    /**
     * Array of curies already checked for permission.  Key is the curie of the
     * message, value is the result
     *
     * @var bool[]
     */
    private $checked = [];

    /**
     * Array of policies, keys by user node ref.
     *
     * @var Policy[]
     */
    private $policies = [];

    /**
     * @param Pbjx         $pbjx
     * @param RequestStack $requestStack
     */
    public function __construct(Pbjx $pbjx, RequestStack $requestStack)
    {
        $this->pbjx = $pbjx;
        $this->requestStack = $requestStack;
    }

    /**
     * {@inheritdoc}
     */
    protected function supports($attribute, $subject)
    {
        if (!is_string($attribute)) {
            return false;
        }

        if (!preg_match(SchemaCurie::VALID_PATTERN, $attribute)) {
            return false;
        }

        return true;
    }

    /**
     * {@inheritdoc}
     */
    protected function voteOnAttribute($attribute, $subject, TokenInterface $token)
    {
        if (isset($this->checked[$attribute])) {
            return $this->checked[$attribute];
        }

        $user = $token->getUser();
        if (!$user instanceof User) {
            return $this->checked[$attribute] = false;
        }

        return $this->checked[$attribute] = $this->getPolicy($user)->isGranted($attribute);
    }

    /**
     * @param User $user
     *
     * @return Policy
     */
    private function getPolicy(User $user): Policy
    {
        $key = $user->getUserNodeRef()->toString();
        if (isset($this->policies[$key])) {
            return $this->policies[$key];
        }

        $node = $user->getUserNode();
        if (!$node->has('roles')) {
            // make an empty policy with no permissions
            return $this->policies[$key] = new Policy();
        }

        $symfonyRequest = $this->requestStack->getCurrentRequest();
        $symfonyRequest->attributes->set('iam_bypass_permissions', true);

        /** @var GetRoleBatchRequest $request */
        $request = GetRoleBatchRequestV1Mixin::findOne()
            ->createMessage()
            ->addToSet('node_refs', $node->get('roles'));

        try {
            $response = $this->pbjx->request($request);
            $this->policies[$key] = new Policy($response->get('nodes', []));
        } catch (\Throwable $e) {
            $this->policies[$key] = new Policy();
        }

        $symfonyRequest->attributes->remove('iam_bypass_permissions');
        return $this->policies[$key];
    }
}
