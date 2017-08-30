<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Gdbots\Iam\Policy;
use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbj\SchemaCurie;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Schemas\Iam\Mixin\GetRoleBatchRequest\GetRoleBatchRequest;
use Gdbots\Schemas\Iam\Mixin\GetRoleBatchRequest\GetRoleBatchRequestV1Mixin;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

final class PbjxPermissionVoter extends Voter
{
    /** @var Pbjx */
    private $pbjx;

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
     * @param Pbjx $pbjx
     */
    public function __construct(Pbjx $pbjx)
    {
        $this->pbjx = $pbjx;
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
     *
     * @throws \Exception
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

        $getRoleBatchRequestSchema = MessageResolver::findOneUsingMixin(GetRoleBatchRequestV1Mixin::create(), 'iam', 'request');
        /** @var GetRoleBatchRequest $request */
        $request = $getRoleBatchRequestSchema->createMessage()->addToSet('node_refs', $node->get('roles'));

        try {
            $response = $this->pbjx->request($request);
            return $this->policies[$key] = new Policy($response->get('nodes', []));
        } catch (\Exception $e) {
        }

        return $this->policies[$key] = new Policy();
    }
}
