<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbj\SchemaCurie;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Iam\Policy;
use Gdbots\Schemas\Iam\Mixin\GetRoleBatchRequest\GetRoleBatchRequest;
use Gdbots\Schemas\Iam\Mixin\GetRoleBatchRequest\GetRoleBatchRequestV1Mixin;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

final class PbjxPermissionVoter extends Voter
{
    /** @var Pbjx */
    private $pbjx;

    /**
     * Array of curies already checked for permission.  Key is the curie of the
     * message, value is the result, @see VoterInterface
     *
     * @var int[]
     */
    private $checked = [];

    /**
     * Array of policies keys by user node ref.
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
     *
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
     * @param TokenInterface $token
     * @param mixed $subject
     * @param array $attributes
     *
     * @return int
     */
    public function vote(TokenInterface $token, $subject, array $attributes = [])
    {
        $vote = VoterInterface::ACCESS_ABSTAIN;

        foreach ($attributes as $attribute) {
            if (!$this->supports($attribute, $subject)) {
                continue;
            }

            $vote = VoterInterface::ACCESS_DENIED;

            if ($this->voteOnAttribute($attribute, $subject, $token) > 0) {
                return VoterInterface::ACCESS_GRANTED;
            }
        }

        return $vote;
    }

    /**
     *
     * {@inheritdoc}
     */
    public function voteOnAttribute($attribute, $subject, TokenInterface $token)
    {
        if (isset($this->checked[$attribute])) {
            return $this->checked[$attribute];
        }

        $user = $token->getUser();
        if (!$user instanceof User) {
            $this->checked[$attribute] = VoterInterface::ACCESS_DENIED;
            return VoterInterface::ACCESS_DENIED;
        }

        $policy = $this->getPolicy($user);
        if ($policy->isGranted($attribute)) {
            $this->checked[$attribute] = VoterInterface::ACCESS_GRANTED;
            return VoterInterface::ACCESS_GRANTED;
        }

        $this->checked[$attribute] = VoterInterface::ACCESS_DENIED;
        return VoterInterface::ACCESS_DENIED;
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
        // store array of policies by user node ref...
        $key = $user->getUserNodeRef()->toString();
        if (isset($this->policies[$key])) {
            return $this->policies[$key];
        }

        $node = $user->getUserNode();
        if (!$node->has('roles')) {
            // make a policy anyways, then stores in this->policies and return it.
            $policy = new Policy([]);
            $this->policies[$key] = $policy;

            return $policy;
        }

        $getRoleBatchRequestSchema = MessageResolver::findOneUsingMixin(GetRoleBatchRequestV1Mixin::create(), 'iam', 'request');

        try {
            /** @var GetRoleBatchRequest $request */
            $request = $getRoleBatchRequestSchema->createMessage()->addToSet('node_refs', $node->get('roles', []));
            $response = $this->pbjx->request($request);
            $policy = new Policy($response->get('nodes', []));

            // store locally, return it.
            $this->policies[$key] = $policy;

            return $policy;
        } catch (\Exception $e) {
            throw new \Exception('Request could not be completed', $e->getCode(), $e);
        }
    }
}
