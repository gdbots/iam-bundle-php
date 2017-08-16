<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbj\SchemaCurie;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Iam\Policy;
use Gdbots\Schemas\Iam\Mixin\GetRoleBatchRequest\GetRoleBatchRequestV1Mixin;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

final class PbjxPermissionVoter implements VoterInterface
{
    /** @var AccessDecisionManagerInterface */
    private $decisionManager;

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
     * @param AccessDecisionManagerInterface $decisionManager
     * @param Pbjx                           $pbjx
     */
    public function __construct(AccessDecisionManagerInterface $decisionManager, Pbjx $pbjx)
    {
        $this->decisionManager = $decisionManager;
        $this->pbjx = $pbjx;
    }

    /**
     * fixme: permission map needs to be driven by repository, static for now for dev
     *
     * {@inheritdoc}
     */
    public function vote(TokenInterface $token, $subject, array $attributes)
    {
        $curie = current($attributes);

        if (!is_string($curie)) {
            return VoterInterface::ACCESS_ABSTAIN;
        }

        if (!preg_match(SchemaCurie::VALID_PATTERN, $curie)) {
            return VoterInterface::ACCESS_ABSTAIN;
        }

        if (isset($this->checked[$curie])) {
            return $this->checked[$curie];
        }

        $user = $token->getUser();
        if (!$user instanceof User) {
            return $this->checked[$curie] = VoterInterface::ACCESS_DENIED;
        }

        $policy = $this->getPolicy($user);
        if ($policy->isGranted($curie)) {
            return $this->checked[$curie] = VoterInterface::ACCESS_GRANTED;
        }

        return $this->checked[$curie] = VoterInterface::ACCESS_DENIED;
    }

    /**
     * @param User $user
     *
     * @return Policy
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

        $request = MessageResolver::findOneUsingMixin(GetRoleBatchRequestV1Mixin::create(), 'iam', 'request');
        $request->addToSet('node_refs', $node->get('roles', []));

        try {
            $response = $this->pbjx->request($request);
        } catch (\Exception $e) {
        }

        $policy = new Policy($response->get('nodes', []));

        // store locally, return it.
        $this->policies[$key] = $policy;

        return $policy;
    }
}
