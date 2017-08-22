<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Acme\Schemas\Iam\Request\GetRoleBatchRequestV1;
use Gdbots\Iam\GetRoleBatchRequestHandler;
use Gdbots\Ncr\Repository\InMemoryNcr;
use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbj\SchemaCurie;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Iam\Policy;
use Gdbots\Schemas\Iam\Mixin\GetRoleBatchRequest\GetRoleBatchRequest;
use Gdbots\Schemas\Iam\Mixin\GetRoleBatchRequest\GetRoleBatchRequestV1Mixin;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

final class PbjxPermissionVoter implements VoterInterface
{
    /** @var Pbjx */
    private $pbjx;

    /** @var  InMemoryNcr */
    private $ncr;

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
     * @param InMemoryNcr $ncr
     */
    public function __construct(Pbjx $pbjx, InMemoryNcr $ncr)
    {
        $this->pbjx = $pbjx;
        $this->ncr = $ncr;
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
            $this->checked[$curie] = VoterInterface::ACCESS_DENIED;
            return VoterInterface::ACCESS_DENIED;
        }

        $policy = $this->getPolicy($user);
        if ($policy->isGranted($curie)) {
            $this->checked[$curie] = VoterInterface::ACCESS_GRANTED;
            return VoterInterface::ACCESS_GRANTED;
        }

        $this->checked[$curie] = VoterInterface::ACCESS_DENIED;
        return VoterInterface::ACCESS_DENIED;
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

        $request = GetRoleBatchRequestV1::create();
        $request->addToSet('node_refs', $node->get('roles', []));
        $handler = new GetRoleBatchRequestHandler($this->ncr);

        $response = null;
        try {
            $response = $handler->handleRequest($request, $this->pbjx);
        } catch (\Exception $e) {
        }

        $policy = new Policy($response->get('nodes', []));

        // store locally, return it.
        $this->policies[$key] = $policy;

        return $policy;
    }
}
