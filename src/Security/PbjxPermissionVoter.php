<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Gdbots\Pbj\SchemaCurie;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

final class PbjxPermissionVoter implements VoterInterface
{
    /**
     * Array of curies already checked for permission.  Key is the curie of the
     * message, value is the result, @see VoterInterface
     *
     * @var int[]
     */
    private $checked = [];

    /** @var AccessDecisionManagerInterface */
    private $decisionManager;

    /** @var array */
    private $permissions;

    /**
     * @param AccessDecisionManagerInterface $decisionManager
     * @param array                          $permissions
     */
    public function __construct(AccessDecisionManagerInterface $decisionManager, array $permissions = [])
    {
        $this->decisionManager = $decisionManager;
        $this->permissions = $permissions;
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

        if (!$token->getUser() instanceof User) {
            return $this->checked[$curie] = VoterInterface::ACCESS_DENIED;
        }

        if (!isset($this->permissions[$curie])) {
            return $this->checked[$curie] = VoterInterface::ACCESS_DENIED;
        }

        $permission = is_array($this->permissions[$curie]) ? $this->permissions[$curie] : [$this->permissions[$curie]];

        if ($this->decisionManager->decide($token, $permission, $subject)) {
            return $this->checked[$curie] = VoterInterface::ACCESS_GRANTED;
        }

        return $this->checked[$curie] = VoterInterface::ACCESS_DENIED;
    }
}
