<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Gdbots\Pbj\MessageRef;
use Gdbots\Schemas\Iam\Mixin\User\User as UserNode;
use Gdbots\Schemas\Ncr\Enum\NodeStatus;
use Gdbots\Schemas\Ncr\NodeRef;
use Symfony\Component\Security\Core\User\AdvancedUserInterface;
use Symfony\Component\Security\Core\User\EquatableInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class User implements AdvancedUserInterface, EquatableInterface
{
    /** @var UserNode */
    protected $node;

    /** @var NodeRef */
    protected $nodeRef;

    /** @var MessageRef */
    protected $userRef;

    /** @var string[] */
    protected $roles = [];

    /**
     * @param UserNode $node
     */
    public function __construct(UserNode $node)
    {
        $this->node = $node;
        $this->nodeRef = NodeRef::fromNode($node);
        $this->userRef = $node->generateMessageRef();

        /** @var NodeRef $role */
        foreach ($this->node->get('roles', []) as $role) {
            $this->roles[] = 'ROLE_' . strtoupper(str_replace('-', '_', $role->getId()));
        }

        if ($this->node->get('is_staff')) {
            $this->roles[] = 'ROLE_USER';
        }
    }

    /**
     * @return UserNode
     */
    public function getUserNode(): UserNode
    {
        return $this->node;
    }

    /**
     * @return NodeRef
     */
    public function getUserNodeRef(): NodeRef
    {
        return $this->nodeRef;
    }

    /**
     * @return MessageRef
     */
    public function getUserRef(): MessageRef
    {
        return $this->userRef;
    }

    /**
     * @return string
     */
    public function getDisplayName(): ?string
    {
        return $this->node->get('title');
    }

    /**
     * {@inheritdoc}
     */
    public function getRoles()
    {
        return $this->roles;
    }

    /**
     * {@inheritdoc}
     */
    public function getPassword()
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function getSalt()
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function getUsername()
    {
        return (string)$this->node->get('_id');
    }

    /**
     * {@inheritdoc}
     */
    public function eraseCredentials()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function isEqualTo(UserInterface $user)
    {
        if (!$user instanceof self) {
            return false;
        }

        return $this->node->equals($user->node);
    }

    /**
     * {@inheritdoc}
     */
    public function isAccountNonExpired()
    {
        return NodeStatus::PUBLISHED()->equals($this->node->get('status'));
    }

    /**
     * {@inheritdoc}
     */
    public function isAccountNonLocked()
    {
        return !$this->node->get('is_blocked');
    }

    /**
     * {@inheritdoc}
     */
    public function isCredentialsNonExpired()
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function isEnabled()
    {
        return NodeStatus::PUBLISHED()->equals($this->node->get('status'))
            && $this->node->get('is_staff')
            && !$this->node->get('is_blocked');
    }
}
