<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Gdbots\Pbj\MessageRef;
use Gdbots\Schemas\Iam\Mixin\App\App;
use Gdbots\Schemas\Iam\Mixin\User\User as UserNode;
use Gdbots\Schemas\Ncr\Enum\NodeStatus;
use Gdbots\Schemas\Ncr\Mixin\Node\Node;
use Gdbots\Schemas\Ncr\NodeRef;
use Symfony\Component\Security\Core\User\EquatableInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class User implements EquatableInterface
{
    /** @var Node|App|UserNode */
    protected $node;

    /** @var NodeRef */
    protected $nodeRef;

    /** @var MessageRef */
    protected $userRef;

    /** @var string[] */
    protected $roles = [];

    /**
     * @param Node $node
     */
    public function __construct(Node $node)
    {
        $this->node = $node;
        $this->nodeRef = NodeRef::fromNode($node);
        $this->userRef = $node->generateMessageRef();

        /** @var NodeRef $role */
        foreach ($this->node->get('roles', []) as $role) {
            $this->roles[] = 'ROLE_' . strtoupper(str_replace('-', '_', $role->getId()));
        }

        if ($this->node instanceof UserNode && $this->node->get('is_staff')) {
            $this->roles[] = 'ROLE_USER';
            $this->roles[] = 'ROLE_STAFF';
        }
    }

    /**
     * @return Node
     */
    public function getUserNode(): Node
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
    public function isEnabled()
    {
        if (!NodeStatus::PUBLISHED()->equals($this->node->get('status'))) {
            return false;
        }

        if ($this->node instanceof UserNode) {
            return !$this->node->get('is_blocked');
        }

        // apps are always enabled when published (for now)
        return true;
    }
}
