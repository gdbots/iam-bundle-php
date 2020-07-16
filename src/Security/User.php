<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Gdbots\Pbj\Message;
use Gdbots\Pbj\WellKnown\MessageRef;
use Gdbots\Pbj\WellKnown\NodeRef;
use Gdbots\Schemas\Ncr\Enum\NodeStatus;
use Symfony\Component\Security\Core\User\EquatableInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class User implements UserInterface, EquatableInterface
{
    protected Message $node;
    protected NodeRef $nodeRef;
    protected MessageRef $messageRef;
    protected array $roles = [];

    public function __construct(Message $node)
    {
        $this->node = $node;
        $this->nodeRef = $node->generateNodeRef();
        $this->messageRef = $node->generateMessageRef();

        /** @var NodeRef $role */
        foreach ($this->node->get('roles', []) as $role) {
            $this->roles[] = 'ROLE_' . strtoupper(str_replace('-', '_', $role->getId()));
        }

        $schema = $this->node::schema();

        if ($schema->hasMixin('gdbots:iam:mixin:user') && $this->node->get('is_staff')) {
            $this->roles[] = 'ROLE_USER';
            $this->roles[] = 'ROLE_STAFF';
        }

        if ($schema->hasMixin('gdbots:iam:mixin:app')) {
            $this->roles[] = 'ROLE_APP';
            $this->roles[] = 'ROLE_' . strtoupper(str_replace('-', '_', $this->nodeRef->getLabel()));
        }
    }

    public function getNode(): Message
    {
        return $this->node;
    }

    public function getNodeRef(): NodeRef
    {
        return $this->nodeRef;
    }

    public function getMessageRef(): MessageRef
    {
        return $this->messageRef;
    }

    public function getDisplayName(): ?string
    {
        return $this->node->get('title');
    }

    public function getRoles()
    {
        return $this->roles;
    }

    public function getPassword()
    {
        return null;
    }

    public function getSalt()
    {
        return null;
    }

    public function getUsername()
    {
        return $this->node->fget('_id');
    }

    public function eraseCredentials()
    {
    }

    public function isEqualTo(UserInterface $user)
    {
        if (!$user instanceof self) {
            return false;
        }

        return $this->node->equals($user->node);
    }

    public function isEnabled(): bool
    {
        if (NodeStatus::PUBLISHED !== $this->node->fget('status')) {
            return false;
        }

        if ($this->node::schema()->hasMixin('gdbots:iam:mixin:user')) {
            return !$this->node->get('is_blocked');
        }

        // apps are always enabled when published (for now)
        return true;
    }
}
