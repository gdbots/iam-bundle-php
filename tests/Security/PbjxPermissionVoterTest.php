<?php
declare(strict_types=1);

namespace Gdbots\Tests\Bundle\IamBundle;

use Acme\Schemas\Iam\Node\RoleV1;
use Gdbots\Schemas\Iam\RoleId;
use Acme\Schemas\Iam\Node\UserV1;
use Gdbots\Bundle\IamBundle\Security\PbjxPermissionVoter;
use Gdbots\Bundle\IamBundle\Security\User;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Pbjx\EventStore\InMemoryEventStore;
use Gdbots\Pbjx\RegisteringServiceLocator;
use Gdbots\Ncr\Repository\InMemoryNcr;
use Gdbots\Schemas\Ncr\NodeRef;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

class ConcreteToken extends AbstractToken
{
    public function __construct(User $user, array $roles)
    {
        parent::__construct($roles);

        $this->setUser($user);
    }

    public function getCredentials()
    {
    }
}

class PbjxPermissionVoterTest extends TestCase
{
    /** @var RegisteringServiceLocator */
    protected $locator;

    /** @var Pbjx */
    protected $pbjx;

    /** @var InMemoryEventStore */
    protected $eventStore;

    /** @var InMemoryNcr */
    protected $ncr;

    /** @var  PbjxPermissionVoter */
    protected $pbjxPermissionVoter;

    /** @var User */
    protected $user;

    /** @var PbjxPermissionVoter */
    protected $voter;

    /** @var  ConcreteToken */
    protected $token;

    /** @var  array */
    protected $attributes;

    protected function setup()
    {
        $this->locator = new RegisteringServiceLocator();
        $this->pbjx = $this->locator->getPbjx();
        $this->eventStore = new InMemoryEventStore($this->pbjx);
        $this->locator->setEventStore($this->eventStore);
        $this->ncr = new InMemoryNcr();
        $this->voter = new PbjxPermissionVoter($this->pbjx);
        $this->attributes = ['acme:blog:command:create-article'];

        $roleNodeRefs = [
            NodeRef::fromNode(RoleV1::create()
                ->set('_id', RoleId::fromString('test1'))
                ->addToSet('allowed', ['acme:blog:command:create-article', 'acme:blog:command:edit-article'])
                ->addToSet('denied', ['acme:blog:command:create-article'])
            ),
        ];

        $this->user = new User(UserV1::create()
            ->addToSet('roles', $roleNodeRefs));
        $this->token = new ConcreteToken($this->user, $this->user->getRoles());
    }

    public function testVote()
    {
        $this->assertEquals(VoterInterface::ACCESS_DENIED, $this->voter->vote($this->token, 0, $this->attributes), "Test Failed");
    }

    protected function tearDown()
    {
        $this->locator = null;
        $this->pbjx = null;
        $this->eventStore = null;
        $this->ncr = null;
        $this->voter = null;
        $this->user = null;
        $this->token = null;
    }
}
