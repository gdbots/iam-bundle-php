<?php
declare(strict_types=1);

namespace Gdbots\Tests\Bundle\IamBundle;

use Acme\Schemas\Iam\Node\RoleV1;
use Acme\Schemas\Iam\Node\UserV1;
use Acme\Schemas\Iam\UserId;
use Gdbots\Bundle\IamBundle\Security\PbjxPermissionVoter;
use Gdbots\Bundle\IamBundle\Security\User;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Pbjx\EventStore\InMemoryEventStore;
use Gdbots\Pbjx\RegisteringServiceLocator;
use Gdbots\Ncr\Repository\InMemoryNcr;
use Gdbots\Schemas\Iam\RoleId;
use Gdbots\Schemas\Ncr\NodeRef;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;

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

    /** @var  AccessDecisionManagerInterface */
    protected $decisionManager;

    protected function setup()
    {
        $this->locator = new RegisteringServiceLocator();
        $this->pbjx = $this->locator->getPbjx();
        $this->eventStore = new InMemoryEventStore($this->pbjx);
        $this->locator->setEventStore($this->eventStore);
        $this->ncr = new InMemoryNcr();
    }

    public function testVote()
    {
        $attributes = ['acme:blog:command:create-article'];
        $expected = true;
        $roles = [
            RoleV1::create()
                ->set('_id', RoleId::fromString('test1'))
                ->addToSet('allowed', ['acme:blog:command:create-article']),
        ];
        $userNode = UserV1::create()
                    ->set('_id', UserId::fromString('user-1'))
                    ->addToSet('roles', $roles);
        $user = new User($userNode);

        $token = new ConcreteToken($user, $user->getRoles());

        $this->decisionManager = new class implements AccessDecisionManagerInterface
        {
            public function decide(TokenInterface $token, array $attributes, $object = null)
            {
                return true;
            }
        };

        $voter = new PbjxPermissionVoter($this->decisionManager, $this->pbjx);
        $this->assertEquals($expected, $voter->vote($token, 0, $attributes), 'Test Failed');
    }
}
