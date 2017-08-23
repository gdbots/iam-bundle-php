<?php
declare(strict_types=1);

namespace Gdbots\Tests\Bundle\IamBundle;

use Acme\Schemas\Iam\Node\RoleV1;
use Acme\Schemas\Iam\Request\GetRoleBatchRequest;
use Acme\Schemas\Iam\Request\GetRoleBatchRequestV1;
use Gdbots\Iam\GetRoleBatchRequestHandler;
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

    /** @var User */
    protected $user;

    /** @var VoterInterface */
    protected $voter;

    /** @var  ConcreteToken */
    protected $token;

    /** @var  array */
    protected $attributes;

    protected function setup()
    {
        $this->locator = new RegisteringServiceLocator();
        $this->pbjx = $this->locator->getPbjx();
        $this->ncr = new InMemoryNcr();
        $handler = new GetRoleBatchRequestHandler($this->ncr);
        $this->locator->registerRequestHandler(GetRoleBatchRequestV1::schema()->getCurie(), $handler);
        $this->voter = new PbjxPermissionVoter($this->pbjx);

        $this->ncr->putNode(
            RoleV1::create()
                ->set('_id', RoleId::fromString('super-user'))
                ->addToSet('allowed', ['test'])
        );

        $this->ncr->putNode(
            RoleV1::create()
                ->set('_id', RoleId::fromString('readonly'))
                ->addToSet('allowed', ['acme:blog:request:*'])
                ->addToSet('denied', ['acme:blog:command:*'])
        );
    }

    public function testVote()
    {
        $user = new User(UserV1::create()
            ->addToSet('roles', [
                NodeRef::fromString('acme:role:super-user'),
            ])
        );
        $token = new ConcreteToken($user, $user->getRoles());

        $this->assertEquals(
            VoterInterface::ACCESS_GRANTED,
            $this->voter->vote($token, null, ['acme:blog:command:create-article']),
            'Super user should be able to create-article'
        );
    }

    protected function tearDown()
    {
        $this->locator = null;
        $this->pbjx = null;
        $this->ncr = null;
        $this->voter = null;
    }
}
