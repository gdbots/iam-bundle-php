<?php
declare(strict_types=1);

namespace Gdbots\Tests\Bundle\IamBundle\Security;

use Acme\Schemas\Iam\Node\RoleV1;
use Acme\Schemas\Iam\Node\UserV1;
use Acme\Schemas\Iam\Request\GetRoleBatchRequestV1;
use Gdbots\Bundle\IamBundle\Security\PbjxPermissionVoter;
use Gdbots\Bundle\IamBundle\Security\User;
use Gdbots\Iam\GetRoleBatchRequestHandler;
use Gdbots\Ncr\Repository\InMemoryNcr;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Pbjx\RegisteringServiceLocator;
use Gdbots\Schemas\Iam\RoleId;
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

    /** @var InMemoryNcr */
    protected $ncr;

    /** @var VoterInterface */
    protected $voter;

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
                ->addToSet('allowed', ['*'])
        );

        $this->ncr->putNode(
            RoleV1::create()
                ->set('_id', RoleId::fromString('subscriber'))
                ->addToSet('allowed', ['acme:blog:request:*'])
                ->addToSet('denied', ['acme:blog:command:*'])
        );

        $this->ncr->putNode(
            RoleV1::create()
                ->set('_id', RoleId::fromString('editor'))
                ->addToSet('allowed', ['acme:blog:request:*'])
                ->addToSet('denied', ['acme:blog:command:*'])
        );
    }

    /**
     * @dataProvider getDataSamples
     *
     * @param array  $roles
     * @param array  $attributes
     * @param string $message
     * @param int    $expected
     */
    public function testVote(array $roles = [], array $attributes = [], string $message, int $expected)
    {
        $user = new User(UserV1::create()->addToSet('roles', $roles));
        $token = new ConcreteToken($user, $user->getRoles());

        $this->assertEquals($expected, $this->voter->vote($token, null, $attributes), $message);
    }

    public function getDataSamples()
    {
        return [
            [
                'roles'      => [
                    NodeRef::fromString('acme:role:super-user'),
                ],
                'attributes' => ['acme:blog:command:create-article'],
                'message'    => 'Super user should be able to create-article',
                'expected'   => VoterInterface::ACCESS_GRANTED,
            ],

            [
                'roles'      => [
                    NodeRef::fromString('acme:role:subscriber'),
                ],
                'attributes' => ['acme:blog:command:create-article'],
                'message'    => 'Subscriber shouldn\'t be able to create-article',
                'expected'   => VoterInterface::ACCESS_DENIED,
            ],

            [
                'roles'      => [
                    NodeRef::fromString('acme:role:editor'),
                ],
                'attributes' => ['acme-blog-create-article'],
                'message'    => 'Curie is invalid, must follow Schemacurie format',
                'expected'   => VoterInterface::ACCESS_ABSTAIN,
            ],

            [
                'roles'      => [
                    NodeRef::fromString('acme:role:editor'),
                ],
                'attributes' => ['ROLE_SUPER_USER'],
                'message'    => 'Role passed instead of Schemacurie',
                'expected'   => VoterInterface::ACCESS_ABSTAIN,
            ],
        ];
    }

    protected function tearDown()
    {
        $this->locator = null;
        $this->pbjx = null;
        $this->ncr = null;
        $this->voter = null;
    }
}
