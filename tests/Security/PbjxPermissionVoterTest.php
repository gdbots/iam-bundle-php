<?php
declare(strict_types=1);

namespace Gdbots\Tests\Bundle\IamBundle\Security;

use Acme\Schemas\Iam\Node\IosAppV1;
use Acme\Schemas\Iam\Node\RoleV1;
use Acme\Schemas\Iam\Node\UserV1;
use Gdbots\Bundle\IamBundle\Security\PbjxPermissionVoter;
use Gdbots\Bundle\IamBundle\Security\User;
use Gdbots\Ncr\GetNodeBatchRequestHandler;
use Gdbots\Ncr\Repository\InMemoryNcr;
use Gdbots\Pbj\WellKnown\NodeRef;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Pbjx\RegisteringServiceLocator;
use Gdbots\Schemas\Iam\RoleId;
use Gdbots\Schemas\Ncr\Request\GetNodeBatchRequestV1;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
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
    protected RegisteringServiceLocator $locator;
    protected Pbjx $pbjx;
    protected InMemoryNcr $ncr;
    protected VoterInterface $voter;

    protected function setUp(): void
    {
        $this->locator = new RegisteringServiceLocator();
        $this->pbjx = $this->locator->getPbjx();
        $this->ncr = new InMemoryNcr();

        $handler = new GetNodeBatchRequestHandler($this->ncr);
        $this->locator->registerRequestHandler(GetNodeBatchRequestV1::schema()->getCurie(), $handler);
        $this->voter = new PbjxPermissionVoter($this->pbjx, new ArrayAdapter());

        $this->ncr->putNode(
            RoleV1::create()
                ->set('_id', RoleId::fromString('super-user'))
                ->addToSet('allowed', ['*'])
        );

        $this->ncr->putNode(
            RoleV1::create()
                ->set('_id', RoleId::fromString('subscriber'))
                ->addToSet('allowed', ['acme:blog:request:*','acme:article:get'])
                ->addToSet('denied', ['acme:blog:command:*'])
        );

        $this->ncr->putNode(
            RoleV1::create()
                ->set('_id', RoleId::fromString('editor'))
                ->addToSet('allowed', ['acme:blog:*','acme:article:*'])
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
    public function testVoteForUser(array $roles, array $attributes, string $message, int $expected)
    {
        $user = new User(UserV1::create()->addToSet('roles', $roles));
        $token = new ConcreteToken($user, $user->getRoles());

        $this->assertEquals($expected, $this->voter->vote($token, null, $attributes), $message);
    }

    /**
     * @dataProvider getDataSamples
     *
     * @param array  $roles
     * @param array  $attributes
     * @param string $message
     * @param int    $expected
     */
    public function testVoteForApp(array $roles, array $attributes, string $message, int $expected)
    {
        $user = new User(IosAppV1::create()->addToSet('roles', $roles));
        $token = new ConcreteToken($user, $user->getRoles());
        $this->assertEquals($expected, $this->voter->vote($token, null, $attributes), $message);
    }

    public static function getDataSamples(): array
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
                    NodeRef::fromString('acme:role:subscriber'),
                    NodeRef::fromString('acme:role:editor'),
                ],
                'attributes' => ['acme:blog:command:delete-blog'],
                'message'    => 'Denied rules take precedence',
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
                'attributes' => ['acme:article:publish'],
                'message'    => 'Editor should be able to publish article.',
                'expected'   => VoterInterface::ACCESS_GRANTED,
            ],

            [
                'roles'      => [
                    NodeRef::fromString('acme:role:subscriber'),
                ],
                'attributes' => ['acme:article:publish'],
                'message'    => 'Subscriber should not be able to publish article.',
                'expected'   => VoterInterface::ACCESS_DENIED,
            ],

            [
                'roles'      => [
                    NodeRef::fromString('acme:role:subscriber'),
                ],
                'attributes' => ['acme:article:get'],
                'message'    => 'Subscriber should be able to get article',
                'expected'   => VoterInterface::ACCESS_GRANTED,
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
}
