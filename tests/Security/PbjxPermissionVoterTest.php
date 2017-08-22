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

    protected function setup()
    {
        $this->locator = new RegisteringServiceLocator();
        $this->pbjx = $this->locator->getPbjx();
        $this->eventStore = new InMemoryEventStore($this->pbjx);
        $this->locator->setEventStore($this->eventStore);
        $this->ncr = new InMemoryNcr();
    }

    /**
     * @dataProvider getVoteSamples
     *
     * @param string $name
     * @param array $attributes
     * @param array $roles
     * @param UserV1 $userNode
     * @param int $expected
     */
    public function testVote(string $name, array $attributes = [], array $roles = [], UserV1 $userNode, int $expected)
    {
        $roleNodeRefs = [];
        foreach ($roles as $role) {
            $roleNodeRefs[] = NodeRef::fromNode($role);
            $this->ncr->putNode($role);
            var_dump(json_encode($role));
        }

        $user = new User($userNode->addToSet('roles', $roleNodeRefs));
        $token = new ConcreteToken($user, $user->getRoles());

        $voter = new PbjxPermissionVoter($this->pbjx, $this->ncr);
        $this->assertEquals($expected, $voter->vote($token, 0, $attributes), "Test [{$name}] Failed");
    }

    public function getVoteSamples()
    {
        return [
            [
                'name'          => 'simple exact match allow',
                'attributes'    => ['acme:blog:command:create-article'],
                'roles'         => [
                    RoleV1::create()
                        ->set('_id', RoleId::fromString('test1'))
                        ->addToSet('allowed', ['acme:blog:command:create-article', 'acme:blog:command:edit-article']),
                ],
                'userNode'      => UserV1::create()
                                    ->set('_id', UserId::fromString('a9b1288a-83b7-11e7-bb31-be2e44b06b34')),
                'expected'      => VoterInterface::ACCESS_GRANTED,
            ],

            [
                'name'          => 'simple exact match deny',
                'attributes'    => ['acme:blog:command:create-article'],
                'roles'    => [
                    RoleV1::create()
                        ->set('_id', RoleId::fromString('test1'))
                        ->addToSet('allowed', ['acme:blog:command:create-article', 'acme:blog:command:edit-article'])
                        ->addToSet('denied', ['acme:blog:command:create-article']),
                ],
                'userNode'      => UserV1::create()
                                    ->set('_id', UserId::fromString('a9b1288a-83b7-11e7-bb31-be2e44b06b34')),
                'expected'      => VoterInterface::ACCESS_DENIED,
            ],

            [
                'name'          => 'message level wildcard',
                'attributes'    => ['acme:blog:command:create-article'],
                'roles'         => [
                    RoleV1::create()
                        ->set('_id', RoleId::fromString('test1'))
                        ->addToSet('allowed', ['acme:blog:command:*']),
                ],
                'userNode'      => UserV1::create()
                                    ->set('_id', UserId::fromString('a9b1288a-83b7-11e7-bb31-be2e44b06b34')),
                'expected'      => VoterInterface::ACCESS_GRANTED,
            ],

            [
                'name'          => 'category level wildcard',
                'attributes'    => ['acme:blog:command:create-article'],
                'roles'         => [
                    RoleV1::create()
                        ->set('_id', RoleId::fromString('test1'))
                        ->addToSet('allowed', ['acme:blog:*']),
                ],
                'userNode'      => UserV1::create()
                                    ->set('_id', UserId::fromString('a9b1288a-83b7-11e7-bb31-be2e44b06b34')),
                'expected'      => VoterInterface::ACCESS_GRANTED,
            ],

            [
                'name'          => 'category level wildcard with deny on commands',
                'attributes'    => ['acme:blog:command:create-article'],
                'roles'         => [
                    RoleV1::create()
                        ->set('_id', RoleId::fromString('test1'))
                        ->addToSet('allowed', ['acme:blog:*'])
                        ->addToSet('denied', ['acme:blog:command:*']),
                ],
                'userNode'      => UserV1::create()
                                    ->set('_id', UserId::fromString('a9b1288a-83b7-11e7-bb31-be2e44b06b34')),
                'expected'      => VoterInterface::ACCESS_DENIED,
            ],

            [
                'name'          => 'category level wildcard with set of denies on commands',
                'attributes'    => ['acme:blog:command:delete-article'],
                'roles'         => [
                    RoleV1::create()
                        ->set('_id', RoleId::fromString('test1'))
                        ->addToSet('allowed', ['acme:blog:*', 'acme:blog:*'])
                        ->addToSet('denied', ['acme:blog:command:create-article', 'acme:blog:command:edit-article']),
                ],
                'userNode'      => UserV1::create()
                                    ->set('_id', UserId::fromString('a9b1288a-83b7-11e7-bb31-be2e44b06b34')),
                'expected'      => VoterInterface::ACCESS_GRANTED,
            ],

            [
                'name'          => 'top level wildcard allowed',
                'attributes'    => ['acme:blog:create-article'],
                'roles'         => [
                    RoleV1::create()
                        ->set('_id', RoleId::fromString('test1'))
                        ->addToSet('allowed', ['*']),
                ],
                'userNode'      => UserV1::create()
                                    ->set('_id', UserId::fromString('a9b1288a-83b7-11e7-bb31-be2e44b06b34')),
                'expected'      => VoterInterface::ACCESS_GRANTED,
            ],

            [
                'name'          => 'top level wildcard allowed with deny on package level',
                'attributes'    => ['acme:blog:request:get-userid'],
                'roles'         => [
                    RoleV1::create()
                        ->set('_id', RoleId::fromString('test1'))
                        ->addToSet('allowed', ['*'])
                        ->addToSet('denied', ['acme:blog:*']),
                ],
                'userNode'      => UserV1::create()
                                    ->set('_id', UserId::fromString('a9b1288a-83b7-11e7-bb31-be2e44b06b34')),
                'expected'      => VoterInterface::ACCESS_DENIED,
            ],

            [
                'name'          => 'action allowed with deny on command level',
                'attributes'    => ['acme:blog:command:create-article'],
                'roles'         => [
                    RoleV1::create()
                        ->set('_id', RoleId::fromString('test1'))
                        ->addToSet('allowed', ['acme:blog:command:create-article'])
                        ->addToSet('denied', ['acme:blog:command:*']),
                ],
                'userNode'      => UserV1::create()
                                    ->set('_id', UserId::fromString('a9b1288a-83b7-11e7-bb31-be2e44b06b34')),
                'expected'      => VoterInterface::ACCESS_DENIED,
            ],
        ];
    }
}
