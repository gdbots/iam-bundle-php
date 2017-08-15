<?php
declare(strict_types=1);

namespace Gdbots\Tests\Bundle\IamBundle;

use Gdbots\Bundle\IamBundle\Security\PbjxPermissionVoter;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Pbjx\EventStore\InMemoryEventStore;
use Gdbots\Pbjx\RegisteringServiceLocator;
use Gdbots\Ncr\Repository\InMemoryNcr;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;

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
        $firewall = 'secured_area';
        $token = new UsernamePasswordToken('admin', null, $firewall, array('ROLE_ADMIN'));
        $subject = '';
        $attributes = ['acme:blog:command:create-article'];
        $expected = true;

        $this->decisionManager = new class implements AccessDecisionManagerInterface
        {
            public function decide(TokenInterface $token, array $attributes, $object = null)
            {
                return true;
            }
        };

        $voter = new PbjxPermissionVoter($this->decisionManager, $this->pbjx);
        $this->assertEquals($expected, $voter->vote($token, $subject, $attributes));
    }
}
