<?php
declare(strict_types=1);

namespace Gdbots\Tests\Bundle\IamBundle;

use Gdbots\Bundle\IamBundle\Security\PbjxPermissionVoter;
use PHPUnit\Framework\TestCase;

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
        $voter = new PbjxPermissionVoter();
    }
}
