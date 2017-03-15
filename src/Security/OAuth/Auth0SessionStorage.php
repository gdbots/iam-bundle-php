<?php
declare(strict_types = 1);

namespace Gdbots\Bundle\IamBundle\Security\OAuth;

use HWI\Bundle\OAuthBundle\OAuth\RequestDataStorage\SessionStorage;
use HWI\Bundle\OAuthBundle\OAuth\ResourceOwnerInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

final class Auth0SessionStorage extends SessionStorage
{
    /** @var SessionInterface */
    private $session;

    /**
     * @param SessionInterface $session
     */
    public function __construct(SessionInterface $session)
    {
        $this->session = $session;
        parent::__construct($session);
    }

    /**
     * In our symfony app, using auth0 lock means symfony isn't generating the
     * authorize_url and so the csrf is scoped all mutant.
     *
     * This scopes it to where symfony is saving it in the session, and the actual
     * token is stored in the value, not as apart of they key name.
     *
     * {@inheritdoc}
     */
    protected function generateKey(ResourceOwnerInterface $resourceOwner, $key, $type)
    {
        return sprintf('_csrf/%s.%s.%s', $resourceOwner->getName(), $resourceOwner->getOption('client_id'), $type);
    }
}
