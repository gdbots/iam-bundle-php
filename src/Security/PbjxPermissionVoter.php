<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Gdbots\Iam\Policy;
use Gdbots\Pbj\SchemaCurie;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Schemas\Iam\Mixin\Role\Role;
use Gdbots\Schemas\Iam\Mixin\User\User as UserNode;
use Gdbots\Schemas\Ncr\Mixin\GetNodeBatchRequest\GetNodeBatchRequest;
use Gdbots\Schemas\Ncr\Request\GetNodeBatchRequestV1;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

class PbjxPermissionVoter extends Voter
{
    /** @var Pbjx */
    protected $pbjx;

    /** @var CacheItemPoolInterface */
    protected $cache;

    /** @var RequestStack */
    protected $requestStack;

    /**
     * Array of curies already checked for permission.  Key is the curie of the
     * message, value is the result
     *
     * @var bool[]
     */
    protected $checked = [];

    /** @var Policy */
    protected $policy = null;

    /**
     * Amount of time in seconds the policy will be cached.
     *
     * @var int
     */
    protected $policyTtl = 300;

    /**
     * @param Pbjx                   $pbjx
     * @param CacheItemPoolInterface $cache
     * @param RequestStack           $requestStack
     * @param int                    $policyTtl
     */
    public function __construct(
        Pbjx $pbjx,
        CacheItemPoolInterface $cache,
        RequestStack $requestStack,
        int $policyTtl = 300
    ) {
        $this->pbjx = $pbjx;
        $this->cache = $cache;
        $this->requestStack = $requestStack;
        $this->policyTtl = $policyTtl;
    }

    /**
     * {@inheritdoc}
     */
    protected function supports($attribute, $subject)
    {
        if (!is_string($attribute)) {
            return false;
        }

        return preg_match(SchemaCurie::VALID_PATTERN, $attribute);
    }

    /**
     * {@inheritdoc}
     */
    protected function voteOnAttribute($attribute, $subject, TokenInterface $token)
    {
        if (isset($this->checked[$attribute])) {
            return $this->checked[$attribute];
        }

        $user = $token->getUser();
        if (!$user instanceof User) {
            return $this->checked[$attribute] = false;
        }

        return $this->checked[$attribute] = $this->getPolicy($user)->isGranted($attribute);
    }

    /**
     * @param User $user
     *
     * @return Policy
     */
    protected function getPolicy(User $user): Policy
    {
        if (null !== $this->policy) {
            return $this->policy;
        }

        $node = $user->getUserNode();
        if (!$node->has('roles')) {
            // make an empty policy with no permissions
            return $this->policy = new Policy();
        }

        $symfonyRequest = $this->requestStack->getCurrentRequest();
        $cacheItem = $this->cache->getItem($this->getPolicyCacheKey($symfonyRequest, $node));
        if ($cacheItem->isHit()) {
            $policy = $cacheItem->get();
            if ($policy instanceof Policy) {
                return $this->policy = $policy;
            }
        }

        $symfonyRequest->attributes->set('iam_bypass_permissions', true);
        $this->policy = new Policy($this->getUsersRoles($symfonyRequest, $node));
        $symfonyRequest->attributes->remove('iam_bypass_permissions');

        $cacheItem->set($this->policy)->expiresAfter($this->policyTtl);
        $this->cache->saveDeferred($cacheItem);

        return $this->policy;
    }

    /**
     * Returns the policy cache key to use for the provided
     * Symfony request and the current user.
     *
     * This must be compliant with psr6 "Key" definition.
     *
     * @link http://www.php-fig.org/psr/psr-6/#definitions
     *
     * The ".php" suffix here is used because the cache item
     * will be stored as serialized php.
     *
     * @param Request  $symfonyRequest
     * @param UserNode $node
     *
     * @return string
     */
    protected function getPolicyCacheKey(Request $symfonyRequest, UserNode $node): string
    {
        // because the policy is really based on the roles we'll cache
        // it based on that, not the user.
        $roles = array_map('strval', $node->get('roles', []));
        sort($roles);
        $hash = md5(implode('', $roles));
        return "policy.{$hash}.php";
    }

    /**
     * @param Request  $symfonyRequest
     * @param UserNode $node
     *
     * @return Role[]
     */
    protected function getUsersRoles(Request $symfonyRequest, UserNode $node): array
    {
        try {
            $request = $this->createGetRoleBatchRequest($symfonyRequest, $node)
                ->addToSet('node_refs', $node->get('roles', []));
            return $this->pbjx->request($request)->get('nodes', []);
        } catch (\Throwable $e) {
            return [];
        }
    }

    /**
     * @param Request  $symfonyRequest
     * @param UserNode $node
     *
     * @return GetNodeBatchRequest
     */
    protected function createGetRoleBatchRequest(Request $symfonyRequest, UserNode $node): GetNodeBatchRequest
    {
        // override if you need to customize the request (e.g. multi-tenant apps)
        return GetNodeBatchRequestV1::create();
    }
}
