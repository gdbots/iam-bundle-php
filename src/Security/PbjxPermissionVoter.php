<?php
declare(strict_types=1);

namespace Gdbots\Bundle\IamBundle\Security;

use Gdbots\Iam\Policy;
use Gdbots\Pbj\Message;
use Gdbots\Pbjx\Pbjx;
use Gdbots\Schemas\Ncr\Request\GetNodeBatchRequestV1;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

class PbjxPermissionVoter extends Voter
{
    protected Pbjx $pbjx;
    protected CacheItemPoolInterface $cache;

    /**
     * Array of curies already checked for permission. Key is the curie of the
     * message, value is the result
     *
     * @var bool[]
     */
    protected array $checked = [];

    protected ?Policy $policy = null;

    /**
     * Amount of time in seconds the policy will be cached.
     */
    protected int $policyTtl;

    public function __construct(Pbjx $pbjx, CacheItemPoolInterface $cache, int $policyTtl = 300)
    {
        $this->pbjx = $pbjx;
        $this->cache = $cache;
        $this->policyTtl = $policyTtl;
    }

    protected function supports(string $attribute, mixed $subject): bool
    {
        return $subject instanceof Message || preg_match('/^[a-z0-9-]+:([a-z0-9\.-]+:){1,2}[\w\/\.:-]*$/', $attribute);
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
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

    protected function getPolicy(User $user): Policy
    {
        if (null !== $this->policy) {
            return $this->policy;
        }

        $node = $user->getNode();
        if (!$node->has('roles')) {
            // make an empty policy with no permissions
            return $this->policy = new Policy();
        }

        $cacheItem = $this->cache->getItem($this->getPolicyCacheKey($node));
        if ($cacheItem->isHit()) {
            $policy = $cacheItem->get();
            if ($policy instanceof Policy) {
                return $this->policy = $policy;
            }
        }

        $this->policy = new Policy($this->getUsersRoles($node));
        $cacheItem->set($this->policy)->expiresAfter($this->policyTtl);
        $this->cache->saveDeferred($cacheItem);

        return $this->policy;
    }

    /**
     * This must be compliant with psr6 "Key" definition.
     *
     * @link http://www.php-fig.org/psr/psr-6/#definitions
     *
     * The ".php" suffix here is used because the cache item
     * will be stored as serialized php.
     *
     * @param Message $node
     *
     * @return string
     */
    protected function getPolicyCacheKey(Message $node): string
    {
        // because the policy is really based on the roles we'll cache
        // it based on that, not the user.
        $roles = array_map('strval', $node->get('roles', []));
        sort($roles);
        $hash = md5(implode('', $roles));
        return "policy.{$hash}.php";
    }

    /**
     * @param Message $node
     *
     * @return Message[]
     */
    protected function getUsersRoles(Message $node): array
    {
        try {
            $request = GetNodeBatchRequestV1::create()
                ->addToSet('node_refs', $node->get('roles', []));
            $request->set('ctx_causator_ref', $request->generateMessageRef());
            return $this->pbjx->request($request)->get('nodes', []);
        } catch (\Throwable $e) {
            return [];
        }
    }
}
