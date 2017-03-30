<?php
declare(strict_types = 1);

namespace Gdbots\Bundle\IamBundle\Form;

use Gdbots\Bundle\PbjxBundle\Form\AbstractPbjType;
use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbj\Schema;
use Gdbots\Schemas\Iam\Mixin\UpdateRole\UpdateRoleV1Mixin;
use Symfony\Component\Form\FormBuilderInterface;

class UpdateRoleType extends AbstractPbjType
{
    /**
     * {@inheritdoc}
     */
    public static function pbjSchema(): Schema
    {
        return MessageResolver::findOneUsingMixin(UpdateRoleV1Mixin::create(), 'iam', 'command');
    }

    /**
     * {@inheritdoc}
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $this->buildPbjForm($builder, $options);
        $builder->add('new_node', RoleType::class);
    }

    /**
     * {@inheritdoc}
     */
    protected function getIgnoredFields(): array
    {
        return ['node_ref', 'old_node', 'new_node'];
    }
}
