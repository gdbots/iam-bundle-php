<?php
declare(strict_types = 1);

namespace Gdbots\Bundle\IamBundle\Form;

use Gdbots\Bundle\PbjxBundle\Form\AbstractPbjType;
use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbj\Schema;
use Gdbots\Schemas\Iam\Mixin\CreateRole\CreateRoleV1Mixin;
use Symfony\Component\Form\FormBuilderInterface;

class CreateRoleType extends AbstractPbjType
{
    /**
     * {@inheritdoc}
     */
    public static function pbjSchema(): Schema
    {
        return MessageResolver::findOneUsingMixin(CreateRoleV1Mixin::create(), 'iam', 'command');
    }

    /**
     * {@inheritdoc}
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $this->buildPbjForm($builder, $options);
        $builder->add('node', RoleType::class);
        $builder->get('node')->remove('status');
    }

    /**
     * {@inheritdoc}
     */
    protected function getIgnoredFields(): array
    {
        return ['node'];
    }
}
