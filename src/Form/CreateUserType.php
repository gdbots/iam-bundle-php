<?php
declare(strict_types = 1);

namespace Gdbots\Bundle\IamBundle\Form;

use Gdbots\Bundle\PbjxBundle\Form\AbstractPbjType;
use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbj\Schema;
use Gdbots\Schemas\Iam\Mixin\CreateUser\CreateUserV1Mixin;
use Symfony\Component\Form\FormBuilderInterface;

class CreateUserType extends AbstractPbjType
{
    /**
     * {@inheritdoc}
     */
    public static function pbjSchema(): Schema
    {
        return MessageResolver::findOneUsingMixin(CreateUserV1Mixin::create(), 'iam', 'command');
    }

    /**
     * {@inheritdoc}
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $this->buildPbjForm($builder, $options);
        $builder->add('node', UserType::class);
        $builder->get('node')
            ->remove('_id')
            ->remove('status')
            ->remove('phone')
            ->remove('networks')
            ->remove('is_blocked');
    }

    /**
     * {@inheritdoc}
     */
    protected function getIgnoredFields(): array
    {
        return ['node'];
    }
}
