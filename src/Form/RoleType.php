<?php
declare(strict_types = 1);

namespace Gdbots\Bundle\IamBundle\Form;

use Gdbots\Bundle\NcrBundle\Form\AbstractNodeType;
use Gdbots\Bundle\PbjxBundle\Form\Type\CollectionType;
use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbj\Schema;
use Gdbots\Pbj\Type\TextType;
use Gdbots\Schemas\Iam\Mixin\Role\RoleV1Mixin;
use Symfony\Component\Form\FormBuilderInterface;

class RoleType extends AbstractNodeType
{
    /**
     * {@inheritdoc}
     */
    public static function pbjSchema(): Schema
    {
        return MessageResolver::findOneUsingMixin(RoleV1Mixin::create(), 'iam', 'node');
    }

    /**
     * {@inheritdoc}
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $this->buildPbjForm($builder, $options);

        $builder->get('_id')->setRequired(true);
        $builder->add('allowed', CollectionType::class, [
            'entry_type' => TextType::class,
            'allow_add' => true,
            'allow_delete' => true,
            'prototype' => true
        ]);
        $builder->add('denied', CollectionType::class, [
            'entry_type' => TextType::class,
            'allow_add' => true,
            'allow_delete' => true,
            'prototype' => true
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getIgnoredFields(): array
    {
        return array_merge(
            parent::getIgnoredFields(),
            [
                'allowed',
                'denied',
            ]
        );
    }
}
