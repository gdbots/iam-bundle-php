<?php
declare(strict_types = 1);

namespace Gdbots\Bundle\IamBundle\Form;

use Gdbots\Bundle\PbjxBundle\Form\AbstractPbjType;
use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbj\Schema;
use Gdbots\Schemas\Iam\Mixin\ListAllRolesRequest\ListAllRolesRequestV1Mixin;
use Symfony\Component\Form\FormBuilderInterface;

class RolesCollectionType extends AbstractPbjType
{
    /**
     * {@inheritdoc}
     */
    public static function pbjSchema(): Schema
    {
        return MessageResolver::findOneUsingMixin(ListAllRolesRequestV1Mixin::create(), 'iam', 'node');
    }

    /**
     * {@inheritdoc}
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $this->buildPbjForm($builder, $options);
        $schema = self::pbjSchema();

        $rolesField = $this->getFormFieldFactory()->create($schema->getField('roles'));
        $builder->add($rolesField->getName(), $rolesField->getType(), $rolesField->getOptions());
    }
}
