<?php
declare(strict_types = 1);

namespace Gdbots\Bundle\IamBundle\Form;

use Gdbots\Bundle\NcrBundle\Form\AbstractNodeType;
use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbj\Schema;
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
        $schema = self::pbjSchema();

        $idField = $schema->getField('_id');
        $formField = $this->getFormFieldFactory()->create($idField);
        $formField->setOption('label', 'Name');
    }
}
