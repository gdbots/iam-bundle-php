<?php
declare(strict_types = 1);

namespace Gdbots\Bundle\IamBundle\Form;

use Gdbots\Bundle\NcrBundle\Form\AbstractNodeType;
use Gdbots\Pbj\Field;
use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbj\Schema;
use Gdbots\Schemas\Common\Enum\PhoneType;
use Gdbots\Schemas\Common\Enum\SocialNetwork;
use Gdbots\Schemas\Iam\Mixin\User\UserV1Mixin;
use Symfony\Component\Form\FormBuilderInterface;

class UserType extends AbstractNodeType
{
    /**
     * {@inheritdoc}
     */
    public static function pbjSchema(): Schema
    {
        return MessageResolver::findOneUsingMixin(UserV1Mixin::create(), 'iam', 'node');
    }

    /**
     * {@inheritdoc}
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $this->buildPbjForm($builder, $options);
        $schema = self::pbjSchema();

        $builder->get('first_name')->setRequired(true);
        $builder->get('email')->setRequired(true);

        $this->createKeyValueField($builder, $schema->getField('phone'), PhoneType::values());
        $this->createKeyValueField($builder, $schema->getField('networks'), SocialNetwork::values());
    }

    /**
     * {@inheritdoc}
     */
    protected function getIgnoredFields(): array
    {
        return array_merge(
            parent::getIgnoredFields(),
            [
                'email_domain',
                'title',
                'roles',
                'phone',
                'networks',
            ]
        );
    }

    /**
     * @param FormBuilderInterface $builder
     * @param Field                $field
     * @param array                $options
     */
    private function createKeyValueField(FormBuilderInterface $builder, Field $field, array $options): void
    {
        unset($options['UNKNOWN']);

        $formField = $this->getFormFieldFactory()->create($field);
        $formField->setOption('entry_options',
            array_merge(
                $formField->getOptions()['entry_options'],
                ['allowed_keys' => $options]
            )
        );

        $builder->add($formField->getName(), $formField->getType(), $formField->getOptions());
    }
}
