<?php
declare(strict_types = 1);

namespace Gdbots\Bundle\IamBundle\Form;

use Gdbots\Bundle\IamBundle\Form\Type\SearchCountType;
use Gdbots\Bundle\IamBundle\Form\Type\SearchTrinaryType;
use Gdbots\Bundle\PbjxBundle\Form\AbstractPbjType;
use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbj\Schema;
use Gdbots\Schemas\Iam\Mixin\SearchUsersRequest\SearchUsersRequestV1Mixin;
use Symfony\Component\Form\FormBuilderInterface;

class SearchUsersRequestType extends AbstractPbjType
{
    /**
     * {@inheritdoc}
     */
    public static function pbjSchema(): Schema
    {
        return MessageResolver::findOneUsingMixin(SearchUsersRequestV1Mixin::create(), 'iam', 'request');
    }

    /**
     * {@inheritdoc}
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $this->buildPbjForm($builder, $options);
        $schema = self::pbjSchema();

        $builder->add('count', SearchCountType::class);
        $builder->add('is_staff', SearchTrinaryType::class);
        $builder->add('is_blocked', SearchTrinaryType::class);

        $sortField = $this->getFormFieldFactory()
            ->create($schema->getField('sort'))
            ->setOption('choices', [
                'relevance'       => 'relevance',
                'created asc'     => 'created-at-asc',
                'created desc'    => 'created-at-desc',
                'updated asc'     => 'updated-at-asc',
                'updated desc'    => 'updated-at-desc',
                'first name asc'  => 'first-name-asc',
                'first name desc' => 'first-name-desc',
                'last name asc'   => 'last-name-asc',
                'last name desc'  => 'last-name-desc',
            ]);
        $builder->add($sortField->getName(), $sortField->getType(), $sortField->getOptions());
    }

    /**
     * {@inheritdoc}
     */
    protected function getIgnoredFields(): array
    {
        return [
            'parsed_query_json',
            'fields_used',
            'count',
            'sort',
            'status',
            'is_staff',
            'is_blocked',
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getHiddenFields(): array
    {
        return ['page'];
    }
}
