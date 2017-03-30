<?php
declare(strict_types = 1);

namespace Gdbots\Bundle\IamBundle\Controller\Admin;

use Gdbots\Bundle\AppBundle\Controller\DeviceViewRendererTrait;
use Gdbots\Bundle\IamBundle\Form\CreateUserType;
use Gdbots\Bundle\IamBundle\Form\SearchUsersRequestType;
use Gdbots\Bundle\IamBundle\Form\UpdateUserType;
use Gdbots\Bundle\IamBundle\Form\UserType;
use Gdbots\Bundle\PbjxBundle\Controller\PbjxAwareControllerTrait;
use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbj\WellKnown\Identifier;
use Gdbots\Schemas\Common\Enum\Trinary;
use Gdbots\Schemas\Iam\Enum\SearchUsersSort;
use Gdbots\Schemas\Iam\Mixin\CreateUser\CreateUser;
use Gdbots\Schemas\Iam\Mixin\GetUserRequest\GetUserRequest;
use Gdbots\Schemas\Iam\Mixin\GetUserRequest\GetUserRequestV1Mixin;
use Gdbots\Schemas\Iam\Mixin\SearchUsersRequest\SearchUsersRequest;
use Gdbots\Schemas\Iam\Mixin\UpdateUser\UpdateUser;
use Gdbots\Schemas\Ncr\NodeRef;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\Form\FormError;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class UserController extends Controller
{
    use DeviceViewRendererTrait;
    use PbjxAwareControllerTrait;

    /**
     * @param Request $request
     *
     * @return Response
     */
    public function searchAction(Request $request): Response
    {
        $schema = SearchUsersRequestType::pbjSchema();
        $this->denyAccessUnlessGranted($schema->getCurie()->toString());

        $input = $request->query->all();
        $input['is_blocked'] = $request->query->getInt('is_blocked', Trinary::FALSE_VAL);

        $form = $this->handlePbjForm($request, SearchUsersRequestType::class, $input);
        /** @var SearchUsersRequest $searchRequest */
        $searchRequest = $schema->createMessage($form->getData());
        $searchResponse = $this->getPbjx()->request($searchRequest);

        return $this->renderPbjForm($searchResponse, $form->createView());
    }

    /**
     * @param Request $request
     *
     * @return Response
     */
    public function createAction(Request $request): Response
    {
        $schema = CreateUserType::pbjSchema();
        $this->denyAccessUnlessGranted($schema->getCurie()->toString());

        $form = $this->handlePbjForm($request, CreateUserType::class);
        /** @var CreateUser $command */
        $command = $schema->createMessage($form->getData());

        if ($form->isSubmitted() && $form->isValid()) {
            try {
                $this->getPbjx()->send($command);
                // fixme: move to event listener to handle flash messages (create symfony events)
                $this->addFlash('success', sprintf(
                    'User <a href="%s" class="alert-link">%s</a> with email "%s" was created.',
                    $this->generateUrl('gdbots_iam_admin_user_show', ['user_id' => $command->get('node')->get('_id')]),
                    htmlspecialchars($command->get('node')->get('first_name')),
                    $command->get('node')->get('email')
                ));
                return $this->redirectToRoute('gdbots_iam_admin_user_search', ['sort' => SearchUsersSort::CREATED_AT_DESC]);
            } catch (\Exception $e) {
                $form->addError(new FormError($e->getMessage()));
            }
        }

        return $this->renderPbjForm($command, $form->createView());
    }

    /**
     * @param Request $request
     *
     * @return Response
     */
    public function showAction(Request $request): Response
    {
        $schema = MessageResolver::findOneUsingMixin(GetUserRequestV1Mixin::create(), 'iam', 'request');
        $this->denyAccessUnlessGranted($schema->getCurie()->toString());

        $userSchema = UserType::pbjSchema();
        $nodeRef = NodeRef::fromString("{$userSchema->getQName()}:{$request->attributes->get('user_id')}");

        /** @var GetUserRequest $getUserRequest */
        $getUserRequest = $schema->createMessage()
            ->set('node_ref', $nodeRef)
            ->set('consistent_read', true);

        return $this->renderPbj($this->getPbjx()->request($getUserRequest)->get('node'));
    }

    /**
     * @param Request $request
     *
     * @return Response
     */
    public function updateAction(Request $request): Response
    {
        $schema = UpdateUserType::pbjSchema();
        $this->denyAccessUnlessGranted($schema->getCurie()->toString());

        $getUserSchema = MessageResolver::findOneUsingMixin(GetUserRequestV1Mixin::create(), 'iam', 'request');
        $userSchema = UserType::pbjSchema();
        $nodeRef = NodeRef::fromString("{$userSchema->getQName()}:{$request->attributes->get('user_id')}");
        $userIdField = $userSchema->getField('_id');
        /** @var Identifier $idClass */
        $idClass = $userIdField->getClassName();
        $id = $idClass::fromString($nodeRef->getId());
        $input = [];

        if ($request->isMethodSafe()) {
            /** @var GetUserRequest $getUserRequest */
            $getUserRequest = $getUserSchema->createMessage()
                ->set('node_ref', $nodeRef)
                ->set('consistent_read', true);
            $input['new_node'] = $this->getPbjx()->request($getUserRequest)->get('node')->toArray();
        }

        $form = $this->handlePbjForm($request, UpdateUserType::class, $input);
        /** @var UpdateUser $command */
        $command = $schema->createMessage($form->getData());
        $command
            ->set('node_ref', $nodeRef)
            ->set('expected_etag', $command->get('new_node')->get('etag'))
            ->get('new_node')->set('_id', $id);

        if ($form->isSubmitted() && $form->isValid()) {
            try {
                $this->getPbjx()->send($command);
                $this->addFlash('success', sprintf(
                    'User <a href="%s" class="alert-link">%s</a> with email "%s" was updated.',
                    $this->generateUrl('gdbots_iam_admin_user_show', ['user_id' => $id->toString()]),
                    htmlspecialchars($command->get('new_node')->get('first_name')),
                    $command->get('new_node')->get('email')
                ));
                return $this->redirectToRoute('gdbots_iam_admin_user_search', ['sort' => SearchUsersSort::UPDATED_AT_DESC]);
            } catch (\Exception $e) {
                $form->addError(new FormError($e->getMessage()));
            }
        }

        return $this->renderPbjForm($command, $form->createView());
    }

    /**
     * @param Request $request
     *
     * @return Response
     */
    public function deleteAction(Request $request): Response
    {
        $schema = DeleteUserType::pbjSchema();
        $schema = MessageResolver::findOneUsingMixin(GetUserRequestV1Mixin::create(), 'iam', 'request');

    }
}
