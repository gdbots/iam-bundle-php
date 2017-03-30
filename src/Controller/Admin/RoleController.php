<?php
declare(strict_types = 1);

namespace Gdbots\Bundle\IamBundle\Controller\Admin;

use Gdbots\Bundle\AppBundle\Controller\DeviceViewRendererTrait;
use Gdbots\Bundle\IamBundle\Form\CreateRoleType;
use Gdbots\Bundle\IamBundle\Form\UpdateRoleType;
use Gdbots\Bundle\IamBundle\Form\RoleType;
use Gdbots\Bundle\PbjxBundle\Controller\PbjxAwareControllerTrait;
use Gdbots\Pbj\MessageResolver;
use Gdbots\Pbj\WellKnown\Identifier;
use Gdbots\Schemas\Common\Enum\Trinary;
use Gdbots\Schemas\Iam\Enum\SearchUsersSort;
use Gdbots\Schemas\Iam\Mixin\CreateRole\CreateRole;
use Gdbots\Schemas\Iam\Mixin\GetRoleRequest\GetRoleRequest;
use Gdbots\Schemas\Iam\Mixin\GetRoleRequest\GetRoleRequestV1Mixin;
use Gdbots\Schemas\Iam\Mixin\ListAllRolesRequest;
use Gdbots\Schemas\Iam\Mixin\UpdateRole\UpdateRole;
use Gdbots\Schemas\Ncr\NodeRef;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\Form\FormError;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class RoleController extends Controller
{
    use DeviceViewRendererTrait;
    use PbjxAwareControllerTrait;

    /**
     * @param Request $request
     *
     * @return Response
     */
    public function listAllAction(Request $request): Response
    {
        $schema = MessageResolver::findOneUsingMixin(GetRoleRequestV1Mixin::create(), 'iam', 'request');
        $this->denyAccessUnlessGranted($schema->getCurie()->toString());

        $roleSchema = RoleType::pbjSchema();
        $nodeRef = NodeRef::fromString("{$roleSchema->getQName()}:{$request->attributes->get('role_id')}");

        /** @var GetUserRequest $getRoleRequest */
        $getRoleRequest = $schema->createMessage()
            ->set('node_ref', $nodeRef)
            ->set('consistent_read', true);

        return $this->renderPbj($this->getPbjx()->request($getRoleRequest)->get('node'));
    }

    /**
     * @param Request $request
     *
     * @return Response
     */
    public function createAction(Request $request): Response
    {
        $schema = CreateRoleType::pbjSchema();
        $this->denyAccessUnlessGranted($schema->getCurie()->toString());

        $form = $this->handlePbjForm($request, CreateRoleType::class);
        /** @var CreateRole $command */
        $command = $schema->createMessage($form->getData());

        if ($form->isSubmitted() && $form->isValid()) {
            try {
                $this->getPbjx()->send($command);
                // fixme: move to event listener to handle flash messages (create symfony events)
                $this->addFlash('success', sprintf(
                    'Role <a href="%s" class="alert-link">%s</a> with id "%s" was created.',
                    $this->generateUrl('gdbots_iam_admin_role_show', ['role_id' => $command->get('node')->get('_id')]),
                    htmlspecialchars($command->get('node')->get('first_name')),
                    $command->get('node')->get('name')
                ));
                return $this->redirectToRoute('gdbots_iam_admin_role_search', ['sort' => SearchUsersSort::CREATED_AT_DESC]);
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
        $schema = MessageResolver::findOneUsingMixin(GetRoleRequestV1Mixin::create(), 'iam', 'request');
        $this->denyAccessUnlessGranted($schema->getCurie()->toString());

        $roleSchema = RoleType::pbjSchema();
        $nodeRef = NodeRef::fromString("{$roleSchema->getQName()}:{$request->attributes->get('role_id')}");

        /** @var GetUserRequest $getRoleRequest */
        $getRoleRequest = $schema->createMessage()
            ->set('node_ref', $nodeRef)
            ->set('consistent_read', true);

        return $this->renderPbj($this->getPbjx()->request($getRoleRequest)->get('node'));
    }

    /**
     * @param Request $request
     *
     * @return Response
     */
    public function updateAction(Request $request): Response
    {
        $schema = UpdateRoleType::pbjSchema();
        $this->denyAccessUnlessGranted($schema->getCurie()->toString());

        $getRoleSchema = MessageResolver::findOneUsingMixin(GetRoleRequestV1Mixin::create(), 'iam', 'request');
        $roleSchema = RoleType::pbjSchema();
        $nodeRef = NodeRef::fromString("{$userSchema->getQName()}:{$request->attributes->get('role_id')}");
        $roleIdField = $roleSchema->getField('_id');
        /** @var Identifier $idClass */
        $idClass = $roleIdField->getClassName();
        $id = $idClass::fromString($nodeRef->getId());
        $input = [];

        if ($request->isMethodSafe()) {
            /** @var GetRoleRequest $getUserRequest */
            $getUserRequest = $getRoleSchema->createMessage()
                ->set('node_ref', $nodeRef)
                ->set('consistent_read', true);
            $input['new_node'] = $this->getPbjx()->request($getUserRequest)->get('node')->toArray();
        }

        $form = $this->handlePbjForm($request, UpdateUserType::class, $input);
        /** @var UpdateRole $command */
        $command = $schema->createMessage($form->getData());
        $command
            ->set('node_ref', $nodeRef)
            ->set('expected_etag', $command->get('new_node')->get('etag'))
            ->get('new_node')->set('_id', $id);

        if ($form->isSubmitted() && $form->isValid()) {
            try {
                $this->getPbjx()->send($command);
                $this->addFlash('success', sprintf(
                    'Role <a href="%s" class="alert-link">%s</a> with id "%s" was updated.',
                    $this->generateUrl('gdbots_iam_admin_role_show', ['role_id' => $id->toString()]),
                    htmlspecialchars($command->get('new_node')->get('label')),
                    $command->get('new_node')->get('label')
                ));
                return $this->redirectToRoute('gdbots_iam_admin_role_show', ['role_id' => $id]);
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
    public function listAction(Request $request): Response
    {
       return null;
    }
}
