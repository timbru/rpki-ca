package nl.bruijnzeels.tim.rpki.ca.provisioning

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import java.util.UUID
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject

sealed trait ProvisioningCommunicatorEvent extends Event

case class ProvisioningCommunicatorCreated(myIdentity: MyIdentity) extends ProvisioningCommunicatorEvent

case class ProvisioningCommunicatorAddedChild(childIdentity: ChildIdentity) extends ProvisioningCommunicatorEvent
case class ProvisioningCommunicatorPerformedChildExchange(exchange: ProvisioningChildExchange) extends ProvisioningCommunicatorEvent
case class ProvisioningChildExchange(childId: UUID, request: ProvisioningCmsObject, response: ProvisioningCmsObject)

case class ProvisioningCommunicatorAddedParent(parentIdentity: ParentIdentity) extends ProvisioningCommunicatorEvent
case class ProvisioningCommunicatorPerformedParentExchange(exchange: ProvisioningParentExchange) extends ProvisioningCommunicatorEvent
case class ProvisioningParentExchange(request: ProvisioningCmsObject, response: ProvisioningCmsObject)