package nl.bruijnzeels.tim.rpki.ca.provisioning

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import java.util.UUID
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject

sealed trait ProvisioningCommunicatorEvent extends Event

case class ProvisioningCommunicatorCreated(aggregateId: UUID, myIdentity: MyIdentity) extends ProvisioningCommunicatorEvent

case class ProvisioningCommunicatorAddedChild(aggregateId: UUID, childIdentity: ChildIdentity) extends ProvisioningCommunicatorEvent
case class ProvisioningCommunicatorPerformedChildExchange(aggregateId: UUID, exchange: ProvisioningChildExchange) extends ProvisioningCommunicatorEvent
case class ProvisioningChildExchange(childId: UUID, request: ProvisioningCmsObject, response: ProvisioningCmsObject)

case class ProvisioningCommunicatorAddedParent(aggregateId: UUID, parentIdentity: ParentIdentity) extends ProvisioningCommunicatorEvent
case class ProvisioningCommunicatorPerformedParentExchange(aggregateId: UUID, exchange: ProvisioningParentExchange) extends ProvisioningCommunicatorEvent
case class ProvisioningParentExchange(request: ProvisioningCmsObject, response: ProvisioningCmsObject)