package nl.bruijnzeels.tim.rpki.ca.provisioning

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import java.util.UUID

sealed trait ProvisioningCommunicatorEvent extends Event

case class ProvisioningCommunicatorCreated(aggregateId: UUID, myIdentity: MyIdentity) extends ProvisioningCommunicatorEvent
