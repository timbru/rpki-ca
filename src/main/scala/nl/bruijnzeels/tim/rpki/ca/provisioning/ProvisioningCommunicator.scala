package nl.bruijnzeels.tim.rpki.ca.provisioning

import java.util.UUID

/**
 * Handles identities, communication messages, and validation between
 * this CA and its children
 */
case class ProvisioningCommunicator(me: MyIdentity, children: Map[UUID, ChildIdentity] = Map.empty) {
  
  def applyEvent(event: ProvisioningCommunicatorEvent) = event match {
    case created: ProvisioningCommunicatorCreated => ProvisioningCommunicator(created.myIdentity) 
  }

}

object ProvisioningCommunicator {
  def create(aggregateId: UUID) = ProvisioningCommunicatorCreated(aggregateId, MyIdentity.create(aggregateId))
}