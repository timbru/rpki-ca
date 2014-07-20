package nl.bruijnzeels.tim.rpki.ca.provisioning

import java.util.UUID
import net.ripe.rpki.commons.provisioning.identity.ChildIdentitySerializer

/**
 * Handles identities, communication messages, and validation between
 * this CA and its children
 */
case class ProvisioningCommunicator(me: MyIdentity, children: Map[UUID, ChildIdentity] = Map.empty) {
  
  def applyEvent(event: ProvisioningCommunicatorEvent) = event match {
    case created: ProvisioningCommunicatorCreated => ProvisioningCommunicator(created.myIdentity)
    case childAdded: ProvisioningCommunicatorAddedChild => copy(children = children + (childAdded.childIdentity.childId -> childAdded.childIdentity))
  }
  
  private def validateChildDoesNotExist(childId: UUID) = if (children.isDefinedAt(childId)) { throw new IllegalArgumentException(s"Child with id $childId} should not exist")}
  private def getChild(childId: UUID) = children.get(childId).get
  
  def addChild(aggregateId: UUID, childId: UUID, childXml: String) = {
    validateChildDoesNotExist(childId)
    val childCert = new ChildIdentitySerializer().deserialize(childXml).getIdentityCertificate()
    val childIdentity = ChildIdentity(childId, childCert)
    ProvisioningCommunicatorAddedChild(aggregateId, childIdentity)
  }

}

object ProvisioningCommunicator {
  def create(aggregateId: UUID) = ProvisioningCommunicatorCreated(aggregateId, MyIdentity.create(aggregateId))
}