package nl.bruijnzeels.tim.rpki.ca.provisioning

import java.util.UUID
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject
import net.ripe.rpki.commons.provisioning.identity.ChildIdentitySerializer
import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload
import net.ripe.rpki.commons.provisioning.x509.ProvisioningCmsCertificateBuilder

/**
 * Handles identities, communication messages, and validation between
 * this CA and its children
 */
case class ProvisioningCommunicator(me: MyIdentity, children: Map[UUID, ChildIdentity] = Map.empty, exchanges: List[ProvisioningChildExchange] = List.empty) {
  
  def applyEvent(event: ProvisioningCommunicatorEvent) = event match {
    case created: ProvisioningCommunicatorCreated => ProvisioningCommunicator(created.myIdentity)
    case childAdded: ProvisioningCommunicatorAddedChild => copy(children = children + (childAdded.childIdentity.childId -> childAdded.childIdentity))
    case exchange: ProvisioningCommunicatorPerformedChildExchange => copy(exchanges = exchanges :+ exchange.exchange)
  }
  
  private def validateChildDoesNotExist(childId: UUID) = if (children.isDefinedAt(childId)) { throw new IllegalArgumentException(s"Child with id $childId} should not exist")}
  private def getChild(childId: UUID) = children.get(childId).get
  
  def addChild(aggregateId: UUID, childId: UUID, childXml: String) = {
    validateChildDoesNotExist(childId)
    val childCert = new ChildIdentitySerializer().deserialize(childXml).getIdentityCertificate()
    val childIdentity = ChildIdentity(childId, childCert)
    ProvisioningCommunicatorAddedChild(aggregateId, childIdentity)
  }
  
  def validateMessage(childId: UUID, cmsObject: ProvisioningCmsObject) = children.get(childId) match {
    case None => ProvisioningMessageValidationFailure("Unknown child")
    case Some(child) => child.validateMessage(cmsObject)
  }
  
  def signResponse(childId: UUID, payload: AbstractProvisioningPayload) = me.createProvisioningCms(childId.toString, payload)
  
  def getExchangesForChild(childId: UUID) = exchanges.filter(_.childId == childId)
  
  
  

}

object ProvisioningCommunicator {
  def create(aggregateId: UUID) = ProvisioningCommunicatorCreated(aggregateId, MyIdentity.create(aggregateId))
}