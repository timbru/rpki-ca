package nl.bruijnzeels.tim.rpki.ca.provisioning

import java.util.UUID
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject
import net.ripe.rpki.commons.provisioning.identity.ChildIdentitySerializer
import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload
import net.ripe.rpki.commons.provisioning.x509.ProvisioningCmsCertificateBuilder
import java.net.URI

/**
 * Handles identities, communication messages, and validation between
 * this CA and its children
 */
case class ProvisioningCommunicator(me: MyIdentity, parent: Option[ParentIdentity] = None, children: Map[UUID, ChildIdentity] = Map.empty, childExchanges: List[ProvisioningChildExchange] = List.empty) {

  val UpDownUri = URI.create("http://invalid.com/") // TODO.. won't use http for now..

  def applyEvent(event: ProvisioningCommunicatorEvent) = event match {
    case created: ProvisioningCommunicatorCreated => ProvisioningCommunicator(created.myIdentity)
    
    case childAdded: ProvisioningCommunicatorAddedChild => copy(children = children + (childAdded.childIdentity.childId -> childAdded.childIdentity))
    case childExchangePerformed: ProvisioningCommunicatorPerformedChildExchange => copy(childExchanges = childExchanges :+ childExchangePerformed.exchange)
    
    case parentAdded: ProvisioningCommunicatorAddedParent => copy(parent = Some(parentAdded.parentIdentity))
  }

  private def validateChildDoesNotExist(childId: UUID) = if (children.isDefinedAt(childId)) { throw new IllegalArgumentException(s"Child with id $childId} should not exist") }
  private def getChild(childId: UUID) = children.get(childId).get

  def addChild(aggregateId: UUID, childId: UUID, childXml: String) = {
    validateChildDoesNotExist(childId)
    val childCert = new ChildIdentitySerializer().deserialize(childXml).getIdentityCertificate()
    val childIdentity = ChildIdentity(childId, childCert)
    ProvisioningCommunicatorAddedChild(aggregateId, childIdentity)
  }
  
  def addParent(aggregateId: UUID, parentXml: String) = ProvisioningCommunicatorAddedParent(aggregateId, ParentIdentity.fromXml(parentXml))

  def validateMessage(childId: UUID, cmsObject: ProvisioningCmsObject) = children.get(childId) match {
    case None => ProvisioningMessageValidationFailure("Unknown child")
    case Some(child) => child.validateMessage(cmsObject)
  }

  def signResponse(childId: UUID, payload: AbstractProvisioningPayload) = me.createProvisioningCms(childId.toString, payload)

  def getExchangesForChild(childId: UUID) = childExchanges.filter(_.childId == childId)

  def getParentXmlForChild(childId: UUID) = {
    import net.ripe.rpki.commons.provisioning.identity._

    children.get(childId).map { child =>
      val childCert = child.identityCertificate
      val parentCert = me.identityCertificate
      val parentIdentity = new ParentIdentity(UpDownUri, me.id.toString, childId.toString, parentCert, childCert)
      new ParentIdentitySerializer().serialize(parentIdentity)
    }
  }

}

object ProvisioningCommunicator {
  def create(aggregateId: UUID) = ProvisioningCommunicatorCreated(aggregateId, MyIdentity.create(aggregateId))
}