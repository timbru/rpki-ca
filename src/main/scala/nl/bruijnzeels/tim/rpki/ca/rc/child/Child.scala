package nl.bruijnzeels.tim.rpki.ca.rc.child

import java.security.PublicKey
import java.util.UUID
import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate

case class ChildKeyCertificates(currentCertificate: X509ResourceCertificate, oldCertificates: List[X509ResourceCertificate] = List.empty) {
  def withNewCertificate(certificate: X509ResourceCertificate) = copy(currentCertificate = certificate, oldCertificates = oldCertificates :+ currentCertificate)
}

case class Child(aggregateId: UUID, id: UUID, entitledResources: IpResourceSet, knownKeys: Map[PublicKey, ChildKeyCertificates] = Map.empty) {

  def applyEvent(event: ChildEvent) = event match {
    case created: ChildCreated => Child.created(created)
    case resourceUpdated: ChildUpdatedResourceEntitlements => copy(entitledResources = resourceUpdated.entitledResources)
    case certReceived: ChildReceivedCertificate => certificateReceived(certReceived.certificate)
  }

  def currentCertificates(): List[X509ResourceCertificate] = knownKeys.values.map(_.currentCertificate).toList

  private def certificateReceived(cert: X509ResourceCertificate) = {
    val pubKey = cert.getPublicKey
    val childCertificates = knownKeys.get(pubKey) match {
      case None => ChildKeyCertificates(cert)
      case Some(ckc) => ckc.withNewCertificate(cert)
    }
    copy(knownKeys = knownKeys + (pubKey -> childCertificates))
  }

}

object Child {
  def created(created: ChildCreated) = Child(aggregateId = created.aggregateId, id = created.childId, entitledResources = created.entitledResources)
}