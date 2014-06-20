package nl.bruijnzeels.tim.rpki.ca.core

import java.security.PublicKey
import java.util.UUID
import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import nl.bruijnzeels.tim.rpki.ca.ta.TaChildCertificateReceived
import nl.bruijnzeels.tim.rpki.ca.ta.ChildEvent
import nl.bruijnzeels.tim.rpki.ca.ta.ChildResourceEntitlementsUpdated

case class ChildKeyCertificates(currentCertificate: X509ResourceCertificate, oldCertificates: List[X509ResourceCertificate] = List.empty) {
  def withNewCertificate(certificate: X509ResourceCertificate) = copy(currentCertificate = certificate, oldCertificates = oldCertificates :+ currentCertificate)
}

case class Child(taId: UUID, id: UUID, entitledResources: IpResourceSet, knownKeys: Map[PublicKey, ChildKeyCertificates] = Map.empty, log: List[String] = List.empty) {

  def applyEvent(event: ChildEvent) = event match {
    case resourceUpdated: ChildResourceEntitlementsUpdated => copy(entitledResources = resourceUpdated.entitledResources, log = log :+ "Updated resources: " + resourceUpdated.entitledResources)
    case certReceived: TaChildCertificateReceived => certificateReceived(certReceived.certificate)
  }

  def currentCertificates(): List[X509ResourceCertificate] = knownKeys.values.map(_.currentCertificate).toList

  private def certificateReceived(cert: X509ResourceCertificate) = {
    val pubKey = cert.getPublicKey
    val childCertificates = knownKeys.get(pubKey) match {
      case None => ChildKeyCertificates(cert)
      case Some(ckc) => ckc.withNewCertificate(cert)
    }
    copy(knownKeys = knownKeys + (pubKey -> childCertificates), log = log :+ "Certificate received: " + cert.getSubject())
  }

}