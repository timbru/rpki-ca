package nl.bruijnzeels.tim.rpki.ca.rc.child

import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import java.util.UUID
import net.ripe.ipresource.IpResourceSet
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event

sealed trait ChildEvent extends Event {
  def childId: UUID
}

case class ChildResourceEntitlementsUpdated(aggregateId: UUID, childId: UUID, entitledResources: IpResourceSet) extends ChildEvent

case class TaChildCertificateReceived(aggregateId: UUID, childId: UUID, certificate: X509ResourceCertificate) extends ChildEvent
case class TaChildCertificateRequestRejected(aggregateId: UUID, childId: UUID, reason: String) extends ChildEvent
case class TaChildCertificateRevocationRequested(aggregateId: UUID, childId: UUID, certificate: X509ResourceCertificate) extends ChildEvent
case class TaChildCertificatePublicationRequested(aggregateId: UUID, childId: UUID, certificate: X509ResourceCertificate) extends ChildEvent
case class TaChildCertificateWithdrawRequested(aggregateId: UUID, childId: UUID, certificate: X509ResourceCertificate) extends ChildEvent

//case class TaChildAutomaticCertificateReissuanceRequested(id: UUID, resourceClass: String, resources: IpResourceSet, oldCertificate: X509ResourceCertificate) extends TaChildEvent

