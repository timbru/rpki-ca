package nl.bruijnzeels.tim.rpki
package ca
package rc
package child

import java.util.UUID

import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import nl.bruijnzeels.tim.rpki.ca.rc.ResourceClassEvent

sealed trait ChildEvent extends ResourceClassEvent {
  def childId: UUID
}

case class ChildCreated(aggregateId: UUID, resourceClassName: String, childId: UUID, entitledResources: IpResourceSet) extends ChildEvent

case class ChildResourceEntitlementsUpdated(aggregateId: UUID, resourceClassName: String, childId: UUID, entitledResources: IpResourceSet) extends ChildEvent
//
case class TaChildCertificateReceived(aggregateId: UUID, resourceClassName: String, childId: UUID, certificate: X509ResourceCertificate) extends ChildEvent
case class TaChildCertificateRequestRejected(aggregateId: UUID, resourceClassName: String, childId: UUID, reason: String) extends ChildEvent
case class TaChildCertificateRevocationRequested(aggregateId: UUID, resourceClassName: String, childId: UUID, certificate: X509ResourceCertificate) extends ChildEvent
case class TaChildCertificatePublicationRequested(aggregateId: UUID, resourceClassName: String, childId: UUID, certificate: X509ResourceCertificate) extends ChildEvent
case class TaChildCertificateWithdrawRequested(aggregateId: UUID, resourceClassName: String, childId: UUID, certificate: X509ResourceCertificate) extends ChildEvent

//case class TaChildAutomaticCertificateReissuanceRequested(id: UUID, resourceClass: String, resources: IpResourceSet, oldCertificate: X509ResourceCertificate) extends TaChildEvent

