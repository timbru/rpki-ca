package nl.bruijnzeels.tim.rpki.ca.ta

import java.util.UUID
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.crl.X509Crl
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningMaterial
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import nl.bruijnzeels.tim.rpki.ca.common.domain.Revocation
import net.ripe.ipresource.IpResourceSet
import nl.bruijnzeels.tim.rpki.ca.signer.PublicationSet
import nl.bruijnzeels.tim.rpki.ca.core.Child

sealed trait TaEvent extends Event

case class TaCreated(id: UUID, name: String) extends TaEvent

sealed trait ChildEvent extends TaEvent {
  def childId: UUID
}

case class ChildResourceEntitlementsUpdated(id: UUID, childId: UUID, entitledResources: IpResourceSet) extends ChildEvent

case class TaChildCertificateReceived(id: UUID, childId: UUID, certificate: X509ResourceCertificate) extends ChildEvent
case class TaChildCertificateRequestRejected(id: UUID, childId: UUID, reason: String) extends ChildEvent
case class TaChildCertificateRevocationRequested(id: UUID, childId: UUID, certificate: X509ResourceCertificate) extends ChildEvent
case class TaChildCertificatePublicationRequested(id: UUID, childId: UUID, certificate: X509ResourceCertificate) extends ChildEvent
case class TaChildCertificateWithdrawRequested(id: UUID, childId: UUID, certificate: X509ResourceCertificate) extends ChildEvent

//case class TaChildAutomaticCertificateReissuanceRequested(id: UUID, resourceClass: String, resources: IpResourceSet, oldCertificate: X509ResourceCertificate) extends TaChildEvent

