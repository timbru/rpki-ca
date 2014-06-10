package nl.bruijnzeels.tim.rpki.ca.ta

import java.util.UUID
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.crl.X509Crl
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningMaterial
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import nl.bruijnzeels.tim.rpki.ca.common.domain.Revocation
import net.ripe.ipresource.IpResourceSet

sealed trait TaEvent extends Event

case class TaCreated(id: UUID, name: String) extends TaEvent
case class TaSignerCreated(id: UUID, signingMaterial: SigningMaterial) extends TaEvent
case class TaChildAdded(id: UUID, child: Child) extends TaEvent

sealed trait TaSignerEvent extends TaEvent

case class TaPublicationSetUpdated(id: UUID, publicationSet: TaPublicationSet) extends TaSignerEvent
case class TaCertificateSigned(id: UUID, certificate: X509ResourceCertificate) extends TaSignerEvent
case class TaChildCertificateSigned(id: UUID, certificate: X509ResourceCertificate) extends TaSignerEvent
case class TaRevocationAdded(id: UUID, revocation: Revocation) extends TaSignerEvent

sealed trait TaChildEvent extends TaEvent {
  def childId: UUID
}

case class TaChildResourceClassAdded(id: UUID, childId: UUID, entitlement: ResourceEntitlement) extends TaChildEvent
case class TaChildResourceClassUpdated(id: UUID, childId: UUID, entitlement: ResourceEntitlement) extends TaChildEvent
case class TaChildResourceClassRemoved(id: UUID, childId: UUID, name: String) extends TaChildEvent

//case class TaChildAutomaticCertificateReissuanceRequested(id: UUID, resourceClass: String, resources: IpResourceSet, oldCertificate: X509ResourceCertificate) extends TaChildEvent
case class TaChildCertificateReceived(id: UUID, childId: UUID, certificate: X509ResourceCertificate) extends TaChildEvent
case class TaChildCertificateRequestRejected(id: UUID, childId: UUID, reason: String) extends TaChildEvent


