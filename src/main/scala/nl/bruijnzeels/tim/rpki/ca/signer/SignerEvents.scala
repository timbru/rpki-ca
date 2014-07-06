package nl.bruijnzeels.tim.rpki.ca.signer

import java.util.UUID

import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import nl.bruijnzeels.tim.rpki.ca.common.domain.Revocation
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningMaterial

sealed trait SignerEvent extends Event

case class SignerCreated(aggregateId: UUID, signingMaterial: SigningMaterial) extends SignerEvent
case class SignerUpdatedPublicationSet(aggregateId: UUID, publicationSet: PublicationSet) extends SignerEvent
case class SignerSignedCertificate(aggregateId: UUID, certificate: X509ResourceCertificate) extends SignerEvent
case class SignerRejectedCertificate(aggregateId: UUID, reason: String) extends SignerEvent
case class SignerAddedRevocation(aggregateId: UUID, revocation: Revocation) extends SignerEvent