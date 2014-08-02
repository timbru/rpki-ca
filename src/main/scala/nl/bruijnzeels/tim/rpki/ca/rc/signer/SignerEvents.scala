package nl.bruijnzeels.tim.rpki
package ca
package rc
package signer

import java.util.UUID
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import common.domain.Revocation
import common.domain.SigningMaterial
import net.ripe.rpki.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayload
import nl.bruijnzeels.tim.rpki.publication.messages.Publish
import nl.bruijnzeels.tim.rpki.publication.messages.Withdraw
import java.math.BigInteger
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.crl.X509Crl

sealed trait SignerEvent extends ResourceClassEvent

case class SignerCreated(aggregateId: UUID, resourceClassName: String) extends SignerEvent
case class SignerSigningMaterialCreated(aggregateId: UUID, resourceClassName: String, signingMaterial: SigningMaterial) extends SignerEvent
case class SignerCreatedPendingCertificateRequest(aggregateId: UUID, resourceClassName: String, request: CertificateIssuanceRequestPayload) extends SignerEvent
case class SignerReceivedCertificate(aggregateId: UUID, resourceClassName: String, certificate: X509ResourceCertificate) extends SignerEvent
case class SignerSignedCertificate(aggregateId: UUID, resourceClassName: String, certificate: X509ResourceCertificate) extends SignerEvent
case class SignerAddedRevocation(aggregateId: UUID, resourceClassName: String, revocation: Revocation) extends SignerEvent

sealed trait PublicationSetEvent extends SignerEvent

case class SignerUpdatedPublicationSet(
    aggregateId: UUID,
    resourceClassName: String,
    number: BigInteger,
    newMft: ManifestCms,
    newCrl: X509Crl,
    publishes: List[Publish] = List.empty,
    withdraws: List[Withdraw] = List.empty) extends PublicationSetEvent