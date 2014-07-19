package nl.bruijnzeels.tim.rpki
package ca
package rc
package signer

import java.util.UUID

import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate

import common.domain.Revocation
import common.domain.SigningMaterial

sealed trait SignerEvent extends ResourceClassEvent

case class SignerCreated(aggregateId: UUID, resourceClassName: String) extends SignerEvent
case class SignerSigningMaterialCreated(aggregateId: UUID, resourceClassName: String, signingMaterial: SigningMaterial) extends SignerEvent
case class SignerUpdatedPublicationSet(aggregateId: UUID, resourceClassName: String, publicationSet: PublicationSet) extends SignerEvent
case class SignerSignedCertificate(aggregateId: UUID, resourceClassName: String, certificate: X509ResourceCertificate) extends SignerEvent
case class SignerAddedRevocation(aggregateId: UUID, resourceClassName: String, revocation: Revocation) extends SignerEvent