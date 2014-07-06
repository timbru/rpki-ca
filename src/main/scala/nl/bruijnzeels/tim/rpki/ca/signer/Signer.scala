package nl.bruijnzeels.tim.rpki.ca.signer

import java.math.BigInteger
import java.net.URI
import java.util.UUID

import org.bouncycastle.pkcs.PKCS10CertificationRequest

import org.joda.time.Period

import net.ripe.ipresource.IpResourceSet

import nl.bruijnzeels.tim.rpki.ca.common.domain.ChildCertificateSignRequest
import nl.bruijnzeels.tim.rpki.ca.common.domain.KeyPairSupport
import nl.bruijnzeels.tim.rpki.ca.common.domain.Revocation
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningMaterial
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningSupport

case class Signer(
  signingMaterial: SigningMaterial,
  publicationSet: Option[PublicationSet] = None,
  revocationList: List[Revocation] = List.empty) {

  import Signer._

  def applyEvents(events: List[SignerEvent]): Signer = events.foldLeft(this)((updated, event) => updated.applyEvent(event))

  def applyEvent(event: SignerEvent): Signer = event match {
    case created: SignerCreated => Signer(created.signingMaterial)
    case published: SignerUpdatedPublicationSet => copy(publicationSet = Some(published.publicationSet))
    case signed: SignerSignedCertificate => copy(signingMaterial = signingMaterial.updateLastSerial(signed.certificate.getSerialNumber()))
    case rejected: SignerRejectedCertificate => this // No effects here, returned to communicate rejection gracefully
    case revoked: SignerAddedRevocation => copy(revocationList = revocationList :+ revoked.revocation)
  }

  /**
   * Re-publish
   */
  def publish(caId: UUID) = publicationSet match {
    case None => PublicationSet.createFirst(caId, signingMaterial)
    case Some(set) => set.publish(caId, signingMaterial)
  }

  /**
   * Sign a child certificate request
   */
  def signChildCertificateRequest(caId: UUID, resources: IpResourceSet, pkcs10Request: PKCS10CertificationRequest): Either[SignerSignedCertificate, SignerRejectedCertificate] = {
    val childCaRequest = ChildCertificateSignRequest(
      pkcs10Request = pkcs10Request,
      resources = resources,
      validityDuration = ChildCaLifeTime,
      serial = signingMaterial.lastSerial.add(BigInteger.ONE))

    val overclaimingResources = new IpResourceSet(resources)
    overclaimingResources.removeAll(signingMaterial.currentCertificate.getResources())

    if (overclaimingResources.isEmpty()) {
      Left(SignerSignedCertificate(caId, SigningSupport.createChildCaCertificate(signingMaterial, childCaRequest)))
    } else {
      Right(SignerRejectedCertificate(caId, s"Child certificate request includes resources not included in parent certificate: ${overclaimingResources}"))
    }

  }

}

object Signer {

  val TrustAnchorLifeTime = Period.years(5)
  val ChildCaLifeTime = Period.years(1)
  val CrlNextUpdate = Period.hours(24)
  val MftNextUpdate = Period.days(1)
  val MftValidityTime = Period.days(7)

  def createSelfSigned(id: UUID, name: String, resources: IpResourceSet, taCertificateUri: URI, publicationDir: URI): List[SignerEvent] = {
    val keyPair = KeyPairSupport.createRpkiKeyPair
    val certificate = SigningSupport.createRootCertificate(name, keyPair, resources, publicationDir, TrustAnchorLifeTime)

    List(
      SignerCreated(id, SigningMaterial(keyPair, certificate, taCertificateUri, BigInteger.ZERO)),
      SignerSignedCertificate(id, certificate))
  }

  def buildFromEvents(events: List[SignerEvent]): Signer = Signer(null).applyEvents(events)

}