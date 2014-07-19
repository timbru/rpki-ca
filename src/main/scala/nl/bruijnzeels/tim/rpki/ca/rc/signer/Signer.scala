package nl.bruijnzeels.tim.rpki
package ca
package rc
package signer

import java.math.BigInteger
import java.net.URI
import java.util.UUID

import org.bouncycastle.pkcs.PKCS10CertificationRequest

import org.joda.time.Period

import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject

import common.domain.ChildCertificateSignRequest
import common.domain.KeyPairSupport
import common.domain.Revocation
import common.domain.SigningMaterial
import common.domain.SigningSupport

case class Signer(
  signingMaterial: SigningMaterial,
  publicationSet: Option[PublicationSet] = None,
  revocationList: List[Revocation] = List.empty) {

  import Signer._
  
  def resources = signingMaterial.currentCertificate.getResources

  def applyEvents(events: List[SignerEvent]): Signer = events.foldLeft(this)((updated, event) => updated.applyEvent(event))

  def applyEvent(event: SignerEvent): Signer = event match {
    case signingMaterialCreated: SignerSigningMaterialCreated => copy(signingMaterial = signingMaterialCreated.signingMaterial)
    case published: SignerUpdatedPublicationSet => copy(publicationSet = Some(published.publicationSet))
    case signed: SignerSignedCertificate => copy(signingMaterial = signingMaterial.updateLastSerial(signed.certificate.getSerialNumber()))
    case rejected: SignerRejectedCertificate => this // No effects here, returned to communicate rejection gracefully
    case revoked: SignerAddedRevocation => copy(revocationList = revocationList :+ revoked.revocation)
  }

  /**
   * Publish or re-publish.
   *
   * Creates initial publication set for the first publication and will use existing publication set
   * so that mft and crl numbers can be tracked properly
   */
  def publish(aggregateId: UUID, resourceClassName: String, products: List[CertificateRepositoryObject] = List.empty) = publicationSet match {
    case None => PublicationSet.createFirst(aggregateId, resourceClassName, signingMaterial, products)
    case Some(set) => set.publish(aggregateId, resourceClassName, signingMaterial, products)
  }

  /**
   * Sign a child certificate request
   */
  def signChildCertificateRequest(aggregateId: UUID, resourceClassName: String, resources: IpResourceSet, pkcs10Request: PKCS10CertificationRequest): Either[SignerSignedCertificate, SignerRejectedCertificate] = {
    val childCaRequest = ChildCertificateSignRequest(
      pkcs10Request = pkcs10Request,
      resources = resources,
      validityDuration = ChildCaLifeTime,
      serial = signingMaterial.lastSerial.add(BigInteger.ONE))

    val overclaimingResources = new IpResourceSet(resources)
    overclaimingResources.removeAll(signingMaterial.currentCertificate.getResources())

    if (overclaimingResources.isEmpty()) {
      Left(SignerSignedCertificate(aggregateId, resourceClassName, SigningSupport.createChildCaCertificate(signingMaterial, childCaRequest)))
    } else {
      Right(SignerRejectedCertificate(aggregateId, resourceClassName, s"Child certificate request includes resources not included in parent certificate: ${overclaimingResources}"))
    }

  }

}

object Signer {

  val TrustAnchorLifeTime = Period.years(5)
  val ChildCaLifeTime = Period.years(1)
  val CrlNextUpdate = Period.hours(24)
  val MftNextUpdate = Period.days(1)
  val MftValidityTime = Period.days(7)

  def createSelfSigned(aggregateId: UUID, resourceClassName: String, name: String, resources: IpResourceSet, taCertificateUri: URI, publicationDir: URI): List[SignerEvent] = {
    val keyPair = KeyPairSupport.createRpkiKeyPair
    val certificate = SigningSupport.createRootCertificate(name, keyPair, resources, publicationDir, TrustAnchorLifeTime)

    List(
      SignerSigningMaterialCreated(aggregateId, resourceClassName, SigningMaterial(keyPair, certificate, taCertificateUri, BigInteger.ZERO)),
      SignerSignedCertificate(aggregateId, resourceClassName, certificate))
  }

  def buildFromEvents(events: List[SignerEvent]): Signer = Signer(null).applyEvents(events)

}