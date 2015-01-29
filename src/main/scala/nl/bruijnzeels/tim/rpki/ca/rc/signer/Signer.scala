package nl.bruijnzeels.tim.rpki
package ca
package rc
package signer

import java.math.BigInteger
import java.net.URI
import java.security.KeyPair
import java.util.UUID

import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.joda.time.Period

import common.domain.ChildCertificateSignRequest
import common.domain.KeyPairSupport
import common.domain.Revocation
import common.domain.SigningMaterial
import common.domain.SigningSupport
import javax.security.auth.x500.X500Principal
import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.crl.X509Crl
import net.ripe.rpki.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayload
import net.ripe.rpki.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayloadBuilder
import net.ripe.rpki.commons.provisioning.x509.pkcs10.RpkiCaCertificateRequestBuilder
import nl.bruijnzeels.tim.rpki.ca.common.domain.CrlRequest
import nl.bruijnzeels.tim.rpki.ca.common.domain.ManifestRequest
import nl.bruijnzeels.tim.rpki.ca.common.domain.RpkiObjectNameSupport

case class Signer(
  signingMaterial: SigningMaterial,
  pendingCertificateRequest: Option[CertificateIssuanceRequestPayload] = None,
  publicationSet: PublicationSet = PublicationSet(BigInteger.ZERO),
  revocationList: List[Revocation] = List.empty) {

  import Signer._

  def resources = signingMaterial.currentCertificate.getResources

  def applyEvents(events: List[SignerEvent]): Signer = events.foldLeft(this)((updated, event) => updated.applyEvent(event))

  def applyEvent(event: SignerEvent): Signer = event match {
    case created: SignerCreated => Signer(null) //
    case signingMaterialCreated: SignerSigningMaterialCreated => copy(signingMaterial = signingMaterialCreated.signingMaterial)
    case pendingRequestCreated: SignerCreatedPendingCertificateRequest => copy(pendingCertificateRequest = Some(pendingRequestCreated.request))
    case certificateReceived: SignerReceivedCertificate => copy(pendingCertificateRequest = None, signingMaterial = signingMaterial.updateCurrentCertificate(certificateReceived.certificate))
    case published: SignerUpdatedPublicationSet => copy(publicationSet = publicationSet.applyEvent(published))
    case signed: SignerSignedCertificate => copy(signingMaterial = signingMaterial.updateLastSerial(signed.certificate.getSerialNumber()))
    case revoked: SignerAddedRevocation => copy(revocationList = revocationList :+ revoked.revocation)
  }

  /**
   * Publish or re-publish.
   *
   * Creates initial publication set for the first publication and will use existing publication set
   * so that mft and crl numbers can be tracked properly
   */
  def publish(resourceClassName: String, products: List[CertificateRepositoryObject] = List.empty) = {

    // Validate that there was no attempt to publish an additional CRL or MFT
    products.foreach(p => p match {
      case crl: X509Crl => throw new IllegalArgumentException("Do not publish CRL manually, will be created here")
      case mft: ManifestCms => throw new IllegalArgumentException("Do not publish CRL manually, will be created here")
      case _ => // Everything okay
    })

    val setNumber = publicationSet.number.add(BigInteger.ONE)

    val mftRevocationOption = publicationSet.mft.map(mft => {
      val mftRevocation = Revocation.forCertificate(mft.getCertificate)
      SignerAddedRevocation(resourceClassName, mftRevocation)
    })

    val newCrl = {
      val revocations = mftRevocationOption.map(_.revocation) match {
        case None => signingMaterial.revocations
        case Some(mftRevocation) => signingMaterial.revocations :+ mftRevocation
      }

      val crlRequest = CrlRequest(nextUpdateDuration = CrlNextUpdate, crlNumber = setNumber, revocations = revocations)
      SigningSupport.createCrl(signingMaterial, crlRequest)
    }

    val newMft = {
      val mftRequest = ManifestRequest(nextUpdateDuration = MftNextUpdate,
        validityDuration = MftValidityTime,
        manifestNumber = setNumber,
        publishedObjects = products :+ newCrl,
        certificateSerial = signingMaterial.lastSerial.add(BigInteger.ONE))
      SigningSupport.createManifest(signingMaterial, mftRequest)
    }

    val manifestSignedEvent = SignerSignedCertificate(resourceClassName, newMft.getCertificate())

    val publicationSetUpdatedEvent = publicationSet.publish(
        resourceClassName = resourceClassName,
        baseUri = signingMaterial.currentCertificate.getRepositoryUri,
        mft = newMft,
        crl = newCrl,
        products = products)

    mftRevocationOption match {
      case None => List(manifestSignedEvent, publicationSetUpdatedEvent)
      case Some(revocationEvent) => List(revocationEvent, manifestSignedEvent, publicationSetUpdatedEvent)
    }
  }

  /**
   * Sign a child certificate request
   */
  def signChildCertificateRequest(resourceClassName: String, resources: IpResourceSet, pkcs10Request: PKCS10CertificationRequest): Either[SignerSignedCertificate, RejectedCertificate] = {
    val childCaRequest = ChildCertificateSignRequest(
      pkcs10Request = pkcs10Request,
      resources = resources,
      validityDuration = ChildCaLifeTime,
      serial = signingMaterial.lastSerial.add(BigInteger.ONE))

    val overclaimingResources = new IpResourceSet(resources)
    overclaimingResources.removeAll(signingMaterial.currentCertificate.getResources())

    if (overclaimingResources.isEmpty()) {
      Left(SignerSignedCertificate(resourceClassName, SigningSupport.createChildCaCertificate(signingMaterial, childCaRequest)))
    } else {
      Right(RejectedCertificate(s"Child certificate request includes resources not included in parent certificate: ${overclaimingResources}"))
    }

  }

}

object Signer {

  val TrustAnchorLifeTime = Period.years(5)
  val ChildCaLifeTime = Period.years(1)
  val CrlNextUpdate = Period.hours(24)
  val MftNextUpdate = Period.days(1)
  val MftValidityTime = Period.days(7)

  def createCertificateIssuanceRequest(className: String, repositoryUri: URI, mftUri: URI, rrdpNotifyUri: URI, subject: X500Principal, keyPair: KeyPair) = {
    val pkcs10Request = new RpkiCaCertificateRequestBuilder()
      .withCaRepositoryUri(repositoryUri)
      .withManifestUri(mftUri)
      .withRrdpNotifyUri(rrdpNotifyUri)
      .withSubject(subject)
      .build(keyPair)

    new CertificateIssuanceRequestPayloadBuilder().withClassName(className).withCertificateRequest(pkcs10Request).build()
  }

  def create(resourceClassName: String, publicationUri: URI, rrdpNotifyUri: URI) = {
    val keyPair = KeyPairSupport.createRpkiKeyPair

    val created = SignerCreated(resourceClassName)

    val signingMaterialCreated = {
      val signingMaterial = SigningMaterial(keyPair, null, publicationUri, rrdpNotifyUri, BigInteger.ZERO)
      SignerSigningMaterialCreated(resourceClassName, signingMaterial)
    }

    val pendingCeritifcateRequest = {
      val mftUri = publicationUri.resolve(RpkiObjectNameSupport.deriveMftFileNameForKey(keyPair.getPublic()))
      val preferredSubject = RpkiObjectNameSupport.deriveSubject(keyPair.getPublic()) // parent may override..
      val request = createCertificateIssuanceRequest(resourceClassName, publicationUri, mftUri, rrdpNotifyUri, preferredSubject, keyPair)
      SignerCreatedPendingCertificateRequest(resourceClassName, request)
    }

    List(created, signingMaterialCreated, pendingCeritifcateRequest)
  }

  def createSelfSigned(
      resourceClassName: String,
      name: String,
      resources: IpResourceSet,
      taCertificateUri: URI,
      publicationDir: URI,
      rrdpNotifyUri: URI): List[SignerEvent] = {
    val keyPair = KeyPairSupport.createRpkiKeyPair
    val certificate = SigningSupport.createRootCertificate(name, keyPair, resources, publicationDir, rrdpNotifyUri, TrustAnchorLifeTime)

    List(
      SignerCreated(resourceClassName),
      SignerSigningMaterialCreated(resourceClassName, SigningMaterial(keyPair, certificate, taCertificateUri, rrdpNotifyUri, BigInteger.ZERO)),
      SignerSignedCertificate(resourceClassName, certificate))
  }

  def buildFromEvents(events: List[SignerEvent]): Signer = Signer(null).applyEvents(events)

}