/**
 * Copyright (c) 2014-2016 Tim Bruijnzeels
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of this software, nor the names of its contributors, nor
 *     the names of the contributors' employers may be used to endorse or promote
 *     products derived from this software without specific prior written
 *     permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package nl.bruijnzeels.tim.rpki
package ca
package rc
package signer

import java.math.BigInteger
import java.net.URI
import java.security.KeyPair
import javax.security.auth.x500.X500Principal

import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms
import net.ripe.rpki.commons.provisioning.payload.issue.request.{CertificateIssuanceRequestPayload, CertificateIssuanceRequestPayloadBuilder}
import net.ripe.rpki.commons.provisioning.x509.pkcs10.RpkiCaCertificateRequestBuilder
import nl.bruijnzeels.tim.rpki.common.domain._
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.joda.time.Period

import scala.collection.JavaConverters._

case class Signer(
  signingMaterial: SigningMaterial,
  pendingCertificateRequest: Option[CertificateIssuanceRequestPayload] = None,
  roas: List[RoaCms] = List.empty,
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
    case signedRoa: SignerSignedRoaCms => copy(signingMaterial = signingMaterial.updateLastSerial(signedRoa.roaCms.getCertificate.getSerialNumber()), roas = roas :+ signedRoa.roaCms)
    case removedRoa: SignerRemovedRoaCms => copy(roas = roas.filter(_ != removedRoa.roaCms))
  }

  /**
   * Publish or re-publish.
   *
   * Creates initial publication set for the first publication and will use existing publication set
   * so that mft and crl numbers can be tracked properly
   */
  def publish(resourceClassName: String, authorisations: List[RoaAuthorisation] = List.empty, products: List[CertificateRepositoryObject] = List.empty) = {

    var serialUsed = signingMaterial.lastSerial
    def nextSerial = {
      serialUsed = serialUsed.add(BigInteger.ONE)
      serialUsed
    }

    val authorisationsInRoas = roas.flatMap { roa =>
      roa.getPrefixes.asScala.flatMap { pfx =>
        List(RoaAuthorisation(roa.getAsn, pfx))
      }
    }

    val roaAuthorisationsToAdd = authorisations.filter(auth => !authorisationsInRoas.contains(auth))
    val roaAuthorisationsToRemove = authorisationsInRoas.filter(existingRoa => !authorisations.contains(existingRoa))

    val newRoaEvents = roaAuthorisationsToAdd.map { auth =>
      SignerSignedRoaCms(resourceClassName, SigningSupport.createRoaCms(signingMaterial, nextSerial, auth))
    }

    val removeRoaEvents = roaAuthorisationsToRemove.flatMap { auth =>
      val existingRoa = roas.find(r => auth.matchesRoa(r)).getOrElse { throw new IllegalArgumentException(s"Can't find ROA for ${auth}")}
      List(
        SignerAddedRevocation(resourceClassName, Revocation.forRoa(existingRoa)),
        SignerRemovedRoaCms(resourceClassName, existingRoa))
    }

    val roasToPublish: List[RoaCms] = roas ++ newRoaEvents.map(_.roaCms)

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
        certificateSerial = nextSerial)
      SigningSupport.createManifest(signingMaterial, mftRequest)
    }

    val manifestSignedEvent = SignerSignedCertificate(resourceClassName, newMft.getCertificate())

    val publicationSetUpdatedEvent = publicationSet.publish(
        resourceClassName = resourceClassName,
        baseUri = signingMaterial.currentCertificate.getRepositoryUri,
        mft = newMft,
        crl = newCrl,
        products = roasToPublish ++ products)

    mftRevocationOption match {
      case None => newRoaEvents ++ removeRoaEvents :+ manifestSignedEvent :+ publicationSetUpdatedEvent
      case Some(revocationEvent) => newRoaEvents ++ removeRoaEvents :+ revocationEvent :+ manifestSignedEvent :+ publicationSetUpdatedEvent
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
      .withNotificationUri(rrdpNotifyUri)
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