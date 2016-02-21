/**
 * Copyright (c) 2014-2015 Tim Bruijnzeels
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
package nl.bruijnzeels.tim.rpki.ca.common.domain

import java.math.BigInteger
import java.net.URI
import java.security.{KeyPair, PublicKey}
import java.util.EnumSet
import javax.security.auth.x500.X500Principal

import grizzled.slf4j.Logger
import net.ripe.ipresource.{IpResourceSet, IpResourceType}
import net.ripe.rpki.commons.crypto.{CertificateRepositoryObject, ValidityPeriod}
import net.ripe.rpki.commons.crypto.cms.manifest.{ManifestCms, ManifestCmsBuilder}
import net.ripe.rpki.commons.crypto.crl.{X509Crl, X509CrlBuilder}
import net.ripe.rpki.commons.crypto.x509cert.{RpkiSignedObjectEeCertificateBuilder, X509CertificateBuilderHelper, X509CertificateInformationAccessDescriptor, X509ResourceCertificate, X509ResourceCertificateBuilder}
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObjectBuilder
import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload
import net.ripe.rpki.commons.provisioning.x509.{ProvisioningCmsCertificateBuilder, ProvisioningIdentityCertificate}
import net.ripe.rpki.commons.provisioning.x509.pkcs10.RpkiCaCertificateRequestParser
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.joda.time.{DateTime, Period}

case class SigningMaterial(
  keyPair: KeyPair,
  currentCertificate: X509ResourceCertificate,
  certificateUri: URI,
  rrdpNotifyUrl: URI,
  lastSerial: BigInteger,
  revocations: List[Revocation] = List.empty) {

  def crlPublicationUri = currentCertificate.getRepositoryUri().resolve(RpkiObjectNameSupport.deriveCrlFileNameForKey(keyPair.getPublic()))
  def mftPublicationUri = currentCertificate.getRepositoryUri().resolve(RpkiObjectNameSupport.deriveMftFileNameForKey(keyPair.getPublic()))
  def signedObjectUri(repositoryObject: CertificateRepositoryObject) = currentCertificate.getRepositoryUri().resolve(RpkiObjectNameSupport.deriveName(repositoryObject))

  def updateLastSerial(serial: BigInteger) = copy(lastSerial = serial)

  def updateCurrentCertificate(certificate: X509ResourceCertificate) = copy(currentCertificate = certificate)

  /**
   * Adds new revocation and purges expired revocations
   */
  def withNewRevocation(revocation: Revocation) = copy(revocations = revocations.filter(_.expiryTime.isAfterNow()) :+ revocation)
}

case class Revocation(serial: BigInteger, revocationTime: DateTime, expiryTime: DateTime)

object Revocation {
  def forCertificate(cert: X509ResourceCertificate) = {
    Revocation(serial = cert.getSerialNumber(), revocationTime = new DateTime(), expiryTime = cert.getValidityPeriod().getNotValidAfter())
  }
}

case class CrlRequest(nextUpdateDuration: Period, crlNumber: BigInteger, revocations: List[Revocation])

case class ManifestRequest(nextUpdateDuration: Period, validityDuration: Period, manifestNumber: BigInteger, publishedObjects: List[CertificateRepositoryObject] = List.empty, certificateSerial: BigInteger)
case class ManifestEntry(name: String, content: Array[Byte])

case class GenericCertificateSignRequestInfo(pubKey: PublicKey, validityPeriod: ValidityPeriod, serial: BigInteger, resources: IpResourceSet)
case class EndEntityCertificateSignRequestInfo(rpkiObjectUri: URI, genericInfo: GenericCertificateSignRequestInfo)

case class ChildCertificateSignRequest(pkcs10Request: PKCS10CertificationRequest, resources: IpResourceSet, validityDuration: Period, serial: BigInteger)

object SigningSupport {

  import X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER
  
  val logger = Logger[SigningSupport.type]

  def createCrl(signingMaterial: SigningMaterial, crlRequest: CrlRequest): X509Crl = {

    val now = new DateTime()
    val builder = (new X509CrlBuilder)
      .withThisUpdateTime(now)
      .withNextUpdateTime(now.plus(crlRequest.nextUpdateDuration))
      .withNumber(crlRequest.crlNumber)
      .withAuthorityKeyIdentifier(signingMaterial.keyPair.getPublic())
      .withIssuerDN(signingMaterial.currentCertificate.getSubject())

    crlRequest.revocations.foldLeft(builder)((b, r) => {
      if (r.expiryTime.isAfter(now)) b.addEntry(r.serial, r.revocationTime)
      else b
    }).build(signingMaterial.keyPair.getPrivate())
  }

  def createManifest(signingMaterial: SigningMaterial, manifestRequest: ManifestRequest): ManifestCms = {
    val now = new DateTime()

    val entries = manifestRequest.publishedObjects.map { po => ManifestEntry(name = RpkiObjectNameSupport.deriveName(po), content = po.getEncoded()) }

    val eeKeyPair = KeyPairSupport.createRpkiKeyPair
    val genericRequestInfo = GenericCertificateSignRequestInfo(pubKey = eeKeyPair.getPublic(), validityPeriod = new ValidityPeriod(now, now.plus(manifestRequest.validityDuration)), serial = manifestRequest.certificateSerial, resources = new IpResourceSet)
    val eeRequestInfo = EndEntityCertificateSignRequestInfo(rpkiObjectUri = signingMaterial.currentCertificate.getManifestUri(), genericInfo = genericRequestInfo)
    val eeCertificate = createEeCertificate(signingMaterial, eeRequestInfo)

    val builder = new ManifestCmsBuilder
    builder.withThisUpdateTime(now)
      .withNextUpdateTime(now.plus(manifestRequest.nextUpdateDuration))
      .withCertificate(eeCertificate)
      .withManifestNumber(manifestRequest.manifestNumber)

    entries.foreach(e => builder.addFile(e.name, e.content))

    builder.build(eeKeyPair.getPrivate())
  }

  private def createEeCertificate(signingMaterial: SigningMaterial, eeRequestInfo: EndEntityCertificateSignRequestInfo) = {
    val builder = new RpkiSignedObjectEeCertificateBuilder()

    builder.withCorrespondingCmsPublicationPoint(eeRequestInfo.rpkiObjectUri)

    builder.withResources(eeRequestInfo.genericInfo.resources)
    builder.withValidityPeriod(eeRequestInfo.genericInfo.validityPeriod)
    builder.withSerial(eeRequestInfo.genericInfo.serial)
    builder.withPublicKey(eeRequestInfo.genericInfo.pubKey)
    builder.withSubjectDN(RpkiObjectNameSupport.deriveSubject(eeRequestInfo.genericInfo.pubKey))

    val resources = eeRequestInfo.genericInfo.resources
    if (resources.isEmpty()) {
      builder.withInheritedResourceTypes(EnumSet.of[IpResourceType](IpResourceType.ASN, IpResourceType.IPv4, IpResourceType.IPv6))
    } else {
      builder.withResources(resources)
    }

    builder.withIssuerDN(signingMaterial.currentCertificate.getSubject())
    builder.withCrlUri(signingMaterial.crlPublicationUri)
    builder.withParentResourceCertificatePublicationUri(signingMaterial.certificateUri)
    builder.withSigningKeyPair(signingMaterial.keyPair)

    builder.build()
  }

  def createChildCaCertificate(signingMaterial: SigningMaterial, childCaCertRequest: ChildCertificateSignRequest) = {
    val reqParser = new RpkiCaCertificateRequestParser(childCaCertRequest.pkcs10Request)

    val now = new DateTime()

    new X509ResourceCertificateBuilder()
      .withCa(true)
      .withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
      .withAuthorityKeyIdentifier(true)
      .withCrlDistributionPoints(signingMaterial.crlPublicationUri)
      .withAuthorityInformationAccess(new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS, signingMaterial.certificateUri))

      .withSubjectInformationAccess(
        new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, reqParser.getCaRepositoryUri),
        new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, reqParser.getManifestUri),
        new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_NOTIFY, reqParser.getNotificationUri))

      .withPublicKey(reqParser.getPublicKey)

      .withSubjectDN(RpkiObjectNameSupport.deriveSubject(reqParser.getPublicKey()))
      .withResources(childCaCertRequest.resources)
      .withValidityPeriod(new ValidityPeriod(now, now.plus(childCaCertRequest.validityDuration)))
      .withSerial(childCaCertRequest.serial)

      .withIssuerDN(signingMaterial.currentCertificate.getSubject())
      .withSigningKeyPair(signingMaterial.keyPair)
      .build()
  }

  def createRootCertificate(name: String, keyPair: KeyPair, resources: IpResourceSet, publicationDir: URI, rpkiNotifyUri: URI, validityDuration: Period) = {
    val now = new DateTime()
    val vp = new ValidityPeriod(now, now.plus(validityDuration))

    val subjectDN = new X500Principal("CN=" + name)
    val manifestUri = publicationDir.resolve(RpkiObjectNameSupport.deriveMftFileNameForKey(keyPair.getPublic()))

    new X509ResourceCertificateBuilder()
      .withCa(true)
      .withAuthorityKeyIdentifier(false)
      .withSigningKeyPair(keyPair)
      .withKeyUsage(KeyUsage.cRLSign | KeyUsage.keyCertSign)
      .withResources(resources)
      .withValidityPeriod(vp)
      .withSerial(BigInteger.ONE)
      .withPublicKey(keyPair.getPublic())
      .withSubjectDN(subjectDN)
      .withSubjectKeyIdentifier(true)
      .withIssuerDN(subjectDN)
      .withSubjectInformationAccess(
        new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, publicationDir),
        new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, manifestUri),
        new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_NOTIFY, rpkiNotifyUri))
      .build()
  }

  def createProvisioningCms(sender: String, recipient: String, signingCertificate: ProvisioningIdentityCertificate, signingKeyPair: KeyPair, payload: AbstractProvisioningPayload) = {
    // set recipient and child properly.. hard to do before this point
    payload.setRecipient(recipient)
    payload.setSender(sender)

    val eeKeyPair = KeyPairSupport.createRpkiKeyPair

    val eeCert = new ProvisioningCmsCertificateBuilder()
      .withIssuerDN(signingCertificate.getSubject())
      .withSubjectDN(RpkiObjectNameSupport.deriveSubject(eeKeyPair.getPublic()))
      .withSigningKeyPair(signingKeyPair)
      .withSerial(BigInteger.valueOf(DateTime.now().toInstant().getMillis())) // Should be safe! No need to revoke and even sharing the same serial for EEs in different requests is very unlikely to be problematic
      .withPublicKey(eeKeyPair.getPublic())
      .withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER)
      .build()

    val crl = new X509CrlBuilder()
      .withIssuerDN(signingCertificate.getSubject())
      .withAuthorityKeyIdentifier(signingKeyPair.getPublic())
      .withThisUpdateTime(DateTime.now)
      .withNextUpdateTime(DateTime.now.plusHours(24))
      .withNumber(BigInteger.valueOf(DateTime.now().toInstant().getMillis()))
      .build(signingKeyPair.getPrivate()).getCrl()

    new ProvisioningCmsObjectBuilder()
      .withCmsCertificate(eeCert.getCertificate())
      .withCrl(crl)
      .withPayloadContent(payload)
      .withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER)
      .build(eeKeyPair.getPrivate())
  }

}