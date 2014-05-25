package nl.bruijnzeels.tim.rpki.ca.common.domain

import java.math.BigInteger
import java.net.URI
import java.security.KeyPair
import java.security.PublicKey
import java.util.EnumSet

import javax.security.auth.x500.X500Principal

import org.bouncycastle.asn1.x509.KeyUsage

import org.joda.time.DateTime
import org.joda.time.Period

import net.ripe.ipresource.IpResourceSet
import net.ripe.ipresource.IpResourceType
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.ValidityPeriod
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsBuilder
import net.ripe.rpki.commons.crypto.crl.X509Crl
import net.ripe.rpki.commons.crypto.crl.X509CrlBuilder
import net.ripe.rpki.commons.crypto.x509cert.RpkiSignedObjectEeCertificateBuilder
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder

case class SigningMaterial(keyPair: KeyPair, currentCertificate: X509ResourceCertificate, certificateUri: URI) {
  def crlPublicationUri = currentCertificate.getRepositoryUri().resolve(RpkiObjectNameSupport.deriveMftFileNameForKey(keyPair.getPublic()))
}

case class CrlRequest(nextUpdateDuration: Period, crlNumber: BigInteger)

case class ManifestRequest(nextUpdateDuration: Period, validityDuration: Period, manifestNumber: BigInteger, publishedObjects: List[CertificateRepositoryObject] = List.empty, certificateSerial: BigInteger)
case class ManifestEntry(name: String, content: Array[Byte])

case class GenericCertificateSignRequestInfo(pubKey: PublicKey, validityPeriod: ValidityPeriod, serial: BigInteger, resources: IpResourceSet)
case class EndEntityCertificateSignRequestInfo(rpkiObjectUri: URI, genericInfo: GenericCertificateSignRequestInfo)

object SigningSupport {

  def createCrl(signingMaterial: SigningMaterial, crlRequest: CrlRequest): X509Crl = {

    val now = new DateTime()
    (new X509CrlBuilder)
      .withThisUpdateTime(now)
      .withNextUpdateTime(now.plus(crlRequest.nextUpdateDuration))
      .withNumber(crlRequest.crlNumber)
      .withAuthorityKeyIdentifier(signingMaterial.keyPair.getPublic())
      .withIssuerDN(signingMaterial.currentCertificate.getSubject())
      .build(signingMaterial.keyPair.getPrivate())
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

  def createRootCertificate(name: String, keyPair: KeyPair, resources: IpResourceSet, publicationDir: URI, validityDuration: Period) = {
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
      .withSubjectInformationAccess(new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, publicationDir),
        new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, manifestUri))
      .build()
  }

}