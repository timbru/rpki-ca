package nl.bruijnzeels.tim.rpki.ca.common.domain

import javax.security.auth.x500.X500Principal
import java.math.BigInteger
import java.net.URI
import java.security.KeyPair
import java.security.PublicKey
import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.crypto.ValidityPeriod
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsBuilder
import net.ripe.rpki.commons.crypto.crl.X509Crl
import net.ripe.rpki.commons.crypto.crl.X509CrlBuilder
import net.ripe.rpki.commons.crypto.x509cert.RpkiSignedObjectEeCertificateBuilder
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder
import org.bouncycastle.asn1.x509.KeyUsage
import org.joda.time.DateTime
import org.joda.time.Period
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.ipresource.IpResourceType
import java.util.EnumSet
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject

case class SigningMaterial(keyPair: KeyPair, currentCertificate: X509ResourceCertificate, certificateUri: URI)
case class GenericCertificateSignRequestInfo(pubKey: PublicKey, validityPeriod: ValidityPeriod, serial: BigInteger, resources: IpResourceSet)
case class EndEntityCertificateSignRequestInfo(rpkiObjectUri: URI, genericInfo: GenericCertificateSignRequestInfo)

case class ManifestEntry(name: String, content: Array[Byte])

object SigningSupport {

  def createCrl(signingMaterial: SigningMaterial, nextUpdateDuration: Period): X509Crl = {
    val now = new DateTime()
    (new X509CrlBuilder)
      .withThisUpdateTime(now)
      .withNextUpdateTime(now.plus(nextUpdateDuration))
      .withNumber(BigInteger.ONE)
      .withAuthorityKeyIdentifier(signingMaterial.keyPair.getPublic())
      .withIssuerDN(signingMaterial.currentCertificate.getSubject())
      .build(signingMaterial.keyPair.getPrivate())
  }
  
  def convertToManifestEntry(repositoryObjects: List[CertificateRepositoryObject]): List[ManifestEntry] = repositoryObjects.map { repoObject =>
    ManifestEntry(name = RpkiObjectNameSupport.deriveName(repoObject), content = repoObject.getEncoded())
  }

  def createManifest(signingMaterial: SigningMaterial, nextUpdateDuration: Period, validityDuration: Period, entries: List[ManifestEntry] = List.empty): ManifestCms = {
    val now = new DateTime()

    val eeKeyPair = KeyPairSupport.createRpkiKeyPair
    val genericRequestInfo = GenericCertificateSignRequestInfo(pubKey = eeKeyPair.getPublic(), validityPeriod = new ValidityPeriod(now, now.plus(validityDuration)), serial = BigInteger.ONE, resources = new IpResourceSet)
    val eeRequestInfo = EndEntityCertificateSignRequestInfo(rpkiObjectUri = signingMaterial.currentCertificate.getManifestUri(), genericInfo = null)
    val eeCertificate = createEeCertificate(signingMaterial, eeRequestInfo)

    val builder = new ManifestCmsBuilder
    builder.withThisUpdateTime(now)
      .withNextUpdateTime(now.plus(nextUpdateDuration))
      .withCertificate(eeCertificate)
      
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

    builder.withSigningKeyPair(signingMaterial.keyPair)
    builder.build()
  }

  def createRootCertificate(name: String, keyPair: KeyPair, resources: IpResourceSet, publicationDir: URI, validityDuration: Period) = {
    val now = new DateTime()
    val vp = new ValidityPeriod(now, now.plus(validityDuration))

    val subjectDN = new X500Principal("CN=" + name)
    val manifestUri = publicationDir.resolve(RpkiObjectNameSupport.deriveMftFileNameForCertificate(keyPair.getPublic()))

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