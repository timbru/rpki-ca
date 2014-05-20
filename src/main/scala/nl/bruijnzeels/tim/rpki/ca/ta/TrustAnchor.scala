package nl.bruijnzeels.tim.rpki.ca.ta

import java.security.KeyPair
import nl.bruijnzeels.tim.rpki.ca.common.domain.KeyPairSupport
import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import org.bouncycastle.asn1.x509.KeyUsage
import javax.security.auth.x500.X500Principal
import net.ripe.rpki.commons.crypto.ValidityPeriod
import org.joda.time.DateTime
import java.math.BigInteger
import java.net.URI
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import java.util.UUID
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms

case class SigningMaterial(keyPair: KeyPair, currentCertificate: X509ResourceCertificate, certificateUri: URI)

case class TaSigner(signingMaterial: SigningMaterial, mft: Option[ManifestCms] = None) {
  
  def applyEvent(event: TaSignerEvent): TaSigner = event match {
    case created: TaSignerCreated => TaSigner(created.signingMaterial)
  }
  
  def updatePublishedObjects() = {
    
    
  }
  
}

object TaSigner {
  
  val TrustAnchorLifeTimeYears = 5
  
  def create(id: UUID, name: String, resources: IpResourceSet, taCertificateUri: URI, publicationDir: URI): TaSignerCreated = {
    val keyPair = KeyPairSupport.createRpkiKeyPair
    val certificate = createRootCertificate(name, keyPair, resources, publicationDir) 

    TaSignerCreated(id, SigningMaterial(keyPair, certificate, taCertificateUri))
  }
  
  def createRootCertificate(name: String, keyPair: KeyPair, resources: IpResourceSet, publicationDir: URI) = {
    val now = new DateTime()
    val vp = new ValidityPeriod(now, now.plusYears(TrustAnchorLifeTimeYears))
      
    val subjectDN = new X500Principal("CN=" + name)
    val manifestUri = publicationDir.resolve(name + ".mft")
    
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

case class TrustAnchor(id: UUID, name: String = "", signer: Option[TaSigner] = None, events: List[TaEvent] = List()) {

  def applyEvent(event: TaEvent): TrustAnchor = event match {
    case created: TaCreated => copy(name = created.name, events = events :+ event)
    case signerCreated: TaSignerCreated => copy(signer = Some(TaSigner(signerCreated.signingMaterial)), events = events :+ event)
  }

  def initialise(resources: IpResourceSet, taCertificateUri: URI, publicationDir: URI) = {
    applyEvent(TaSigner.create(id, name, resources, taCertificateUri, publicationDir))
  }
  
  def publish() = {
    
  }
  
  
}

object TrustAnchor {

  def rebuild(events: List[TaEvent]): TrustAnchor = {
    var ta = TrustAnchor(events(0).id)
    for (e <- events) {
      ta = ta.applyEvent(e)
    }
    ta.copy(events = List())
  }

  def create(id: UUID, name: String): TrustAnchor = {
    val ta = TrustAnchor(id)
    ta.applyEvent(TaCreated(id, name))
  }

}
