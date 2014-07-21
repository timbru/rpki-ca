package nl.bruijnzeels.tim.rpki.ca.provisioning

import java.math.BigInteger
import java.security.KeyPair
import java.util.UUID
import org.joda.time.DateTime
import javax.security.auth.x500.X500Principal
import net.ripe.rpki.commons.crypto.crl.X509CrlBuilder
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper
import net.ripe.rpki.commons.provisioning.x509.ProvisioningCmsCertificateBuilder
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificateBuilder
import nl.bruijnzeels.tim.rpki.ca.common.domain.KeyPairSupport
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObjectBuilder
import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload
import nl.bruijnzeels.tim.rpki.ca.common.domain.RpkiObjectNameSupport
import java.net.URI

case class MyIdentity(id: UUID, identityCertificate: ProvisioningIdentityCertificate, keyPair: KeyPair) {
  
  import X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER
  
  

  def toChildIdentity() = new net.ripe.rpki.commons.provisioning.identity.ChildIdentity(id.toString, identityCertificate)
  


  def createProvisioningCms(recipient: String, payload: AbstractProvisioningPayload) = {
    // set recipient and child properly.. hard to do before this point
    payload.setRecipient(recipient)
    payload.setSender(id.toString)
    
    val eeKeyPair = KeyPairSupport.createRpkiKeyPair

    val eeCert = new ProvisioningCmsCertificateBuilder()
      .withIssuerDN(identityCertificate.getSubject())
      .withSubjectDN(RpkiObjectNameSupport.deriveSubject(eeKeyPair.getPublic()))
      .withSigningKeyPair(keyPair)
      .withSerial(BigInteger.valueOf(DateTime.now().toInstant().getMillis())) // Todo: track serials
      .withPublicKey(eeKeyPair.getPublic())
      .withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER)
      .build()

    val crl = new X509CrlBuilder()
      .withIssuerDN(identityCertificate.getSubject())
      .withAuthorityKeyIdentifier(keyPair.getPublic())
      .withThisUpdateTime(DateTime.now)
      .withNextUpdateTime(DateTime.now.plusHours(24))
      .withNumber(BigInteger.valueOf(DateTime.now().toInstant().getMillis()))
      .build(keyPair.getPrivate()).getCrl()

    new ProvisioningCmsObjectBuilder()
      .withCmsCertificate(eeCert.getCertificate())
      .withCrl(crl)
      .withPayloadContent(payload)
      .withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER)
      .build(eeKeyPair.getPrivate())
  }

}

object MyIdentity {

  def create(id: UUID) = {
    val kp = KeyPairSupport.createRpkiKeyPair
    val cert = new ProvisioningIdentityCertificateBuilder()
      .withSelfSigningKeyPair(kp)
      .withSelfSigningSubject(new X500Principal("CN=" + id.toString))
      .build()

    MyIdentity(id = id, identityCertificate = cert, keyPair = kp)
  }

}