package nl.bruijnzeels.tim.rpki.ca.common.domain

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.crl.X509Crl
import java.security.PublicKey
import net.ripe.rpki.commons.crypto.util.KeyPairUtil
import org.bouncycastle.util.encoders.HexEncoder
import java.io.ByteArrayOutputStream
import java.io.IOException
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import javax.security.auth.x500.X500Principal

object RpkiObjectNameSupport {

  private def hexEncodeKeyIdentifier(keyIdentifier: Array[Byte]): String = {
    val hexEncoder = new HexEncoder()
    val out = new ByteArrayOutputStream()
    try {
      hexEncoder.encode(keyIdentifier, 0, keyIdentifier.length, out)
      out.flush()
      out.toString()
    } catch {
      case e: IOException => throw new IllegalArgumentException("Exception hex encoding data", e)
    }
  }

  private def hexEncodePubKey(publicKey: PublicKey): String = {
    hexEncodeKeyIdentifier(KeyPairUtil.getKeyIdentifier(publicKey))
  }
  
  def deriveSubject(publicKey: PublicKey): X500Principal = {
    new X500Principal("CN=" + hexEncodePubKey(publicKey))
  }
  
  def deriveMftFileNameForCertificate(publishingCertificatePublicKey: PublicKey): String = hexEncodePubKey(publishingCertificatePublicKey) + ".mft"

  def deriveName(rpkiRepositoryObject: CertificateRepositoryObject): String = rpkiRepositoryObject match {
    case crl: X509Crl => hexEncodeKeyIdentifier(crl.getAuthorityKeyIdentifier()) + ".crl"
    case mft: ManifestCms => hexEncodeKeyIdentifier(mft.getCertificate().getAuthorityKeyIdentifier()) + ".mft"
    case cer: X509ResourceCertificate => hexEncodeKeyIdentifier(cer.getSubjectKeyIdentifier()) + ".cer"
    case roa: RoaCms => hexEncodeKeyIdentifier(roa.getCertificate().getSubjectKeyIdentifier()) + ".roa"
    case _ => throw new IllegalArgumentException("Unknown repository object type: " + rpkiRepositoryObject.getClass())
  }

}