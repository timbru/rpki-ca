package nl.bruijnzeels.tim.rpki.ca.common.domain

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.PublicKey

import javax.security.auth.x500.X500Principal

import org.bouncycastle.util.encoders.HexEncoder

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms
import net.ripe.rpki.commons.crypto.crl.X509Crl
import net.ripe.rpki.commons.crypto.util.KeyPairUtil
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate

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

  def deriveCrlFileNameForKey(publicKey: PublicKey): String = hexEncodePubKey(publicKey) + ".crl"
  def deriveMftFileNameForKey(publicKey: PublicKey): String = hexEncodePubKey(publicKey) + ".mft"

  def deriveName(rpkiRepositoryObject: CertificateRepositoryObject): String = rpkiRepositoryObject match {
    case crl: X509Crl => hexEncodeKeyIdentifier(crl.getAuthorityKeyIdentifier()) + ".crl"
    case mft: ManifestCms => hexEncodeKeyIdentifier(mft.getCertificate().getAuthorityKeyIdentifier()) + ".mft"
    case cer: X509ResourceCertificate => hexEncodeKeyIdentifier(cer.getSubjectKeyIdentifier()) + ".cer"
    case roa: RoaCms => hexEncodeKeyIdentifier(roa.getCertificate().getSubjectKeyIdentifier()) + ".roa"
    case _ => throw new IllegalArgumentException("Unknown repository object type: " + rpkiRepositoryObject.getClass())
  }

}