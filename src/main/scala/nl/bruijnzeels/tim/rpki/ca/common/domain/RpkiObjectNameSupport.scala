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

import java.io.{ByteArrayOutputStream, IOException}
import java.security.PublicKey
import javax.security.auth.x500.X500Principal

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms
import net.ripe.rpki.commons.crypto.crl.X509Crl
import net.ripe.rpki.commons.crypto.util.KeyPairUtil
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import org.bouncycastle.util.encoders.HexEncoder

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