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
package nl.bruijnzeels.tim.rpki.ca.rc.child

import java.security.PublicKey
import java.util.UUID
import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate

case class ChildKeyCertificates(currentCertificate: X509ResourceCertificate, oldCertificates: List[X509ResourceCertificate] = List.empty) {
  def withNewCertificate(certificate: X509ResourceCertificate) = copy(currentCertificate = certificate, oldCertificates = oldCertificates :+ currentCertificate)
}

case class Child(id: UUID, entitledResources: IpResourceSet, knownKeys: Map[PublicKey, ChildKeyCertificates] = Map.empty) {

  def applyEvent(event: ChildEvent) = event match {
    case created: ChildCreated => Child.created(created)
    case resourceUpdated: ChildUpdatedResourceEntitlements => copy(entitledResources = resourceUpdated.entitledResources)
    case certReceived: ChildReceivedCertificate => certificateReceived(certReceived.certificate)
  }

  def currentCertificates(): List[X509ResourceCertificate] = knownKeys.values.map(_.currentCertificate).toList

  private def certificateReceived(cert: X509ResourceCertificate) = {
    val pubKey = cert.getPublicKey
    val childCertificates = knownKeys.get(pubKey) match {
      case None => ChildKeyCertificates(cert)
      case Some(ckc) => ckc.withNewCertificate(cert)
    }
    copy(knownKeys = knownKeys + (pubKey -> childCertificates))
  }

}

object Child {
  def created(created: ChildCreated) = Child(id = created.childId, entitledResources = created.entitledResources)
}