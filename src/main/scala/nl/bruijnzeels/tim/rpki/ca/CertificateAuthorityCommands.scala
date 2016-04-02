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
package nl.bruijnzeels.tim.rpki.ca

import java.net.URI
import java.util.UUID

import net.ripe.ipresource.IpResourceSet
import nl.bruijnzeels.tim.rpki.common.cqrs.{Command, VersionedId}
import nl.bruijnzeels.tim.rpki.common.domain.RoaAuthorisation

sealed trait CertificateAuthorityCommand extends Command

/**
  * Create a CertificateAuthority to use with a parent (i.e. not as a TrustAnchor)
  */
case class CertificateAuthorityCreate(aggregateId: UUID, name: String, baseUrl: URI, rrdpNotifyUrl: URI) extends CertificateAuthorityCommand {
  def versionedId = VersionedId(aggregateId)
}

/**
  * Create as a Trust Anchor, i.e. this CA has no parent and uses self-signed certificates
  */
case class CertificateAuthorityCreateAsTrustAnchor(aggregateId: UUID, name: String, certificateUrl: URI, baseUrl: URI, rrdpNotifyUrl: URI, resources: IpResourceSet) extends CertificateAuthorityCommand {
  def versionedId = VersionedId(aggregateId)
}



/**
  * Add a parent. A CertificateAuthority can have only one parent (at least for now)
  */
case class CertificateAuthorityAddParent(versionedId: VersionedId, parentXml: String) extends CertificateAuthorityCommand

/**
  * Add a child. A CertificateAuthority can have many children
  */
case class CertificateAuthorityAddChild(versionedId: VersionedId, childId: UUID, childXml: String, childResources: IpResourceSet) extends CertificateAuthorityCommand

/**
  * Update a Child CA's resources. Just updates the eligible resources, but will only re-issue
  * on request. Even if resources are shrunk.
  *
  * TODO: Implement command to force shrink issued certificates for children that don't request
  * in time voluntarily
  */
case class CertificateAuthorityUpdateChildResources(versionedId: VersionedId, childId: UUID, childResources: IpResourceSet) extends CertificateAuthorityCommand

/**
  * Create a new set of published objects, including a new mft and CRL.
  * Note: this does include publishing to a repository, this just creates the latest set.
  */
case class CertificateAuthorityPublish(versionedId: VersionedId) extends CertificateAuthorityCommand

/**
  * Add a ROA configuration. Will ensure that a ROA is created as needed.
  * Note that the ROAs are not created until a CertificateAuthorityPublish is issued. This
  * ensures that multiple ROA configurations can be added/removed and published as a set.
  */
case class CertificateAuthorityAddRoa(versionedId: VersionedId, roaAuthorisation: RoaAuthorisation) extends CertificateAuthorityCommand

/**
  * Remove a ROA configuration. Will ensure that a ROA is created as needed.
  * Note that the ROAs are not created until a CertificateAuthorityPublish is issued. This
  * ensures that multiple ROA configurations can be added/removed and published as a set.
  */
case class CertificateAuthorityRemoveRoa(versionedId: VersionedId, roaAuthorisation: RoaAuthorisation) extends CertificateAuthorityCommand