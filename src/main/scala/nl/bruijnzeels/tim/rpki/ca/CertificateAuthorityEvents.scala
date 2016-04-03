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

import java.math.BigInteger
import java.net.URI
import java.util.UUID

import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms
import net.ripe.rpki.commons.crypto.crl.X509Crl
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject
import net.ripe.rpki.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayload
import nl.bruijnzeels.tim.rpki.ca.provisioning.{ChildIdentity, MyIdentity, ParentIdentity}
import nl.bruijnzeels.tim.rpki.common.cqrs.Event
import nl.bruijnzeels.tim.rpki.common.domain.{Revocation, RoaAuthorisation, SigningMaterial}
import nl.bruijnzeels.tim.rpki.publication.messages.{Publish, Withdraw}


/*

 All EVENTS for the CertificateAuthority AggregateRoot.

 All in one file so that sealed traits can be used, and we get compiler warnings for missing implementations
 for handling these events.

 */


sealed trait CertificateAuthorityEvent extends Event
case class CertificateAuthorityCreated(aggregateId: UUID, name: String, baseUrl: URI, rrdpNotifyUrl: URI) extends CertificateAuthorityEvent
case class ResourceClassCreated(resourceClassName: String) extends CertificateAuthorityEvent
case class ResourceClassRemoved(resourceClassName: String) extends CertificateAuthorityEvent
case class ProvisioningCommunicatorCreated(myIdentity: MyIdentity) extends CertificateAuthorityEvent


sealed trait ProvisioningCommunicatorEvent extends CertificateAuthorityEvent
case class ProvisioningCommunicatorAddedChild(childIdentity: ChildIdentity) extends ProvisioningCommunicatorEvent
case class ProvisioningCommunicatorPerformedChildExchange(exchange: ProvisioningChildExchange) extends ProvisioningCommunicatorEvent
case class ProvisioningChildExchange(childId: UUID, request: ProvisioningCmsObject, response: ProvisioningCmsObject)
case class ProvisioningCommunicatorAddedParent(parentIdentity: ParentIdentity) extends ProvisioningCommunicatorEvent
case class ProvisioningCommunicatorPerformedParentExchange(exchange: ProvisioningParentExchange) extends ProvisioningCommunicatorEvent
case class ProvisioningParentExchange(request: ProvisioningCmsObject, response: ProvisioningCmsObject)

sealed trait ResourceClassEvent extends CertificateAuthorityEvent {
  def resourceClassName: String
}

sealed trait SignerEvent extends ResourceClassEvent
case class SignerCreated(resourceClassName: String) extends SignerEvent
case class SignerSigningMaterialCreated(resourceClassName: String, signingMaterial: SigningMaterial) extends SignerEvent
case class SignerCreatedPendingCertificateRequest(resourceClassName: String, request: CertificateIssuanceRequestPayload) extends SignerEvent
case class SignerReceivedCertificate(resourceClassName: String, certificate: X509ResourceCertificate) extends SignerEvent
case class SignerSignedTaCertificate(resourceClassName: String, certificate: X509ResourceCertificate) extends SignerEvent
case class SignerSignedManifest(resourceClassName: String, manifest: ManifestCms) extends SignerEvent
case class SignerSignedCaCertificate(resourceClassName: String, certificate: X509ResourceCertificate) extends SignerEvent
case class SignerRemovedCaCertificate(resourceClassName: String, certificate: X509ResourceCertificate) extends SignerEvent
case class SignerAddedRevocation(resourceClassName: String, revocation: Revocation) extends SignerEvent
case class SignerSignedRoaCms(resourceClassName: String, roaCms: RoaCms) extends SignerEvent
case class SignerRemovedRoaCms(resourceClassName: String, roaCms: RoaCms) extends SignerEvent

sealed trait PublicationSetEvent extends SignerEvent
case class SignerUpdatedPublicationSet(resourceClassName: String, number: BigInteger, newMft: ManifestCms, newCrl: X509Crl, publishes: List[Publish] = List.empty, withdraws: List[Withdraw] = List.empty) extends PublicationSetEvent
case class SignerUnpublishedAll(resourceClassName: String, withdraws: List[Withdraw]) extends SignerEvent

case class ChildCreated(resourceClassName: String, childId: UUID, entitledResources: IpResourceSet) extends ResourceClassEvent
case class ChildRemoved(resourceClassName: String, childId: UUID) extends ResourceClassEvent
sealed trait ChildEvent extends ResourceClassEvent {
  def childId: UUID
  def resourceClassName: String
}
case class ChildUpdatedResourceEntitlements(resourceClassName: String, childId: UUID, entitledResources: IpResourceSet) extends ChildEvent
case class ChildReceivedCertificate(resourceClassName: String, childId: UUID, certificate: X509ResourceCertificate) extends ChildEvent

sealed trait RoaConfigurationEvent extends CertificateAuthorityEvent
case class RoaConfigurationPrefixAdded(roaAuthorisation: RoaAuthorisation) extends RoaConfigurationEvent
case class RoaConfigurationPrefixRemoved(roaAuthorisation: RoaAuthorisation) extends RoaConfigurationEvent

