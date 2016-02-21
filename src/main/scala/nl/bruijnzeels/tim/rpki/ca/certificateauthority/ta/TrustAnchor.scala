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
package nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta

import java.net.URI
import java.util.UUID
import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject
import net.ripe.rpki.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayload
import net.ripe.rpki.commons.provisioning.payload.issue.response.CertificateIssuanceResponsePayloadBuilder
import net.ripe.rpki.commons.provisioning.payload.list.request.ResourceClassListQueryPayload
import net.ripe.rpki.commons.provisioning.payload.list.response.ResourceClassListResponsePayloadBuilder
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.{CertificateIssuanceResponse, ListQueryResponse, ParentCertificateAuthority}
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.AggregateRoot
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.VersionedId
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningChildExchange
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningCommunicator
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningCommunicatorCreated
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningCommunicatorEvent
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningCommunicatorPerformedChildExchange
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningMessageValidationFailure
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningMessageValidationSuccess
import nl.bruijnzeels.tim.rpki.ca.rc.ResourceClass
import nl.bruijnzeels.tim.rpki.ca.rc.ResourceClassCreated
import nl.bruijnzeels.tim.rpki.ca.rc.ResourceClassEvent
import nl.bruijnzeels.tim.rpki.ca.rc.signer.Signer
import nl.bruijnzeels.tim.rpki.ca.rc.signer.SignerSignedCertificate
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.TrustAnchorAggregate

/**
 * Root Certificate Authority for RPKI. Does not have a parent CA and has a self-signed certificate.
 */
case class TrustAnchor(
  versionedId: VersionedId,
  name: String,
  resourceClass: ResourceClass = null,
  communicator: ProvisioningCommunicator = null,
  events: List[Event] = List.empty) extends ParentCertificateAuthority {

  override def applyEvents(events: List[Event]): TrustAnchor = events.foldLeft(this)((updated, event) => updated.applyEvent(event))
  override def clearEventList() = copy(events = List.empty)
  override def aggregateType = TrustAnchorAggregate

  def applyEvent(event: Event): TrustAnchor = event match {
    case resourceClassCreated: ResourceClassCreated => copy(resourceClass = ResourceClass.created(resourceClassCreated), events = events :+ event)
    case resourceClassEvent: ResourceClassEvent => copy(resourceClass = resourceClass.applyEvent(resourceClassEvent), events = events :+ event)
    case communicatorCreated: ProvisioningCommunicatorCreated => copy(communicator = ProvisioningCommunicator(communicatorCreated.myIdentity), events = events :+ event)
    case comminicatorEvent: ProvisioningCommunicatorEvent => copy(communicator = communicator.applyEvent(comminicatorEvent), events = events :+ event)
  }

  def publish(): TrustAnchor = applyEvents(resourceClass.publish)

  def addChild(childId: UUID, childXml: String, childResources: IpResourceSet): TrustAnchor = {
    resourceClass.addChild(childId, childResources) match {
      case Left(created) => applyEvents(List(created, communicator.addChild(childId, childXml)))
      case Right(failed) => throw new TrustAnchorException(failed.reason)
    }
  }

  /**
   * Creates a TAL for this Trust Anchor
   */
  def tal = {
    val rootCertUri = resourceClass.currentSigner.signingMaterial.certificateUri
    val rootCert = resourceClass.currentSigner.signingMaterial.currentCertificate.getCertificate
    val rootCertFingerPrint = X509CertificateUtil.getEncodedSubjectPublicKeyInfo(rootCert).grouped(60).mkString("\n")

    s"${rootCertUri}\n\n${rootCertFingerPrint}"
  }

  /**
   * Will return a new TA that has the response registered with the child
   */
  override def processListQuery(childId: UUID, request: ProvisioningCmsObject): ListQueryResponse = {
    communicator.validateChildRequest(childId, request) match {
      case failure: ProvisioningMessageValidationFailure => throw new TrustAnchorException(failure.reason)
      case success: ProvisioningMessageValidationSuccess => {
        success.payload match {
          case query: ResourceClassListQueryPayload => {
            val builder = new ResourceClassListResponsePayloadBuilder()
            builder.addClassElement(resourceClass.buildClassResponseForChild(childId))
            val responsePayload = builder.build()

            val response = communicator.signResponse(childId, responsePayload)

            ListQueryResponse(
                updatedParent = applyEvent(ProvisioningCommunicatorPerformedChildExchange(ProvisioningChildExchange(childId, request, response))),
                response = response)
          }
          case _ => throw new TrustAnchorException("Expected resource class list query")
        }
      }
    }
  }

  /**
   * Will return a new TA that has the response registered with the child
   */
  override def processCertificateIssuanceRequest(childId: UUID, request: ProvisioningCmsObject): CertificateIssuanceResponse = {
    communicator.validateChildRequest(childId, request) match {
      case failure: ProvisioningMessageValidationFailure => throw new TrustAnchorException(failure.reason)
      case success: ProvisioningMessageValidationSuccess => {
        success.payload match {
          case issuancePayload: CertificateIssuanceRequestPayload => {

            val requestedResources = {
              if (issuancePayload.getRequestElement().getAllocatedAsn() == null &&
                issuancePayload.getRequestElement().getAllocatedIpv4() == null &&
                issuancePayload.getRequestElement().getAllocatedIpv6() == null) {
                None
              } else {
                val resources = new IpResourceSet()
                resources.addAll(issuancePayload.getRequestElement().getAllocatedAsn())
                resources.addAll(issuancePayload.getRequestElement().getAllocatedIpv4())
                resources.addAll(issuancePayload.getRequestElement().getAllocatedIpv6())
                Some(resources)
              }
            }

            resourceClass.processChildCertificateRequest(childId, requestedResources, issuancePayload.getRequestElement().getCertificateRequest()) match {
              case Right(failure) => throw new TrustAnchorException(failure.reason) // TODO: Return error response instead
              case Left(events) => {
                val signed = events.collect { case e: SignerSignedCertificate => e }.head

                val responsePayload = new CertificateIssuanceResponsePayloadBuilder()
                  .withClassElement(resourceClass.buildCertificateIssuanceResponse(childId, signed.certificate))
                  .build()

                val response = communicator.signResponse(childId, responsePayload)

                CertificateIssuanceResponse(
                    updatedParent = applyEvents(events :+ ProvisioningCommunicatorPerformedChildExchange(ProvisioningChildExchange(childId, request, response))),
                    response = response)
              }
            }

          }
          case _ => throw new TrustAnchorException("Expected a certificate issuance request")
        }
      }
    }
  }

}

object TrustAnchor {

  val DefaultResourceClassName = "default"

  def rebuild(events: List[Event]): TrustAnchor = events.head match {
    case created: TrustAnchorCreated => TrustAnchor(versionedId = VersionedId(created.aggregateId), name = created.name, events = List(created)).applyEvents(events.tail)
    case event: Event => throw new IllegalArgumentException(s"First event MUST be creation of the TrustAnchor, was: ${event}")
  }

  def create(aggregateId: UUID, name: String, taCertificateUri: URI, publicationDir: URI, rrdpUri: URI, resources: IpResourceSet): TrustAnchor = {
    val taCreated = TrustAnchorCreated(aggregateId, name)
    val resourceClassCreatedEvent = ResourceClassCreated(DefaultResourceClassName)
    val createSignerEvents = Signer.createSelfSigned(DefaultResourceClassName, name, resources, taCertificateUri, publicationDir, rrdpUri)
    val createProvisioningCommunicatorEvent = ProvisioningCommunicator.create(aggregateId)

    rebuild(List(taCreated, resourceClassCreatedEvent) ++ createSignerEvents :+ createProvisioningCommunicatorEvent)
  }
}

case class TrustAnchorException(msg: String) extends RuntimeException