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
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject
import net.ripe.rpki.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayload
import net.ripe.rpki.commons.provisioning.payload.issue.response.{CertificateIssuanceResponsePayload, CertificateIssuanceResponsePayloadBuilder}
import net.ripe.rpki.commons.provisioning.payload.list.request.{ResourceClassListQueryPayload, ResourceClassListQueryPayloadBuilder}
import net.ripe.rpki.commons.provisioning.payload.list.response.{ResourceClassListResponseClassElement, ResourceClassListResponsePayload, ResourceClassListResponsePayloadBuilder}
import nl.bruijnzeels.tim.rpki.ca.provisioning._
import nl.bruijnzeels.tim.rpki.ca.rc.ResourceClass
import nl.bruijnzeels.tim.rpki.ca.rc.signer.Signer
import nl.bruijnzeels.tim.rpki.ca.roas.RoaConfiguration
import nl.bruijnzeels.tim.rpki.common.cqrs.{CertificationAuthorityAggregate, Event, VersionedId}
import nl.bruijnzeels.tim.rpki.common.domain.RoaAuthorisation

import scala.collection.JavaConverters.asScalaBufferConverter

/**
  * A CertificateAuthority
  *
  * Can be created as a Trust Anchor, in that case a self signed certificate with any resource set can be used
  * Or can be created as a 'normal' CA, in which case a parent CA needs to be added.
  *
  * Can have any number of Child CAs
  *
  * Note: Although the requests and issuance between CAs here follow the semantics of the RPKI provisioning
  * protocol, remote parent/children are not yet supported. The same XML is used but the provisioningCMS wrapping
  * and verification of trust is missing (i.e. we can assume that requests can be trusted).
  *
  */
case class CertificateAuthority(
  versionedId: VersionedId,
  name: String,
  baseUrl: URI,
  rrdpNotifyUrl: URI,
  resourceClasses: Map[String, ResourceClass] = Map.empty,
  communicator: ProvisioningCommunicator = null, // will be set by communicator created event
  roaConfiguration: RoaConfiguration = new RoaConfiguration(),
  events: List[Event] = List.empty) extends ParentCertificateAuthority {

  override def applyEvents(events: List[Event]): CertificateAuthority = events.foldLeft(this)((updated, event) => updated.applyEvent(event))

  override def clearEventList(): CertificateAuthority = copy(events = List.empty)

  override def aggregateType = CertificationAuthorityAggregate

  def applyEvent(event: Event): CertificateAuthority = event match {

    case e: ProvisioningCommunicatorCreated =>
      copy(communicator = ProvisioningCommunicator(e.myIdentity), events = events :+ e)

    case e: ProvisioningCommunicatorEvent =>
      copy(communicator = communicator.applyEvent(e), events = events :+ e)

    case e: ResourceClassCreated =>
      copy(resourceClasses = resourceClasses + (e.resourceClassName -> ResourceClass.created(e)), events = events :+ e)

    case e: ResourceClassEvent => {
      val rc = resourceClasses.getOrElse(e.resourceClassName, throw new IllegalArgumentException("Got event for unknown resource class"))
      copy(resourceClasses = resourceClasses + (rc.resourceClassName -> rc.applyEvent(e)), events = events :+ e)
    }

    case e: RoaConfigurationEvent => copy (roaConfiguration = roaConfiguration.applyEvent(e), events = events :+ e)
  }

  def addParent(parentXml: String): CertificateAuthority = applyEvent(communicator.addParent(parentXml))

  def addChild(childId: UUID, childXml: String, childResources: IpResourceSet): CertificateAuthority = {
    if(!communicator.children.contains(childId)) {
      applyEvent(communicator.addChild(childId, childXml)).updateChild(childId, childResources)
    } else {
      throw new CertificateAuthorityException(s"Unknown child with id ${childId}")
    }
  }

  def updateChild(childId: UUID, childResources: IpResourceSet) = {
    if(!communicator.children.contains(childId)) {
      throw new CertificateAuthorityException(s"Unknown child with id ${childId}")
    }

    val childEvents = resourceClasses.values.toList.flatMap { rc =>
      val entitledResources = rc.currentSigner.resources
      entitledResources.retainAll(childResources)
      rc.updateChild(childId, entitledResources)
    }

    applyEvents(childEvents)
  }

  def addRoa(roaAuthorisation: RoaAuthorisation): CertificateAuthority = applyEvent(roaConfiguration.addRoaAuthorisation(roaAuthorisation))

  def removeRoa(roaAuthorisation: RoaAuthorisation): CertificateAuthority = applyEvent(roaConfiguration.removeRoaAuthorisation(roaAuthorisation))

  def publish(): CertificateAuthority = {
    applyEvents(resourceClasses.values.toList.flatMap { rc =>
      val roaAuthorisations = roaConfiguration.findRelevantRoaPrefixes(rc.currentSigner.resources)
      rc.publish(roaAuthorisations)})
  }

  override def processListQuery(childId: UUID, request: ProvisioningCmsObject): ListQueryResponse = {
    communicator.validateChildRequest(childId, request) match {
      case failure: ProvisioningMessageValidationFailure => throw new CertificateAuthorityException(failure.reason) // TODO: handle gracefully?
      case success: ProvisioningMessageValidationSuccess => {
        success.payload match {
          case query: ResourceClassListQueryPayload => {
            val builder = new ResourceClassListResponsePayloadBuilder()

            for (rc <- resourceClasses.values) {
              builder.addClassElement(rc.buildClassResponseForChild(childId))
            }
            val responsePayload = builder.build()

            val response = communicator.signResponse(childId, responsePayload)

            ListQueryResponse(
              updatedParent = applyEvent(ProvisioningCommunicatorPerformedChildExchange(ProvisioningChildExchange(childId, request, response))),
              response = response)
          }
          case _ => throw new CertificateAuthorityException("Expected resource class list query")
        }
      }
    }
  }

  override def processCertificateIssuanceRequest(childId: UUID, request: ProvisioningCmsObject): CertificateIssuanceResponse = {
    communicator.validateChildRequest(childId, request) match {
      case failure: ProvisioningMessageValidationFailure => throw new CertificateAuthorityException(failure.reason)
      case success: ProvisioningMessageValidationSuccess => {
        success.payload match {
          case requestPayload: CertificateIssuanceRequestPayload => {

            val requestedResources = {
              if (requestPayload.getRequestElement().getAllocatedAsn() == null &&
                requestPayload.getRequestElement().getAllocatedIpv4() == null &&
                requestPayload.getRequestElement().getAllocatedIpv6() == null) {
                None
              } else {
                val resources = new IpResourceSet()
                resources.addAll(requestPayload.getRequestElement().getAllocatedAsn())
                resources.addAll(requestPayload.getRequestElement().getAllocatedIpv4())
                resources.addAll(requestPayload.getRequestElement().getAllocatedIpv6())
                Some(resources)
              }
            }

            val resourceClass = resourceClasses.getOrElse(requestPayload.getRequestElement.getClassName, {
              throw new CertificateAuthorityException("Don't have resource class for request")
            })

            val events = resourceClass.processChildCertificateRequest(childId, requestedResources, requestPayload.getRequestElement().getCertificateRequest())

            val signed = events.collect { case e: SignerSignedCaCertificate => e }.head
            val responsePayload = new CertificateIssuanceResponsePayloadBuilder()
                  .withClassElement(resourceClass.buildCertificateIssuanceResponse(childId, signed.certificate))
                  .build()

            val response = communicator.signResponse(childId, responsePayload)

            CertificateIssuanceResponse(
              updatedParent = applyEvents(events :+ ProvisioningCommunicatorPerformedChildExchange(ProvisioningChildExchange(childId, request, response))),
              response = response)
          }
          case _ => throw new CertificateAuthorityException("Expected a certificate issuance request")
        }
      }
    }
  }

  def createResourceClassListRequest(): ProvisioningCmsObject = communicator.signRequest(new ResourceClassListQueryPayloadBuilder().build())

  def createCertificateIssuanceRequests(): List[ProvisioningCmsObject] = {
    resourceClasses.values.filter(_.currentSigner.pendingCertificateRequest.isDefined).map { rc =>
      communicator.signRequest(rc.currentSigner.pendingCertificateRequest.get)
    }.toList
  }



  def processResourceClassListResponse(myRequest: ProvisioningCmsObject, response: ProvisioningCmsObject) = {


    communicator.validateParentResponse(response) match {
      case failure: ProvisioningMessageValidationFailure => throw new CertificateAuthorityException(failure.reason)
      case success: ProvisioningMessageValidationSuccess => {
        success.payload match {
          case classListResponse: ResourceClassListResponsePayload => {
            val resourceClassEvents = classListResponse.getClassElements().asScala.flatMap { element =>
              val className = element.getClassName()

              resourceClasses.get(className) match {
                case Some(rc) => rc.processResourceClassResponse(element)
                case None => List(ResourceClassCreated(className)) ++
                  Signer.create(className, baseUrl.resolve(s"${versionedId.id}/${className}/"), rrdpNotifyUrl) :+
                  ProvisioningCommunicatorPerformedParentExchange(ProvisioningParentExchange(myRequest, response))
              }
            }.toList
            applyEvents(resourceClassEvents)
          }
          // TODO: Gracefully handle error response (other response types are more problematic though)
          // TODO: Handle resource class disappearing on response -> remove resource class, and unpublish everything
          case _ => throw new CertificateAuthorityException("Expected resource class list response, but got: " + success.payload.getType())
        }
      }
    }

  }

  def processCeritificateIssuanceResponse(myRequest: ProvisioningCmsObject, response: ProvisioningCmsObject) = {
    communicator.validateParentResponse(response) match {
      case failure: ProvisioningMessageValidationFailure => throw new CertificateAuthorityException(failure.reason)
      case success: ProvisioningMessageValidationSuccess => {
        success.payload match {
          case issuanceResponse: CertificateIssuanceResponsePayload =>
            val resourceClassName = issuanceResponse.getClassElement().getClassName()
            val certificate = issuanceResponse.getClassElement().getCertificateElement().getCertificate()
            val signerReceivedCertificate = SignerReceivedCertificate(resourceClassName, certificate)

            val pcPerformedCommunication = ProvisioningCommunicatorPerformedParentExchange(ProvisioningParentExchange(myRequest, response))

            applyEvents(List(signerReceivedCertificate, pcPerformedCommunication))
          case _ => {
            // TODO: Gracefully handle error response (other response types are more problematic though)
            throw new CertificateAuthorityException("Expected resource certificate issuance response, but got: " + success.payload.getType())
          }
        }
      }
    }
  }
}

object CertificateAuthority {

  val DefaultResourceClassName = "default"

  def rebuild(events: List[Event]): CertificateAuthority = events.head match {
    case created: CertificateAuthorityCreated =>
      CertificateAuthority(
        versionedId = VersionedId(created.aggregateId),
        name = created.name,
        baseUrl = created.baseUrl,
        rrdpNotifyUrl = created.rrdpNotifyUrl,
        events = List(created)).applyEvents(events.tail)

    case event: Event =>
      throw new IllegalArgumentException(s"First event MUST be creation of the CertificateAuthority, was: ${event}")
  }

  def create(id: UUID, name: String, publicationDirUrl: URI, rrdpNotifyUrl: URI): CertificateAuthority = {
    val created = CertificateAuthorityCreated(aggregateId = id, name = name, baseUrl = publicationDirUrl, rrdpNotifyUrl = rrdpNotifyUrl)
    val createdProvisioningCommunicator = ProvisioningCommunicator.create(id)

    rebuild(List(created, createdProvisioningCommunicator))
  }

  def createAsTrustAnchor(id: UUID, name: String, resources: IpResourceSet, taCertificateUri: URI, publicationDirUrl: URI, rrdpNotifyUrl: URI): CertificateAuthority = {
    val created = CertificateAuthorityCreated(aggregateId = id, name = name, baseUrl = publicationDirUrl, rrdpNotifyUrl = rrdpNotifyUrl)
    val createdProvisioningCommunicator = ProvisioningCommunicator.create(id)

    val createdResourceClass = ResourceClassCreated(DefaultResourceClassName)
    val createdSelfSignedSigner = Signer.createSelfSigned(DefaultResourceClassName, name, resources, taCertificateUri, publicationDirUrl, rrdpNotifyUrl)

    rebuild(List(created, createdResourceClass) ++ createdSelfSignedSigner :+ createdProvisioningCommunicator)
  }

  def printTal(ca: CertificateAuthority) = {
    try {
      val resourceClass = ca.resourceClasses.get(DefaultResourceClassName).get
      val rootCertUri = resourceClass.currentSigner.signingMaterial.certificateUri
      val rootCert = resourceClass.currentSigner.signingMaterial.currentCertificate.getCertificate
      val rootCertFingerPrint = X509CertificateUtil.getEncodedSubjectPublicKeyInfo(rootCert).grouped(60).mkString("\n")
      s"${rootCertUri}\n\n${rootCertFingerPrint}"
    } catch {
      case _: Throwable => s"Could not create TAL for CA ${ca.name}. Are you sure this CA is a TrustAnchor?"
    }
  }

}

case class CertificateAuthorityException(msg: String) extends RuntimeException
