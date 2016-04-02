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
package nl.bruijnzeels.tim.rpki.ca.rc

import java.util.UUID

import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import net.ripe.rpki.commons.provisioning.payload.common.{CertificateElementBuilder, GenericClassElementBuilder}
import net.ripe.rpki.commons.provisioning.payload.list.response.ResourceClassListResponseClassElement
import nl.bruijnzeels.tim.rpki.ca._
import nl.bruijnzeels.tim.rpki.ca.rc.child.Child
import nl.bruijnzeels.tim.rpki.ca.rc.signer.Signer
import nl.bruijnzeels.tim.rpki.common.domain.{RoaAuthorisation, RpkiObjectNameSupport}
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.joda.time.{DateTime, DateTimeZone}

import scala.collection.JavaConverters._

/**
 * The name for this class: ResourceClass is taken from the "Provisioning Resource Certificates" Protocol.
 * See: http://tools.ietf.org/html/rfc6492
 *
 * Essentially a Certificate Authority as a logical entity may not get all their resources in a single bundle.
 * Instead resources may be grouped in what are called resource classes.
 *
 */
case class ResourceClass(
  resourceClassName: String,
  currentSigner: Signer,
  children: Map[UUID, Child] = Map.empty) {

  def applyEvents(events: List[ResourceClassEvent]): ResourceClass = events.foldLeft(this)((updated, event) => updated.applyEvent(event))

  def applyEvent(event: ResourceClassEvent): ResourceClass = event match {
    case signerCreated: SignerCreated => copy(currentSigner = Signer(null))
    case signerEvent: SignerEvent => copy(currentSigner = currentSigner.applyEvent(signerEvent))
    case childCreated: ChildCreated => copy(children = children + (childCreated.childId -> Child.created(childCreated)))
    case childEvent: ChildEvent => copy(children = processChildEvent(childEvent))
  }

  private def processChildEvent(event: ChildEvent) = {
    val child = children.getOrElse(event.childId, throw new IllegalArgumentException(s"Unknown child with id: ${event.childId}"))
    children + (child.id -> child.applyEvent(event))
  }

  private def isOverclaiming(resources: IpResourceSet) = {
    val overclaiming = new IpResourceSet(resources) // Don't modify input..
    overclaiming.removeAll(currentSigner.resources)
    !overclaiming.isEmpty
  }

  private def createClassElementBuilder(child: Child) = {
    new GenericClassElementBuilder()
      .withClassName(resourceClassName)
      .withCertificateAuthorityUri(List(currentSigner.signingMaterial.certificateUri).asJava)
      .withIpResourceSet(child.entitledResources)
      .withValidityNotAfter(new DateTime().plusYears(1).withZone(DateTimeZone.UTC))
      .withIssuer(currentSigner.signingMaterial.currentCertificate)
  }

  def buildClassResponseForChild(childId: UUID) = {
    val child = children.get(childId).get

    val responseBuilder = createClassElementBuilder(child)

    val certificateUri = currentSigner.signingMaterial.certificateUri

    responseBuilder.withCertificateAuthorityUri(List(certificateUri).asJava)

    // Here we return *all* certificates
    val certificateElements = child.currentCertificates.map { certificate => val certificatePublicationUri = currentSigner.signingMaterial.currentCertificate.getRepositoryUri().resolve(RpkiObjectNameSupport.deriveName(certificate))

      new CertificateElementBuilder().withIpResources(certificate.getResources())
        .withCertificatePublishedLocations(List(certificatePublicationUri).asJava)
        .withCertificate(certificate).build()
    }

    if (certificateElements.size > 0) {
      responseBuilder.withCertificateElements(certificateElements.asJava).buildResourceClassListResponseClassElement()
    } else {
      responseBuilder.buildResourceClassListResponseClassElement()
    }
  }

  def buildCertificateIssuanceResponse(childId: UUID, certificate: X509ResourceCertificate) = {
    val certificateElement = {
      val certificatePublicationUri = currentSigner.signingMaterial.currentCertificate.getRepositoryUri().resolve(RpkiObjectNameSupport.deriveName(certificate))
      new CertificateElementBuilder().withIpResources(certificate.getResources())
        .withCertificatePublishedLocations(List(certificatePublicationUri).asJava)
        .withCertificate(certificate).build()
    }

    createClassElementBuilder(children.get(childId).get)
      .withCertificateElements(List(certificateElement).asJava)
      .withCertificateAuthorityUri(List(currentSigner.signingMaterial.certificateUri).asJava)
      .buildCertificateIssuanceResponseClassElement()
  }

  def processResourceClassResponse(element: ResourceClassListResponseClassElement): Option[SignerCreatedPendingCertificateRequest] = {

    def getResourcesElement(element: ResourceClassListResponseClassElement) = {
      val resources = element.getResourceSetAsn
      resources.addAll(element.getResourceSetIpv4)
      resources.addAll(element.getResourceSetIpv6)
      resources
    }

    val entitledResources = getResourcesElement(element)
    val entitledNotAfter = element.getValidityNotAfter

    currentSigner.requestCertificateIfNeeded(resourceClassName, entitledResources, entitledNotAfter)
  }

  def updateChild(childId: UUID, entitledResources: IpResourceSet): Option[ChildEvent] = {
    if (isOverclaiming(entitledResources)) {
      throw new CertificateAuthorityException("Trying to assign resources to child not held by this CA")
    }

    children.isDefinedAt(childId) match {
      case true => entitledResources.isEmpty match {
        case true => ??? // remove and revoke
        case false => Some(ChildUpdatedResourceEntitlements(resourceClassName, childId, entitledResources))
      }
      case false => entitledResources.isEmpty match {
        case true => None
        case false => Some(ChildCreated(resourceClassName, childId, entitledResources))
      }
    }

  }

  /**
   * <p>
   * Process a certificate sign request for a child. Returns list of events in case this is successful,
   * or an error in case:
   * </p>
   * <ul>
   *   <li>the child is not known</li>
   *   <li>the request includes resources the child is not entitled to</li>
   *   <li>the request includes resources this resource class is not authoritative over</li>
   * </ul>
   */
  def processChildCertificateRequest(childId: UUID, requestedResources: Option[IpResourceSet], pkcs10Request: PKCS10CertificationRequest): List[ResourceClassEvent] = children.get(childId) match {

    case None => throw new CertificateAuthorityException(s"Unknown child with id: ${childId}")

    case Some(child) => {
      val resources = requestedResources.getOrElse(child.entitledResources)
      if (!child.entitledResources.contains(resources)) {
        throw new CertificateAuthorityException(s"Child is not entitled to all resources in set: ${resources}")
      } else {
        val signed = currentSigner.signChildCertificateRequest(resourceClassName, resources, pkcs10Request)
        val childReceived = ChildReceivedCertificate(resourceClassName, childId, signed.certificate)
        val newCertificateEvents = List(signed, childReceived)

        child.currentCertificateForKey(signed.certificate.getPublicKey) match {
          case None => newCertificateEvents
          case Some(cert) => {
            currentSigner.revokeCaCertificate(resourceClassName, cert) ++ newCertificateEvents
          }
        }
      }
    }
  }

  /**
   * Publish this resource class and all current certificates
   */
  def publish(authorisations: List[RoaAuthorisation] = List.empty) = currentSigner.publish(resourceClassName, authorisations)

}

object ResourceClass {
  def created(created: ResourceClassCreated) = ResourceClass(resourceClassName = created.resourceClassName, currentSigner = null)
}