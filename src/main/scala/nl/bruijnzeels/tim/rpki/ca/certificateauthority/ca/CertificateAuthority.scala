package nl.bruijnzeels.tim.rpki.ca.certificateauthority.ca

import scala.collection.JavaConverters.asScalaBufferConverter

import java.net.URI
import java.util.UUID

import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject
import net.ripe.rpki.commons.provisioning.payload.issue.response.CertificateIssuanceResponsePayload
import net.ripe.rpki.commons.provisioning.payload.list.response.ResourceClassListResponsePayload

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.AggregateRoot
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningCommunicator
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningCommunicatorCreated
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningCommunicatorEvent
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningCommunicatorPerformedParentExchange
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningMessageValidationFailure
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningMessageValidationSuccess
import nl.bruijnzeels.tim.rpki.ca.provisioning.ProvisioningParentExchange
import nl.bruijnzeels.tim.rpki.ca.rc.ResourceClass
import nl.bruijnzeels.tim.rpki.ca.rc.ResourceClassCreated
import nl.bruijnzeels.tim.rpki.ca.rc.ResourceClassEvent
import nl.bruijnzeels.tim.rpki.ca.rc.signer.Signer
import nl.bruijnzeels.tim.rpki.ca.rc.signer.SignerReceivedCertificate

/**
 *  A Certificate Authority in RPKI. Needs to have a parent which can be either
 *  another Certificate Authority, or a Trust Anchor.
 *
 *  For now this implementation will only support having a single parent, and can
 *  have no children. It does not support ROAs yet, either..
 *
 *  Future versions though should support the notion of multiple parents, and
 *  multiple resource classes coming from them, and multiple children, and of
 *  course ROAs..
 */
case class CertificateAuthority(
  id: UUID,
  name: String,
  baseUrl: URI,
  rrdpNotifyUrl: URI,
  resourceClasses: Map[String, ResourceClass] = Map.empty,
  communicator: ProvisioningCommunicator = null, // will be set by communicator created event
  events: List[Event] = List.empty) extends AggregateRoot {

  override def applyEvents(events: List[Event]): CertificateAuthority = events.foldLeft(this)((updated, event) => updated.applyEvent(event))
  override def clearEventList(): CertificateAuthority = copy(events = List.empty)

  def applyEvent(event: Event): CertificateAuthority = event match {
    case communicatorCreated: ProvisioningCommunicatorCreated =>
      copy(communicator = ProvisioningCommunicator(communicatorCreated.myIdentity),
        events = events :+ event)

    case communicatorEvent: ProvisioningCommunicatorEvent =>
      copy(communicator = communicator.applyEvent(communicatorEvent),
        events = events :+ event)

    case resourceClassCreated: ResourceClassCreated =>
      copy(resourceClasses = resourceClasses + (resourceClassCreated.resourceClassName -> ResourceClass.created(resourceClassCreated)),
        events = events :+ event)

    case resourceClassEvent: ResourceClassEvent =>
      copy(resourceClasses = processResourceClassEvent(resourceClassEvent),
        events = events :+ event)
  }

  def processResourceClassEvent(event: ResourceClassEvent) = {
    val rc = resourceClasses.getOrElse(event.resourceClassName, throw new IllegalArgumentException("Got event for unknown resource class"))
    resourceClasses + (rc.resourceClassName -> rc.applyEvent(event))
  }

  def addParent(parentXml: String) = applyEvent(communicator.addParent(id, parentXml))

  def publish(): CertificateAuthority = {
    applyEvents(resourceClasses.values.toList.flatMap(rc => rc.publish))
  }


  def processResourceClassListResponse(myRequest: ProvisioningCmsObject, response: ProvisioningCmsObject) = {
    communicator.validateParentResponse(response) match {
      case failure: ProvisioningMessageValidationFailure => throw new CertificateAuthorityException(failure.reason)
      case success: ProvisioningMessageValidationSuccess => {
        success.payload match {
          case classListResponse: ResourceClassListResponsePayload => {
            val resourceClassEvents = classListResponse.getClassElements().asScala.map(_.getClassName()).flatMap { className =>
              if (resourceClasses.contains(className)) {
                ??? // won't do updates for now
              } else {
                List(ResourceClassCreated(id, className)) ++
                  Signer.create(id, className, baseUrl.resolve(s"/${id}/${className}/"), rrdpNotifyUrl) :+
                  ProvisioningCommunicatorPerformedParentExchange(id, ProvisioningParentExchange(myRequest, response))
              }
            }.toList
            applyEvents(resourceClassEvents)
          }
          // TODO: Gracefully handle error response (other response types are more problematic though)
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
            val signerReceivedCertificate = SignerReceivedCertificate(id, resourceClassName, certificate)

            val pcPerformedCommunication = ProvisioningCommunicatorPerformedParentExchange(id, ProvisioningParentExchange(myRequest, response))

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

  def rebuild(events: List[Event]): CertificateAuthority = events.head match {
    case created: CertificateAuthorityCreated =>
      CertificateAuthority(
        id = created.aggregateId,
        name = created.name,
        baseUrl = created.baseUrl,
        rrdpNotifyUrl = created.rrdpNotifyUrl,
        events = List(created)).applyEvents(events.tail)

    case event: Event =>
      throw new IllegalArgumentException(s"First event MUST be creation of the CertificateAuthority, was: ${event}")
  }

  def create(id: UUID, name: String, baseUrl: URI, rrdpNotifyUrl: URI) = {
    val created = CertificateAuthorityCreated(aggregateId = id, name = name, baseUrl = baseUrl, rrdpNotifyUrl = rrdpNotifyUrl)
    val createdProvisioningCommunicator = ProvisioningCommunicator.create(id)

    rebuild(List(created, createdProvisioningCommunicator))
  }
}

case class CertificateAuthorityException(msg: String) extends RuntimeException
