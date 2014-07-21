package nl.bruijnzeels.tim.rpki.ca
package certificateauthority.ca

import java.util.UUID

import common.cqrs.Event
import provisioning.ProvisioningCommunicator
import rc.ResourceClass

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
  resourceClass: List[ResourceClass] = List.empty,
  communicator: ProvisioningCommunicator = null,
  events: List[Event] = List.empty) {
  
  def applyEvents(events: List[Event]): CertificateAuthority = events.foldLeft(this)((updated, event) => updated.applyEvent(event))
  
  def applyEvent(event: Event): CertificateAuthority = event match {
    case _ => ???
  }

}

object CertificateAuthority {
  
  def rebuild(events: List[Event]): CertificateAuthority = events.head match {
    case created: CertificateAuthorityCreated => CertificateAuthority(id = created.aggregateId, name = created.name, events = List(created)).applyEvents(events.tail)
    case event: Event => throw new IllegalArgumentException(s"First event MUST be creation of the TrustAnchor, was: ${event}")
  }
  
  def create(id: UUID, name: String) = {
    val created = CertificateAuthorityCreated(aggregateId = id, name = name)
    
    rebuild(List(created))
  }

}
