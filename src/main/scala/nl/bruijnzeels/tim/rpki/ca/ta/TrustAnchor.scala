package nl.bruijnzeels.tim.rpki.ca.ta

import java.net.URI
import java.util.UUID

import net.ripe.ipresource.IpResourceSet

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import nl.bruijnzeels.tim.rpki.ca.signer.Signer
import nl.bruijnzeels.tim.rpki.ca.signer.SignerCreated
import nl.bruijnzeels.tim.rpki.ca.signer.SignerEvent

class TrustAnchorException(msg: String) extends RuntimeException(msg)

case class TrustAnchor(id: UUID, name: String = "", signer: Option[Signer] = None, events: List[Event] = List.empty) {

  def applyEvents(events: List[Event]): TrustAnchor = {
    events.foldLeft(this)((updated, event) => updated.applyEvent(event))
  }

  def applyEvent(event: Event): TrustAnchor = event match {
    case created: TaCreated => copy(name = created.name, events = events :+ event)
    case signerCreated: SignerCreated => copy(signer = Some(Signer(signerCreated.signingMaterial)), events = events :+ event)
    case signerEvent: SignerEvent => copy(signer = applySignerEvent(signerEvent), events = events :+ event)
  }

  private def applySignerEvent(signerEvent: SignerEvent) = Some(signer.get.applyEvent(signerEvent))

  // Signer support
  private def validateSignerExists(): Unit = if (signer.isEmpty) { throw new TrustAnchorException("No signer initialised") }
  private def validateSignerEmpty(): Unit = if (!signer.isEmpty) { throw new TrustAnchorException("Signer already initialised") }

  /**
   * Creates a signer for this TrustAnchor
   */
  def initialise(resources: IpResourceSet, taCertificateUri: URI, publicationDir: URI): TrustAnchor = {
    validateSignerEmpty()
    applyEvents(Signer.createSelfSigned(id, name, resources, taCertificateUri, publicationDir))
  }

  /**
   * Create a new publication set with an updated CRL and MFT for all current objects
   */
  def publish(): TrustAnchor = {
    validateSignerExists()
    applyEvents(signer.get.publish(id))
  }

}

object TrustAnchor {

  def rebuild(events: List[Event]): TrustAnchor = {
    TrustAnchor(events(0).aggregateId).applyEvents(events).copy(events = List())
  }

  def create(id: UUID, name: String): TrustAnchor = {
    TrustAnchor(id).applyEvent(TaCreated(id, name))
  }

}
