package nl.bruijnzeels.tim.rpki.publication.server

import scala.Option.option2Iterable
import java.math.BigInteger
import java.net.URI
import java.util.UUID
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.AggregateRoot
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import nl.bruijnzeels.tim.rpki.publication.messages.Delta
import nl.bruijnzeels.tim.rpki.publication.messages.DeltaReference
import nl.bruijnzeels.tim.rpki.publication.messages.Deltas
import nl.bruijnzeels.tim.rpki.publication.messages.Notification
import nl.bruijnzeels.tim.rpki.publication.messages.PublicationProtocolMessage
import nl.bruijnzeels.tim.rpki.publication.messages.Publish
import nl.bruijnzeels.tim.rpki.publication.messages.ReferenceHash
import nl.bruijnzeels.tim.rpki.publication.messages.Snapshot
import nl.bruijnzeels.tim.rpki.publication.messages.SnapshotReference
import nl.bruijnzeels.tim.rpki.publication.messages.Withdraw
import nl.bruijnzeels.tim.rpki.publication.messages.DeltaProtocolMessage

case class PublicationServer(
  id: UUID,
  sessionId: UUID,
  rrdpBaseUri: URI,
  serial: BigInteger,
  snapshot: Snapshot,
  deltas: List[Deltas] = List.empty,
  events: List[Event] = List.empty) extends AggregateRoot {

  private val MaxDeltas = 100

  override def applyEvents(events: List[Event]): PublicationServer = events.foldLeft(this)((updated, event) => updated.applyEvent(event))
  override def clearEventList(): PublicationServer = copy(events = List.empty)

  def applyEvent(event: Event): PublicationServer = event match {
    case created: PublicationServerCreated =>
      copy(id = created.aggregateId,
        sessionId = created.sessionId,
        rrdpBaseUri = created.rrdpBaseUri,
        serial = BigInteger.ZERO,
        snapshot = Snapshot(created.sessionId, BigInteger.ZERO, List.empty),
        events = events :+ event)
    case receivedDeltas: PublicationServerReceivedDeltas => copy(deltas = (List(receivedDeltas.deltas) ++ deltas).take(MaxDeltas), events = events :+ receivedDeltas)
    case receivedSnapshot: PublicationServerReceivedSnapshot => copy(serial = receivedSnapshot.snapshot.serial, snapshot = receivedSnapshot.snapshot, events = events :+ receivedSnapshot)
  }

  def publish(messages: List[PublicationProtocolMessage]) = {

    val deltasReceivedEvent = {
      val delta = Delta(serial = serial.add(BigInteger.ONE), messages = messages)
      val newDeltas = Deltas(sessionId = sessionId, from = serial, to = delta.serial, deltas = List(delta))
      PublicationServerReceivedDeltas(id, newDeltas)
    }

    val snapshotReceivedEvent = {
      val publishes = messages.collect { case p: Publish => p }

      val withdrawnHashes = messages.collect { case w: Withdraw => w }.map { _.hash }
      val updatedHashes = publishes.flatMap(_.replaces)
      val hashesToRemove = withdrawnHashes ++ updatedHashes

      val remainingPublishes = snapshot.publishes.filterNot(o => hashesToRemove.contains(ReferenceHash.fromBytes(o.repositoryObject.getEncoded)))

      val newSnapshot = Snapshot(sessionId, serial.add(BigInteger.ONE), remainingPublishes ++ publishes)
      PublicationServerReceivedSnapshot(id, newSnapshot)
    }

    applyEvents(List(deltasReceivedEvent, snapshotReceivedEvent))
  }

  /**
   * Create a notification file for the current version, with pointers to full dumps and deltas
   */
  def notificationFile: Notification = {

    val snapshotReference = SnapshotReference(uri = fileUrl(snapshot), hash = ReferenceHash.fromXml(snapshot.toXml))
    val deltasReferences = deltas.map { d =>
      DeltaReference(uri = fileUrl(d), from = d.from, to = d.to, hash = ReferenceHash.fromXml(d.toXml))
    }

    Notification(sessionId, serial, snapshotReference, deltasReferences)
  }

  private def fileUrl(file: DeltaProtocolMessage) = rrdpBaseUri.resolve(s"${ReferenceHash.fromXml(file.toXml)}.xml")

}

object PublicationServer {
  def create(aggregateId: UUID, baseUri: URI) = PublicationServer(null, null, null, null, null).applyEvent(PublicationServerCreated(aggregateId, UUID.randomUUID(), baseUri))
  def rebuild(events: List[Event]) = PublicationServer(null, null, null, null, null).applyEvents(events)
}