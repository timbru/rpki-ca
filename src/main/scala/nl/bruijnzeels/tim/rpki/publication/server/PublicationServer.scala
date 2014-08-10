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

case class PublicationServer(
  id: UUID,
  sessionId: UUID,
  serial: BigInteger,
  snapshot: Snapshot,
  deltas: List[Deltas] = List.empty,
  events: List[Event] = List.empty) extends AggregateRoot {

  private val BaseUri = URI.create("http://localhost:8080/rrdp/")
  private val MaxDeltas = 100

  override def applyEvents(events: List[Event]): PublicationServer = events.foldLeft(this)((updated, event) => updated.applyEvent(event))
  override def clearEventList(): PublicationServer = copy(events = List.empty)

  def applyEvent(event: Event): PublicationServer = event match {
    case created: PublicationServerCreated =>
      copy(id = created.aggregateId,
        sessionId = created.sessionId,
        serial = BigInteger.ZERO,
        snapshot = Snapshot(created.sessionId, BigInteger.ZERO, List.empty),
        events = events :+ event)
    case receivedDelta: PublicationServerReceivedDelta => applyDelta(receivedDelta)
  }

  def applyDelta(receivedDelta: PublicationServerReceivedDelta) = {
    val delta = receivedDelta.delta
    val publishes = delta.messages.collect { case p: Publish => p }

    val withdrawnHashes = delta.messages.collect { case w: Withdraw => w }.map { _.hash }
    val updatedHashes = publishes.flatMap(_.replaces)
    val hashesToRemove = withdrawnHashes ++ updatedHashes

    val remainingPublishes = snapshot.publishes.filterNot(o => hashesToRemove.contains(ReferenceHash.fromBytes(o.repositoryObject.getEncoded)))

    val newSnapshot = Snapshot(sessionId, delta.serial, remainingPublishes ++ publishes)

    val newDeltas = Deltas(sessionId = sessionId, from = serial, to = delta.serial, deltas = List(delta))

    copy(serial = delta.serial, snapshot = newSnapshot, deltas = (List(newDeltas) ++ deltas).take(MaxDeltas), events = events :+ receivedDelta)
  }

  def publish(messages: List[PublicationProtocolMessage]) = applyEvent(PublicationServerReceivedDelta(id, Delta(serial = serial.add(BigInteger.ONE), messages = messages)))

  /**
   * Create a notification file for the current version, with pointers to full dumps and deltas
   */
  def notificationFile: Notification = {

    val snapshotReference = SnapshotReference(uri = snapshotUrl, serial = serial, hash = ReferenceHash.fromXml(snapshot.toXml))
    val deltasReferences = deltas.map { d =>
      DeltaReference(uri = deltaUrl(d.from, d.to), from = d.from, to = d.to, hash = ReferenceHash.fromXml(d.toXml))
    }

    Notification(sessionId, serial, List(snapshotReference), deltasReferences)
  }

  private def snapshotUrl = BaseUri.resolve(s"${sessionId}/snapshot/snapshot-${serial}.xml")
  private def deltaUrl(from: BigInteger, to: BigInteger) = BaseUri.resolve(s"${sessionId}/deltas/delta-${from}-${to}.xml")

}

object PublicationServer {
  def create(aggregateId: UUID) = PublicationServer(null, null, null, null).applyEvent(PublicationServerCreated(aggregateId, UUID.randomUUID()))
  def rebuild(events: List[Event]) = PublicationServer(null, null, null, null).applyEvents(events)
}