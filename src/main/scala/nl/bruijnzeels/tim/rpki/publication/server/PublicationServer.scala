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
package nl.bruijnzeels.tim.rpki.publication.server

import scala.Option.option2Iterable
import java.math.BigInteger
import java.net.URI
import java.util.UUID
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.AggregateRoot
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import nl.bruijnzeels.tim.rpki.publication.messages.Delta
import nl.bruijnzeels.tim.rpki.publication.messages.DeltaReference
import nl.bruijnzeels.tim.rpki.publication.messages.Notification
import nl.bruijnzeels.tim.rpki.publication.messages.PublicationProtocolMessage
import nl.bruijnzeels.tim.rpki.publication.messages.Publish
import nl.bruijnzeels.tim.rpki.publication.messages.ReferenceHash
import nl.bruijnzeels.tim.rpki.publication.messages.Snapshot
import nl.bruijnzeels.tim.rpki.publication.messages.SnapshotReference
import nl.bruijnzeels.tim.rpki.publication.messages.Withdraw
import nl.bruijnzeels.tim.rpki.publication.messages.DeltaProtocolMessage
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.VersionedId
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.PublicationServerAggregate

case class PublicationServer(
  versionedId: VersionedId,
  sessionId: UUID,
  rrdpBaseUri: URI,
  serial: BigInteger,
  snapshot: Snapshot,
  deltas: List[Delta] = List.empty,
  events: List[Event] = List.empty) extends AggregateRoot {

  private val MaxDeltas = 100

  override def applyEvents(events: List[Event]): PublicationServer = events.foldLeft(this)((updated, event) => updated.applyEvent(event))
  override def clearEventList(): PublicationServer = copy(events = List.empty)
  override def aggregateType = PublicationServerAggregate

  def applyEvent(event: Event): PublicationServer = event match {
    case created: PublicationServerCreated =>
      copy(versionedId = VersionedId(created.aggregateId),
        sessionId = created.sessionId,
        rrdpBaseUri = created.rrdpBaseUri,
        serial = BigInteger.ZERO,
        snapshot = Snapshot(created.sessionId, BigInteger.ZERO, List.empty),
        events = events :+ event)
    case receivedDelta: PublicationServerReceivedDelta => copy(deltas = (List(receivedDelta.delta) ++ deltas).take(MaxDeltas), events = events :+ receivedDelta)
    case receivedSnapshot: PublicationServerReceivedSnapshot => copy(serial = receivedSnapshot.snapshot.serial, snapshot = receivedSnapshot.snapshot, events = events :+ receivedSnapshot)
  }

  def publish(messages: List[PublicationProtocolMessage]) = {

    val deltaReceivedEvent = {
      PublicationServerReceivedDelta(Delta(sessionId = sessionId, serial = serial.add(BigInteger.ONE), messages = messages))
    }

    val snapshotReceivedEvent = {
      val publishes = messages.collect { case p: Publish => p }

      val withdrawnHashes = messages.collect { case w: Withdraw => w }.map { _.hash }
      val updatedHashes = publishes.flatMap(_.replaces)
      val hashesToRemove = withdrawnHashes ++ updatedHashes

      val remainingPublishes = snapshot.publishes.filterNot(o => hashesToRemove.contains(ReferenceHash.fromBytes(o.repositoryObject.getEncoded)))

      val newSnapshot = Snapshot(sessionId, serial.add(BigInteger.ONE), remainingPublishes ++ publishes)
      PublicationServerReceivedSnapshot(newSnapshot)
    }

    applyEvents(List(deltaReceivedEvent, snapshotReceivedEvent))
  }

  /**
   * Create a notification file for the current version, with pointers to full dumps and deltas
   */
  def notificationFile: Notification = {

    val snapshotReference = SnapshotReference(uri = fileUrl(snapshot), hash = ReferenceHash.fromXml(snapshot.toXml))
    val deltasReferences = deltas.map { d =>
      DeltaReference(uri = fileUrl(d), serial = d.serial, hash = ReferenceHash.fromXml(d.toXml))
    }

    Notification(sessionId, serial, snapshotReference, deltasReferences)
  }

  private def fileUrl(file: DeltaProtocolMessage) = rrdpBaseUri.resolve(s"${ReferenceHash.fromXml(file.toXml)}.xml")

}

object PublicationServer {
  def create(aggregateId: UUID, baseUri: URI) = PublicationServer(null, null, null, null, null).applyEvent(PublicationServerCreated(aggregateId, UUID.randomUUID(), baseUri))
  def rebuild(events: List[Event]) = PublicationServer(null, null, null, null, null).applyEvents(events)
}