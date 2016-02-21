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
package nl.bruijnzeels.tim.rpki.ca.common.cqrs

import java.util.UUID

object EventStore {

  // TODO: Use persistent thread safe storage, sign and verify this shit!, log this stuff?
  var storedEventList: List[StoredEvent] = List.empty

  var listeners: List[EventListener] = List.empty

  def subscribe(listener: EventListener) = listeners = listeners :+ listener

  def retrieve(aggregateType: AggregateRootType, aggregateId: UUID): List[Event] = storedEventList.filter(e => e.aggregateType == aggregateType && e.versionedId.id == aggregateId).map(_.event)

  def store(aggregate: AggregateRoot): Unit =  {
    val aggregateType = aggregate.aggregateType
    val newVersionedId = aggregate.versionedId.next
    val newStoredEvents = aggregate.events.map(StoredEvent(aggregateType, newVersionedId, _))

    storedEventList = storedEventList ++ newStoredEvents
    listeners.foreach(l => l.handle(newStoredEvents))
  }

  def clear(): Unit = {
    storedEventList = List.empty
    listeners = List.empty
  }
}

trait EventListener {
    def handle(events: List[StoredEvent]): Unit
}

case class StoredEvent(aggregateType: AggregateRootType, versionedId: VersionedId, event: Event)