package nl.bruijnzeels.tim.rpki.ca.common.cqrs

import scala.collection.Map
import java.util.UUID

object EventStore {

  // TODO: Use persistent thread safe storage, sign and verify this shit!, log this stuff?
  var storedEventList: List[StoredEvent] = List.empty

  var listeners: List[EventListener] = List.empty

  def subscribe(listener: EventListener) = listeners = listeners :+ listener

  def retrieve(aggregateId: UUID): List[Event] = storedEventList.filter(_.versionedId.id == aggregateId).map(_.event)

  def store(events: List[Event], newVersionedId: VersionedId): Unit =  {
    val newStoredEvents = events.map(StoredEvent(newVersionedId, _))
    
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

case class StoredEvent(versionedId: VersionedId, event: Event)