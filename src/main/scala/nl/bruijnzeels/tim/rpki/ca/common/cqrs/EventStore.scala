package nl.bruijnzeels.tim.rpki.ca.common.cqrs

import scala.collection.Map
import java.util.UUID

object EventStore {

  // TODO: Use persistent thread safe storage, sign and verify this shit!, log this stuff?
  var eventList: List[Event] = List.empty

  var listeners: List[EventListener] = List.empty

  def subscribe(listener: EventListener) = listeners = listeners :+ listener

  def retrieve(aggregateId: UUID): List[Event] = eventList.filter(_.aggregateId == aggregateId)

  def store(events: List[Event]): Unit =  {
    eventList = eventList ++ events
    listeners.foreach(l => l.handle(events))
  }

  def clear(): Unit = {
    eventList = List.empty
    listeners = List.empty
  }
}

trait EventListener {
    def handle(events: List[Event]): Unit
}
