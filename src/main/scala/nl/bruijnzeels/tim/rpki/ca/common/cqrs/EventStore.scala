package nl.bruijnzeels.tim.rpki.ca.common.cqrs

import scala.collection.Map
import java.util.UUID

object EventStore {
  
  // TODO: Have a nice thread safe event store. Use STM?
  var eventList: List[Event] = List.empty
  
  def retrieve(aggregateId: UUID): List[Event] = eventList.filter(_.id == aggregateId)
  def store(events: List[Event]): Unit = eventList = eventList ++ events
  def clear(): Unit = eventList = List.empty
}
