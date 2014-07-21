package nl.bruijnzeels.tim.rpki.ca.common.cqrs

import scala.collection.Map
import java.util.UUID

object EventStore {

  // TODO: Use persistent thread safe storage, sign and verify this shit!, log this stuff?
  var eventList: List[Event] = List.empty

  def retrieve(aggregateId: UUID): List[Event] = eventList.filter(_.aggregateId == aggregateId)
  def store(events: List[Event]): Unit = eventList = eventList ++ events
  def clear(): Unit = eventList = List.empty
}
