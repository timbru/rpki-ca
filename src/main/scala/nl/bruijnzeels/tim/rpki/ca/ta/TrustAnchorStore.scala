package nl.bruijnzeels.tim.rpki.ca.ta

import java.util.UUID
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event

object TrustAnchorStore {

  def load(id: UUID): Option[TrustAnchor] = {
    val events = TaEventStore.retrieve(id)
    if (events.size == 0) {
      None
    } else {
      Some(TrustAnchor.rebuild(events).clearEventList())
    }
  }

  def save(ta: TrustAnchor) = {
    TaEventStore.store(ta.events)
  }

}

object TaEventStore {

  // TODO: Have a nice thread safe event store. Use STM?
  var eventList: List[Event] = List.empty

  def retrieve(aggregateId: UUID): List[Event] = eventList.filter(_.aggregateId == aggregateId)
  def store(events: List[Event]): Unit = eventList = eventList ++ events
  def clear(): Unit = eventList = List.empty
}