package nl.bruijnzeels.tim.rpki.ca.common.cqrs

import org.scalatest.Finders
import org.scalatest.FunSuite
import org.scalatest.Matchers
import nl.bruijnzeels.tim.rpki.publication.server.PublicationServer
import java.util.UUID

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class EventStoreTest extends FunSuite with Matchers {

  test("Should let listener subscribe to new events") {

    case object TestEvent extends Event
    
    val events = List(TestEvent)
    val newVersionedId = VersionedId(UUID.randomUUID())
    
    val expectedStored = events.map(StoredEvent(newVersionedId, _))

    val listener = new EventListener {
      override def handle(events: List[StoredEvent]) = { events should equal (expectedStored) }
    }
    EventStore.subscribe(listener)

    EventStore.store(events, newVersionedId);
  }

}