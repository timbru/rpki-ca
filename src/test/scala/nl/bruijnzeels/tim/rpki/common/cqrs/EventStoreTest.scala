/**
 * Copyright (c) 2014-2016 Tim Bruijnzeels
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
package nl.bruijnzeels.tim.rpki.common.cqrs

import java.net.URI
import java.util.UUID

import nl.bruijnzeels.tim.rpki.publication.server.{PublicationServer, PublicationServerCreated}
import org.scalatest.{FunSuite, Matchers}

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class EventStoreTest extends FunSuite with Matchers {

  test("Should let listener subscribe to new events") {

    val PublicationServerId = UUID.fromString("170cd869-f729-47e7-9415-38b21da67ac1")
    val RrdpBaseUrl = URI.create("http://localhost:8080/rrdp/")
    val server = PublicationServer.create(PublicationServerId, RrdpBaseUrl)

    val listener = new EventListener {
        override def handle(storedEvents: List[StoredEvent]) = {
          storedEvents should have size (1)
          val stored = storedEvents(0)
          stored.aggregateType should equal (PublicationServerAggregate)
          stored.versionedId should equal (VersionedId(PublicationServerId, 1))
          stored.event.isInstanceOf[PublicationServerCreated] should be (true)
        }
    }
    EventStore.subscribe(listener)

    EventStore.store(server);
  }

}