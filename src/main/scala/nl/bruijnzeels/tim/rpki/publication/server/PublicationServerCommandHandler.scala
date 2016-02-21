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

import java.util.UUID

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.{EventStore, PublicationServerAggregate}

object PublicationServerCommandDispatcher {

  def load(id: UUID): Option[PublicationServer] = {
    val events = EventStore.retrieve(PublicationServerAggregate, id)
    if (events.size == 0) {
      None
    } else {
      Some(PublicationServer.rebuild(events).clearEventList())
    }
  }

  def save(server: PublicationServer) = {
    EventStore.store(server)
  }

  def dispatch(command: PublicationServerCommand) = {
    val serverId = command.versionedId.id
    val existingServer = load(serverId)

    if (existingServer.isDefined && command.isInstanceOf[PublicationServerCreate]) {
      throw new IllegalArgumentException(s"Can't create new CA with id ${serverId}, TA with same id exists")
    }

    if (!existingServer.isDefined && !command.isInstanceOf[PublicationServerCreate]) {
      throw new IllegalArgumentException(s"Can't find exisiting CA with id ${serverId} for command")
    }

    val updatedCa = command match {
      case create: PublicationServerCreate => PublicationServerCreateHandler.handle(create)
      case publish: PublicationServerPublish => PublicationServerPublishHandler.handle(publish, existingServer.get)
    }

    save(updatedCa)
    updatedCa
  }
}

object PublicationServerCreateHandler {
  def handle(create: PublicationServerCreate) = PublicationServer.create(create.aggregateId, create.rrdpBaseUri)
}

sealed trait PublicationServerCommandHandler[C <: PublicationServerCommand] {
  def handle(command: C, server: PublicationServer): PublicationServer
}

object PublicationServerPublishHandler extends PublicationServerCommandHandler[PublicationServerPublish] {
  def handle(command: PublicationServerPublish, server: PublicationServer) = server.publish(command.messages)
}

